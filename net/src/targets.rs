use anyhow::{Result, anyhow};
use std::net::Ipv4Addr;

pub fn expand_targets(specs: &[String]) -> Result<Vec<String>> {
    let mut targets = Vec::new();

    for spec in specs {
        append_expanded_target(&mut targets, spec)?;
    }
    dedup_preserving_order(&mut targets);

    Ok(targets)
}

fn append_expanded_target(targets: &mut Vec<String>, spec: &str) -> Result<()> {
    if spec.is_empty() {
        return Ok(());
    }

    for item in spec
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some(alias) = expand_alias(item) {
            append_expanded_target(targets, alias)?;
            continue;
        }

        if item.contains('/') {
            extend_expanded(targets, expand_cidr(item)?);
            continue;
        }

        if item.contains('-') && is_ipv4_range(item) {
            extend_expanded(targets, expand_range(item)?);
            continue;
        }

        if item.parse::<Ipv4Addr>().is_ok() || looks_like_hostname(item) {
            extend_expanded(targets, [item.to_string()]);
            continue;
        }

        return Err(anyhow!("unsupported target spec: {item}"));
    }

    Ok(())
}

pub(crate) fn expand_alias(value: &str) -> Option<&'static str> {
    match value {
        "10" => Some("10.0.0.0/8"),
        "172" => Some("172.16.0.0/12"),
        "192" => Some("192.168.0.0/16"),
        _ => None,
    }
}

fn expand_cidr(cidr: &str) -> Result<Vec<String>> {
    let (ip, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid cidr: {cidr}"))?;
    let base_ip = ip
        .parse::<Ipv4Addr>()
        .map_err(|_| anyhow!("invalid cidr ip: {cidr}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| anyhow!("invalid cidr prefix: {cidr}"))?;

    if prefix > 32 {
        return Err(anyhow!("invalid cidr prefix: {cidr}"));
    }

    if prefix == 8 {
        return Ok(sample_subnet8(base_ip));
    }

    let host_bits = 32 - prefix as u32;
    let max_hosts = 1u64 << host_bits;
    if max_hosts > 1_048_576 {
        return Err(anyhow!("cidr too large to expand safely: {cidr}"));
    }

    let base = u32::from(base_ip) & (!0u32 << host_bits);
    let count = 1u32 << host_bits;
    let mut hosts = Vec::with_capacity(count as usize);
    for offset in 0..count {
        hosts.push(Ipv4Addr::from(base + offset).to_string());
    }
    Ok(hosts)
}

fn sample_subnet8(base_ip: Ipv4Addr) -> Vec<String> {
    use std::collections::HashSet;
    let first_octet = base_ip.octets()[0];
    let mut seen = HashSet::with_capacity(674);
    let mut hosts = Vec::with_capacity(674);
    let common_second_octets = [0u8, 1, 2, 10, 100, 200, 254];

    for second_octet in common_second_octets {
        for third_octet in (0u8..=250).step_by(10) {
            let ip1 = Ipv4Addr::new(first_octet, second_octet, third_octet, 1).to_string();
            if seen.insert(ip1.clone()) {
                hosts.push(ip1);
            }
            let ip2 = Ipv4Addr::new(first_octet, second_octet, third_octet, 254).to_string();
            if seen.insert(ip2.clone()) {
                hosts.push(ip2);
            }
            let ip3 = Ipv4Addr::new(
                first_octet,
                second_octet,
                third_octet,
                sampled_host_octet(first_octet, second_octet, third_octet, 0),
            )
            .to_string();
            if seen.insert(ip3.clone()) {
                hosts.push(ip3);
            }
        }
    }

    for second_octet in (0u8..=224).step_by(32) {
        for third_octet in (0u8..=224).step_by(32) {
            let ip1 = Ipv4Addr::new(first_octet, second_octet, third_octet, 1).to_string();
            if seen.insert(ip1.clone()) {
                hosts.push(ip1);
            }
            let ip2 = Ipv4Addr::new(
                first_octet,
                second_octet,
                third_octet,
                sampled_host_octet(first_octet, second_octet, third_octet, 1),
            )
            .to_string();
            if seen.insert(ip2.clone()) {
                hosts.push(ip2);
            }
        }
    }

    hosts
}

fn sampled_host_octet(first_octet: u8, second_octet: u8, third_octet: u8, salt: u8) -> u8 {
    2 + ((u16::from(first_octet) * 31
        + u16::from(second_octet) * 17
        + u16::from(third_octet) * 13
        + u16::from(salt) * 19)
        % 252) as u8
}

fn expand_range(spec: &str) -> Result<Vec<String>> {
    let (start, end) = spec
        .split_once('-')
        .ok_or_else(|| anyhow!("invalid range: {spec}"))?;
    let start_ip = start
        .parse::<Ipv4Addr>()
        .map_err(|_| anyhow!("invalid start ip: {spec}"))?;

    if let Ok(end_ip) = end.parse::<Ipv4Addr>() {
        return expand_full_range(start_ip, end_ip);
    }

    let suffix = end
        .parse::<u8>()
        .map_err(|_| anyhow!("invalid end ip range: {spec}"))?;
    let start_octets = start_ip.octets();
    if start_octets[3] > suffix {
        return Err(anyhow!("invalid short ip range: {spec}"));
    }

    let mut hosts = Vec::new();
    for last in start_octets[3]..=suffix {
        hosts.push(
            Ipv4Addr::new(start_octets[0], start_octets[1], start_octets[2], last).to_string(),
        );
    }
    Ok(hosts)
}

fn expand_full_range(start: Ipv4Addr, end: Ipv4Addr) -> Result<Vec<String>> {
    let start = u32::from(start);
    let end = u32::from(end);
    if start > end {
        return Err(anyhow!("invalid ip range"));
    }
    let count = u64::from(end - start) + 1;
    if count > 1_048_576 {
        return Err(anyhow!("ip range too large to expand safely"));
    }

    let mut hosts = Vec::with_capacity(count as usize);
    for current in start..=end {
        hosts.push(Ipv4Addr::from(current).to_string());
    }
    Ok(hosts)
}

fn looks_like_hostname(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
}

fn is_ipv4_range(value: &str) -> bool {
    value
        .split_once('-')
        .map(|(start, _)| start.parse::<Ipv4Addr>().is_ok())
        .unwrap_or(false)
}

fn extend_expanded(targets: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    targets.extend(values);
}

/// Remove duplicate targets while preserving first-occurrence order. Cross-spec
/// overlaps (e.g. an alias plus an explicit CIDR that intersects it) are
/// deduplicated once at the end rather than rebuilding a set of every target on
/// each append, which kept multi-spec expansion quadratic in practice.
fn dedup_preserving_order(targets: &mut Vec<String>) {
    use std::collections::HashSet;
    let mut seen = HashSet::with_capacity(targets.len());
    targets.retain(|value| seen.insert(value.clone()));
}
