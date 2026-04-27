use anyhow::{Result, anyhow};
use std::collections::{BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const SERVICE_PORTS: &str = "21,22,23,25,110,135,139,143,162,389,445,465,502,587,636,873,993,995,1433,1521,2222,3306,3389,5020,5432,5672,5671,6379,8161,8443,9000,9092,9093,9200,10051,11211,15672,15671,27017,61616,61613";
const DB_PORTS: &str = "1433,1521,3306,5432,5672,6379,7687,9042,9093,9200,11211,27017,61616";
const WEB_PORTS: &str = "80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8005,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10051,10250,12018,12443,14000,15672,15671,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,20880,21000,21501,21502,28018";
const MAIN_PORTS: &str = "21,22,23,80,81,110,135,139,143,389,443,445,502,873,993,995,1433,1521,3306,5432,5672,6379,7001,7687,8000,8005,8009,8080,8089,8443,9000,9042,9092,9200,10051,11211,15672,27017,61616";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliveHost {
    pub host: String,
    pub protocol: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliveHostProbe {
    pub attempted: bool,
    pub alive_hosts: Vec<AliveHost>,
}

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();

    for item in spec
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some(group) = named_port_group(item) {
            for port in parse_ports(group)? {
                ports.insert(port);
            }
            continue;
        }

        if let Some((start, end)) = item.split_once('-') {
            let Ok(start) = start.parse::<u16>() else {
                continue;
            };
            let Ok(end) = end.parse::<u16>() else {
                continue;
            };
            let (from, to) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };

            for port in from..=to {
                if port != 0 {
                    ports.insert(port);
                }
            }
        } else {
            let Ok(port) = item.parse::<u16>() else {
                continue;
            };
            if port != 0 {
                ports.insert(port);
            }
        }
    }

    Ok(ports.into_iter().collect())
}

fn named_port_group(value: &str) -> Option<&'static str> {
    match value {
        "service" => Some(SERVICE_PORTS),
        "db" => Some(DB_PORTS),
        "web" => Some(WEB_PORTS),
        "all" => Some("1-65535"),
        "main" => Some(MAIN_PORTS),
        _ => None,
    }
}

pub fn expand_targets(specs: &[String]) -> Result<Vec<String>> {
    let mut targets = Vec::new();

    for spec in specs {
        append_expanded_target(&mut targets, spec)?;
    }

    Ok(targets)
}

pub fn scan_tcp_ports(
    hosts: &[String],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
) -> Result<Vec<OpenPort>> {
    let mut queue = VecDeque::new();
    for host in hosts {
        for port in ports {
            queue.push_back((host.clone(), *port));
        }
    }

    let queue = Arc::new(Mutex::new(queue));
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let worker_count = concurrency
        .max(1)
        .min(hosts.len().saturating_mul(ports.len()).max(1));

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let open_ports = Arc::clone(&open_ports);
            let errors = Arc::clone(&errors);

            scope.spawn(move || {
                loop {
                    let next = {
                        let mut queue = queue.lock().expect("queue lock poisoned");
                        queue.pop_front()
                    };

                    let Some((host, port)) = next else {
                        break;
                    };

                    match try_connect(&host, port, timeout) {
                        Ok(true) => open_ports
                            .lock()
                            .expect("open port lock poisoned")
                            .push(OpenPort { host, port }),
                        Ok(false) => {}
                        Err(error) => errors.lock().expect("error lock poisoned").push(error),
                    }
                }
            });
        }
    });

    let errors = Arc::try_unwrap(errors)
        .expect("all workers should exit")
        .into_inner()
        .expect("error lock poisoned");
    if let Some(error) = errors.into_iter().next() {
        return Err(error);
    }

    let mut open_ports = Arc::try_unwrap(open_ports)
        .expect("all workers should exit")
        .into_inner()
        .expect("open port lock poisoned");
    open_ports.sort_by(|left, right| {
        left.host
            .cmp(&right.host)
            .then_with(|| left.port.cmp(&right.port))
    });
    Ok(open_ports)
}

pub fn probe_live_hosts(
    hosts: &[String],
    timeout: Duration,
    concurrency: usize,
    use_ping_label: bool,
) -> Result<AliveHostProbe> {
    if hosts.is_empty() {
        return Ok(AliveHostProbe {
            attempted: false,
            alive_hosts: Vec::new(),
        });
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(hosts.to_vec())));
    let alive_hosts = Arc::new(Mutex::new(Vec::new()));
    let attempted = Arc::new(Mutex::new(false));
    let command_missing = Arc::new(Mutex::new(false));
    let worker_count = concurrency.max(1).min(hosts.len()).min(50);
    let protocol = if use_ping_label { "PING" } else { "ICMP" };

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let alive_hosts = Arc::clone(&alive_hosts);
            let attempted = Arc::clone(&attempted);
            let command_missing = Arc::clone(&command_missing);

            scope.spawn(move || {
                loop {
                    if *command_missing
                        .lock()
                        .expect("command missing lock poisoned")
                    {
                        break;
                    }

                    let next = {
                        let mut queue = queue.lock().expect("queue lock poisoned");
                        queue.pop_front()
                    };
                    let Some(host) = next else {
                        break;
                    };

                    match ping_host(&host, timeout) {
                        Ok(alive) => {
                            *attempted.lock().expect("attempted lock poisoned") = true;
                            if alive {
                                alive_hosts
                                    .lock()
                                    .expect("alive host lock poisoned")
                                    .push(AliveHost { host, protocol });
                            }
                        }
                        Err(PingError::CommandUnavailable) => {
                            *command_missing
                                .lock()
                                .expect("command missing lock poisoned") = true;
                            break;
                        }
                    }
                }
            });
        }
    });

    let attempted = *attempted.lock().expect("attempted lock poisoned");
    let command_missing = *command_missing
        .lock()
        .expect("command missing lock poisoned");
    let mut alive_hosts = Arc::try_unwrap(alive_hosts)
        .expect("all workers should exit")
        .into_inner()
        .expect("alive host lock poisoned");
    alive_hosts.sort_by(|left, right| left.host.cmp(&right.host));
    alive_hosts.dedup_by(|left, right| left.host == right.host);
    Ok(AliveHostProbe {
        attempted: attempted && !command_missing,
        alive_hosts,
    })
}

fn try_connect(host: &str, port: u16, timeout: Duration) -> Result<bool> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        return Ok(TcpStream::connect_timeout(&addr, timeout).is_ok());
    }

    let addr = format!("{host}:{port}");
    let socket_addrs = addr
        .to_socket_addrs()
        .map_err(|error| anyhow!("failed to resolve {addr}: {error}"))?;

    for socket_addr in socket_addrs {
        if TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

#[derive(Debug)]
enum PingError {
    CommandUnavailable,
}

fn ping_host(host: &str, timeout: Duration) -> std::result::Result<bool, PingError> {
    let timeout_secs = timeout.as_secs().max(1).min(u64::from(u32::MAX));
    let mut command = Command::new("ping");
    if cfg!(target_os = "windows") {
        command.args([
            "-n",
            "1",
            "-w",
            &timeout_secs.saturating_mul(1000).to_string(),
            host,
        ]);
    } else if cfg!(target_os = "macos") {
        command.args(["-c", "1", "-W", &timeout_secs.to_string(), host]);
    } else {
        command.args(["-c", "1", "-w", &timeout_secs.to_string(), host]);
    }

    match command.output() {
        Ok(output) => Ok(output.status.success()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(PingError::CommandUnavailable)
        }
        Err(_) => Ok(false),
    }
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
            append_unique(targets, expand_cidr(item)?);
            continue;
        }

        if item.contains('-') && is_ipv4_range(item) {
            append_unique(targets, expand_range(item)?);
            continue;
        }

        if item.parse::<Ipv4Addr>().is_ok() || looks_like_hostname(item) {
            append_unique(targets, [item.to_string()]);
            continue;
        }

        return Err(anyhow!("unsupported target spec: {item}"));
    }

    Ok(())
}

fn expand_alias(value: &str) -> Option<&'static str> {
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
    let first_octet = base_ip.octets()[0];
    let mut hosts = Vec::with_capacity(674);
    let common_second_octets = [0u8, 1, 2, 10, 100, 200, 254];

    for second_octet in common_second_octets {
        for third_octet in (0u8..=250).step_by(10) {
            hosts.push(Ipv4Addr::new(first_octet, second_octet, third_octet, 1).to_string());
            hosts.push(Ipv4Addr::new(first_octet, second_octet, third_octet, 254).to_string());
            hosts.push(
                Ipv4Addr::new(
                    first_octet,
                    second_octet,
                    third_octet,
                    sampled_host_octet(first_octet, second_octet, third_octet, 0),
                )
                .to_string(),
            );
        }
    }

    for second_octet in (0u8..=224).step_by(32) {
        for third_octet in (0u8..=224).step_by(32) {
            hosts.push(Ipv4Addr::new(first_octet, second_octet, third_octet, 1).to_string());
            hosts.push(
                Ipv4Addr::new(
                    first_octet,
                    second_octet,
                    third_octet,
                    sampled_host_octet(first_octet, second_octet, third_octet, 1),
                )
                .to_string(),
            );
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

fn append_unique(targets: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !targets.iter().any(|existing| existing == &value) {
            targets.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener};

    #[test]
    fn parses_named_port_groups() {
        let ports = parse_ports("main").expect("ports should parse");
        assert!(ports.contains(&21));
        assert!(ports.contains(&3306));
        assert!(ports.contains(&61616));
    }

    #[test]
    fn parses_port_ranges() {
        let ports = parse_ports("80,443,100-102").expect("ports should parse");
        assert_eq!(ports, vec![80, 100, 101, 102, 443]);
    }

    #[test]
    fn parses_named_port_groups_per_item() {
        let ports = parse_ports("main,web,10086").expect("ports should parse");
        assert!(ports.contains(&21));
        assert!(ports.contains(&18080));
        assert!(ports.contains(&10086));
    }

    #[test]
    fn skips_invalid_port_tokens_like_go() {
        let ports = parse_ports("80,abc,70000,10-12,1-x,0,443").expect("ports should parse");
        assert_eq!(ports, vec![10, 11, 12, 80, 443]);
    }

    #[test]
    fn expands_short_aliases_and_ranges() {
        let hosts = expand_targets(&["192.168.1.1-3".to_string(), "example.com".to_string()])
            .expect("targets should expand");
        assert_eq!(
            hosts,
            vec![
                "192.168.1.1".to_string(),
                "192.168.1.2".to_string(),
                "192.168.1.3".to_string(),
                "example.com".to_string()
            ]
        );
    }

    #[test]
    fn expands_cidr_targets() {
        let hosts = expand_targets(&["192.168.1.0/30".to_string()]).expect("cidr should expand");
        assert_eq!(
            hosts,
            vec![
                "192.168.1.0".to_string(),
                "192.168.1.1".to_string(),
                "192.168.1.2".to_string(),
                "192.168.1.3".to_string()
            ]
        );
    }

    #[test]
    fn expands_large_full_ranges_without_error() {
        let hosts =
            expand_targets(&["10.0.0.0-10.1.0.0".to_string()]).expect("range should expand");
        assert_eq!(hosts.len(), 65_537);
        assert_eq!(hosts.first().map(String::as_str), Some("10.0.0.0"));
        assert_eq!(hosts.last().map(String::as_str), Some("10.1.0.0"));
    }

    #[test]
    fn expands_10_alias_with_sampling() {
        let hosts = expand_targets(&["10".to_string()]).expect("alias should expand");
        assert_eq!(hosts.len(), 672);
        assert!(hosts.contains(&"10.0.0.1".to_string()));
        assert!(hosts.contains(&"10.254.250.254".to_string()));
    }

    #[test]
    fn expands_172_alias_without_error() {
        assert_eq!(expand_alias("172"), Some("172.16.0.0/12"));
    }

    #[test]
    fn scans_open_tcp_port() {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("test listener should bind on localhost");
        let port = listener
            .local_addr()
            .expect("listener should have a local addr")
            .port();

        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });

        let results = scan_tcp_ports(
            &["127.0.0.1".to_string()],
            &[port],
            Duration::from_millis(300),
            4,
        )
        .expect("tcp scan should succeed");

        assert_eq!(
            results,
            vec![OpenPort {
                host: "127.0.0.1".to_string(),
                port
            }]
        );

        let _ = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)));
        let _ = handle.join();
    }

    #[test]
    fn probes_localhost_as_alive() {
        let probe = probe_live_hosts(&["127.0.0.1".to_string()], Duration::from_secs(1), 4, true)
            .expect("liveness probe should succeed");

        assert!(probe.attempted);
        assert_eq!(
            probe.alive_hosts,
            vec![AliveHost {
                host: "127.0.0.1".to_string(),
                protocol: "PING",
            }]
        );
    }
}
