use anyhow::Result;
use rscan_net::{expand_targets, parse_ports};
use rscan_plugins::{OpenService, PluginDefinition};
use std::collections::BTreeSet;

pub(crate) fn expand_direct_host_ports(specs: &[String]) -> Result<Vec<OpenService>> {
    let mut targets = Vec::new();

    for spec in specs {
        let Some((host_spec, port_spec)) = spec.split_once(':') else {
            continue;
        };
        let port = port_spec.parse::<u16>()?;
        for host in expand_targets(&[host_spec.to_string()])? {
            if !targets
                .iter()
                .any(|existing: &OpenService| existing.host == host && existing.port == port)
            {
                targets.push(OpenService { host, port });
            }
        }
    }

    Ok(targets)
}

pub(crate) fn count_unique_hosts(open_ports: &[OpenService]) -> usize {
    open_ports
        .iter()
        .map(|open| open.host.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

pub(crate) fn append_unique_open_ports(
    target: &mut Vec<rscan_net::OpenPort>,
    extras: Vec<OpenService>,
) {
    for extra in extras {
        if !target
            .iter()
            .any(|existing| existing.host == extra.host && existing.port == extra.port)
        {
            target.push(rscan_net::OpenPort {
                host: extra.host,
                port: extra.port,
            });
        }
    }
}

pub(crate) fn parse_ports_or_empty(spec: &str) -> Result<Vec<u16>> {
    if spec.trim().is_empty() {
        Ok(Vec::new())
    } else {
        parse_ports(spec)
    }
}

pub(crate) fn exclude_hosts(hosts: Vec<String>, excluded_hosts: &[String]) -> Vec<String> {
    if excluded_hosts.is_empty() {
        return hosts;
    }

    let excluded = excluded_hosts.iter().collect::<BTreeSet<_>>();
    hosts
        .into_iter()
        .filter(|host| !excluded.contains(host))
        .collect()
}

pub(crate) fn exclude_ports(ports: Vec<u16>, excluded_ports: &[u16]) -> Vec<u16> {
    if excluded_ports.is_empty() {
        return ports;
    }

    let excluded = excluded_ports.iter().copied().collect::<BTreeSet<_>>();
    ports
        .into_iter()
        .filter(|port| !excluded.contains(port))
        .collect()
}

pub(crate) fn build_web_targets(
    explicit_urls: &[String],
    open_ports: &[rscan_net::OpenPort],
) -> Result<Vec<String>> {
    let web_ports = parse_ports("web")?.into_iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();

    for url in explicit_urls {
        if seen.insert(url.clone()) {
            targets.push(url.clone());
        }
    }

    for open in open_ports {
        if web_ports.contains(&open.port) {
            let target = format!("{}:{}", open.host, open.port);
            if seen.insert(target.clone()) {
                targets.push(target);
            }
        }
    }

    Ok(targets)
}

pub(crate) fn build_service_targets(
    mode: &str,
    _plugin_defs: &[PluginDefinition],
    scan_hosts: &[String],
    scan_ports: &[u16],
    open_ports: &[rscan_net::OpenPort],
) -> Vec<OpenService> {
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();

    for open in open_ports {
        let key = (open.host.clone(), open.port);
        if seen.insert(key.clone()) {
            targets.push(OpenService {
                host: key.0,
                port: key.1,
            });
        }
    }

    if mode.eq_ignore_ascii_case("all") {
        return targets;
    }

    for host in scan_hosts {
        for port in scan_ports {
            let key = (host.clone(), *port);
            if seen.insert(key.clone()) {
                targets.push(OpenService {
                    host: key.0,
                    port: key.1,
                });
            }
        }
    }

    targets
}
