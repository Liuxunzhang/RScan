use anyhow::{Result, anyhow};
use std::collections::BTreeSet;

use crate::port_groups::{DB_PORTS, MAIN_PORTS, SERVICE_PORTS, WEB_PORTS};

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
            let start = start
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid port range start: {item}"))?;
            let end = end
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid port range end: {item}"))?;
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
            let port = item
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid port: {item}"))?;
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
