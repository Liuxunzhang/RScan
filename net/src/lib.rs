use anyhow::{Result, anyhow};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

mod port_groups;
mod ports;
mod targets;

use port_groups::LIVENESS_TCP_PORTS;
pub use ports::parse_ports;
pub use targets::expand_targets;

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

/// Common TCP ports used as a liveness signal when ICMP is unavailable.

#[derive(Debug, Clone)]
struct ResolvedHost {
    host: String,
    addrs: Vec<IpAddr>,
}

/// Pre-resolve hosts once so the connect hot path never calls DNS per port.
fn resolve_hosts(hosts: &[String]) -> Result<Vec<ResolvedHost>> {
    let mut resolved = Vec::with_capacity(hosts.len());
    for host in hosts {
        let addrs = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            // Resolve with a dummy port; only the IP list is retained.
            let probe = format!("{host}:0");
            probe
                .to_socket_addrs()
                .map_err(|error| anyhow!("failed to resolve {host}: {error}"))?
                .map(|socket| socket.ip())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        if addrs.is_empty() {
            return Err(anyhow!("failed to resolve {host}: no addresses"));
        }
        resolved.push(ResolvedHost {
            host: host.clone(),
            addrs,
        });
    }
    Ok(resolved)
}

fn try_connect_resolved(addrs: &[IpAddr], port: u16, timeout: Duration) -> bool {
    for ip in addrs {
        let addr = SocketAddr::new(*ip, port);
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

pub fn scan_tcp_ports(
    hosts: &[String],
    ports: &[u16],
    timeout: Duration,
    concurrency: usize,
) -> Result<Vec<OpenPort>> {
    if hosts.is_empty() || ports.is_empty() {
        return Ok(Vec::new());
    }

    let resolved = resolve_hosts(hosts)?;
    let total_tasks = resolved.len().saturating_mul(ports.len());
    let next_index = AtomicUsize::new(0);
    let worker_count = concurrency.max(1).min(total_tasks);

    let mut open_ports = thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_index = &next_index;
            let resolved = &resolved;
            workers.push(scope.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    if index >= total_tasks {
                        break;
                    }

                    let host = &resolved[index / ports.len()];
                    let port = ports[index % ports.len()];
                    if try_connect_resolved(&host.addrs, port, timeout) {
                        local.push(OpenPort {
                            host: host.host.clone(),
                            port,
                        });
                    }
                }
                local
            }));
        }

        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("TCP scan worker panicked"))
            .collect::<Vec<_>>()
    });
    open_ports.sort_by(|left, right| {
        left.host
            .cmp(&right.host)
            .then_with(|| left.port.cmp(&right.port))
    });
    Ok(open_ports)
}

/// Primary liveness path: TCP connect probes against common ports (no external
/// `ping` process). Hosts that accept a connection on any probe port are alive.
/// When `use_ping_label` is true the reported protocol stays `"PING"` for
/// fscan-compatible labeling; otherwise `"ICMP"` (historical label even though
/// the primary probe is TCP connect / connection-refused based).
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

    let resolved = match resolve_hosts(hosts) {
        Ok(resolved) => resolved,
        Err(_) => {
            // Resolution failure: still report attempted=false so callers fall
            // back to scanning the full host list (same as historical behavior
            // when ping was unavailable).
            return Ok(AliveHostProbe {
                attempted: false,
                alive_hosts: Vec::new(),
            });
        }
    };

    let next_index = AtomicUsize::new(0);
    let total = resolved.len();
    let worker_count = concurrency.max(1).min(total).min(50);
    let protocol = if use_ping_label { "PING" } else { "ICMP" };

    let mut alive_hosts = thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_index = &next_index;
            let resolved = &resolved;
            workers.push(scope.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    if index >= total {
                        break;
                    }
                    let host = &resolved[index];
                    if host_is_alive_tcp(&host.addrs, timeout) {
                        local.push(AliveHost {
                            host: host.host.clone(),
                            protocol,
                        });
                    }
                }
                local
            }));
        }

        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("liveness worker panicked"))
            .collect::<Vec<_>>()
    });
    alive_hosts.sort_by(|left, right| left.host.cmp(&right.host));
    alive_hosts.dedup_by(|left, right| left.host == right.host);
    Ok(AliveHostProbe {
        attempted: true,
        alive_hosts,
    })
}

fn host_is_alive_tcp(addrs: &[IpAddr], timeout: Duration) -> bool {
    // Short per-port budget so multi-port liveness stays cheap.
    let per_port = timeout
        .checked_div(LIVENESS_TCP_PORTS.len() as u32)
        .unwrap_or(timeout)
        .max(Duration::from_millis(50))
        .min(timeout);

    for &port in LIVENESS_TCP_PORTS {
        if try_connect_resolved(addrs, port, per_port) {
            return true;
        }
    }

    // Final check: any TCP listener on a high-chance port already covered;
    // also treat successful ICMP-less hosts with open ephemeral listeners
    // via a zero-cost loopback-style connect attempt is not needed.
    // If the host rejects all probes with RST quickly, try_connect returns
    // false for closed ports — but for 127.0.0.1 tests we also accept a
    // connect to an ephemeral "is host reachable" via port 0 which is invalid.
    // Instead: consider host alive if ANY connect returns a definitive TCP
    // answer (open OR refused) rather than timeout/unreachable.
    host_is_reachable_tcp(addrs, per_port)
}

/// Returns true when the host yields a TCP response (open or actively refused)
/// on common ports, distinguishing dead/filtered hosts (timeouts) from live ones.
fn host_is_reachable_tcp(addrs: &[IpAddr], timeout: Duration) -> bool {
    for &port in LIVENESS_TCP_PORTS {
        for ip in addrs {
            let addr = SocketAddr::new(*ip, port);
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_) => return true,
                Err(error) => {
                    // Connection refused => host is up and actively rejecting.
                    if error.kind() == std::io::ErrorKind::ConnectionRefused {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::expand_alias;
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

    #[test]
    fn resolves_hosts_once_before_port_scan_hot_path() {
        // Hostname that maps to loopback; scanning multiple ports must not
        // re-resolve per port (covered by resolve_hosts preprocessing).
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("test listener should bind on localhost");
        let port = listener
            .local_addr()
            .expect("listener should have a local addr")
            .port();
        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });

        let resolved = resolve_hosts(&["localhost".to_string()]).expect("resolve localhost");
        assert_eq!(resolved.len(), 1);
        assert!(!resolved[0].addrs.is_empty());

        let closed = if port == 1 { 2 } else { 1 };
        let results = scan_tcp_ports(
            &["localhost".to_string()],
            &[port, closed],
            Duration::from_millis(300),
            4,
        )
        .expect("tcp scan should succeed");
        assert!(
            results
                .iter()
                .any(|open| open.host == "localhost" && open.port == port),
            "expected open port {port} on localhost, got {results:?}"
        );

        let _ = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)));
        let _ = handle.join();
    }

    #[test]
    fn liveness_marks_open_listener_host_alive_and_filters_dead() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        // Keep the listener alive for the duration of the probe.
        let _listener = listener;

        // 127.0.0.1 is always reachable (connection refused or open).
        let probe = probe_live_hosts(
            &["127.0.0.1".to_string(), "203.0.113.1".to_string()],
            Duration::from_millis(200),
            4,
            false,
        )
        .expect("liveness probe should succeed");

        assert!(probe.attempted);
        assert!(
            probe
                .alive_hosts
                .iter()
                .any(|host| host.host == "127.0.0.1" && host.protocol == "ICMP"),
            "127.0.0.1 should be alive: {:?}",
            probe.alive_hosts
        );
        // 203.0.113.0/24 is TEST-NET-3 (documentation); should time out as dead.
        assert!(
            !probe
                .alive_hosts
                .iter()
                .any(|host| host.host == "203.0.113.1"),
            "documentation address should not be alive: {:?}",
            probe.alive_hosts
        );
    }

    #[test]
    fn primary_liveness_path_does_not_spawn_ping_command() {
        // Structural + behavioral pin: probe_live_hosts succeeds without
        // requiring the external ping binary (TCP reachability under the hood).
        let probe = probe_live_hosts(
            &["127.0.0.1".to_string()],
            Duration::from_millis(500),
            2,
            false,
        )
        .expect("tcp liveness must work without external ping");
        assert!(probe.attempted);
        assert_eq!(probe.alive_hosts[0].protocol, "ICMP");
        // Source pin: production section (before tests) must use TCP helpers and
        // must not shell out via std::process.
        let source = include_str!("lib.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert!(
            production.contains("fn host_is_reachable_tcp"),
            "primary liveness path should use TCP reachability helpers"
        );
        let forbidden = ["std", "process", "Command"].join("::");
        assert!(
            !production.contains(&forbidden),
            "primary liveness path must not spawn external processes via {forbidden}"
        );
    }
}
