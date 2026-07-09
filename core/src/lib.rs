use anyhow::Result;
use rscan_config::AppConfig;
use rscan_fingerprint::{ServiceFingerprintTarget, fingerprint_services};
use rscan_net::{expand_targets, parse_ports, probe_live_hosts, scan_tcp_ports};
use rscan_output::{ResultType, ScanResult, keys};
use rscan_plugins::{scan_services, select_plugins};
use rscan_poc::{PocExecutionOptions, filter_pocs, load_embedded_pocs, load_pocs_from_path};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;
mod pipeline;
mod result_builders;
mod summary;
mod targets;
pub(crate) use pipeline::target_count;
use pipeline::{
    build_plugin_context, build_service_runtime_bundle, execute_pocs_for_targets,
    is_local_only_mode, plugin_result_type, scan_web_targets, selected_local_modules,
};
use result_builders::{
    build_fingerprint_scan_result, build_local_results, build_web_scan_result, now_timestamp,
    selected_web_modules,
};
pub use summary::{ExecutionReport, ScanSummary};
use summary::{
    enabled_disabled, liveness_mode, summarize_counted_items, summarize_items, top_alive_subnets,
};
use targets::{
    append_unique_open_ports, build_service_targets, build_web_targets, count_unique_hosts,
    exclude_hosts, exclude_ports, expand_direct_host_ports, parse_ports_or_empty,
};

#[derive(Debug, Clone)]
pub struct Application {
    config: AppConfig,
}

impl Application {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub fn render_scan_plan(&self) -> Result<String> {
        let mode = self.config.scan.mode.to_string();
        let local_modules = selected_local_modules(&mode, self.config.scan.local_mode);
        let resolved = self.config.resolve_inputs()?;
        let expanded_hosts = expand_targets(&resolved.hosts)?;
        let direct_host_ports = expand_direct_host_ports(&resolved.host_ports)?;
        let excluded_hosts = expand_targets(&resolved.exclude_hosts)?;
        let ports = parse_ports(&resolved.ports)?;
        let excluded_ports = parse_ports_or_empty(&resolved.exclude_ports)?;
        let service_plugins = select_plugins(&mode)
            .into_iter()
            .map(|plugin| plugin.key.to_string())
            .collect::<Vec<_>>();
        let web_modules = selected_web_modules(&mode);
        let selected_pocs = self.selected_pocs()?;
        let selected_poc_names = selected_pocs
            .iter()
            .map(|poc| poc.name.clone())
            .collect::<Vec<_>>();

        Ok(format!(
            "scan plan:\n  mode: {}\n  targets: {}\n  hosts: {}\n  ports: {}\n  excluded_hosts: {}\n  excluded_ports: {}\n  service_plugins: {}\n  web_modules: {}\n  local_modules: {}\n  selected_pocs: {}\n  fingerprint: {}\n  threads: scan={}, module={}, poc={}\n  timeouts: scan={}s, global={}s, web={}s\n  liveness: {}",
            mode,
            target_count(&self.config),
            expanded_hosts.len() + count_unique_hosts(&direct_host_ports),
            ports.len() + direct_host_ports.len(),
            excluded_hosts.len(),
            excluded_ports.len(),
            summarize_items(&service_plugins),
            summarize_items(&web_modules),
            summarize_items(&local_modules),
            summarize_counted_items(&selected_poc_names),
            enabled_disabled(self.config.scan.enable_fingerprint),
            self.config.scan.threads,
            self.config.scan.module_threads,
            self.config.poc.workers,
            self.config.scan.timeout_secs,
            self.config.scan.global_timeout_secs,
            self.config.web.web_timeout_secs,
            liveness_mode(&self.config),
        ))
    }

    pub fn run(&self) -> Result<ExecutionReport> {
        self.run_with_emitter(|_| Ok(()))
    }

    /// Run the full scan pipeline, invoking `emit` for each finding as it is
    /// produced (progressive emission). The returned report still contains the
    /// complete result set for summary generation.
    pub fn run_with_emitter<F>(&self, mut emit: F) -> Result<ExecutionReport>
    where
        F: FnMut(ScanResult) -> Result<()>,
    {
        let mode = self.config.scan.mode.to_string();
        let local_modules = selected_local_modules(&mode, self.config.scan.local_mode);
        let local_only_mode = !local_modules.is_empty() && is_local_only_mode(&mode);
        let resolved = self.config.resolve_inputs()?;
        let expanded_hosts = expand_targets(&resolved.hosts)?;
        let direct_open_ports = expand_direct_host_ports(&resolved.host_ports)?;
        let excluded_hosts = expand_targets(&resolved.exclude_hosts)?;
        let ports = parse_ports(&resolved.ports)?;
        let excluded_ports = parse_ports_or_empty(&resolved.exclude_ports)?;
        let scan_hosts = exclude_hosts(expanded_hosts, &excluded_hosts);
        let candidate_host_count = scan_hosts.len() + count_unique_hosts(&direct_open_ports);
        let scan_ports = exclude_ports(ports, &excluded_ports);
        let mut results = Vec::new();
        let mut alive_hosts = Vec::new();

        let push =
            |result: ScanResult, results: &mut Vec<ScanResult>, emit: &mut F| -> Result<()> {
                emit(result.clone())?;
                results.push(result);
                Ok(())
            };

        let scan_hosts = if local_only_mode
            || scan_hosts.len() <= 1
            || self.config.scan.disable_ping
            || scan_ports.is_empty()
        {
            scan_hosts
        } else {
            let liveness = probe_live_hosts(
                &scan_hosts,
                Duration::from_secs(self.config.scan.timeout_secs.clamp(1, 3)),
                usize::from(self.config.scan.threads),
                self.config.scan.use_ping,
            )?;
            if liveness.attempted {
                for alive in &liveness.alive_hosts {
                    push(
                        ScanResult {
                            time: now_timestamp(),
                            kind: ResultType::Host,
                            target: alive.host.clone(),
                            status: "alive".to_string(),
                            details: BTreeMap::from([(
                                keys::PROTOCOL.to_string(),
                                json!(alive.protocol),
                            )]),
                        },
                        &mut results,
                        &mut emit,
                    )?;
                }
                alive_hosts = liveness
                    .alive_hosts
                    .iter()
                    .map(|alive| alive.host.clone())
                    .collect::<Vec<_>>();
                liveness
                    .alive_hosts
                    .into_iter()
                    .map(|alive| alive.host)
                    .collect::<Vec<_>>()
            } else {
                scan_hosts
            }
        };
        let mut open_ports = if local_only_mode || scan_hosts.is_empty() || scan_ports.is_empty() {
            Vec::new()
        } else {
            scan_tcp_ports(
                &scan_hosts,
                &scan_ports,
                Duration::from_secs(self.config.scan.timeout_secs),
                usize::from(self.config.scan.threads),
            )?
        };
        append_unique_open_ports(&mut open_ports, direct_open_ports);
        for open in &open_ports {
            push(
                ScanResult {
                    time: now_timestamp(),
                    kind: ResultType::Port,
                    target: open.host.clone(),
                    status: "open".to_string(),
                    details: BTreeMap::from([(keys::PORT.to_string(), json!(open.port))]),
                },
                &mut results,
                &mut emit,
            )?;
        }
        let fingerprint_results = if self.config.scan.enable_fingerprint && !open_ports.is_empty() {
            fingerprint_services(
                &open_ports
                    .iter()
                    .map(|open| ServiceFingerprintTarget {
                        host: open.host.clone(),
                        port: open.port,
                    })
                    .collect::<Vec<_>>(),
                Duration::from_secs(5),
                usize::from(self.config.scan.threads),
            )?
        } else {
            Vec::new()
        };
        for fp in &fingerprint_results {
            push(build_fingerprint_scan_result(fp), &mut results, &mut emit)?;
        }
        let service_plugin_defs = select_plugins(&mode);
        let service_targets = build_service_targets(
            &mode,
            &service_plugin_defs,
            &scan_hosts,
            &scan_ports,
            &open_ports,
        );
        let service_findings = if service_plugin_defs.is_empty() || service_targets.is_empty() {
            Vec::new()
        } else {
            let runtime = build_service_runtime_bundle(&self.config, &resolved);
            scan_services(
                &service_targets,
                &mode,
                &build_plugin_context(&self.config, &resolved),
                &runtime,
            )?
        };
        let service_finding_count = service_findings.len();
        for finding in service_findings {
            push(
                ScanResult {
                    time: now_timestamp(),
                    kind: plugin_result_type(&finding.plugin),
                    target: finding.target.host,
                    status: finding.status,
                    details: finding.details,
                },
                &mut results,
                &mut emit,
            )?;
        }
        let web_targets = if local_only_mode {
            Vec::new()
        } else {
            build_web_targets(&resolved.urls, &open_ports)?
        };
        let web_results = scan_web_targets(
            &web_targets,
            &self.config.web,
            usize::from(self.config.scan.threads),
        );
        let web_result_count = web_results.len();
        let selected_plugin_count =
            service_plugin_defs.len() + local_modules.len() + selected_web_modules(&mode).len();
        let local_results = build_local_results(&local_modules)?;
        let local_result_count = local_results.len();
        for result in local_results {
            push(result, &mut results, &mut emit)?;
        }
        for web in &web_results {
            push(build_web_scan_result(web), &mut results, &mut emit)?;
        }
        let selected_pocs = self.selected_pocs()?;
        let poc_target_count = if selected_pocs.is_empty() {
            0
        } else {
            web_results.len()
        };
        let poc_matches = if selected_pocs.is_empty() || web_results.is_empty() {
            Vec::new()
        } else {
            let options = PocExecutionOptions {
                timeout_secs: self.config.web.web_timeout_secs,
                cookie: self.config.web.cookie.clone(),
                http_proxy: self.config.web.http_proxy.clone(),
                socks5_proxy: self.config.web.socks5_proxy.clone(),
                workers: usize::from(self.config.poc.workers),
            };
            execute_pocs_for_targets(&web_results, &selected_pocs, &options)?
        };
        let poc_match_count = poc_matches.len();
        for poc in poc_matches {
            let mut details = BTreeMap::from([(keys::POC.to_string(), json!(poc.poc_name))]);
            if let Some(group) = poc.group.filter(|group| !group.is_empty()) {
                details.insert(keys::GROUP.to_string(), json!(group));
            }
            if !poc.variables.is_empty() {
                details.insert(keys::VARIABLES.to_string(), json!(poc.variables));
            }
            push(
                ScanResult {
                    time: now_timestamp(),
                    kind: ResultType::Vuln,
                    target: poc.target,
                    status: "vulnerable".to_string(),
                    details,
                },
                &mut results,
                &mut emit,
            )?;
        }
        let alive_subnets_16 = if candidate_host_count > 1000 {
            top_alive_subnets(&alive_hosts, 16, usize::from(self.config.scan.live_top))
        } else {
            Vec::new()
        };
        let alive_subnets_24 = if candidate_host_count > 256 {
            top_alive_subnets(&alive_hosts, 24, usize::from(self.config.scan.live_top))
        } else {
            Vec::new()
        };

        Ok(ExecutionReport {
            summary: ScanSummary {
                mode: self.config.scan.mode.to_string(),
                target_count: scan_hosts.len() + resolved.urls.len(),
                host_result_count: results
                    .iter()
                    .filter(|result| result.kind == ResultType::Host)
                    .count(),
                username_count: resolved.usernames.len(),
                password_count: resolved.passwords.len(),
                output_enabled: !self.config.output.no_write,
                threads: self.config.scan.threads,
                timeout_secs: self.config.scan.timeout_secs,
                port_count: if scan_hosts.is_empty() {
                    open_ports.len()
                } else {
                    scan_ports.len() + resolved.host_ports.len()
                },
                expanded_host_count: candidate_host_count,
                excluded_host_count: excluded_hosts.len(),
                excluded_port_count: if scan_hosts.is_empty() {
                    0
                } else {
                    excluded_ports.len()
                },
                open_port_count: open_ports.len(),
                web_target_count: web_targets.len(),
                web_result_count,
                selected_plugin_count,
                service_finding_count,
                local_result_count,
                poc_target_count,
                selected_poc_count: selected_pocs.len(),
                poc_match_count,
                alive_subnets_16,
                alive_subnets_24,
            },
            results,
        })
    }

    fn selected_pocs(&self) -> Result<Vec<rscan_poc::Poc>> {
        if self.config.poc.disable_poc_scan {
            return Ok(Vec::new());
        }
        if !self.config.poc.full && self.config.poc.poc_name.is_none() {
            return Ok(Vec::new());
        }

        let all = if let Some(path) = &self.config.poc.poc_path {
            load_pocs_from_path(path)?
        } else {
            load_embedded_pocs()?
        };
        let selected = if let Some(name) = &self.config.poc.poc_name {
            filter_pocs(&all, name).into_iter().cloned().collect()
        } else {
            all
        };
        Ok(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rscan_fingerprint::ServiceFingerprint;
    use rscan_web::WebScanResult;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn emits_results_progressively_during_port_scan() {
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_emit = Arc::clone(&seen);
        let report = Application::new(
            AppConfig::from_tokens([
                "-h",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-np",
                "-silent",
                "-no",
            ])
            .expect("config should parse"),
        )
        .run_with_emitter(|result| {
            seen_for_emit
                .lock()
                .expect("seen lock")
                .push(result.kind.as_str().to_string());
            Ok(())
        })
        .expect("scan should succeed");

        let _ = std::net::TcpStream::connect(format!("127.0.0.1:{port}"));
        let _ = server.join();

        let emitted = seen.lock().expect("seen lock").clone();
        assert!(
            emitted.iter().any(|kind| kind == "PORT"),
            "expected progressive PORT emission, got {emitted:?}; report={:?}",
            report.results
        );
        assert!(
            report
                .results
                .iter()
                .any(|result| result.kind == ResultType::Port),
            "report should still contain port results"
        );
    }

    #[test]
    fn executes_discovery_scan_and_applies_exclusions() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let report = Application::new(
            AppConfig::from_tokens([
                "-h",
                "127.0.0.1,127.0.0.2",
                "-eh",
                "127.0.0.2",
                "-p",
                &format!("{port},65534"),
                "-ep",
                "65534",
                "-t",
                "8",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        assert_eq!(report.summary.expanded_host_count, 1);
        assert_eq!(report.summary.excluded_host_count, 1);
        assert_eq!(report.summary.port_count, 1);
        assert_eq!(report.summary.excluded_port_count, 1);
        assert_eq!(report.summary.open_port_count, 1);
        assert_eq!(report.summary.service_finding_count, 0);
        assert_eq!(report.summary.web_result_count, 0);
        assert_eq!(report.summary.local_result_count, 0);
        assert_eq!(report.summary.poc_match_count, 0);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].kind, ResultType::Port);
        assert_eq!(report.results[0].target, "127.0.0.1");
        assert_eq!(report.results[0].details["port"], json!(port));
    }

    #[test]
    fn executes_web_scan_for_url_targets() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = "<html><title>RabbitMQ UI</title>RabbitMQ Management</html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        let report = Application::new(
            AppConfig::from_tokens(["-u", &format!("http://127.0.0.1:{port}")])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.web_target_count, 1);
        assert_eq!(report.summary.web_result_count, 1);
        assert_eq!(report.summary.service_finding_count, 0);
        assert_eq!(report.summary.local_result_count, 0);
        assert_eq!(report.summary.poc_match_count, 0);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].kind, ResultType::Service);
        assert_eq!(report.results[0].status, "identified");
        assert_eq!(report.results[0].details["title"], json!("RabbitMQ UI"));
    }

    #[test]
    fn executes_web_scan_for_discovered_web_ports() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = [18080_u16, 18082, 19001, 20000]
            .into_iter()
            .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
            .expect("listener should bind on a known web port");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (_probe, _) = listener.accept().expect("probe should arrive");
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("web request should arrive");
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .expect("timeout should set");
                let mut buffer = [0u8; 1024];
                let size = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..size]);
                if request.contains("GET ") {
                    let body = "<html><title>Auto Web</title></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("response should write");
                    break;
                }
            }
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string()])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.open_port_count, 1);
        assert_eq!(report.summary.web_target_count, 1);
        assert_eq!(report.summary.web_result_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service && result.details["title"] == json!("Auto Web")
        }));
    }

    #[test]
    fn executes_named_poc_for_url_targets() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 2048];
                let size = stream.read(&mut buffer).expect("request should read");
                let request = String::from_utf8_lossy(&buffer[..size]);
                let body = if request.contains("GET /app/kibana ") {
                    "<html><body>.kibanaWelcomeView</body></html>"
                } else {
                    "<html><title>Kibana</title></html>"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should write");
            }
        });

        let report = Application::new(
            AppConfig::from_tokens([
                "-u",
                &format!("http://127.0.0.1:{port}"),
                "-pocname",
                "kibana-unauth",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.selected_poc_count, 1);
        assert_eq!(report.summary.poc_target_count, 1);
        assert_eq!(report.summary.poc_match_count, 1);
        assert_eq!(report.summary.service_finding_count, 0);
        assert_eq!(report.summary.local_result_count, 0);
        assert!(
            report
                .results
                .iter()
                .any(|result| result.kind == ResultType::Service)
        );
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "vulnerable"
                && result.details["poc"] == json!("poc-yaml-kibana-unauth")
        }));
    }

    #[test]
    fn loads_selected_pocs_from_custom_path() {
        use std::{env, fs};

        let root = env::temp_dir().join(format!("rscan-core-poc-test-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temp poc dir should exist");
        fs::write(
            root.join("custom.yaml"),
            "name: poc-yaml-custom-core\nrules:\n  - method: GET\n    path: /\n    expression: response.status == 200\n",
        )
        .expect("custom poc should write");

        let app = Application::new(
            AppConfig::from_tokens(["-full", "-pocpath", root.to_string_lossy().as_ref()])
                .expect("config should parse"),
        );
        let selected = app.selected_pocs().expect("custom pocs should load");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "poc-yaml-custom-core");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn renders_scan_plan_with_selected_poc_details() {
        let plan = Application::new(
            AppConfig::from_tokens([
                "-u",
                "http://127.0.0.1:8080",
                "-pocname",
                "kibana-unauth",
                "-num",
                "8",
            ])
            .expect("config should parse"),
        )
        .render_scan_plan()
        .expect("plan should render");

        assert!(plan.contains("scan plan:"));
        assert!(plan.contains("selected_pocs: 1 (poc-yaml-kibana-unauth)"));
        assert!(plan.contains("threads: scan=600, module=10, poc=8"));
        assert!(plan.contains("timeouts: scan=3s, global=180s, web=5s"));
        assert!(plan.contains("liveness: icmp"));
    }

    #[test]
    fn records_alive_hosts_before_port_scan() {
        use std::net::{SocketAddr, TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let _ = listener.accept();
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1,198.51.100.1", "-p", &port.to_string()])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Host
                && result.target == "127.0.0.1"
                && result.status == "alive"
                && result.details["protocol"] == json!("ICMP")
        }));
        assert_eq!(report.summary.host_result_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Port
                && result.target == "127.0.0.1"
                && result.details["port"] == json!(port)
        }));

        let _ = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(200),
        );
        let _ = server.join();
    }

    #[test]
    fn records_service_fingerprint_results_when_enabled() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("connection should arrive");
                stream
                    .write_all(b"SSH-2.0-OpenSSH_9.6\r\n")
                    .expect("banner should write");
            }
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-fingerprint"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "identified"
                && result.details["service"] == json!("ssh")
                && result.details["banner"] == json!("SSH-2.0-OpenSSH_9.6.")
        }));
    }

    #[test]
    fn records_unknown_service_fingerprint_results_when_no_match_exists() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("connection should arrive");
                stream
                    .write_all(b"mystery service banner\r\n")
                    .expect("banner should write");
            }
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-fingerprint"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "identified"
                && result.details["service"] == json!("unknown")
                && result.details["banner"] == json!("mystery service banner.")
        }));
    }

    #[test]
    fn records_html_body_service_fingerprint_as_http() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("connection should arrive");
                stream
                    .write_all(b"<html><title>hello</title></html>\r\n")
                    .expect("banner should write");
            }
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-fingerprint"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "identified"
                && result.details["service"] == json!("http")
                && result.details["banner"] == json!("<html><title>hello</title></html>.")
        }));
    }

    #[test]
    fn keeps_go_style_fingerprint_timeout_for_slow_banners() {
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let _ = listener.accept().expect("port probe should arrive");
            let (mut stream, _) = listener
                .accept()
                .expect("fingerprint connection should arrive");
            thread::sleep(Duration::from_secs(4));
            stream
                .write_all(b"SSH-2.0-OpenSSH_9.6\r\n")
                .expect("banner should write");
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-fingerprint"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "identified"
                && result.details["service"] == json!("ssh")
                && result.details["banner"] == json!("SSH-2.0-OpenSSH_9.6.")
        }));
    }

    #[test]
    fn omits_empty_fingerprint_banner_from_service_results() {
        let result = build_fingerprint_scan_result(&ServiceFingerprint {
            host: "127.0.0.1".to_string(),
            port: 443,
            service: "https".to_string(),
            version: None,
            banner: String::new(),
            extras: BTreeMap::from([("vendor_product".to_string(), "nginx".to_string())]),
        });

        assert_eq!(result.kind, ResultType::Service);
        assert_eq!(result.status, "identified");
        assert_eq!(result.details["port"], json!(443));
        assert_eq!(result.details["service"], json!("https"));
        assert_eq!(result.details["product"], json!("nginx"));
        assert!(!result.details.contains_key("banner"));
    }

    #[test]
    fn keeps_only_go_visible_fingerprint_extra_fields() {
        let result = build_fingerprint_scan_result(&ServiceFingerprint {
            host: "127.0.0.1".to_string(),
            port: 8080,
            service: "http".to_string(),
            version: Some("1.0".to_string()),
            banner: "HTTP/1.1 200 OK".to_string(),
            extras: BTreeMap::from([
                ("vendor_product".to_string(), "nginx".to_string()),
                ("os".to_string(), "linux".to_string()),
                ("info".to_string(), "reverse proxy".to_string()),
                ("hostname".to_string(), "edge01".to_string()),
                ("device_type".to_string(), "load balancer".to_string()),
                ("cpe".to_string(), "cpe:/a:nginx:nginx".to_string()),
            ]),
        });

        assert_eq!(result.details["product"], json!("nginx"));
        assert_eq!(result.details["os"], json!("linux"));
        assert_eq!(result.details["info"], json!("reverse proxy"));
        assert!(!result.details.contains_key("hostname"));
        assert!(!result.details.contains_key("device_type"));
        assert!(!result.details.contains_key("cpe"));
    }

    #[test]
    fn includes_go_style_web_result_details() {
        let result = build_web_scan_result(&WebScanResult {
            original_target: "127.0.0.1:18080".to_string(),
            requested_url: "http://127.0.0.1:18080/".to_string(),
            final_url: "http://127.0.0.1:18080/".to_string(),
            status_code: 200,
            title: "RabbitMQ UI".to_string(),
            length: "1234".to_string(),
            headers: BTreeMap::from([
                ("server".to_string(), "nginx".to_string()),
                ("content-type".to_string(), "text/html".to_string()),
            ]),
            fingerprints: vec!["RabbitMQ".to_string()],
        });

        assert_eq!(result.kind, ResultType::Service);
        assert_eq!(result.status, "identified");
        assert_eq!(result.details["service"], json!("http"));
        assert_eq!(result.details["Url"], json!("http://127.0.0.1:18080/"));
        assert_eq!(result.details["port"], json!("18080"));
        assert_eq!(result.details["length"], json!("1234"));
        assert_eq!(result.details["fingerprints"], json!(vec!["RabbitMQ"]));
        assert_eq!(result.details["server_info"]["title"], json!("RabbitMQ UI"));
        assert_eq!(result.details["server_info"]["status_code"], json!(200));
        assert_eq!(result.details["server_info"]["server"], json!("nginx"));
    }

    #[test]
    fn includes_redirect_url_for_redirected_web_results() {
        let result = build_web_scan_result(&WebScanResult {
            original_target: "127.0.0.1:8080".to_string(),
            requested_url: "http://127.0.0.1:8080/".to_string(),
            final_url: "https://127.0.0.1:8443/login".to_string(),
            status_code: 200,
            title: "Login".to_string(),
            length: "20".to_string(),
            headers: BTreeMap::new(),
            fingerprints: Vec::new(),
        });

        assert_eq!(
            result.details["server_info"]["redirect_Url"],
            json!("https://127.0.0.1:8443/login")
        );
    }

    #[test]
    fn ranks_alive_subnets_by_count() {
        let ranked = top_alive_subnets(
            &[
                "10.0.1.1".to_string(),
                "10.0.1.2".to_string(),
                "10.0.2.1".to_string(),
                "10.0.2.2".to_string(),
                "10.0.2.3".to_string(),
            ],
            24,
            1,
        );

        assert_eq!(ranked, vec![("10.0.2.0/24".to_string(), 3)]);
    }

    #[test]
    fn counts_named_webtitle_mode_as_selected_plugin() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = "<html><title>Named WebTitle</title></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        let report = Application::new(
            AppConfig::from_tokens(["-m", "webtitle", "-u", &format!("http://127.0.0.1:{port}")])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.web_result_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "identified"
                && result.details["title"] == json!("Named WebTitle")
        }));
    }

    #[test]
    fn counts_named_webpoc_mode_as_selected_plugin() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 2048];
                let size = stream.read(&mut buffer).expect("request should read");
                let request = String::from_utf8_lossy(&buffer[..size]);
                let body = if request.contains("GET /app/kibana ") {
                    "<html><body>.kibanaWelcomeView</body></html>"
                } else {
                    "<html><title>Named WebPoc</title></html>"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should write");
            }
        });

        let report = Application::new(
            AppConfig::from_tokens([
                "-m",
                "webpoc",
                "-u",
                &format!("http://127.0.0.1:{port}"),
                "-pocname",
                "kibana-unauth",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.selected_poc_count, 1);
        assert_eq!(report.summary.poc_match_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "vulnerable"
                && result.details["poc"] == json!("poc-yaml-kibana-unauth")
        }));
    }

    #[test]
    fn executes_memcached_service_plugin() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 2048];
                let size = stream.read(&mut buffer).expect("request should read");
                let request = String::from_utf8_lossy(&buffer[..size]);
                if request.starts_with("stats") {
                    stream
                        .write_all(b"STAT pid 1\r\nEND\r\n")
                        .expect("response should write");
                } else {
                    stream
                        .write_all(b"VERSION 1.6.9\r\n")
                        .expect("response should write");
                }
            }
        });

        let report = Application::new(
            AppConfig::from_tokens([
                "-h",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-m",
                "memcached",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.service_finding_count, 1);
        assert_eq!(report.summary.local_result_count, 0);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "unauthorized-access"
                && result.details["service"] == json!("memcached")
        }));
    }

    #[test]
    fn executes_snmp_service_plugin_without_tcp_open_port() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket should bind");
        let port = socket.local_addr().expect("local addr").port();

        let server = std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            let (size, peer) = socket
                .recv_from(&mut buffer)
                .expect("request should arrive");
            assert!(size > 0);
            socket
                .send_to(&snmp_response_bytes("public", "Core SNMP"), peer)
                .expect("response should write");
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-m", "snmp"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert_eq!(report.summary.open_port_count, 0);
        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.service_finding_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "weak-community"
                && result.details["service"] == json!("snmp")
        }));
    }

    #[test]
    fn collects_local_info_in_local_mode() {
        let report =
            Application::new(AppConfig::from_tokens(["-local"]).expect("config should parse"))
                .run()
                .expect("scan should run");

        assert_eq!(report.summary.local_result_count, 1);
        assert_eq!(report.summary.selected_plugin_count, 32);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "local-info"
                && result.details.contains_key("hostname")
        }));
    }

    #[test]
    fn collects_local_info_in_named_localinfo_mode() {
        let report = Application::new(
            AppConfig::from_tokens(["-m", "localinfo"]).expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        assert_eq!(report.summary.open_port_count, 0);
        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.local_result_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "local-info"
                && result.target == "localhost"
        }));
    }

    #[test]
    fn named_dcinfo_mode_is_noop_on_non_windows() {
        let report = Application::new(
            AppConfig::from_tokens(["-m", "dcinfo"]).expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        assert_eq!(report.summary.open_port_count, 0);
        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.service_finding_count, 0);
        assert_eq!(report.summary.local_result_count, 0);
    }

    #[test]
    fn named_minidump_mode_is_noop_on_non_windows() {
        let report = Application::new(
            AppConfig::from_tokens(["-m", "minidump"]).expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        assert_eq!(report.summary.open_port_count, 0);
        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.service_finding_count, 0);
        assert_eq!(report.summary.local_result_count, 0);
    }

    fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + value.len());
        encoded.push(tag);
        encoded.push(value.len() as u8);
        encoded.extend_from_slice(value);
        encoded
    }

    fn ber_integer(value: i32) -> Vec<u8> {
        ber_tlv(0x02, &[(value & 0xff) as u8])
    }

    fn ber_octet_string(value: &[u8]) -> Vec<u8> {
        ber_tlv(0x04, value)
    }

    fn snmp_response_bytes(community: &str, system: &str) -> Vec<u8> {
        let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let varbind = ber_tlv(
            0x30,
            &[ber_tlv(0x06, &oid), ber_octet_string(system.as_bytes())].concat(),
        );
        let varbinds = ber_tlv(0x30, &varbind);
        let pdu = ber_tlv(
            0xa2,
            &[ber_integer(1), ber_integer(0), ber_integer(0), varbinds].concat(),
        );
        ber_tlv(
            0x30,
            &[ber_integer(1), ber_octet_string(community.as_bytes()), pdu].concat(),
        )
    }
}
