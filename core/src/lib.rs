use anyhow::Result;
use rscan_config::{AppConfig, parse_scan_mode_list};
use rscan_fingerprint::{ServiceFingerprint, ServiceFingerprintTarget, fingerprint_services};
use rscan_net::{expand_targets, parse_ports, probe_live_hosts, scan_tcp_ports};
use rscan_output::{ResultType, ScanResult};
use rscan_platform::{collect_dc_info, collect_local_system_info, collect_minidump};
use rscan_plugins::{
    AuthRuntimeOptions, ConnectionRuntimeOptions, OpenService, PluginContext,
    RedisRuntimeOptions, ServiceScanRuntimeOptions, scan_services, select_plugins,
    set_auth_runtime_options, set_connection_runtime_options, set_redis_runtime_options,
    set_service_scan_runtime_options,
};
use rscan_poc::{
    PocExecutionOptions, execute_pocs, filter_pocs, load_embedded_pocs, load_pocs_from_path,
};
use rscan_web::{WebScanResult, poc_aliases_for_fingerprints, scan_target};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::time::Duration;
use time::{OffsetDateTime, macros::format_description};

#[derive(Debug, Clone)]
pub struct Application {
    config: AppConfig,
}

impl Application {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub fn validate_mode_selection(&self) -> Result<()> {
        validate_mode_selection(&self.config.scan.mode.to_string())
    }

    pub fn render_scan_plan(&self) -> Result<String> {
        self.validate_mode_selection()?;
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
        self.validate_mode_selection()?;
        let mode = self.config.scan.mode.to_string();
        let web_modules = selected_web_modules(&mode);
        let local_modules = selected_local_modules(&mode, self.config.scan.local_mode);
        let resolved = self.config.resolve_inputs()?;
        let local_only_mode = should_run_local_only(&self.config, &resolved, &local_modules);
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
        let scan_hosts = if local_only_mode
            || scan_hosts.len() <= 1
            || self.config.scan.disable_ping
            || scan_ports.is_empty()
        {
            scan_hosts
        } else {
            let liveness = probe_live_hosts(
                &scan_hosts,
                Duration::from_secs(self.config.scan.timeout_secs.min(3).max(1)),
                usize::from(self.config.scan.threads),
                self.config.scan.use_ping,
            )?;
            if liveness.attempted {
                results.extend(liveness.alive_hosts.iter().map(|alive| ScanResult {
                    time: now_timestamp(),
                    kind: ResultType::Host,
                    target: alive.host.clone(),
                    status: "alive".to_string(),
                    details: BTreeMap::from([("protocol".to_string(), json!(alive.protocol))]),
                }));
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
        results.extend(open_ports.iter().map(|open| ScanResult {
            time: now_timestamp(),
            kind: ResultType::Port,
            target: open.host.clone(),
            status: "open".to_string(),
            details: BTreeMap::from([("port".to_string(), json!(open.port))]),
        }));
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
        results.extend(
            fingerprint_results
                .iter()
                .map(build_fingerprint_scan_result),
        );
        let service_plugin_defs = select_plugins(&mode);
        let service_targets = build_service_targets(&mode, &open_ports);
        let service_findings = if service_plugin_defs.is_empty() || service_targets.is_empty() {
            Vec::new()
        } else {
            set_auth_runtime_options(AuthRuntimeOptions {
                domain: self.config.auth.domain.clone(),
                hashes: resolved.hashes.clone(),
                extra_usernames: resolved.extra_usernames.clone(),
                extra_passwords: resolved.extra_passwords.clone(),
                disable_brute: self.config.scan.disable_brute,
            });
            set_redis_runtime_options(RedisRuntimeOptions {
                redis_file: self.config.redis.redis_file.clone(),
                redis_shell: self.config.redis.redis_shell.clone(),
                disable_redis: self.config.redis.disable_redis,
                redis_write_path: self.config.redis.redis_write_path.clone(),
                redis_write_content: self.config.redis.redis_write_content.clone(),
                redis_write_file: self.config.redis.redis_write_file.clone(),
            });
            set_connection_runtime_options(ConnectionRuntimeOptions {
                max_retries: self.config.scan.max_retries,
            });
            set_service_scan_runtime_options(ServiceScanRuntimeOptions {
                module_threads: self.config.scan.module_threads,
                global_timeout_secs: self.config.scan.global_timeout_secs,
                log_errors: self.config.output.log_level.eq_ignore_ascii_case("debug"),
            });
            scan_services(
                &service_targets,
                &mode,
                &PluginContext {
                    usernames: resolved.usernames.clone(),
                    passwords: resolved.passwords.clone(),
                    timeout_secs: self.config.scan.timeout_secs,
                    ssh_key_path: self.config.auth.ssh_key_path.clone(),
                },
            )?
        };
        let service_finding_count = service_findings.len();
        let should_run_web = should_run_web_scan(&mode, &resolved.urls, &web_modules);
        let include_all_open_ports_for_web =
            should_include_all_open_ports_for_web(&mode, &web_modules);
        let web_targets = if local_only_mode || !should_run_web {
            Vec::new()
        } else {
            build_web_targets(&resolved.urls, &open_ports, include_all_open_ports_for_web)?
        };
        let web_results = web_targets
            .iter()
            .filter_map(|target| scan_target(target, &self.config.web).ok())
            .collect::<Vec<_>>();
        let web_result_count = web_results.len();
        results.extend(service_findings.into_iter().map(|finding| ScanResult {
            time: now_timestamp(),
            kind: plugin_result_type(&finding.plugin),
            target: finding.target.host,
            status: finding.status,
            details: finding.details,
        }));
        let selected_plugin_count =
            service_plugin_defs.len() + local_modules.len() + web_modules.len();
        let local_results = build_local_results(&local_modules)?;
        let local_result_count = local_results.len();
        results.extend(local_results);
        results.extend(web_results.iter().map(build_web_scan_result));
        let selected_pocs = self.selected_pocs()?;
        let available_pocs = self.available_pocs()?;
        let poc_target_count = if available_pocs.is_empty() {
            0
        } else {
            web_results.len()
        };
        let poc_matches = if available_pocs.is_empty() || web_results.is_empty() {
            Vec::new()
        } else {
            let options = PocExecutionOptions {
                timeout_secs: self.config.web.web_timeout_secs,
                cookie: self.config.web.cookie.clone(),
                http_proxy: self.config.web.http_proxy.clone(),
                socks5_proxy: self.config.web.socks5_proxy.clone(),
                workers: usize::from(self.config.poc.workers),
            };
            let explicit_poc_name = self.config.poc.poc_name.as_deref();
            web_results
                .iter()
                .map(|target| {
                    let target_pocs =
                        select_pocs_for_web_result(&available_pocs, target, explicit_poc_name);
                    if target_pocs.is_empty() {
                        Ok(Vec::new())
                    } else {
                        execute_pocs(
                            &normalize_poc_target(&target.final_url),
                            &target_pocs,
                            &options,
                        )
                    }
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        };
        let poc_match_count = poc_matches.len();
        results.extend(poc_matches.into_iter().map(|poc| {
            let mut details = BTreeMap::from([("poc".to_string(), json!(poc.poc_name))]);
            if let Some(group) = poc.group.filter(|group| !group.is_empty()) {
                details.insert("group".to_string(), json!(group));
            }
            if !poc.variables.is_empty() {
                details.insert("variables".to_string(), json!(poc.variables));
            }
            ScanResult {
                time: now_timestamp(),
                kind: ResultType::Vuln,
                target: poc.target,
                status: "vulnerable".to_string(),
                details,
            }
        }));
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
        let all = self.available_pocs()?;
        let selected = if let Some(name) = &self.config.poc.poc_name {
            filter_pocs(&all, name).into_iter().cloned().collect()
        } else {
            all
        };
        Ok(selected)
    }

    fn available_pocs(&self) -> Result<Vec<rscan_poc::Poc>> {
        if self.config.poc.disable_poc_scan {
            return Ok(Vec::new());
        }
        let mode = self.config.scan.mode.to_string();
        let web_modules = selected_web_modules(&mode);
        let implicit_web_pocs =
            mode == "all" || web_modules.iter().any(|module| module == "webpoc");
        if !self.config.poc.full && self.config.poc.poc_name.is_none() && !implicit_web_pocs {
            return Ok(Vec::new());
        }

        if let Some(path) = &self.config.poc.poc_path {
            load_pocs_from_path(path)
        } else {
            load_embedded_pocs()
        }
    }
}

fn select_pocs_for_web_result(
    available_pocs: &[rscan_poc::Poc],
    target: &WebScanResult,
    explicit_poc_name: Option<&str>,
) -> Vec<rscan_poc::Poc> {
    if !target.fingerprints.is_empty() {
        let aliases = poc_aliases_for_fingerprints(&target.fingerprints);
        if aliases.is_empty() {
            return Vec::new();
        }

        let aliases = aliases
            .into_iter()
            .map(|alias| alias.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        return available_pocs
            .iter()
            .filter(|poc| {
                let poc_name = poc.name.to_ascii_lowercase();
                aliases.iter().any(|alias| poc_name.contains(alias))
            })
            .cloned()
            .collect();
    }

    if let Some(name) = explicit_poc_name {
        return filter_pocs(available_pocs, name)
            .into_iter()
            .cloned()
            .collect();
    }

    available_pocs.to_vec()
}

fn build_local_results(modules: &[String]) -> Result<Vec<ScanResult>> {
    let mut results = Vec::new();
    for module in modules {
        match module.as_str() {
            "localinfo" => results.push(build_local_info_result()?),
            "dcinfo" => {
                if let Some(result) = build_dcinfo_result()? {
                    results.push(result);
                }
            }
            "minidump" => {
                if let Some(result) = build_minidump_result()? {
                    results.push(result);
                }
            }
            _ => {}
        }
    }
    Ok(results)
}

fn selected_web_modules(mode: &str) -> Vec<String> {
    let selected = parse_scan_mode_list(mode);
    if selected.is_empty() {
        return Vec::new();
    }

    selected
        .into_iter()
        .filter(|item| matches!(item.as_str(), "webtitle" | "webpoc"))
        .collect()
}

fn validate_mode_selection(mode: &str) -> Result<()> {
    if mode == "all" {
        return Ok(());
    }

    let selected = parse_scan_mode_list(mode);
    if selected.is_empty() {
        return Ok(());
    }

    let mut allowed = rscan_plugins::registered_plugins()
        .into_iter()
        .map(|plugin| plugin.key.to_string())
        .collect::<BTreeSet<_>>();
    allowed.extend(
        ["webtitle", "webpoc", "localinfo", "dcinfo", "minidump"]
            .into_iter()
            .map(str::to_string),
    );

    let invalid = selected
        .into_iter()
        .filter(|item| !allowed.contains(item))
        .collect::<Vec<_>>();
    if invalid.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("invalid scan mode: {}", invalid.join(", "))
    }
}

fn should_run_web_scan(mode: &str, explicit_urls: &[String], web_modules: &[String]) -> bool {
    !explicit_urls.is_empty() || mode == "all" || !web_modules.is_empty()
}

fn should_include_all_open_ports_for_web(mode: &str, web_modules: &[String]) -> bool {
    mode != "all" && !web_modules.is_empty()
}

fn build_local_info_result() -> Result<ScanResult> {
    let local = collect_local_system_info()?;
    let mut details = BTreeMap::from([
        ("hostname".to_string(), json!(local.hostname)),
        ("username".to_string(), json!(local.username)),
        ("os".to_string(), json!(local.os)),
        ("arch".to_string(), json!(local.arch)),
    ]);
    if let Some(home_dir) = local.home_dir {
        details.insert(
            "home_dir".to_string(),
            json!(home_dir.to_string_lossy().to_string()),
        );
    }
    if let Some(current_dir) = local.current_dir {
        details.insert(
            "current_dir".to_string(),
            json!(current_dir.to_string_lossy().to_string()),
        );
    }
    if !local.sensitive_files.is_empty() {
        details.insert(
            "sensitive_files".to_string(),
            json!(
                local
                    .sensitive_files
                    .into_iter()
                    .map(|path| path.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
            ),
        );
    }
    Ok(ScanResult {
        time: now_timestamp(),
        kind: ResultType::Service,
        target: "localhost".to_string(),
        status: "local-info".to_string(),
        details,
    })
}

fn build_minidump_result() -> Result<Option<ScanResult>> {
    let Some(minidump) = collect_minidump()? else {
        return Ok(None);
    };

    Ok(Some(ScanResult {
        time: now_timestamp(),
        kind: ResultType::Vuln,
        target: "localhost".to_string(),
        status: "minidump-created".to_string(),
        details: BTreeMap::from([
            ("service".to_string(), json!("minidump")),
            ("process_name".to_string(), json!(minidump.process_name)),
            ("pid".to_string(), json!(minidump.pid)),
            (
                "output_path".to_string(),
                json!(minidump.output_path.to_string_lossy().to_string()),
            ),
        ]),
    }))
}

fn build_dcinfo_result() -> Result<Option<ScanResult>> {
    let Some(dcinfo) = collect_dc_info()? else {
        return Ok(None);
    };

    Ok(Some(ScanResult {
        time: now_timestamp(),
        kind: ResultType::Service,
        target: "localhost".to_string(),
        status: "dcinfo".to_string(),
        details: BTreeMap::from([
            ("service".to_string(), json!("dcinfo")),
            ("domain".to_string(), json!(dcinfo.domain)),
            (
                "domain_controllers".to_string(),
                json!(dcinfo.domain_controllers),
            ),
        ]),
    }))
}

fn should_run_local_only(
    config: &AppConfig,
    resolved: &rscan_config::ResolvedInputs,
    local_modules: &[String],
) -> bool {
    config.scan.local_mode
        || (!local_modules.is_empty()
            && resolved.hosts.is_empty()
            && resolved.host_ports.is_empty()
            && resolved.urls.is_empty())
}

fn selected_local_modules(mode: &str, local_mode: bool) -> Vec<String> {
    let selected = parse_scan_mode_list(mode)
        .into_iter()
        .filter(|item| matches!(item.as_str(), "localinfo" | "dcinfo" | "minidump"))
        .collect::<Vec<_>>();
    if !selected.is_empty() {
        selected
    } else if local_mode {
        all_local_modules()
    } else {
        Vec::new()
    }
}

fn all_local_modules() -> Vec<String> {
    vec![
        "localinfo".to_string(),
        "dcinfo".to_string(),
        "minidump".to_string(),
    ]
}

fn target_count(config: &AppConfig) -> usize {
    config.targets.defined_target_count()
}

fn expand_direct_host_ports(specs: &[String]) -> Result<Vec<OpenService>> {
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

fn count_unique_hosts(open_ports: &[OpenService]) -> usize {
    open_ports
        .iter()
        .map(|open| open.host.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

fn append_unique_open_ports(target: &mut Vec<rscan_net::OpenPort>, extras: Vec<OpenService>) {
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

fn liveness_mode(config: &AppConfig) -> &'static str {
    if config.scan.disable_ping {
        "disabled"
    } else if config.scan.use_ping {
        "ping"
    } else {
        "icmp"
    }
}

fn summarize_items(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn summarize_counted_items(items: &[String]) -> String {
    match items.len() {
        0 => "0".to_string(),
        1..=4 => format!("{} ({})", items.len(), items.join(", ")),
        _ => format!("{} ({} ...)", items.len(), items[..4].join(", ")),
    }
}

fn enabled_disabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

fn top_alive_subnets(hosts: &[String], prefix: u8, top: usize) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::new();
    for host in hosts {
        let Some(subnet) = subnet_bucket(host, prefix) else {
            continue;
        };
        *counts.entry(subnet).or_insert(0usize) += 1;
    }

    let mut ranked = counts.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked.truncate(top);
    ranked
}

fn subnet_bucket(host: &str, prefix: u8) -> Option<String> {
    let octets = host.parse::<std::net::Ipv4Addr>().ok()?.octets();
    match prefix {
        16 => Some(format!("{}.{}.0.0/16", octets[0], octets[1])),
        24 => Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])),
        _ => None,
    }
}

fn format_alive_subnets(items: &[(String, usize)]) -> String {
    items
        .iter()
        .map(|(subnet, count)| format!("{subnet}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    pub summary: ScanSummary,
    pub results: Vec<ScanResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub mode: String,
    pub target_count: usize,
    pub host_result_count: usize,
    pub username_count: usize,
    pub password_count: usize,
    pub output_enabled: bool,
    pub threads: u16,
    pub timeout_secs: u64,
    pub port_count: usize,
    pub expanded_host_count: usize,
    pub excluded_host_count: usize,
    pub excluded_port_count: usize,
    pub open_port_count: usize,
    pub web_target_count: usize,
    pub web_result_count: usize,
    pub selected_plugin_count: usize,
    pub service_finding_count: usize,
    pub local_result_count: usize,
    pub poc_target_count: usize,
    pub selected_poc_count: usize,
    pub poc_match_count: usize,
    pub alive_subnets_16: Vec<(String, usize)>,
    pub alive_subnets_24: Vec<(String, usize)>,
}

impl Display for ScanSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rscan workspace initialized (mode: {}, targets: {}, hosts: {}, alive_hosts: {}, ports: {}, excluded_hosts: {}, excluded_ports: {}, open_ports: {}, selected_plugins: {}, service_findings: {}, web_targets: {}, web_results: {}, local_results: {}, poc_targets: {}, selected_pocs: {}, poc_matches: {}, users: {}, passwords: {}, threads: {}, timeout: {}s, output: {})",
            self.mode,
            self.target_count,
            self.expanded_host_count,
            self.host_result_count,
            self.port_count,
            self.excluded_host_count,
            self.excluded_port_count,
            self.open_port_count,
            self.selected_plugin_count,
            self.service_finding_count,
            self.web_target_count,
            self.web_result_count,
            self.local_result_count,
            self.poc_target_count,
            self.selected_poc_count,
            self.poc_match_count,
            self.username_count,
            self.password_count,
            self.threads,
            self.timeout_secs,
            if self.output_enabled {
                "enabled"
            } else {
                "disabled"
            }
        )?;
        if !self.alive_subnets_16.is_empty() {
            write!(
                f,
                "\n  alive_top_16: {}",
                format_alive_subnets(&self.alive_subnets_16)
            )?;
        }
        if !self.alive_subnets_24.is_empty() {
            write!(
                f,
                "\n  alive_top_24: {}",
                format_alive_subnets(&self.alive_subnets_24)
            )?;
        }
        Ok(())
    }
}

fn plugin_result_type(plugin: &str) -> ResultType {
    match plugin {
        "findnet" | "netbios" => ResultType::Service,
        _ => ResultType::Vuln,
    }
}

fn parse_ports_or_empty(spec: &str) -> Result<Vec<u16>> {
    if spec.trim().is_empty() {
        Ok(Vec::new())
    } else {
        parse_ports(spec)
    }
}

fn exclude_hosts(hosts: Vec<String>, excluded_hosts: &[String]) -> Vec<String> {
    if excluded_hosts.is_empty() {
        return hosts;
    }

    let excluded = excluded_hosts.iter().collect::<BTreeSet<_>>();
    hosts
        .into_iter()
        .filter(|host| !excluded.contains(host))
        .collect()
}

fn exclude_ports(ports: Vec<u16>, excluded_ports: &[u16]) -> Vec<u16> {
    if excluded_ports.is_empty() {
        return ports;
    }

    let excluded = excluded_ports.iter().copied().collect::<BTreeSet<_>>();
    ports
        .into_iter()
        .filter(|port| !excluded.contains(port))
        .collect()
}

fn build_web_targets(
    explicit_urls: &[String],
    open_ports: &[rscan_net::OpenPort],
    include_all_open_ports: bool,
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
        if include_all_open_ports || web_ports.contains(&open.port) {
            let target = format!("{}:{}", open.host, open.port);
            if seen.insert(target.clone()) {
                targets.push(target);
            }
        }
    }

    Ok(targets)
}

fn build_service_targets(mode: &str, open_ports: &[rscan_net::OpenPort]) -> Vec<OpenService> {
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

    if mode == "all" {
        return targets;
    }

    targets
}

fn now_timestamp() -> String {
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    now.format(&format)
        .unwrap_or_else(|_| "1970-01-01 00:00:00".to_string())
}

fn build_fingerprint_scan_result(service: &ServiceFingerprint) -> ScanResult {
    let mut details = BTreeMap::from([
        ("port".to_string(), json!(service.port)),
        ("service".to_string(), json!(service.service.clone())),
    ]);
    if !service.banner.is_empty() {
        details.insert("banner".to_string(), json!(service.banner.clone()));
    }
    if let Some(version) = &service.version {
        details.insert("version".to_string(), json!(version));
    }
    for (key, value) in &service.extras {
        match key.as_str() {
            "vendor_product" => {
                details.insert("product".to_string(), json!(value));
            }
            "os" | "info" => {
                details.insert(key.clone(), json!(value));
            }
            _ => {}
        }
    }
    ScanResult {
        time: now_timestamp(),
        kind: ResultType::Service,
        target: service.host.clone(),
        status: "identified".to_string(),
        details,
    }
}

fn build_web_scan_result(web: &WebScanResult) -> ScanResult {
    let mut server_info = BTreeMap::from([
        ("title".to_string(), json!(web.title.clone())),
        ("length".to_string(), json!(web.length.clone())),
        ("status_code".to_string(), json!(web.status_code)),
    ]);
    if web.requested_url != web.final_url {
        server_info.insert("redirect_Url".to_string(), json!(web.final_url.clone()));
    }
    for (key, value) in &web.headers {
        server_info.insert(key.to_lowercase(), json!(value));
    }

    let mut details = BTreeMap::from([
        ("service".to_string(), json!("http")),
        ("title".to_string(), json!(web.title.clone())),
        ("Url".to_string(), json!(web.final_url.clone())),
        ("status_code".to_string(), json!(web.status_code)),
        ("length".to_string(), json!(web.length.clone())),
        ("server_info".to_string(), json!(server_info)),
        ("fingerprints".to_string(), json!(web.fingerprints.clone())),
    ]);
    if let Some(port) = web_result_port(&web.final_url) {
        details.insert("port".to_string(), json!(port));
    }

    ScanResult {
        time: now_timestamp(),
        kind: ResultType::Service,
        target: web_result_target(web),
        status: "identified".to_string(),
        details,
    }
}

fn web_result_target(web: &WebScanResult) -> String {
    web_authority_host(&web.requested_url)
        .or_else(|| web_authority_host(&web.final_url))
        .unwrap_or_else(|| web.original_target.clone())
}

fn web_authority_host(url: &str) -> Option<String> {
    let (_, remainder) = url.split_once("://")?;
    let authority = remainder.split('/').next()?.rsplit('@').next()?;
    if authority.is_empty() {
        return None;
    }
    if authority.starts_with('[') {
        return authority.find(']').map(|end| authority[..=end].to_string());
    }
    Some(
        authority
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(authority)
            .to_string(),
    )
}

fn normalize_poc_target(url: &str) -> String {
    let Some((scheme, remainder)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or(remainder);
    format!("{scheme}://{authority}")
}

fn web_result_port(url: &str) -> Option<String> {
    let (scheme, remainder) = url.split_once("://")?;
    let authority = remainder.split('/').next().unwrap_or(remainder);
    if authority.is_empty() {
        return None;
    }

    if let Some(port) = authority.rsplit(':').next()
        && authority.contains(':')
        && port.chars().all(|ch| ch.is_ascii_digit())
    {
        return Some(port.to_string());
    }

    match scheme {
        "http" => Some("80".to_string()),
        "https" => Some("443".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

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
            AppConfig::from_tokens(["-u", &format!("http://127.0.0.1:{port}"), "-nopoc"])
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
    fn falls_back_from_explicit_https_url_targets_like_go() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 1024];
                let size = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..size]);
                if !request.starts_with("GET ") {
                    continue;
                }
                let body = "<html><title>HTTPS URL Fallback</title></html>";
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
        });

        let report = Application::new(
            AppConfig::from_tokens(["-u", &format!("https://127.0.0.1:{port}"), "-nopoc"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.web_target_count, 1);
        assert_eq!(report.summary.web_result_count, 1);
        assert_eq!(report.results[0].status, "identified");
        assert_eq!(
            report.results[0].details["title"],
            json!("HTTPS URL Fallback")
        );
        assert_eq!(
            report.results[0].details["Url"],
            json!(format!("http://127.0.0.1:{port}/"))
        );
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
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-nopoc"])
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
    fn skips_web_scan_for_non_web_custom_plugin_modes_like_go() {
        use std::io::{ErrorKind, Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = [18080_u16, 18082, 19001, 20000]
            .into_iter()
            .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
            .expect("listener should bind on a known web port");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("timeout should set");
                        let mut buffer = [0u8; 1024];
                        let size = stream.read(&mut buffer).unwrap_or(0);
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        if request.starts_with("stats") {
                            stream
                                .write_all(b"ERROR\r\n")
                                .expect("response should write");
                        } else {
                            let body = "<html><title>Should Not Scan Web</title></html>";
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            stream
                                .write_all(response.as_bytes())
                                .expect("response should write");
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept should succeed: {error}"),
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

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.web_target_count, 0);
        assert_eq!(report.summary.web_result_count, 0);
        assert!(!report.results.iter().any(
            |result| result.kind == ResultType::Service && result.details.contains_key("title")
        ));
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
    fn executes_named_poc_from_url_origin_like_go() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::{env, fs};

        let root = env::temp_dir().join(format!("rscan-core-poc-origin-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temp poc dir should exist");
        fs::write(
            root.join("origin.yaml"),
            "name: poc-yaml-origin-only\nrules:\n  - method: GET\n    path: kibana\n    expression: response.body.bcontains(b\"origin-only-poc\")\n",
        )
        .expect("custom poc should write");

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 2048];
                let size = stream.read(&mut buffer).expect("request should read");
                let request = String::from_utf8_lossy(&buffer[..size]);
                let body = if request.starts_with("GET /app/login?x=1 ") {
                    "<html><title>Login</title></html>"
                } else if request.starts_with("GET /kibana ") {
                    "<html><body>origin-only-poc</body></html>"
                } else {
                    "<html><body>wrong-base</body></html>"
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
                &format!("http://127.0.0.1:{port}/app/login?x=1"),
                "-pocpath",
                root.to_string_lossy().as_ref(),
                "-pocname",
                "origin-only",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.selected_poc_count, 1);
        assert_eq!(report.summary.poc_match_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "vulnerable"
                && result.details["poc"] == json!("poc-yaml-origin-only")
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
        assert_eq!(result.target, "127.0.0.1");
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
        assert_eq!(result.target, "127.0.0.1");
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
    fn named_webtitle_scans_non_web_ports_like_go() {
        use std::io::{ErrorKind, Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind(("127.0.0.1", 12345))
            .or_else(|_| TcpListener::bind(("127.0.0.1", 12346)))
            .expect("listener should bind on a non-web port");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut accepts = 0usize;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accepts += 1;
                        let mut buffer = [0u8; 1024];
                        let size = stream.read(&mut buffer).unwrap_or(0);
                        if accepts == 1 {
                            continue;
                        }
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        if !request.starts_with("GET ") {
                            continue;
                        }
                        let body = "<html><title>Named Non-Web WebTitle</title></html>";
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
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept should succeed: {error}"),
                }
            }
        });

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-m", "webtitle"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.web_target_count, 1);
        assert_eq!(report.summary.web_result_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "identified"
                && result.details["title"] == json!("Named Non-Web WebTitle")
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
    fn named_webpoc_loads_default_pocs_like_go() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::{env, fs};

        let root =
            env::temp_dir().join(format!("rscan-core-webpoc-default-{}", std::process::id()));
        fs::create_dir_all(&root).expect("temp poc dir should exist");
        fs::write(
            root.join("custom.yaml"),
            "name: poc-yaml-webpoc-default\nrules:\n  - method: GET\n    path: /\n    expression: response.body.bcontains(b\"named-webpoc-default\")\n",
        )
        .expect("custom poc should write");

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 2048];
                let _ = stream.read(&mut buffer).expect("request should read");
                let body = "<html><title>Named WebPoc Default</title>named-webpoc-default</html>";
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
                "-pocpath",
                root.to_string_lossy().as_ref(),
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
                && result.details["poc"] == json!("poc-yaml-webpoc-default")
        }));
    }

    #[test]
    fn runs_only_fingerprint_matched_pocs_like_go() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::{env, fs};

        let root = env::temp_dir().join(format!(
            "rscan-core-webpoc-fingerprint-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("temp poc dir should exist");
        fs::write(
            root.join("weblogic.yaml"),
            "name: poc-yaml-weblogic-match\nrules:\n  - method: GET\n    path: /\n    expression: response.body.bcontains(b\"fingerprint-routed-poc\")\n",
        )
        .expect("weblogic poc should write");
        fs::write(
            root.join("rabbitmq.yaml"),
            "name: poc-yaml-rabbitmq-match\nrules:\n  - method: GET\n    path: /\n    expression: response.body.bcontains(b\"fingerprint-routed-poc\")\n",
        )
        .expect("rabbitmq poc should write");

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 2048];
                let _ = stream.read(&mut buffer).expect("request should read");
                let body = "<html><title>Oracle WebLogic Server 管理控制台</title>fingerprint-routed-poc</html>";
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
                "-pocpath",
                root.to_string_lossy().as_ref(),
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");

        assert_eq!(report.summary.selected_poc_count, 2);
        assert_eq!(report.summary.poc_match_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "vulnerable"
                && result.details["poc"] == json!("poc-yaml-weblogic-match")
        }));
        assert!(!report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "vulnerable"
                && result.details["poc"] == json!("poc-yaml-rabbitmq-match")
        }));
    }

    #[test]
    fn prioritizes_fingerprint_pocs_over_explicit_poc_name_like_go() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::{env, fs};

        let root = env::temp_dir().join(format!(
            "rscan-core-webpoc-precedence-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("temp poc dir should exist");
        fs::write(
            root.join("weblogic.yaml"),
            "name: poc-yaml-weblogic-match\nrules:\n  - method: GET\n    path: /weblogic\n    expression: response.body.bcontains(b\"fingerprint-priority-poc\")\n",
        )
        .expect("weblogic poc should write");
        fs::write(
            root.join("rabbitmq.yaml"),
            "name: poc-yaml-rabbitmq-match\nrules:\n  - method: GET\n    path: /rabbitmq\n    expression: response.body.bcontains(b\"fingerprint-priority-poc\")\n",
        )
        .expect("rabbitmq poc should write");

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen_requests = Arc::clone(&requests);

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 2048];
                let bytes = stream.read(&mut buffer).expect("request should read");
                let request = String::from_utf8_lossy(&buffer[..bytes]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                seen_requests
                    .lock()
                    .expect("requests should lock")
                    .push(path.clone());
                let body = if path == "/" {
                    "<html><title>Oracle WebLogic Server 管理控制台</title>fingerprint-priority-poc</html>"
                } else {
                    "fingerprint-priority-poc"
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
                "-pocpath",
                root.to_string_lossy().as_ref(),
                "-pocname",
                "rabbitmq-match",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server thread should exit");
        let requests = requests.lock().expect("requests should lock").clone();

        assert_eq!(report.summary.selected_poc_count, 1);
        assert_eq!(report.summary.poc_match_count, 1);
        assert_eq!(requests, vec!["/".to_string(), "/weblogic".to_string()]);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "vulnerable"
                && result.details["poc"] == json!("poc-yaml-weblogic-match")
        }));
        assert!(!report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "vulnerable"
                && result.details["poc"] == json!("poc-yaml-rabbitmq-match")
        }));
    }

    #[test]
    fn executes_memcached_service_plugin() {
        use std::io::{ErrorKind, Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0u8; 2048];
                        let size = stream.read(&mut buffer).expect("request should read");
                        if size == 0 {
                            continue;
                        }
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
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept should succeed: {error}"),
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
    fn executes_comma_separated_service_plugins_like_go() {
        use std::io::{ErrorKind, Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0u8; 2048];
                        let size = stream.read(&mut buffer).expect("request should read");
                        if size == 0 {
                            continue;
                        }
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        if request.starts_with("stats") {
                            stream
                                .write_all(b"STAT pid 1\r\nEND\r\n")
                                .expect("response should write");
                        } else if request.starts_with("info") || request.starts_with("INFO") {
                            stream
                                .write_all(b"ERROR\r\n")
                                .expect("response should write");
                        } else {
                            stream
                                .write_all(b"VERSION 1.6.9\r\n")
                                .expect("response should write");
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept should succeed: {error}"),
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
                "redis,memcached",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert_eq!(report.summary.selected_plugin_count, 2);
        assert_eq!(report.summary.service_finding_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "unauthorized-access"
                && result.details["service"] == json!("memcached")
        }));
    }

    #[test]
    fn skips_snmp_service_plugin_without_explicit_hostport_like_go() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket should bind");
        let port = socket.local_addr().expect("local addr").port();
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("socket timeout should set");

        let report = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-p", &port.to_string(), "-m", "snmp"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        assert_eq!(report.summary.open_port_count, 0);
        assert_eq!(report.summary.selected_plugin_count, 1);
        assert_eq!(report.summary.service_finding_count, 0);
        let mut buffer = [0u8; 2048];
        let err = socket
            .recv_from(&mut buffer)
            .expect_err("snmp request should not be sent");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "unexpected recv error: {err}"
        );
    }

    #[test]
    fn mixed_remote_and_local_modes_keep_remote_scan_like_go() {
        use std::io::{ErrorKind, Read, Write};
        use std::thread;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buffer = [0u8; 2048];
                        let size = stream.read(&mut buffer).expect("request should read");
                        if size == 0 {
                            continue;
                        }
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
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept should succeed: {error}"),
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
                "memcached,localinfo",
            ])
            .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert_eq!(report.summary.selected_plugin_count, 2);
        assert_eq!(report.summary.service_finding_count, 1);
        assert_eq!(report.summary.local_result_count, 1);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Vuln
                && result.status == "unauthorized-access"
                && result.details["service"] == json!("memcached")
        }));
        assert!(
            report.results.iter().any(|result| {
                result.kind == ResultType::Service && result.status == "local-info"
            })
        );
    }

    #[test]
    fn executes_snmp_service_plugin_for_explicit_hostport_like_go() {
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
            AppConfig::from_tokens(["-h", &format!("127.0.0.1:{port}"), "-m", "snmp"])
                .expect("config should parse"),
        )
        .run()
        .expect("scan should run");

        server.join().expect("server should finish");

        assert_eq!(report.summary.open_port_count, 1);
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
        assert_eq!(report.summary.selected_plugin_count, 33);
        assert!(report.results.iter().any(|result| {
            result.kind == ResultType::Service
                && result.status == "local-info"
                && result.details.contains_key("hostname")
        }));
    }

    #[test]
    fn local_mode_selects_all_local_modules_like_go() {
        assert_eq!(
            selected_local_modules("all", true),
            vec![
                "localinfo".to_string(),
                "dcinfo".to_string(),
                "minidump".to_string()
            ]
        );
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

    #[test]
    fn rejects_invalid_scan_mode_entries_like_go() {
        let app = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-m", "ssh,invalid"])
                .expect("config should parse"),
        );

        let error = app
            .render_scan_plan()
            .expect_err("invalid scan mode should fail before rendering");

        assert!(error.to_string().contains("invalid scan mode: invalid"));
    }

    #[test]
    fn rejects_mixed_case_scan_mode_entries_like_go() {
        let app = Application::new(
            AppConfig::from_tokens(["-h", "127.0.0.1", "-m", "WebTitle"])
                .expect("config should parse"),
        );

        let error = app
            .render_scan_plan()
            .expect_err("mixed-case scan mode should fail like go");

        assert!(error.to_string().contains("invalid scan mode: WebTitle"));
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
