use rscan_config::AppConfig;
use rscan_output::ScanResult;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

pub(crate) fn liveness_mode(config: &AppConfig) -> &'static str {
    if config.scan.disable_ping {
        "disabled"
    } else if config.scan.use_ping {
        "ping"
    } else {
        "icmp"
    }
}

pub(crate) fn summarize_items(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

pub(crate) fn summarize_counted_items(items: &[String]) -> String {
    match items.len() {
        0 => "0".to_string(),
        1..=4 => format!("{} ({})", items.len(), items.join(", ")),
        _ => format!("{} ({} ...)", items.len(), items[..4].join(", ")),
    }
}

pub(crate) fn enabled_disabled(value: bool) -> &'static str {
    if value { "enabled" } else { "disabled" }
}

pub(crate) fn top_alive_subnets(hosts: &[String], prefix: u8, top: usize) -> Vec<(String, usize)> {
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
        writeln!(
            f,
            "scan summary\n  mode: {}\n  scope: targets={}, hosts={}, ports={}\n  filters: excluded_hosts={}, excluded_ports={}\n  findings: alive_hosts={}, open_ports={}, module_findings={}, web_results={}, poc_matches={}, local_results={}\n  modules: selected_plugins={}\n  web: targets={}, identified={}\n  pocs: targets={}, selected={}, matches={}\n  auth: users={}, passwords={}\n  runtime: threads={}, timeout={}s\n  output: {}",
            self.mode,
            self.target_count,
            self.expanded_host_count,
            self.port_count,
            self.excluded_host_count,
            self.excluded_port_count,
            self.host_result_count,
            self.open_port_count,
            self.service_finding_count,
            self.web_result_count,
            self.poc_match_count,
            self.local_result_count,
            self.selected_plugin_count,
            self.web_target_count,
            self.web_result_count,
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
