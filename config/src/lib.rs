use serde::{Deserialize, Serialize};
use std::env;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::iter::Peekable;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const VERSION: &str = "2.0.1";
pub const DEFAULT_OUTPUT_FILE: &str = "result.txt";
pub const DEFAULT_MAIN_PORTS: &str = "21,22,23,80,81,110,135,139,143,389,443,445,502,873,993,995,1433,1521,3306,5432,5672,6379,7001,7687,8000,8005,8009,8080,8089,8443,9000,9042,9092,9200,10051,11211,15672,27017,61616";
pub const DEFAULT_LOG_LEVEL: &str = "success";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CommandAction {
    #[default]
    Run,
    Help,
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Txt,
    Json,
    Csv,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.to_ascii_lowercase().as_str() {
            "txt" => Ok(Self::Txt),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            _ => Err(ConfigError::InvalidOutputFormat(value.to_string())),
        }
    }
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Txt => "txt",
            Self::Json => "json",
            Self::Csv => "csv",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ScanMode {
    #[default]
    All,
    Named(String),
}

impl From<String> for ScanMode {
    fn from(value: String) -> Self {
        if value == "all" {
            Self::All
        } else {
            Self::Named(value)
        }
    }
}

impl Display for ScanMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all"),
            Self::Named(value) => f.write_str(value),
        }
    }
}

pub fn parse_scan_mode_list(mode: &str) -> Vec<String> {
    let mut parsed = Vec::new();
    for item in mode.split(',').map(str::trim).filter(|item| !item.is_empty()) {
        let item = item.to_string();
        if !parsed.contains(&item) {
            parsed.push(item);
        }
    }
    parsed
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetConfig {
    pub host: Option<String>,
    pub exclude_hosts: Option<String>,
    pub ports: String,
    pub exclude_ports: Option<String>,
    pub hosts_file: Option<PathBuf>,
    pub ports_file: Option<PathBuf>,
    pub url: Option<String>,
    pub urls_file: Option<PathBuf>,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            host: None,
            exclude_hosts: None,
            ports: DEFAULT_MAIN_PORTS.to_string(),
            exclude_ports: None,
            hosts_file: None,
            ports_file: None,
            url: None,
            urls_file: None,
        }
    }
}

impl TargetConfig {
    pub fn defined_target_count(&self) -> usize {
        usize::from(self.host.is_some())
            + usize::from(self.url.is_some())
            + usize::from(self.hosts_file.is_some())
            + usize::from(self.urls_file.is_some())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub threads: u16,
    pub timeout_secs: u64,
    pub module_threads: u16,
    pub global_timeout_secs: u64,
    pub live_top: u16,
    pub disable_ping: bool,
    pub use_ping: bool,
    pub enable_fingerprint: bool,
    pub local_mode: bool,
    pub disable_brute: bool,
    pub max_retries: u8,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            mode: ScanMode::All,
            threads: 600,
            timeout_secs: 3,
            module_threads: 10,
            global_timeout_secs: 180,
            live_top: 10,
            disable_ping: false,
            use_ping: false,
            enable_fingerprint: false,
            local_mode: false,
            disable_brute: false,
            max_retries: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub add_users: Option<String>,
    pub add_passwords: Option<String>,
    pub users_file: Option<PathBuf>,
    pub passwords_file: Option<PathBuf>,
    pub hash_file: Option<PathBuf>,
    pub hash_value: Option<String>,
    pub domain: Option<String>,
    pub ssh_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebConfig {
    pub cookie: Option<String>,
    pub web_timeout_secs: u64,
    pub http_proxy: Option<String>,
    pub socks5_proxy: Option<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            cookie: None,
            web_timeout_secs: 5,
            http_proxy: None,
            socks5_proxy: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocConfig {
    pub poc_path: Option<PathBuf>,
    pub poc_name: Option<String>,
    pub full: bool,
    pub dns_log: bool,
    pub workers: u16,
    pub disable_poc_scan: bool,
}

impl Default for PocConfig {
    fn default() -> Self {
        Self {
            poc_path: None,
            poc_name: None,
            full: false,
            dns_log: false,
            workers: 20,
            disable_poc_scan: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RedisConfig {
    pub redis_file: Option<PathBuf>,
    pub redis_shell: Option<String>,
    pub disable_redis: bool,
    pub redis_write_path: Option<String>,
    pub redis_write_content: Option<String>,
    pub redis_write_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputConfig {
    pub path: PathBuf,
    pub format: OutputFormat,
    pub no_write: bool,
    pub silent: bool,
    pub no_color: bool,
    pub log_level: String,
    pub show_progress: bool,
    pub show_scan_plan: bool,
    pub slow_log_output: bool,
    pub api_addr: Option<String>,
    pub secret_key: Option<String>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_OUTPUT_FILE),
            format: OutputFormat::Txt,
            no_write: false,
            silent: false,
            no_color: false,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            show_progress: false,
            show_scan_plan: false,
            slow_log_output: false,
            api_addr: None,
            secret_key: None,
        }
    }
}

impl OutputConfig {
    pub fn effective_format(&self) -> OutputFormat {
        if self.api_addr.is_some() {
            OutputFormat::Csv
        } else {
            self.format
        }
    }

    pub fn effective_path(&self) -> PathBuf {
        if self.api_addr.is_some() {
            let dir = self
                .path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            dir.join("fscanapi.csv")
        } else {
            self.path.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub shellcode: Option<String>,
    pub language: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            shellcode: None,
            language: "zh".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub action: CommandAction,
    pub targets: TargetConfig,
    pub scan: ScanConfig,
    pub auth: AuthConfig,
    pub web: WebConfig,
    pub poc: PocConfig,
    pub redis: RedisConfig,
    pub output: OutputConfig,
    pub runtime: RuntimeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResolvedInputs {
    pub hosts: Vec<String>,
    pub host_ports: Vec<String>,
    pub exclude_hosts: Vec<String>,
    pub urls: Vec<String>,
    pub usernames: Vec<String>,
    pub extra_usernames: Vec<String>,
    pub passwords: Vec<String>,
    pub extra_passwords: Vec<String>,
    pub hashes: Vec<String>,
    pub ports: String,
    pub exclude_ports: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        if let Ok(fs_args) = env::var("FS_ARGS") {
            let parsed = shlex::split(&fs_args)
                .ok_or_else(|| ConfigError::InvalidEnvironmentArgs(fs_args.clone()))?;
            if !parsed.is_empty() {
                return Self::from_tokens(parsed);
            }
        }

        Self::from_tokens(env::args().skip(1))
    }

    pub fn from_tokens<I, S>(tokens: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut config = Self::default();
        let mut iter = tokens.into_iter().map(Into::into).peekable();

        while let Some(token) = iter.next() {
            let (flag, inline_value) = split_flag_value(&token);

            match flag {
                "-help" | "--help" | "-?" => config.action = CommandAction::Help,
                "-version" | "--version" => config.action = CommandAction::Version,

                "-h" | "--host" => {
                    config.targets.host = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-eh" | "--exclude-hosts" => {
                    config.targets.exclude_hosts = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-p" | "--ports" => {
                    config.targets.ports = value_for(flag, inline_value, &mut iter)?
                }
                "-ep" | "--exclude-ports" => {
                    config.targets.exclude_ports = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-hf" | "--hosts-file" => {
                    config.targets.hosts_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }
                "-pf" | "--ports-file" => {
                    config.targets.ports_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }
                "-u" | "--url" => {
                    config.targets.url = Some(value_for(flag, inline_value, &mut iter)?)
                }
                "-uf" | "--urls-file" => {
                    config.targets.urls_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }

                "-m" | "--mode" => {
                    config.scan.mode = ScanMode::from(value_for(flag, inline_value, &mut iter)?);
                }
                "-t" | "--threads" => {
                    config.scan.threads =
                        parse_u16(flag, value_for(flag, inline_value, &mut iter)?)?;
                }
                "-time" | "--timeout" => {
                    config.scan.timeout_secs =
                        parse_u64(flag, value_for(flag, inline_value, &mut iter)?)?;
                }
                "-mt" | "--module-threads" => {
                    config.scan.module_threads =
                        parse_u16(flag, value_for(flag, inline_value, &mut iter)?)?;
                }
                "-gt" | "--global-timeout" => {
                    config.scan.global_timeout_secs =
                        parse_u64(flag, value_for(flag, inline_value, &mut iter)?)?;
                }
                "-top" | "--top" => {
                    config.scan.live_top =
                        parse_u16(flag, value_for(flag, inline_value, &mut iter)?)?;
                }
                "-np" | "--disable-ping" => config.scan.disable_ping = true,
                "-ping" | "--ping" => config.scan.use_ping = true,
                "-fingerprint" | "--fingerprint" => config.scan.enable_fingerprint = true,
                "-local" | "--local" => config.scan.local_mode = true,
                "-nobr" | "--disable-brute" => config.scan.disable_brute = true,
                "-retry" | "--retry" => {
                    config.scan.max_retries =
                        parse_u8(flag, value_for(flag, inline_value, &mut iter)?)?;
                }

                "-user" | "--user" => {
                    config.auth.username = Some(value_for(flag, inline_value, &mut iter)?)
                }
                "-pwd" | "--pwd" => {
                    config.auth.password = Some(value_for(flag, inline_value, &mut iter)?)
                }
                "-usera" | "--usera" => {
                    config.auth.add_users = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-pwda" | "--pwda" => {
                    config.auth.add_passwords = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-userf" | "--userf" => {
                    config.auth.users_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }
                "-pwdf" | "--pwdf" => {
                    config.auth.passwords_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }
                "-hashf" | "--hashf" => {
                    config.auth.hash_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }
                "-hash" | "--hash" => {
                    config.auth.hash_value = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-domain" | "--domain" => {
                    config.auth.domain = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-sshkey" | "--sshkey" => {
                    config.auth.ssh_key_path =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }

                "-cookie" | "--cookie" => {
                    config.web.cookie = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-wt" | "--wt" => {
                    config.web.web_timeout_secs =
                        parse_u64(flag, value_for(flag, inline_value, &mut iter)?)?;
                }
                "-proxy" | "--proxy" => {
                    config.web.http_proxy = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-socks5" | "--socks5" => {
                    config.web.socks5_proxy = Some(value_for(flag, inline_value, &mut iter)?);
                }

                "-pocpath" | "--pocpath" => {
                    config.poc.poc_path =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }
                "-pocname" | "--pocname" => {
                    config.poc.poc_name = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-full" | "--full" => config.poc.full = true,
                "-dns" | "--dns" => config.poc.dns_log = true,
                "-num" | "--num" => {
                    config.poc.workers =
                        parse_u16(flag, value_for(flag, inline_value, &mut iter)?)?;
                }
                "-nopoc" | "--nopoc" => config.poc.disable_poc_scan = true,

                "-rf" | "--rf" => {
                    config.redis.redis_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }
                "-rs" | "--rs" => {
                    config.redis.redis_shell = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-noredis" | "--noredis" => config.redis.disable_redis = true,
                "-rwp" | "--rwp" => {
                    config.redis.redis_write_path = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-rwc" | "--rwc" => {
                    config.redis.redis_write_content =
                        Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-rwf" | "--rwf" => {
                    config.redis.redis_write_file =
                        Some(PathBuf::from(value_for(flag, inline_value, &mut iter)?));
                }

                "-o" | "--output" => {
                    config.output.path = PathBuf::from(value_for(flag, inline_value, &mut iter)?);
                }
                "-f" | "--format" => {
                    config.output.format =
                        OutputFormat::parse(&value_for(flag, inline_value, &mut iter)?)?;
                }
                "-no" | "--no" => config.output.no_write = true,
                "-silent" | "--silent" => config.output.silent = true,
                "-nocolor" | "--nocolor" => config.output.no_color = true,
                "-log" | "--log" => {
                    config.output.log_level = value_for(flag, inline_value, &mut iter)?;
                }
                "-pg" | "--pg" => config.output.show_progress = true,
                "-sp" | "--sp" => config.output.show_scan_plan = true,
                "-slow" | "--slow" => config.output.slow_log_output = true,
                "-api" | "--api" => {
                    config.output.api_addr = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-secret" | "--secret" => {
                    config.output.secret_key = Some(value_for(flag, inline_value, &mut iter)?);
                }

                "-sc" | "--sc" => {
                    config.runtime.shellcode = Some(value_for(flag, inline_value, &mut iter)?);
                }
                "-lang" | "--lang" => {
                    config.runtime.language = value_for(flag, inline_value, &mut iter)?;
                }

                _ if flag.starts_with('-') => {
                    return Err(ConfigError::UnknownFlag(flag.to_string()));
                }
                _ => return Err(ConfigError::UnexpectedArgument(token)),
            }
        }

        Ok(config.normalized())
    }

    pub fn resolve_inputs(&self) -> Result<ResolvedInputs, ConfigError> {
        let mut resolved = ResolvedInputs {
            ports: effective_ports(&self.targets),
            exclude_ports: self.targets.exclude_ports.clone().unwrap_or_default(),
            ..ResolvedInputs::default()
        };

        if let Some(host) = &self.targets.host {
            append_target_specs(&mut resolved.hosts, &mut resolved.host_ports, host)?;
        }
        if let Some(host) = &self.targets.exclude_hosts {
            append_split_csv(&mut resolved.exclude_hosts, host);
        }
        if let Some(path) = &self.targets.hosts_file {
            let host_entries = read_host_entries(path)?;
            append_unique(&mut resolved.hosts, host_entries.hosts);
            append_unique(&mut resolved.host_ports, host_entries.host_ports);
        }

        if let Some(url) = &self.targets.url {
            append_split_csv(&mut resolved.urls, url);
        }
        if let Some(path) = &self.targets.urls_file {
            append_unique(&mut resolved.urls, read_nonempty_lines(path)?);
        }

        if let Some(username) = &self.auth.username {
            append_split_csv(&mut resolved.usernames, username);
        }
        if let Some(path) = &self.auth.users_file {
            append_unique(&mut resolved.usernames, read_nonempty_lines(path)?);
        }
        if let Some(username) = &self.auth.add_users {
            append_split_csv(&mut resolved.extra_usernames, username);
        }

        if let Some(password) = &self.auth.password {
            append_split_csv(&mut resolved.passwords, password);
        }
        if let Some(path) = &self.auth.passwords_file {
            append_unique(&mut resolved.passwords, read_nonempty_lines(path)?);
        }
        if let Some(password) = &self.auth.add_passwords {
            append_split_csv(&mut resolved.extra_passwords, password);
        }

        if let Some(hash) = &self.auth.hash_value {
            append_hash(&mut resolved.hashes, hash)?;
        }
        if let Some(path) = &self.auth.hash_file {
            for hash in read_nonempty_lines(path)? {
                append_hash(&mut resolved.hashes, &hash)?;
            }
        }

        if let Some(path) = &self.targets.ports_file {
            resolved.ports = read_nonempty_lines(path)?.join(",");
        }

        Ok(resolved)
    }

    pub fn validate_run_mode(&self) -> Result<(), ConfigError> {
        let has_remote_targets = self.targets.defined_target_count() > 0;
        let has_local_mode = self.scan.local_mode
            || (self.targets.defined_target_count() == 0 && matches_local_mode(&self.scan.mode));

        match (has_remote_targets, has_local_mode) {
            (false, false) => Err(ConfigError::MissingScanTarget),
            (true, true) => Err(ConfigError::ConflictingScanModes),
            _ => Ok(()),
        }
    }

    fn normalized(mut self) -> Self {
        normalize_http_proxy(&mut self.web.http_proxy);
        normalize_socks5_proxy(&mut self.web.socks5_proxy);
        if self.web.socks5_proxy.is_some() {
            self.scan.disable_ping = true;
        }
        self
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid FS_ARGS content: {0}")]
    InvalidEnvironmentArgs(String),
    #[error("unknown flag: {0}")]
    UnknownFlag(String),
    #[error("missing value for flag: {0}")]
    MissingValue(String),
    #[error("unexpected positional argument: {0}")]
    UnexpectedArgument(String),
    #[error("invalid output format: {0}")]
    InvalidOutputFormat(String),
    #[error("invalid value for {flag}: {value}")]
    InvalidNumericValue { flag: String, value: String },
    #[error("failed to read file {path}: {source}")]
    ReadFileFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid hash value: {0}")]
    InvalidHashValue(String),
    #[error("specify scan parameters")]
    MissingScanTarget,
    #[error("scan target modes conflict")]
    ConflictingScanModes,
}

fn split_flag_value(token: &str) -> (&str, Option<String>) {
    if let Some((flag, value)) = token.split_once('=') {
        if flag.starts_with('-') {
            return (flag, Some(value.to_string()));
        }
    }
    (token, None)
}

fn value_for(
    flag: &str,
    inline_value: Option<String>,
    iter: &mut Peekable<impl Iterator<Item = String>>,
) -> Result<String, ConfigError> {
    if let Some(value) = inline_value {
        return Ok(value);
    }

    iter.next()
        .ok_or_else(|| ConfigError::MissingValue(flag.to_string()))
}

fn parse_u64(flag: &str, value: String) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidNumericValue {
            flag: flag.to_string(),
            value,
        })
}

fn parse_u16(flag: &str, value: String) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidNumericValue {
            flag: flag.to_string(),
            value,
        })
}

fn parse_u8(flag: &str, value: String) -> Result<u8, ConfigError> {
    value
        .parse::<u8>()
        .map_err(|_| ConfigError::InvalidNumericValue {
            flag: flag.to_string(),
            value,
        })
}

fn normalize_http_proxy(proxy: &mut Option<String>) {
    let Some(value) = proxy.as_mut() else {
        return;
    };

    *value = match value.as_str() {
        "1" => "http://127.0.0.1:8080".to_string(),
        "2" => "socks5://127.0.0.1:1080".to_string(),
        other if other.contains("://") => other.to_string(),
        other => format!("http://127.0.0.1:{other}"),
    };
}

fn matches_local_mode(mode: &ScanMode) -> bool {
    matches!(
        mode,
        ScanMode::Named(value)
            if parse_scan_mode_list(value)
                .into_iter()
                .any(|item| matches!(item.as_str(), "localinfo" | "dcinfo" | "minidump"))
    )
}

fn effective_ports(targets: &TargetConfig) -> String {
    if targets.ports_file.is_none() && targets.ports == DEFAULT_MAIN_PORTS {
        "main,web".to_string()
    } else {
        targets.ports.clone()
    }
}

fn normalize_socks5_proxy(proxy: &mut Option<String>) {
    let Some(value) = proxy.as_mut() else {
        return;
    };

    if value.starts_with("socks5://") {
        return;
    }

    *value = if value.contains(':') {
        format!("socks5://{value}")
    } else {
        format!("socks5://127.0.0.1:{value}")
    };
}

fn read_nonempty_lines(path: &Path) -> Result<Vec<String>, ConfigError> {
    let content = fs::read_to_string(path).map_err(|source| ConfigError::ReadFileFailed {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

#[derive(Default)]
struct HostEntries {
    hosts: Vec<String>,
    host_ports: Vec<String>,
}

fn read_host_entries(path: &Path) -> Result<HostEntries, ConfigError> {
    let content = fs::read_to_string(path).map_err(|source| ConfigError::ReadFileFailed {
        path: path.to_path_buf(),
        source,
    })?;

    let mut entries = HostEntries::default();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        append_target_specs(&mut entries.hosts, &mut entries.host_ports, line)?;
    }

    Ok(entries)
}

fn append_unique(target: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn append_split_csv(target: &mut Vec<String>, value: &str) {
    append_unique(
        target,
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned),
    );
}

fn append_target_specs(
    hosts: &mut Vec<String>,
    host_ports: &mut Vec<String>,
    value: &str,
) -> Result<(), ConfigError> {
    for item in value.split(',').map(str::trim).filter(|item| !item.is_empty()) {
        append_target_spec(hosts, host_ports, item)?;
    }
    Ok(())
}

fn append_target_spec(
    hosts: &mut Vec<String>,
    host_ports: &mut Vec<String>,
    value: &str,
) -> Result<(), ConfigError> {
    if let Some((host, port)) = value.split_once(':') {
        let port = port.trim();
        if !host.trim().is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0) {
            append_unique(host_ports, [format!("{}:{port}", host.trim())]);
            return Ok(());
        }
    }

    append_unique(hosts, [value.to_string()]);
    Ok(())
}

fn append_hash(target: &mut Vec<String>, value: &str) -> Result<(), ConfigError> {
    for hash in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if hash.len() != 32 {
            return Err(ConfigError::InvalidHashValue(hash.to_string()));
        }

        if !target.iter().any(|existing| existing == hash) {
            target.push(hash.to_string());
        }
    }

    Ok(())
}

pub fn help_text() -> &'static str {
    help_text_for("zh")
}

pub fn help_text_for(language: &str) -> &'static str {
    if language.eq_ignore_ascii_case("en") {
        return "Usage: rscan [options]\n\
\n\
Targets:\n\
  -h <host>          Target host/CIDR/range\n\
  -eh <hosts>        Exclude hosts\n\
  -p <ports>         Ports (default: fscan main ports)\n\
  -ep <ports>        Exclude ports\n\
  -hf <file>         Hosts file\n\
  -pf <file>         Ports file\n\
  -u <url>           Target URL\n\
  -uf <file>         URL file\n\
\n\
Scan control:\n\
  -m <mode>          Scan mode (default: all)\n\
  -t <num>           Thread count (default: 600)\n\
  -time <sec>        Timeout seconds (default: 3)\n\
  -mt <num>          Module threads (default: 10)\n\
  -gt <sec>          Global timeout (default: 180)\n\
  -top <num>         Live subnet top count (default: 10)\n\
  -np                Disable ping/icmp liveness\n\
  -ping              Prefer system ping\n\
  -fingerprint       Enable service fingerprinting\n\
  -local             Local mode\n\
  -nobr              Disable brute force\n\
  -retry <num>       Retry count (default: 3)\n\
\n\
Auth/Web/POC:\n\
  -user/-pwd/-userf/-pwdf/-hash/-hashf/-domain/-sshkey\n\
  -cookie/-wt/-proxy/-socks5\n\
  -pocpath/-pocname/-full/-dns/-num/-nopoc\n\
  -rf/-rs/-noredis/-rwp/-rwc/-rwf\n\
\n\
Output/runtime:\n\
  -o <file>          Output file (default: result.txt)\n\
  -f <format>        txt|json|csv\n\
  -no                Disable output writing\n\
  -silent            Silent mode\n\
  -nocolor           Disable color\n\
  -log <level>       Log level (default: success)\n\
  -pg                Show progress\n\
  -sp                Show scan plan\n\
  -slow              Slow log output\n\
  -api <addr>        API endpoint; forces csv output to fscanapi.csv\n\
  -secret <key>      API secret key\n\
  -sc <shellcode>    Shellcode option\n\
  -lang <lang>       Language (default: zh)\n\
  -help              Show help\n\
  -version           Show version\n\
\n\
Note: the parser intentionally accepts Go-style single-dash multi-letter flags\n\
to stay compatible with the current fscan CLI.";
    }

    "用法: rscan [选项]\n\
\n\
目标:\n\
  -h <host>          目标主机/CIDR/范围\n\
  -eh <hosts>        排除主机\n\
  -p <ports>         端口 (默认: fscan main ports)\n\
  -ep <ports>        排除端口\n\
  -hf <file>         主机文件\n\
  -pf <file>         端口文件\n\
  -u <url>           目标 URL\n\
  -uf <file>         URL 文件\n\
\n\
扫描控制:\n\
  -m <mode>          扫描模式 (默认: all)\n\
  -t <num>           并发线程数 (默认: 600)\n\
  -time <sec>        单次超时秒数 (默认: 3)\n\
  -mt <num>          模块线程数 (默认: 10)\n\
  -gt <sec>          全局超时 (默认: 180)\n\
  -top <num>         存活网段 Top 数 (默认: 10)\n\
  -np                禁用 ping/icmp 存活探测\n\
  -ping              优先使用系统 ping\n\
  -fingerprint       启用服务指纹识别\n\
  -local             本地模式\n\
  -nobr              禁用暴力破解\n\
  -retry <num>       重试次数 (默认: 3)\n\
\n\
认证/Web/POC:\n\
  -user/-pwd/-userf/-pwdf/-hash/-hashf/-domain/-sshkey\n\
  -cookie/-wt/-proxy/-socks5\n\
  -pocpath/-pocname/-full/-dns/-num/-nopoc\n\
  -rf/-rs/-noredis/-rwp/-rwc/-rwf\n\
\n\
输出/运行时:\n\
  -o <file>          输出文件 (默认: result.txt)\n\
  -f <format>        txt|json|csv\n\
  -no                禁止写出结果\n\
  -silent            静默模式\n\
  -nocolor           禁用颜色\n\
  -log <level>       日志级别 (默认: success)\n\
  -pg                显示进度\n\
  -sp                显示扫描计划\n\
  -slow              慢速日志输出\n\
  -api <addr>        API 地址; 会强制输出到 fscanapi.csv\n\
  -secret <key>      API 密钥\n\
  -sc <shellcode>    Shellcode 选项\n\
  -lang <lang>       语言 (默认: zh)\n\
  -help              显示帮助\n\
  -version           显示版本\n\
\n\
说明: 解析器会保留 Go 风格的单横线多字符参数，\n\
以兼容当前 fscan CLI。"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_go_defaults() {
        let config = AppConfig::from_tokens(Vec::<String>::new()).expect("defaults should parse");

        assert_eq!(config.targets.ports, DEFAULT_MAIN_PORTS);
        assert_eq!(config.scan.threads, 600);
        assert_eq!(config.scan.timeout_secs, 3);
        assert_eq!(config.web.web_timeout_secs, 5);
        assert_eq!(config.poc.workers, 20);
        assert_eq!(config.output.path, PathBuf::from(DEFAULT_OUTPUT_FILE));
        assert_eq!(config.output.format, OutputFormat::Txt);
        assert_eq!(config.runtime.language, "zh");
    }

    #[test]
    fn parses_go_style_flags() {
        let config = AppConfig::from_tokens([
            "-h",
            "192.168.1.1/24",
            "-eh",
            "192.168.1.1",
            "-m",
            "redis",
            "-t",
            "300",
            "-time",
            "8",
            "-user",
            "root",
            "-pwd",
            "secret",
            "-proxy",
            "http://127.0.0.1:8080",
            "-pocname",
            "weblogic",
            "-o",
            "scan.csv",
            "-f",
            "csv",
            "-silent",
            "-lang",
            "en",
        ])
        .expect("config should parse");

        assert_eq!(config.targets.host.as_deref(), Some("192.168.1.1/24"));
        assert_eq!(config.targets.exclude_hosts.as_deref(), Some("192.168.1.1"));
        assert_eq!(config.scan.mode, ScanMode::Named("redis".to_string()));
        assert_eq!(config.scan.threads, 300);
        assert_eq!(config.scan.timeout_secs, 8);
        assert_eq!(config.auth.username.as_deref(), Some("root"));
        assert_eq!(config.auth.password.as_deref(), Some("secret"));
        assert_eq!(
            config.web.http_proxy.as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(config.poc.poc_name.as_deref(), Some("weblogic"));
        assert_eq!(config.output.path, PathBuf::from("scan.csv"));
        assert_eq!(config.output.format, OutputFormat::Csv);
        assert!(config.output.silent);
        assert_eq!(config.runtime.language, "en");
    }

    #[test]
    fn supports_equals_syntax_and_api_output_override() {
        let config = AppConfig::from_tokens([
            "-o=reports/out.txt",
            "-f=json",
            "-api=http://127.0.0.1:8088",
            "-secret=token",
        ])
        .expect("config should parse");

        assert_eq!(config.output.effective_format(), OutputFormat::Csv);
        assert_eq!(
            config.output.effective_path(),
            PathBuf::from("reports").join("fscanapi.csv")
        );
        assert_eq!(
            config.output.api_addr.as_deref(),
            Some("http://127.0.0.1:8088")
        );
        assert_eq!(config.output.secret_key.as_deref(), Some("token"));
    }

    #[test]
    fn normalizes_proxy_shortcuts_and_disables_ping_for_socks5() {
        let config = AppConfig::from_tokens(["-proxy", "1", "-socks5", "1080"])
            .expect("config should parse");

        assert_eq!(
            config.web.http_proxy.as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            config.web.socks5_proxy.as_deref(),
            Some("socks5://127.0.0.1:1080")
        );
        assert!(config.scan.disable_ping);
    }

    #[test]
    fn normalizes_socks5_host_and_port() {
        let config =
            AppConfig::from_tokens(["-socks5", "10.0.0.8:1088"]).expect("config should parse");

        assert_eq!(
            config.web.socks5_proxy.as_deref(),
            Some("socks5://10.0.0.8:1088")
        );
        assert!(config.scan.disable_ping);
    }

    #[test]
    fn returns_help_text_for_requested_language() {
        assert!(help_text_for("zh").contains("用法: rscan"));
        assert!(help_text_for("en").contains("Usage: rscan"));
    }

    #[test]
    fn rejects_unknown_flags() {
        let error = AppConfig::from_tokens(["-unknown"]).expect_err("flag should fail");
        assert!(matches!(error, ConfigError::UnknownFlag(_)));
    }

    #[test]
    fn rejects_invalid_numeric_values() {
        let error = AppConfig::from_tokens(["-t", "abc"]).expect_err("numeric parse should fail");
        assert!(matches!(error, ConfigError::InvalidNumericValue { .. }));
    }

    #[test]
    fn resolves_inline_inputs() {
        let config = AppConfig::from_tokens([
            "-h",
            "10.0.0.1,10.0.0.2,10.0.0.3:8443",
            "-u",
            "http://a,http://b",
            "-user",
            "root,admin",
            "-usera",
            "guest,oracle",
            "-pwd",
            "pass1,pass2",
            "-pwda",
            "pass3,{user}@2024",
            "-hash",
            "0123456789abcdef0123456789abcdef",
        ])
        .expect("config should parse");

        let resolved = config.resolve_inputs().expect("inputs should resolve");
        assert_eq!(resolved.hosts, vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(resolved.host_ports, vec!["10.0.0.3:8443"]);
        assert_eq!(resolved.exclude_hosts, Vec::<String>::new());
        assert_eq!(resolved.urls, vec!["http://a", "http://b"]);
        assert_eq!(resolved.usernames, vec!["root", "admin"]);
        assert_eq!(resolved.extra_usernames, vec!["guest", "oracle"]);
        assert_eq!(resolved.passwords, vec!["pass1", "pass2"]);
        assert_eq!(resolved.extra_passwords, vec!["pass3", "{user}@2024"]);
        assert_eq!(
            resolved.hashes,
            vec!["0123456789abcdef0123456789abcdef".to_string()]
        );
        assert_eq!(resolved.exclude_ports, "");
    }

    #[test]
    fn expands_default_ports_to_main_and_web_groups() {
        let config = AppConfig::from_tokens(["-h", "127.0.0.1"]).expect("config should parse");
        let resolved = config.resolve_inputs().expect("inputs should resolve");
        assert_eq!(resolved.ports, "main,web");
    }

    #[test]
    fn resolves_file_inputs() {
        let base = std::env::temp_dir().join(format!("rscan-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("temp dir should exist");

        let hosts_file = base.join("hosts.txt");
        let ports_file = base.join("ports.txt");
        let urls_file = base.join("urls.txt");
        let users_file = base.join("users.txt");
        let passwords_file = base.join("passwords.txt");
        let hash_file = base.join("hashes.txt");

        std::fs::write(
            &hosts_file,
            "# comment\n10.0.0.1\n10.0.0.2:8443\n10.0.0.3:9443 # inline comment\n",
        )
        .expect("hosts file");
        std::fs::write(&ports_file, "80\n443\n").expect("ports file");
        std::fs::write(&urls_file, "http://a\nhttp://b\n").expect("urls file");
        std::fs::write(&users_file, "root\nadmin\n").expect("users file");
        std::fs::write(&passwords_file, "pass1\npass2\n").expect("passwords file");
        std::fs::write(&hash_file, "0123456789abcdef0123456789abcdef\n").expect("hash file");

        let config = AppConfig::from_tokens([
            "-hf",
            hosts_file.to_string_lossy().as_ref(),
            "-pf",
            ports_file.to_string_lossy().as_ref(),
            "-uf",
            urls_file.to_string_lossy().as_ref(),
            "-userf",
            users_file.to_string_lossy().as_ref(),
            "-pwdf",
            passwords_file.to_string_lossy().as_ref(),
            "-hashf",
            hash_file.to_string_lossy().as_ref(),
        ])
        .expect("config should parse");

        let resolved = config.resolve_inputs().expect("inputs should resolve");
        assert_eq!(resolved.hosts, vec!["10.0.0.1"]);
        assert_eq!(resolved.host_ports, vec!["10.0.0.2:8443", "10.0.0.3:9443"]);
        assert_eq!(resolved.urls, vec!["http://a", "http://b"]);
        assert_eq!(resolved.usernames, vec!["root", "admin"]);
        assert_eq!(resolved.passwords, vec!["pass1", "pass2"]);
        assert_eq!(resolved.ports, "80,443");
        assert_eq!(
            resolved.hashes,
            vec!["0123456789abcdef0123456789abcdef".to_string()]
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resolves_exclusion_inputs() {
        let config = AppConfig::from_tokens([
            "-h",
            "10.0.0.1,10.0.0.2",
            "-eh",
            "10.0.0.2",
            "-ep",
            "80,443",
        ])
        .expect("config should parse");

        let resolved = config.resolve_inputs().expect("inputs should resolve");
        assert_eq!(resolved.exclude_hosts, vec!["10.0.0.2"]);
        assert_eq!(resolved.exclude_ports, "80,443");
    }

    #[test]
    fn validates_single_runtime_mode() {
        let config = AppConfig::from_tokens(["-h", "10.0.0.1"]).expect("config should parse");
        config.validate_run_mode().expect("single host mode should pass");

        let config = AppConfig::from_tokens(["-u", "http://127.0.0.1"]).expect("config should parse");
        config.validate_run_mode().expect("single url mode should pass");

        let config = AppConfig::from_tokens(["-local"]).expect("config should parse");
        config.validate_run_mode().expect("local mode should pass");

        let config = AppConfig::from_tokens(["-m", "localinfo"]).expect("config should parse");
        config
            .validate_run_mode()
            .expect("named local mode should pass");
    }

    #[test]
    fn rejects_missing_runtime_target() {
        let config = AppConfig::from_tokens(Vec::<String>::new()).expect("defaults should parse");
        let error = config
            .validate_run_mode()
            .expect_err("missing target should fail");
        assert!(matches!(error, ConfigError::MissingScanTarget));
    }

    #[test]
    fn rejects_conflicting_runtime_modes() {
        let config = AppConfig::from_tokens(["-h", "10.0.0.1", "-u", "http://127.0.0.1"])
            .expect("config should parse");
        config
            .validate_run_mode()
            .expect("host and url should be allowed like go");

        let config = AppConfig::from_tokens(["-h", "10.0.0.1", "-local"])
            .expect("config should parse");
        let error = config
            .validate_run_mode()
            .expect_err("host and local should conflict");
        assert!(matches!(error, ConfigError::ConflictingScanModes));

        let config = AppConfig::from_tokens(["-h", "10.0.0.1", "-m", "redis,localinfo"])
            .expect("config should parse");
        config
            .validate_run_mode()
            .expect("host mode should allow mixed local plugin list like go");
    }
}
