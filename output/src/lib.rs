use anyhow::{Context, Result};
use rscan_config::{OutputConfig, OutputFormat};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Static string constants for BTreeMap keys to avoid repeated allocations
pub mod keys {
    pub const PORT: &str = "port";
    pub const SERVICE: &str = "service";
    pub const TITLE: &str = "title";
    pub const STATUS_CODE: &str = "status_code";
    pub const BANNER: &str = "banner";
    pub const VERSION: &str = "version";
    pub const PRODUCT: &str = "product";
    pub const OS: &str = "os";
    pub const INFO: &str = "info";
    pub const URL: &str = "Url";
    pub const LENGTH: &str = "length";
    pub const FINGERPRINTS: &str = "fingerprints";
    pub const SERVER_INFO: &str = "server_info";
    pub const REDIRECT_URL: &str = "redirect_Url";
    pub const POC: &str = "poc";
    pub const GROUP: &str = "group";
    pub const VARIABLES: &str = "variables";
    pub const PROTOCOL: &str = "protocol";
    pub const PROCESS_NAME: &str = "process_name";
    pub const PID: &str = "pid";
    pub const OUTPUT_PATH: &str = "output_path";
    pub const DOMAIN: &str = "domain";
    pub const DOMAIN_CONTROLLERS: &str = "domain_controllers";
    pub const HOSTNAME: &str = "hostname";
    pub const USERNAME: &str = "username";
    pub const ARCH: &str = "arch";
    pub const HOME_DIR: &str = "home_dir";
    pub const CURRENT_DIR: &str = "current_dir";
    pub const SENSITIVE_FILES: &str = "sensitive_files";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultType {
    #[serde(rename = "HOST")]
    Host,
    #[serde(rename = "PORT")]
    Port,
    #[serde(rename = "SERVICE")]
    Service,
    #[serde(rename = "VULN")]
    Vuln,
}

impl ResultType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "HOST",
            Self::Port => "PORT",
            Self::Service => "SERVICE",
            Self::Vuln => "VULN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub time: String,
    #[serde(rename = "type")]
    pub kind: ResultType,
    pub target: String,
    pub status: String,
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug)]
pub struct OutputManager {
    path: Option<PathBuf>,
    format: OutputFormat,
    sink: Option<OutputSink>,
}

#[derive(Debug)]
enum OutputSink {
    Text(BufWriter<File>),
    Json(BufWriter<File>),
    Csv(csv::Writer<BufWriter<File>>),
}

impl OutputManager {
    pub fn initialize(config: &OutputConfig) -> Result<Self> {
        if config.no_write {
            return Ok(Self {
                path: None,
                format: config.effective_format(),
                sink: None,
            });
        }

        let path = config.effective_path();
        let format = config.effective_format();

        ensure_parent_dir(&path)?;

        let sink = match format {
            OutputFormat::Txt => {
                let file = File::create(&path)
                    .with_context(|| format!("failed to create {}", path.display()))?;
                OutputSink::Text(BufWriter::new(file))
            }
            OutputFormat::Json => {
                let file = File::create(&path)
                    .with_context(|| format!("failed to create {}", path.display()))?;
                OutputSink::Json(BufWriter::new(file))
            }
            OutputFormat::Csv => {
                let file = File::create(&path)
                    .with_context(|| format!("failed to create {}", path.display()))?;
                let mut writer = csv::Writer::from_writer(BufWriter::new(file));
                writer.write_record(["Time", "Type", "Target", "Status", "Details"])?;
                OutputSink::Csv(writer)
            }
        };

        Ok(Self {
            path: Some(path),
            format,
            sink: Some(sink),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn format(&self) -> OutputFormat {
        self.format
    }

    pub fn write_result(&mut self, result: &ScanResult) -> Result<()> {
        let Some(sink) = &mut self.sink else {
            return Ok(());
        };

        match sink {
            OutputSink::Text(file) => {
                let details = result
                    .details
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(
                    file,
                    "[{}] {} {} {} {}",
                    result.time,
                    result.kind.as_str(),
                    result.target,
                    result.status,
                    details
                )?;
            }
            OutputSink::Json(file) => {
                serde_json::to_writer_pretty(file.by_ref(), result)?;
                writeln!(file)?;
            }
            OutputSink::Csv(writer) => {
                writer.write_record([
                    result.time.as_str(),
                    result.kind.as_str(),
                    result.target.as_str(),
                    result.status.as_str(),
                    serde_json::to_string(&result.details)?.as_str(),
                ])?;
            }
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        let Some(sink) = &mut self.sink else {
            return Ok(());
        };

        match sink {
            OutputSink::Text(file) | OutputSink::Json(file) => file.flush()?,
            OutputSink::Csv(writer) => writer.flush()?,
        }

        Ok(())
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rscan_config::OutputConfig;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn disables_output_when_requested() {
        let manager = OutputManager::initialize(&OutputConfig {
            no_write: true,
            ..OutputConfig::default()
        })
        .expect("manager should initialize");

        assert!(manager.path().is_none());
    }

    #[test]
    fn uses_api_output_override() {
        let manager = OutputManager::initialize(&OutputConfig {
            path: PathBuf::from("reports/out.txt"),
            api_addr: Some("http://127.0.0.1:8088".to_string()),
            ..OutputConfig::default()
        })
        .expect("manager should initialize");

        assert_eq!(manager.format(), OutputFormat::Csv);
        assert_eq!(
            manager.path().expect("output path should exist"),
            Path::new("reports/fscanapi.csv")
        );
    }

    #[test]
    fn writes_pretty_json_records() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rscan-output-{unique}.json"));
        let mut manager = OutputManager::initialize(&OutputConfig {
            format: OutputFormat::Json,
            path: path.clone(),
            ..OutputConfig::default()
        })
        .expect("manager should initialize");

        manager
            .write_result(&ScanResult {
                time: "2025-01-01T00:00:00Z".to_string(),
                kind: ResultType::Service,
                target: "127.0.0.1".to_string(),
                status: "identified".to_string(),
                details: BTreeMap::from([("port".to_string(), json!(22))]),
            })
            .expect("json result should write");
        manager.flush().expect("json result should flush");

        let content = fs::read_to_string(&path).expect("json output should exist");
        assert!(content.contains("\n  \"time\": \"2025-01-01T00:00:00Z\""));
        assert!(content.ends_with("}\n"));

        fs::remove_file(path).expect("temp output should be removable");
    }
}
