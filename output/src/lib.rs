use anyhow::{Context, Result};
use rscan_config::{OutputConfig, OutputFormat};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone)]
pub struct OutputManager {
    path: Option<PathBuf>,
    format: OutputFormat,
}

impl OutputManager {
    pub fn initialize(config: &OutputConfig) -> Result<Self> {
        if config.no_write {
            return Ok(Self {
                path: None,
                format: config.effective_format(),
            });
        }

        let path = config.effective_path();
        let format = config.effective_format();
        let append_mode = config.api_addr.is_none();

        ensure_parent_dir(&path)?;

        match format {
            OutputFormat::Txt | OutputFormat::Json => {
                open_output_file(&path, append_mode)
                    .with_context(|| format!("failed to create {}", path.display()))?;
            }
            OutputFormat::Csv => {
                let should_write_headers = !append_mode || file_is_empty_or_missing(&path)?;
                let file = open_output_file(&path, append_mode)
                    .with_context(|| format!("failed to create {}", path.display()))?;
                if should_write_headers {
                    let mut writer = csv::WriterBuilder::new()
                        .has_headers(false)
                        .from_writer(file);
                    writer.write_record(["Time", "Type", "Target", "Status", "Details"])?;
                    writer.flush()?;
                }
            }
        }

        Ok(Self {
            path: Some(path),
            format,
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn write_result(&self, result: &ScanResult) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        match self.format {
            OutputFormat::Txt => {
                let mut file = OpenOptions::new().append(true).open(path)?;
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
            OutputFormat::Json => {
                let mut file = OpenOptions::new().append(true).open(path)?;
                serde_json::to_writer_pretty(&mut file, result)?;
                writeln!(file)?;
            }
            OutputFormat::Csv => {
                let mut writer = csv::WriterBuilder::new()
                    .has_headers(false)
                    .from_writer(OpenOptions::new().append(true).open(path)?);
                writer.write_record([
                    result.time.as_str(),
                    result.kind.as_str(),
                    result.target.as_str(),
                    result.status.as_str(),
                    serde_json::to_string(&result.details)?.as_str(),
                ])?;
                writer.flush()?;
            }
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

fn open_output_file(path: &Path, append_mode: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if append_mode {
        options.append(true);
    } else {
        options.truncate(true);
    }
    options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

fn file_is_empty_or_missing(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len() == 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
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

        assert_eq!(manager.format, OutputFormat::Csv);
        assert_eq!(
            manager.path().expect("output path should exist"),
            Path::new("reports/rscanapi.csv")
        );
    }

    #[test]
    fn writes_pretty_json_records() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rscan-output-{unique}.json"));
        let manager = OutputManager::initialize(&OutputConfig {
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

        let content = fs::read_to_string(&path).expect("json output should exist");
        assert!(content.contains("\n  \"time\": \"2025-01-01T00:00:00Z\""));
        assert!(content.ends_with("}\n"));

        fs::remove_file(path).expect("temp output should be removable");
    }

    #[test]
    fn appends_json_records_across_initializations_like_go() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rscan-output-append-{unique}.json"));

        for port in [22, 80] {
            let manager = OutputManager::initialize(&OutputConfig {
                format: OutputFormat::Json,
                path: path.clone(),
                ..OutputConfig::default()
            })
            .expect("manager should initialize");

            manager
                .write_result(&ScanResult {
                    time: format!("2025-01-01T00:00:{port:02}Z"),
                    kind: ResultType::Service,
                    target: "127.0.0.1".to_string(),
                    status: "identified".to_string(),
                    details: BTreeMap::from([("port".to_string(), json!(port))]),
                })
                .expect("json result should write");
        }

        let content = fs::read_to_string(&path).expect("json output should exist");
        let records = serde_json::Deserializer::from_str(&content)
            .into_iter::<serde_json::Value>()
            .map(|value| value.expect("json record should parse"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["details"]["port"], json!(22));
        assert_eq!(records[1]["details"]["port"], json!(80));

        fs::remove_file(path).expect("temp output should be removable");
    }

    #[test]
    fn appends_csv_records_without_rewriting_headers() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rscan-output-append-{unique}.csv"));

        for port in [22, 80] {
            let manager = OutputManager::initialize(&OutputConfig {
                format: OutputFormat::Csv,
                path: path.clone(),
                ..OutputConfig::default()
            })
            .expect("manager should initialize");

            manager
                .write_result(&ScanResult {
                    time: format!("2025-01-01T00:00:{port:02}Z"),
                    kind: ResultType::Service,
                    target: "127.0.0.1".to_string(),
                    status: "identified".to_string(),
                    details: BTreeMap::from([("port".to_string(), json!(port))]),
                })
                .expect("csv result should write");
        }

        let content = fs::read_to_string(&path).expect("csv output should exist");
        let lines = content.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "Time,Type,Target,Status,Details");
        assert!(lines[1].contains(",SERVICE,127.0.0.1,identified,"));
        assert!(lines[2].contains(",SERVICE,127.0.0.1,identified,"));

        fs::remove_file(path).expect("temp output should be removable");
    }
}
