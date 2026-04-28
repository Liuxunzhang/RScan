use anyhow::Result;
use rscan_config::{AppConfig, CommandAction, VERSION, help_text, help_text_for};
use rscan_core::Application;
use rscan_output::{OutputManager, ResultType, ScanResult};
use serde_json::Value;
use std::thread;
use std::time::{Duration, Instant};

const OBFUSCATION_KEY: u8 = 0x5a;
const BANNER_WIDTH: usize = 46;
const BANNER_LINES: [&[u8]; 5] = [
    &[
        122, 122, 122, 5, 5, 5, 5, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
        122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122, 122,
        122, 122, 122, 5, 122, 122, 122, 122,
    ],
    &[
        122, 122, 38, 122, 122, 5, 122, 6, 122, 122, 122, 5, 5, 5, 122, 122, 5, 5, 5, 122, 122, 5,
        5, 5, 122, 5, 5, 122, 5, 122, 5, 122, 5, 5, 122, 122, 122, 122, 122, 38, 122, 38, 122, 122,
        122,
    ],
    &[
        122, 122, 38, 122, 38, 5, 115, 122, 38, 122, 117, 122, 5, 5, 38, 117, 122, 5, 5, 38, 117,
        122, 5, 5, 117, 122, 5, 58, 122, 38, 122, 125, 5, 122, 6, 122, 122, 122, 122, 38, 122, 38,
        122, 122, 122,
    ],
    &[
        122, 122, 38, 122, 122, 5, 122, 102, 122, 122, 6, 5, 5, 122, 6, 122, 114, 5, 5, 38, 122,
        114, 5, 38, 122, 114, 5, 38, 122, 38, 122, 38, 122, 38, 122, 38, 122, 122, 122, 38, 5, 38,
        122, 122, 122,
    ],
    &[
        122, 122, 38, 5, 38, 122, 6, 5, 6, 122, 38, 5, 5, 5, 117, 6, 5, 5, 5, 38, 6, 5, 5, 5, 6, 5,
        5, 118, 5, 38, 5, 38, 122, 38, 5, 38, 122, 122, 122, 114, 5, 115, 122, 122, 122,
    ],
];
const BANNER_LABEL: &[u8] = &[
    122, 122, 122, 122, 122, 122, 8, 41, 57, 59, 52, 122, 12, 63, 40, 41, 51, 53, 52, 96, 122,
];
const RSCAN_NAME: &[u8] = &[40, 41, 57, 59, 52];

fn main() -> Result<()> {
    let config = match AppConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}\n\n{}", help_text());
            std::process::exit(2);
        }
    };

    match config.action {
        CommandAction::Help => {
            println!("{}", help_text_for(&config.runtime.language));
            return Ok(());
        }
        CommandAction::Version => {
            println!("{} {}", decode_obfuscated(RSCAN_NAME), VERSION);
            return Ok(());
        }
        CommandAction::Run => {}
    }

    if let Err(error) = config.validate_run_mode() {
        eprintln!(
            "error: {error}\n\n{}",
            help_text_for(&config.runtime.language)
        );
        std::process::exit(2);
    }

    let stdout_enabled = should_write_stdout(&config);
    if stdout_enabled {
        print_banner();
    }

    let app = Application::new(config.clone());
    if config.output.show_scan_plan {
        println!("{}", app.render_scan_plan()?);
    }

    let mut output = OutputManager::initialize(&config.output)?;
    let started = Instant::now();
    if stdout_enabled {
        println!("{} scan started", elapsed_prefix(started.elapsed()));
    }
    let report = app.run()?;

    let total_results = report.results.len();
    for (index, result) in report.results.iter().enumerate() {
        output.write_result(result)?;
        if stdout_enabled {
            let progress = if config.output.show_progress && total_results > 0 {
                format!("[{}/{}] ", index + 1, total_results)
            } else {
                String::new()
            };
            let line = format!(
                "{} {progress}{}",
                elapsed_prefix(started.elapsed()),
                format_result_line(result)
            );
            println!(
                "{}",
                colorize_line(&line, result.kind.as_str(), config.output.no_color)
            );
            if config.output.slow_log_output {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    output.flush()?;

    if stdout_enabled {
        println!(
            "{} scan completed: {} results",
            elapsed_prefix(started.elapsed()),
            report.results.len()
        );
        if let Some(path) = output.path() {
            println!(
                "{} output: {}",
                elapsed_prefix(started.elapsed()),
                path.display()
            );
        }
        println!("{}", report.summary);
    }

    Ok(())
}

fn should_write_stdout(config: &AppConfig) -> bool {
    if config.output.silent {
        return false;
    }

    !config.output.log_level.eq_ignore_ascii_case("error")
}

fn print_banner() {
    println!("┌{}┐", "─".repeat(BANNER_WIDTH));
    for line in BANNER_LINES {
        println!(
            "│{:<width$}│",
            decode_obfuscated(line),
            width = BANNER_WIDTH
        );
    }
    println!("└{}┘", "─".repeat(BANNER_WIDTH));
    println!("{}{VERSION}\n", decode_obfuscated(BANNER_LABEL));
}

fn decode_obfuscated(bytes: &[u8]) -> String {
    let decoded = bytes
        .iter()
        .map(|byte| byte ^ OBFUSCATION_KEY)
        .collect::<Vec<_>>();
    String::from_utf8(decoded).expect("obfuscated string must be valid utf-8")
}

fn elapsed_prefix(elapsed: Duration) -> String {
    let millis = elapsed.as_millis();
    if millis < 1_000 {
        format!("[{millis}ms]  ")
    } else if millis < 10_000 {
        format!("[{:.2}s]  ", elapsed.as_secs_f64())
    } else {
        format!("[{:.1}s]  ", elapsed.as_secs_f64())
    }
}

fn format_result_line(result: &ScanResult) -> String {
    let target = display_target(result);
    let details = display_details(result);
    if details.is_empty() {
        format!(
            "{:<7} {:<32} {}",
            result.kind.as_str(),
            target,
            result.status
        )
    } else {
        format!(
            "{:<7} {:<32} {:<14} {}",
            result.kind.as_str(),
            target,
            result.status,
            details
        )
    }
}

fn display_target(result: &ScanResult) -> String {
    match result.kind {
        ResultType::Port => result
            .details
            .get("port")
            .and_then(json_value_as_display)
            .map(|port| format!("{}:{port}", result.target))
            .unwrap_or_else(|| result.target.clone()),
        _ => result.target.clone(),
    }
}

fn display_details(result: &ScanResult) -> String {
    match result.kind {
        ResultType::Host => result
            .details
            .get("protocol")
            .and_then(json_value_as_display)
            .map(|protocol| format!("protocol={protocol}"))
            .unwrap_or_default(),
        ResultType::Port => String::new(),
        ResultType::Service => service_details(result),
        ResultType::Vuln => vuln_details(result),
    }
}

fn service_details(result: &ScanResult) -> String {
    let mut parts = Vec::new();
    push_detail(&mut parts, result, "service");
    push_detail(&mut parts, result, "title");
    push_detail(&mut parts, result, "status_code");
    push_detail(&mut parts, result, "product");
    push_detail(&mut parts, result, "version");
    parts.join(" ")
}

fn vuln_details(result: &ScanResult) -> String {
    let mut parts = Vec::new();
    push_detail(&mut parts, result, "service");
    push_detail(&mut parts, result, "type");
    push_detail(&mut parts, result, "poc");
    push_detail(&mut parts, result, "group");
    parts.join(" ")
}

fn push_detail(parts: &mut Vec<String>, result: &ScanResult, key: &str) {
    if let Some(value) = result.details.get(key).and_then(json_value_as_display)
        && !value.is_empty()
    {
        parts.push(format!("{key}={value}"));
    }
}

fn json_value_as_display(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn colorize_line(line: &str, kind: &str, no_color: bool) -> String {
    if no_color {
        return line.to_string();
    }

    let code = match kind {
        "HOST" => "36",
        "PORT" => "33",
        "SERVICE" => "32",
        "VULN" => "31",
        _ => "0",
    };
    format!("\u{1b}[{code}m{line}\u{1b}[0m")
}
