use anyhow::Result;
use rscan_config::{AppConfig, CommandAction, VERSION, help_text, help_text_for};
use rscan_core::Application;
use rscan_output::OutputManager;
use std::thread;
use std::time::Duration;

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
            println!("rscan {}", VERSION);
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

    let app = Application::new(config.clone());
    if let Err(error) = app.validate_mode_selection() {
        eprintln!(
            "error: {error}\n\n{}",
            help_text_for(&config.runtime.language)
        );
        std::process::exit(2);
    }
    if config.output.show_scan_plan {
        println!("{}", app.render_scan_plan()?);
    }

    let output = OutputManager::initialize(&config.output)?;
    let stdout_enabled = should_write_stdout(&config);
    let report = app.run()?;

    let total_results = report.results.len();
    for (index, result) in report.results.iter().enumerate() {
        output.write_result(result)?;
        if stdout_enabled {
            let prefix = if config.output.show_progress && total_results > 0 {
                format!("[{}/{}] ", index + 1, total_results)
            } else {
                String::new()
            };
            let line = format!(
                "{}discovered {} {} {}",
                prefix,
                result.kind.as_str(),
                result.target,
                result.status
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

    if stdout_enabled {
        if let Some(path) = output.path() {
            println!("initialized output: {}", path.display());
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
