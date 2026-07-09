//! Scan-pipeline execution helpers extracted from the main orchestration.
//!
//! These free functions own the parallel web/POC execution loops and the
//! translation from `AppConfig`/`ResolvedInputs` into the runtime bundles
//! consumed by service plugins, keeping `Application::run_with_emitter` focused
//! on pipeline ordering.

use anyhow::Result;
use rscan_config::{AppConfig, ResolvedInputs, WebConfig};
use rscan_output::ResultType;
use rscan_plugins::{
    AuthRuntimeOptions, ConnectionRuntimeOptions, Ms17010RuntimeOptions, PluginContext,
    RedisRuntimeOptions, ServiceRuntimeBundle, ServiceScanRuntimeOptions,
};
use rscan_poc::{Poc, PocExecutionOptions, PocMatch, execute_pocs};
use rscan_web::{WebScanResult, WebScanner};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

pub(crate) fn build_service_runtime_bundle(
    config: &AppConfig,
    resolved: &ResolvedInputs,
) -> ServiceRuntimeBundle {
    ServiceRuntimeBundle {
        auth: AuthRuntimeOptions {
            domain: config.auth.domain.clone(),
            hashes: resolved.hashes.clone(),
            disable_brute: config.scan.disable_brute,
        },
        redis: RedisRuntimeOptions {
            redis_file: config.redis.redis_file.clone(),
            redis_shell: config.redis.redis_shell.clone(),
            disable_redis: config.redis.disable_redis,
            redis_write_path: config.redis.redis_write_path.clone(),
            redis_write_content: config.redis.redis_write_content.clone(),
            redis_write_file: config.redis.redis_write_file.clone(),
        },
        ms17010: Ms17010RuntimeOptions {
            shellcode: config.runtime.shellcode.clone(),
        },
        connection: ConnectionRuntimeOptions {
            max_retries: config.scan.max_retries,
        },
        service: ServiceScanRuntimeOptions {
            module_threads: config.scan.module_threads,
            global_timeout_secs: config.scan.global_timeout_secs,
            log_errors: config.output.log_level.eq_ignore_ascii_case("debug"),
        },
    }
}

pub(crate) fn build_plugin_context(config: &AppConfig, resolved: &ResolvedInputs) -> PluginContext {
    PluginContext {
        usernames: resolved.usernames.clone(),
        passwords: resolved.passwords.clone(),
        timeout_secs: config.scan.timeout_secs,
        ssh_key_path: config.auth.ssh_key_path.clone(),
    }
}

pub(crate) fn is_local_only_mode(mode: &str) -> bool {
    matches!(
        mode.to_ascii_lowercase().as_str(),
        "localinfo" | "dcinfo" | "minidump"
    )
}

pub(crate) fn selected_local_modules(mode: &str, local_mode: bool) -> Vec<String> {
    let mode = mode.to_ascii_lowercase();
    if is_local_only_mode(&mode) {
        vec![mode]
    } else if local_mode {
        vec!["localinfo".to_string()]
    } else {
        Vec::new()
    }
}

pub(crate) fn target_count(config: &AppConfig) -> usize {
    config.targets.defined_target_count()
}

pub(crate) fn plugin_result_type(plugin: &str) -> ResultType {
    match plugin {
        "findnet" | "netbios" => ResultType::Service,
        _ => ResultType::Vuln,
    }
}

pub(crate) fn scan_web_targets(
    targets: &[String],
    config: &WebConfig,
    concurrency: usize,
) -> Vec<WebScanResult> {
    if targets.is_empty() {
        return Vec::new();
    }

    let Ok(scanner) = WebScanner::new(config) else {
        return Vec::new();
    };
    let worker_count = concurrency.max(1).min(targets.len());
    let next_index = AtomicUsize::new(0);
    let total = targets.len();

    let mut results = thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let next_index = &next_index;
            let scanner = scanner.clone();
            workers.push(scope.spawn(move || {
                let mut local = Vec::new();
                loop {
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    if index >= total {
                        break;
                    }
                    if let Ok(result) = scanner.scan_target(&targets[index]) {
                        local.push((index, result));
                    }
                }
                local
            }));
        }

        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("web scan worker panicked"))
            .collect::<Vec<_>>()
    });
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

pub(crate) fn execute_pocs_for_targets(
    targets: &[WebScanResult],
    pocs: &[Poc],
    options: &PocExecutionOptions,
) -> Result<Vec<PocMatch>> {
    if targets.is_empty() || pocs.is_empty() {
        return Ok(Vec::new());
    }

    let total_workers = options.workers.max(1);
    let target_workers = total_workers.min(targets.len());
    let per_target_workers = (total_workers / target_workers).max(1);
    let next_index = AtomicUsize::new(0);
    let total = targets.len();

    let (mut matches, errors) = thread::scope(|scope| {
        let mut workers = Vec::with_capacity(target_workers);
        for _ in 0..target_workers {
            let next_index = &next_index;
            let mut options = options.clone();
            options.workers = per_target_workers;

            workers.push(scope.spawn(move || {
                let mut local_matches = Vec::new();
                let mut local_errors = Vec::new();
                loop {
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    if index >= total {
                        break;
                    }
                    let target = &targets[index].final_url;
                    match execute_pocs(target, pocs, &options) {
                        Ok(target_matches) => local_matches.push((index, target_matches)),
                        Err(error) => local_errors.push(error),
                    }
                }
                (local_matches, local_errors)
            }));
        }

        let mut matches = Vec::new();
        let mut errors = Vec::new();
        for worker in workers {
            let (mut worker_matches, mut worker_errors) =
                worker.join().expect("POC worker panicked");
            matches.append(&mut worker_matches);
            errors.append(&mut worker_errors);
        }
        (matches, errors)
    });

    if let Some(error) = errors.into_iter().next() {
        return Err(error);
    }
    matches.sort_by_key(|(index, _)| *index);
    Ok(matches
        .into_iter()
        .flat_map(|(_, target_matches)| target_matches)
        .collect())
}
