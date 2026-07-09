use anyhow::Result;
use rscan_fingerprint::ServiceFingerprint;
use rscan_output::{ResultType, ScanResult, keys};
use rscan_platform::{collect_dc_info, collect_local_system_info, collect_minidump};
use rscan_web::WebScanResult;
use serde_json::json;
use std::collections::BTreeMap;
use time::{OffsetDateTime, macros::format_description};

pub(crate) fn build_local_results(modules: &[String]) -> Result<Vec<ScanResult>> {
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

pub(crate) fn selected_web_modules(mode: &str) -> Vec<String> {
    match mode.to_ascii_lowercase().as_str() {
        "webtitle" => vec!["webtitle".to_string()],
        "webpoc" => vec!["webpoc".to_string()],
        _ => Vec::new(),
    }
}

fn build_local_info_result() -> Result<ScanResult> {
    let local = collect_local_system_info()?;
    let mut details = BTreeMap::from([
        (keys::HOSTNAME.to_string(), json!(local.hostname)),
        (keys::USERNAME.to_string(), json!(local.username)),
        (keys::OS.to_string(), json!(local.os)),
        (keys::ARCH.to_string(), json!(local.arch)),
    ]);
    if let Some(home_dir) = local.home_dir {
        details.insert(
            keys::HOME_DIR.to_string(),
            json!(home_dir.to_string_lossy().to_string()),
        );
    }
    if let Some(current_dir) = local.current_dir {
        details.insert(
            keys::CURRENT_DIR.to_string(),
            json!(current_dir.to_string_lossy().to_string()),
        );
    }
    if !local.sensitive_files.is_empty() {
        details.insert(
            keys::SENSITIVE_FILES.to_string(),
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
            (keys::SERVICE.to_string(), json!("minidump")),
            (keys::PROCESS_NAME.to_string(), json!(minidump.process_name)),
            (keys::PID.to_string(), json!(minidump.pid)),
            (
                keys::OUTPUT_PATH.to_string(),
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
            (keys::SERVICE.to_string(), json!("dcinfo")),
            (keys::DOMAIN.to_string(), json!(dcinfo.domain)),
            (
                keys::DOMAIN_CONTROLLERS.to_string(),
                json!(dcinfo.domain_controllers),
            ),
        ]),
    }))
}

pub(crate) fn now_timestamp() -> String {
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    now.format(&format)
        .unwrap_or_else(|_| "1970-01-01 00:00:00".to_string())
}

pub(crate) fn build_fingerprint_scan_result(service: &ServiceFingerprint) -> ScanResult {
    let mut details = BTreeMap::from([
        (keys::PORT.to_string(), json!(service.port)),
        (keys::SERVICE.to_string(), json!(service.service.clone())),
    ]);
    if !service.banner.is_empty() {
        details.insert(keys::BANNER.to_string(), json!(service.banner.clone()));
    }
    if let Some(version) = &service.version {
        details.insert(keys::VERSION.to_string(), json!(version));
    }
    for (key, value) in &service.extras {
        match key.as_str() {
            "vendor_product" => {
                details.insert(keys::PRODUCT.to_string(), json!(value));
            }
            "os" => {
                details.insert(keys::OS.to_string(), json!(value));
            }
            "info" => {
                details.insert(keys::INFO.to_string(), json!(value));
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

pub(crate) fn build_web_scan_result(web: &WebScanResult) -> ScanResult {
    let mut server_info = BTreeMap::from([
        (keys::TITLE.to_string(), json!(web.title.clone())),
        (keys::LENGTH.to_string(), json!(web.length.clone())),
        (keys::STATUS_CODE.to_string(), json!(web.status_code)),
    ]);
    if web.requested_url != web.final_url {
        server_info.insert(keys::REDIRECT_URL.to_string(), json!(web.final_url.clone()));
    }
    for (key, value) in &web.headers {
        server_info.insert(key.to_lowercase(), json!(value));
    }

    let mut details = BTreeMap::from([
        (keys::SERVICE.to_string(), json!("http")),
        (keys::TITLE.to_string(), json!(web.title.clone())),
        (keys::URL.to_string(), json!(web.final_url.clone())),
        (keys::STATUS_CODE.to_string(), json!(web.status_code)),
        (keys::LENGTH.to_string(), json!(web.length.clone())),
        (keys::SERVER_INFO.to_string(), json!(server_info)),
        (
            keys::FINGERPRINTS.to_string(),
            json!(web.fingerprints.clone()),
        ),
    ]);
    if let Some(port) = web_result_port(&web.final_url) {
        details.insert(keys::PORT.to_string(), json!(port));
    }

    ScanResult {
        time: now_timestamp(),
        kind: ResultType::Service,
        target: web.final_url.clone(),
        status: "identified".to_string(),
        details,
    }
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
