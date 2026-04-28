use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_rsync(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
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

pub(crate) fn rsync_login(
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
    if auth_response.contains("@RSYNCD: AUTHREQD") {
        if let (Some(username), Some(password)) = (username, password) {
            write_and_flush(
                &mut auth_stream,
                format!("{username} {password}\n").as_bytes(),
            )?;
            let final_response = read_line(&mut auth_stream)?;
            if !final_response.contains("@ERROR") {
                return Ok(Some(module_name));
            }
        }
    }
    Ok(None)
}
