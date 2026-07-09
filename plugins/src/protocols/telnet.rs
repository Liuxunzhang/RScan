//! Telnet unauthorized-access / weak-password detection plugin.

use crate::connection::{connect_stream, read_available, write_and_flush};
use crate::credentials::{passwords_for_user, usernames_for_service};
use crate::runtime::brute_force_disabled;
use crate::{OpenService, PluginContext, PluginFinding};
use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelnetAccess {
    NoAuth,
    NeedsAuth,
}
pub(crate) fn scan_telnet(
    target: &OpenService,
    context: &PluginContext,
) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if probe_telnet_access(target, context.timeout_secs)? == TelnetAccess::NoAuth {
        return Ok(Some(PluginFinding {
            plugin: "telnet".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("telnet")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
            ]),
        }));
    }

    for username in usernames_for_service("telnet", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if telnet_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "telnet".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("telnet")),
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

fn probe_telnet_access(target: &OpenService, timeout_secs: u64) -> Result<TelnetAccess> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let banner = read_available(&mut stream)?;
    if looks_like_shell_prompt(&banner) && !looks_like_login_prompt(&banner) {
        Ok(TelnetAccess::NoAuth)
    } else {
        Ok(TelnetAccess::NeedsAuth)
    }
}

fn telnet_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let mut response = read_available(&mut stream)?;

    if looks_like_shell_prompt(&response) && !looks_like_login_prompt(&response) {
        return Ok(true);
    }

    if looks_like_login_prompt(&response) {
        write_and_flush(&mut stream, format!("{username}\n").as_bytes())?;
        response = read_available(&mut stream)?;
    }

    if looks_like_password_prompt(&response) {
        write_and_flush(&mut stream, format!("{password}\n").as_bytes())?;
        response = read_available(&mut stream)?;
    }

    if contains_auth_failure(&response) {
        return Ok(false);
    }

    Ok(looks_like_shell_prompt(&response))
}

fn looks_like_login_prompt(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("login:")
        || value.contains("username:")
        || value.contains("user name:")
        || value.contains("login as:")
}

fn looks_like_password_prompt(value: &str) -> bool {
    value.to_ascii_lowercase().contains("password:")
}

fn contains_auth_failure(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("incorrect")
        || value.contains("failed")
        || value.contains("denied")
        || value.contains("invalid")
}

fn looks_like_shell_prompt(value: &str) -> bool {
    let trimmed = value.trim_end();
    trimmed.ends_with('#') || trimmed.ends_with('$') || trimmed.ends_with('>')
}
