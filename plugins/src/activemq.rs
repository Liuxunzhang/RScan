use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_activemq(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
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

pub(crate) fn activemq_login(
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
