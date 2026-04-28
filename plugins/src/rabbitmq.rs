use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;

use super::*;

pub(crate) fn scan_rabbitmq(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    scan_rabbitmq_with(target, context, rabbitmq_login)
}

pub(crate) fn scan_rabbitmq_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, u64) -> Result<bool>,
{
    if brute_force_disabled() {
        return Ok(None);
    }
    if login(target, "guest", "guest", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "rabbitmq".to_string(),
            target: target.clone(),
            status: "weak-password".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("rabbitmq")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("weak-password")),
                ("username".to_string(), json!("guest")),
                ("password".to_string(), json!("guest")),
            ]),
        }));
    }

    for username in usernames_for_service("rabbitmq", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if username == "guest" && password == "guest" {
                continue;
            }
            if login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "rabbitmq".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("rabbitmq")),
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

pub(crate) fn rabbitmq_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout_ms = timeout_secs.max(1) * 1000;
    let username = percent_encode_amqp_credential(username);
    let password = percent_encode_amqp_credential(password);
    let url = format!(
        "amqp://{username}:{password}@{}:{}/?connection_timeout={timeout_ms}",
        target.host, target.port
    );

    match AmqpConnection::insecure_open(&url) {
        Ok(connection) => {
            let _ = connection.close();
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

pub(crate) fn percent_encode_amqp_credential(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
