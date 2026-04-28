use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_rdp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_rdp_with(target, context, rdp_login)
}

pub(crate) fn scan_rdp_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    for username in usernames_for_service("rdp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if login(target, &username, &password, &domain, context.timeout_secs)? {
                let mut details = BTreeMap::from([
                    ("service".to_string(), json!("rdp")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                ]);
                if !domain.is_empty() {
                    details.insert("domain".to_string(), json!(domain));
                }
                return Ok(Some(PluginFinding {
                    plugin: "rdp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details,
                }));
            }
        }
    }

    Ok(None)
}

pub(crate) fn rdp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let stream = connect_stream(target, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set rdp read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set rdp write timeout")?;

    let mut connector = RdpConnector::new().screen(800, 600).credentials(
        domain.to_string(),
        username.to_string(),
        password.to_string(),
    );

    match connector.connect(stream) {
        Ok(mut client) => {
            let _ = client.shutdown();
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}
