use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_ssh(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("ssh", context) {
        if let Some(key_path) = &context.ssh_key_path {
            if ssh_key_login(target, &username, key_path, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ssh".to_string(),
                    target: target.clone(),
                    status: "vulnerable".to_string(),
                    details: BTreeMap::from([
                        ("port".to_string(), json!(target.port)),
                        ("service".to_string(), json!("ssh")),
                        ("username".to_string(), json!(username)),
                        ("type".to_string(), json!("weak-password")),
                        ("auth_type".to_string(), json!("key")),
                        (
                            "key_path".to_string(),
                            json!(key_path.to_string_lossy().to_string()),
                        ),
                    ]),
                }));
            }
        }

        for password in passwords_for_user(Some(username.as_str()), context) {
            if ssh_password_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ssh".to_string(),
                    target: target.clone(),
                    status: "vulnerable".to_string(),
                    details: BTreeMap::from([
                        ("port".to_string(), json!(target.port)),
                        ("service".to_string(), json!("ssh")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                        ("type".to_string(), json!("weak-password")),
                        ("auth_type".to_string(), json!("password")),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

pub(crate) fn ssh_password_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let stream = connect_stream(target, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set ssh read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set ssh write timeout")?;

    let mut session = ssh2::Session::new().context("failed to create ssh session")?;
    session.set_timeout((timeout.as_millis().min(u32::MAX as u128)) as u32);
    session.set_tcp_stream(stream);
    session.handshake().context("ssh handshake failed")?;
    session
        .userauth_password(username, password)
        .context("ssh password authentication failed")?;

    if !session.authenticated() {
        return Ok(false);
    }

    let _ = session
        .channel_session()
        .context("ssh session channel open failed")?;
    Ok(true)
}

pub(crate) fn ssh_key_login(
    target: &OpenService,
    username: &str,
    key_path: &PathBuf,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let stream = connect_stream(target, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set ssh read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set ssh write timeout")?;

    let mut session = ssh2::Session::new().context("failed to create ssh session")?;
    session.set_timeout((timeout.as_millis().min(u32::MAX as u128)) as u32);
    session.set_tcp_stream(stream);
    session.handshake().context("ssh handshake failed")?;
    session
        .userauth_pubkey_file(username, None, key_path, None)
        .with_context(|| {
            format!(
                "ssh public key authentication failed for {}",
                key_path.display()
            )
        })?;

    if !session.authenticated() {
        return Ok(false);
    }

    let _ = session
        .channel_session()
        .context("ssh session channel open failed")?;
    Ok(true)
}
