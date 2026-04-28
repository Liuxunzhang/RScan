use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use super::*;

pub(crate) fn scan_imap(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("imap", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if imap_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "imap".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("imap")),
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

pub(crate) fn imap_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Ok(mut stream) = connect_stream(target, timeout) {
        if imap_login_with_stream(&mut stream, username, password)? {
            return Ok(true);
        }
    }

    let mut tls_stream = connect_tls_stream(target, timeout)?;
    imap_login_with_stream(&mut tls_stream, username, password)
}

pub(crate) fn imap_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if banner.is_empty() {
        return Ok(false);
    }

    write_and_flush_io(
        stream,
        format!("a001 LOGIN \"{username}\" \"{password}\"\r\n").as_bytes(),
    )?;

    loop {
        let line = read_line_io(stream)?;
        if line.is_empty() {
            return Ok(false);
        }
        if line.contains("a001 OK") {
            let _ = write_and_flush_io(stream, b"a002 LOGOUT\r\n");
            return Ok(true);
        }
        if line.contains("a001 NO") || line.contains("a001 BAD") {
            return Ok(false);
        }
    }
}
