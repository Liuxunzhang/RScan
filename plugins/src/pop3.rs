use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use super::*;

pub(crate) fn scan_pop3(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("pop3", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            let (authenticated, tls) =
                pop3_login(target, &username, &password, context.timeout_secs)?;
            if authenticated {
                return Ok(Some(PluginFinding {
                    plugin: "pop3".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("pop3")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("weak-password")),
                        ("username".to_string(), json!(username)),
                        ("password".to_string(), json!(password)),
                        ("tls".to_string(), json!(tls)),
                    ]),
                }));
            }
        }
    }

    Ok(None)
}

pub(crate) fn pop3_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<(bool, bool)> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Ok(mut stream) = connect_stream(target, timeout) {
        if pop3_login_with_stream(&mut stream, username, password)? {
            return Ok((true, false));
        }
    }

    let mut tls_stream = connect_tls_stream(target, timeout)?;
    Ok((
        pop3_login_with_stream(&mut tls_stream, username, password)?,
        true,
    ))
}

pub(crate) fn pop3_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if !banner.starts_with("+OK") {
        return Ok(false);
    }

    write_and_flush_io(stream, format!("USER {username}\r\n").as_bytes())?;
    let user_response = read_line_io(stream)?;
    if !user_response.starts_with("+OK") {
        return Ok(false);
    }

    write_and_flush_io(stream, format!("PASS {password}\r\n").as_bytes())?;
    let pass_response = read_line_io(stream)?;
    let _ = write_and_flush_io(stream, b"QUIT\r\n");
    Ok(pass_response.starts_with("+OK"))
}
