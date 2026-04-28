use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_ftp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if ftp_login(target, "anonymous", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "ftp".to_string(),
            target: target.clone(),
            status: "anonymous-login".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("ftp")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-login")),
                ("username".to_string(), json!("anonymous")),
                ("password".to_string(), json!("")),
            ]),
        }));
    }

    for username in usernames_for_service("ftp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if ftp_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "ftp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("ftp")),
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

pub(crate) fn ftp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    let _ = read_available(&mut stream)?;
    write_and_flush(&mut stream, format!("USER {username}\r\n").as_bytes())?;
    let user_response = read_available(&mut stream)?;
    let user_code = ftp_status_code(&user_response);
    if user_code == Some(230) {
        let _ = write_and_flush(&mut stream, b"QUIT\r\n");
        return Ok(true);
    }
    if user_code != Some(331) {
        return Ok(false);
    }

    write_and_flush(&mut stream, format!("PASS {password}\r\n").as_bytes())?;
    let pass_response = read_available(&mut stream)?;
    let _ = write_and_flush(&mut stream, b"QUIT\r\n");
    Ok(ftp_status_code(&pass_response) == Some(230))
}

pub(crate) fn ftp_status_code(response: &str) -> Option<u16> {
    response
        .lines()
        .find_map(|line| line.get(0..3).and_then(|code| code.parse::<u16>().ok()))
}
