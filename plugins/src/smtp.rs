use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use super::*;

pub(crate) fn scan_smtp(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if smtp_login(target, "", "", context.timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "smtp".to_string(),
            target: target.clone(),
            status: "anonymous-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("smtp")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("anonymous-access")),
                ("anonymous".to_string(), json!(true)),
            ]),
        }));
    }

    for username in usernames_for_service("smtp", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if smtp_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "smtp".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("smtp")),
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

pub(crate) fn smtp_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    match connect_stream(target, timeout) {
        Ok(mut stream) => match smtp_login_with_stream(&mut stream, username, password) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(_) => {
                let mut tls_stream = connect_tls_stream(target, timeout)?;
                smtp_login_with_stream(&mut tls_stream, username, password)
            }
        },
        Err(_) => {
            let mut tls_stream = connect_tls_stream(target, timeout)?;
            smtp_login_with_stream(&mut tls_stream, username, password)
        }
    }
}

pub(crate) fn smtp_login_with_stream<S>(stream: &mut S, username: &str, password: &str) -> Result<bool>
where
    S: Read + Write,
{
    let banner = read_line_io(stream)?;
    if banner.is_empty() {
        anyhow::bail!("missing smtp banner");
    }
    if !smtp_code_is(&banner, 220) {
        return Ok(false);
    }

    write_and_flush_io(stream, b"EHLO rscan\r\n")?;
    let ehlo = read_smtp_response(stream)?;
    if !smtp_code_is(&ehlo, 250) {
        return Ok(false);
    }

    if username.is_empty() {
        write_and_flush_io(stream, b"MAIL FROM:<test@test.com>\r\n")?;
        let response = read_smtp_response(stream)?;
        let _ = write_and_flush_io(stream, b"QUIT\r\n");
        return Ok(smtp_code_is(&response, 250));
    }

    let auth_payload =
        base64::engine::general_purpose::STANDARD.encode(format!("\u{0}{username}\u{0}{password}"));
    write_and_flush_io(stream, format!("AUTH PLAIN {auth_payload}\r\n").as_bytes())?;
    let auth_response = read_smtp_response(stream)?;
    if !smtp_code_is(&auth_response, 235) {
        return Ok(false);
    }

    write_and_flush_io(stream, b"MAIL FROM:<test@test.com>\r\n")?;
    let mail_response = read_smtp_response(stream)?;
    let _ = write_and_flush_io(stream, b"QUIT\r\n");
    Ok(smtp_code_is(&mail_response, 250))
}

pub(crate) fn smtp_code_is(response: &str, code: u16) -> bool {
    response
        .lines()
        .last()
        .and_then(|line| line.get(0..3))
        .and_then(|prefix| prefix.parse::<u16>().ok())
        == Some(code)
}

pub(crate) fn read_smtp_response<S>(stream: &mut S) -> Result<String>
where
    S: Read,
{
    let mut response = String::new();
    loop {
        let line = read_line_io(stream)?;
        if line.is_empty() {
            break;
        }
        let done = line.as_bytes().get(3).copied() != Some(b'-');
        response.push_str(&line);
        if done {
            break;
        }
    }
    Ok(response)
}
