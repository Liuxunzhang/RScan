use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::*;

pub(crate) fn scan_postgres(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    for username in usernames_for_service("postgres", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if postgres_login(target, &username, &password, context.timeout_secs)? {
                return Ok(Some(PluginFinding {
                    plugin: "postgres".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("postgresql")),
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

pub(crate) fn postgres_login(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, &postgres_startup_message(username, "postgres"))?;

    let mut authenticated = false;
    loop {
        match postgres_read_message(&mut stream) {
            Ok((b'R', payload)) => match postgres_auth_code(&payload)? {
                0 => authenticated = true,
                3 => write_and_flush(&mut stream, &postgres_password_message(password))?,
                5 => {
                    let salt = payload.get(4..8).context("missing postgres md5 salt")?;
                    write_and_flush(
                        &mut stream,
                        &postgres_password_message(&postgres_md5_password(
                            username, password, salt,
                        )),
                    )?;
                }
                _ => return Ok(false),
            },
            Ok((b'Z', _)) => return Ok(authenticated),
            Ok((b'E', _)) => return Ok(false),
            Ok(_) => {}
            Err(error)
                if authenticated
                    && error
                        .root_cause()
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| {
                            matches!(
                                io.kind(),
                                ErrorKind::UnexpectedEof
                                    | ErrorKind::ConnectionReset
                                    | ErrorKind::TimedOut
                                    | ErrorKind::WouldBlock
                            )
                        }) =>
            {
                return Ok(true);
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn postgres_startup_message(username: &str, database: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&196_608u32.to_be_bytes());
    payload.extend_from_slice(b"user\0");
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(b"database\0");
    payload.extend_from_slice(database.as_bytes());
    payload.push(0x00);
    payload.extend_from_slice(b"client_encoding\0UTF8\0");
    payload.push(0x00);

    let mut message = Vec::with_capacity(payload.len() + 4);
    message.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(&payload);
    message
}

pub(crate) fn postgres_password_message(password: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(password.len() + 6);
    payload.push(b'p');
    payload.extend_from_slice(&((password.len() + 5) as u32).to_be_bytes());
    payload.extend_from_slice(password.as_bytes());
    payload.push(0x00);
    payload
}

pub(crate) fn postgres_md5_password(username: &str, password: &str, salt: &[u8]) -> String {
    let first = format!("{:x}", md5::compute(format!("{password}{username}")));
    let mut second = first.into_bytes();
    second.extend_from_slice(salt);
    format!("md5{:x}", md5::compute(second))
}

pub(crate) fn postgres_read_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut tag = [0u8; 1];
    stream
        .read_exact(&mut tag)
        .context("failed to read postgres message tag")?;
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .context("failed to read postgres message length")?;
    let size = u32::from_be_bytes(length) as usize;
    if size < 4 {
        anyhow::bail!("invalid postgres message length");
    }
    let mut payload = vec![0u8; size - 4];
    stream
        .read_exact(&mut payload)
        .context("failed to read postgres message payload")?;
    Ok((tag[0], payload))
}

pub(crate) fn postgres_auth_code(payload: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = payload
        .get(0..4)
        .context("missing postgres auth code")?
        .try_into()
        .context("invalid postgres auth code")?;
    Ok(u32::from_be_bytes(bytes))
}
