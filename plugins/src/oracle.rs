use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_oracle(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_oracle_with(target, context, oracle_login)
}

pub(crate) fn scan_oracle_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64, bool) -> Result<bool>,
{
    let mut attempted = BTreeSet::new();

    for (username, password) in ORACLE_HIGH_RISK_CREDENTIALS {
        let username = (*username).to_string();
        let password = (*password).to_string();
        if !attempted.insert((username.clone(), password.clone())) {
            continue;
        }
        if let Some(finding) = oracle_attempt_service_names(
            target,
            &username,
            &password,
            context.timeout_secs,
            &mut login,
        )? {
            return Ok(Some(finding));
        }
    }

    for raw_username in usernames_for_service("oracle", context) {
        let username = raw_username.to_ascii_uppercase();
        for password in passwords_for_user(Some(raw_username.as_str()), context) {
            if !attempted.insert((username.clone(), password.clone())) {
                continue;
            }
            if let Some(finding) = oracle_attempt_service_names(
                target,
                &username,
                &password,
                context.timeout_secs,
                &mut login,
            )? {
                return Ok(Some(finding));
            }
        }
    }

    Ok(None)
}

pub(crate) fn oracle_attempt_service_names<F>(
    target: &OpenService,
    username: &str,
    password: &str,
    timeout_secs: u64,
    login: &mut F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64, bool) -> Result<bool>,
{
    for service_name in ORACLE_COMMON_SERVICE_NAMES {
        if login(
            target,
            username,
            password,
            service_name,
            timeout_secs,
            false,
        )? || (username.eq_ignore_ascii_case("SYS")
            && login(target, username, password, service_name, timeout_secs, true)?)
        {
            return Ok(Some(PluginFinding {
                plugin: "oracle".to_string(),
                target: target.clone(),
                status: "weak-password".to_string(),
                details: BTreeMap::from([
                    ("service".to_string(), json!("oracle")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                    ("service_name".to_string(), json!(service_name)),
                ]),
            }));
        }
    }

    Ok(None)
}

pub(crate) fn oracle_login(
    target: &OpenService,
    username: &str,
    password: &str,
    service_name: &str,
    timeout_secs: u64,
    as_sysdba: bool,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build oracle runtime")?;

    runtime.block_on(async {
        let mut config = OracleConfig::new(&target.host, target.port, service_name, username, password)
            .connect_timeout(timeout);
        if as_sysdba {
            config = config.with_sysdba();
        }
        match tokio::time::timeout(timeout, OracleConnection::connect_with_config(config)).await {
            Ok(Ok(connection)) => {
                let _ = tokio::time::timeout(timeout, connection.close()).await;
                Ok(true)
            }
            Ok(Err(_)) | Err(_) => Ok(false),
        }
    })
}
