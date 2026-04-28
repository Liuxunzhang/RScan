use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_smb(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_smb_with(target, context, smb_login)
}

pub(crate) fn scan_smb2(target: &OpenService, context: &PluginContext) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    scan_smb2_with(target, context, smb2_login)
}

pub(crate) fn scan_smb_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, u64) -> Result<bool>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    for username in usernames_for_service("smb", context) {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if login(target, &username, &password, &domain, context.timeout_secs)? {
                let mut details = BTreeMap::from([
                    ("service".to_string(), json!("smb")),
                    ("port".to_string(), json!(target.port)),
                    ("type".to_string(), json!("weak-password")),
                    ("username".to_string(), json!(username)),
                    ("password".to_string(), json!(password)),
                ]);
                if !domain.is_empty() {
                    details.insert("domain".to_string(), json!(domain));
                }
                return Ok(Some(PluginFinding {
                    plugin: "smb".to_string(),
                    target: target.clone(),
                    status: "weak-password".to_string(),
                    details,
                }));
            }
        }
    }

    Ok(None)
}

pub(crate) fn scan_smb2_with<F>(
    target: &OpenService,
    context: &PluginContext,
    mut login: F,
) -> Result<Option<PluginFinding>>
where
    F: FnMut(&OpenService, &str, &str, &str, Smb2AuthMode, u64) -> Result<Option<Vec<String>>>,
{
    let runtime = current_auth_runtime_options();
    let domain = runtime.domain.unwrap_or_default();
    let usernames = usernames_for_service("smb2", context);
    if !runtime.hashes.is_empty() {
        for username in usernames {
            for hash in &runtime.hashes {
                if let Some(shares) = login(
                    target,
                    &username,
                    hash,
                    &domain,
                    Smb2AuthMode::Hash,
                    context.timeout_secs,
                )? {
                    return Ok(Some(build_smb2_finding(
                        target,
                        &username,
                        hash,
                        &domain,
                        Smb2AuthMode::Hash,
                        shares,
                    )));
                }
            }
        }
        return Ok(None);
    }

    for username in usernames {
        for password in passwords_for_user(Some(username.as_str()), context) {
            if let Some(shares) = login(
                target,
                &username,
                &password,
                &domain,
                Smb2AuthMode::Password,
                context.timeout_secs,
            )? {
                return Ok(Some(build_smb2_finding(
                    target,
                    &username,
                    &password,
                    &domain,
                    Smb2AuthMode::Password,
                    shares,
                )));
            }
        }
    }

    Ok(None)
}

pub(crate) fn smb_login(
    target: &OpenService,
    username: &str,
    password: &str,
    domain: &str,
    timeout_secs: u64,
) -> Result<bool> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build smb runtime")?;

    runtime.block_on(async {
        let client = Smb2Client::connect(Smb2ClientConfig {
            addr: format!("{}:{}", target.host, target.port),
            timeout,
            username: username.to_string(),
            password: password.to_string(),
            nt_hash: None,
            domain: domain.to_string(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: false,
            dfs_target_overrides: Default::default(),
        })
        .await;

        match client {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    })
}

pub(crate) fn smb2_login(
    target: &OpenService,
    username: &str,
    credential: &str,
    domain: &str,
    auth_mode: Smb2AuthMode,
    timeout_secs: u64,
) -> Result<Option<Vec<String>>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let nt_hash = match auth_mode {
        Smb2AuthMode::Password => None,
        Smb2AuthMode::Hash => Some(
            hex::decode(credential)
                .with_context(|| format!("invalid smb2 hash for user {username}"))?,
        ),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build smb2 runtime")?;

    runtime.block_on(async {
        let client = Smb2Client::connect(Smb2ClientConfig {
            addr: format!("{}:{}", target.host, target.port),
            timeout,
            username: username.to_string(),
            password: credential.to_string(),
            nt_hash,
            domain: domain.to_string(),
            auto_reconnect: false,
            compression: false,
            dfs_enabled: false,
            dfs_target_overrides: Default::default(),
        })
        .await;

        match client {
            Ok(mut client) => match client.list_shares().await {
                Ok(shares) => Ok(Some(
                    shares
                        .into_iter()
                        .map(|share| share.name)
                        .collect::<Vec<_>>(),
                )),
                Err(_) => Ok(Some(Vec::new())),
            },
            Err(_) => Ok(None),
        }
    })
}

pub(crate) fn build_smb2_finding(
    target: &OpenService,
    username: &str,
    credential: &str,
    domain: &str,
    auth_mode: Smb2AuthMode,
    shares: Vec<String>,
) -> PluginFinding {
    let mut details = BTreeMap::from([
        ("service".to_string(), json!("smb2")),
        ("port".to_string(), json!(target.port)),
        ("type".to_string(), json!("weak-auth")),
        ("username".to_string(), json!(username)),
        ("credential".to_string(), json!(credential)),
        (
            "auth_type".to_string(),
            json!(match auth_mode {
                Smb2AuthMode::Password => "password",
                Smb2AuthMode::Hash => "hash",
            }),
        ),
    ]);
    if !domain.is_empty() {
        details.insert("domain".to_string(), json!(domain));
    }
    if !shares.is_empty() {
        details.insert("shares".to_string(), json!(shares));
    }
    PluginFinding {
        plugin: "smb2".to_string(),
        target: target.clone(),
        status: "weak-auth".to_string(),
        details,
    }
}
