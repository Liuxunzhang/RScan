use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

use super::*;

pub(crate) fn scan_elasticsearch(
    target: &OpenService,
    context: &PluginContext,
) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(context.timeout_secs.max(1)))
        .build()
        .context("failed to build elasticsearch client")?;

    for scheme in ["http", "https"] {
        let base = format!("{scheme}://{}:{}", target.host, target.port);
        let unauth = client.get(format!("{base}/_cat/indices")).send();
        if let Ok(response) = unauth {
            if response.status().is_success() {
                return Ok(Some(PluginFinding {
                    plugin: "elasticsearch".to_string(),
                    target: target.clone(),
                    status: "unauthorized".to_string(),
                    details: BTreeMap::from([
                        ("service".to_string(), json!("elasticsearch")),
                        ("port".to_string(), json!(target.port)),
                        ("type".to_string(), json!("unauthorized")),
                        ("scheme".to_string(), json!(scheme)),
                    ]),
                }));
            }
        }

        for username in usernames_for_service("elasticsearch", context) {
            for password in passwords_for_user(Some(username.as_str()), context) {
                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                let response = client
                    .get(format!("{base}/_cat/indices"))
                    .header(reqwest::header::AUTHORIZATION, format!("Basic {auth}"))
                    .send();
                if let Ok(response) = response {
                    if response.status().is_success() {
                        return Ok(Some(PluginFinding {
                            plugin: "elasticsearch".to_string(),
                            target: target.clone(),
                            status: "weak-password".to_string(),
                            details: BTreeMap::from([
                                ("service".to_string(), json!("elasticsearch")),
                                ("port".to_string(), json!(target.port)),
                                ("type".to_string(), json!("weak-password")),
                                ("scheme".to_string(), json!(scheme)),
                                ("username".to_string(), json!(username)),
                                ("password".to_string(), json!(password)),
                            ]),
                        }));
                    }
                }
            }
        }
    }

    Ok(None)
}
