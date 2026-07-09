//! Memcached unauthorized-access detection plugin.

use crate::connection::send_tcp_command;
use crate::{OpenService, PluginContext, PluginFinding};
use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;
pub(crate) fn scan_memcached(
    target: &OpenService,
    context: &PluginContext,
) -> Result<Option<PluginFinding>> {
    let response = send_tcp_command(target, b"stats\r\n", context.timeout_secs)?;
    if response.contains("STAT ") {
        return Ok(Some(PluginFinding {
            plugin: "memcached".to_string(),
            target: target.clone(),
            status: "unauthorized-access".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("memcached")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("unauthorized-access")),
                ("stats".to_string(), json!(response)),
            ]),
        }));
    }
    Ok(None)
}
