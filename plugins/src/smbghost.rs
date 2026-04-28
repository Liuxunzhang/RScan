use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;

use super::*;

pub(crate) fn scan_smbghost(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if brute_force_disabled() {
        return Ok(None);
    }
    if detect_smbghost(target, timeout_secs)? {
        return Ok(Some(PluginFinding {
            plugin: "smbghost".to_string(),
            target: target.clone(),
            status: "vulnerable".to_string(),
            details: BTreeMap::from([
                ("service".to_string(), json!("smb")),
                ("port".to_string(), json!(target.port)),
                ("type".to_string(), json!("cve-2020-0796")),
                ("name".to_string(), json!("SmbGhost")),
            ]),
        }));
    }

    Ok(None)
}
