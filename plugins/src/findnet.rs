use anyhow::Result;
use serde_json::json;
use std::collections::BTreeMap;

use super::*;

pub(crate) fn scan_findnet(target: &OpenService, timeout_secs: u64) -> Result<Option<PluginFinding>> {
    if let Some((hostname, ipv4, ipv6)) = findnet_probe(target, timeout_secs)? {
        let mut details = BTreeMap::new();
        if !hostname.is_empty() {
            details.insert("hostname".to_string(), json!(hostname));
        }
        if !ipv4.is_empty() {
            details.insert("ipv4".to_string(), json!(ipv4));
        }
        if !ipv6.is_empty() {
            details.insert("ipv6".to_string(), json!(ipv6));
        }
        return Ok(Some(PluginFinding {
            plugin: "findnet".to_string(),
            target: target.clone(),
            status: "identified".to_string(),
            details,
        }));
    }

    Ok(None)
}
