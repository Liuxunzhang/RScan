//! Default credential dictionaries and per-service credential resolution shared
//! across brute-force service plugins.

use crate::PluginContext;
use crate::dictionaries::DEFAULT_PASSWORDS;

pub(crate) fn default_usernames(service: &str) -> &'static [&'static str] {
    match service {
        "ftp" => &[
            "ftp", "admin", "www", "web", "root", "db", "wwwroot", "data",
        ],
        "smb" => &["administrator", "admin", "guest"],
        "smb2" => &["administrator", "admin", "guest"],
        "ssh" => &["root", "admin"],
        "telnet" => &["root", "admin", "test"],
        "rdp" => &["administrator", "admin", "guest"],
        "smtp" => &[
            "admin",
            "root",
            "postmaster",
            "mail",
            "smtp",
            "administrator",
        ],
        "imap" => &["admin", "mail", "postmaster", "root", "user", "test"],
        "pop3" => &["admin", "root", "mail", "user", "test", "postmaster"],
        "activemq" => &["admin", "root", "activemq", "system", "user"],
        "rsync" => &["rsync", "root", "admin", "backup"],
        "rabbitmq" => &[
            "guest",
            "admin",
            "administrator",
            "rabbit",
            "rabbitmq",
            "root",
        ],
        "ldap" => &[
            "admin",
            "administrator",
            "root",
            "cn=admin",
            "cn=administrator",
            "cn=manager",
        ],
        "kafka" => &["admin", "kafka", "root", "test"],
        "mssql" => &["sa", "sql"],
        "oracle" => &["sys", "system", "admin", "test", "web", "orcl"],
        "mysql" => &["root", "mysql"],
        "postgres" => &["postgres", "admin"],
        "neo4j" => &["neo4j", "admin", "root", "test"],
        "cassandra" => &["cassandra", "admin", "root", "system"],
        "elasticsearch" => &["elastic", "admin", "kibana"],
        _ => &[],
    }
}

pub(crate) fn usernames_for_service(service: &str, context: &PluginContext) -> Vec<String> {
    if context.usernames.is_empty() {
        default_usernames(service)
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        context.usernames.clone()
    }
}

pub(crate) fn passwords_for_user(username: Option<&str>, context: &PluginContext) -> Vec<String> {
    let seeds: Vec<String> = if context.passwords.is_empty() {
        DEFAULT_PASSWORDS
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        context.passwords.clone()
    };

    let mut expanded = Vec::new();
    for password in seeds {
        let candidate = match username {
            Some(username) => password.replace("{user}", username),
            None => password,
        };
        if !expanded.iter().any(|existing| existing == &candidate) {
            expanded.push(candidate);
        }
    }
    expanded
}
