use anyhow::{Context, Result, anyhow};
use encoding_rs::GBK;
use regex::Regex;
use reqwest::Proxy;
use reqwest::blocking::{Client, ClientBuilder};
use rscan_config::WebConfig;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

const OBFUSCATION_KEY: u8 = 0x5a;
const USER_AGENT: &[u8] = &[
    23, 53, 32, 51, 54, 54, 59, 117, 111, 116, 106, 122, 114, 57, 53, 55, 42, 59, 46, 51, 56, 54,
    63, 97, 122, 40, 41, 57, 59, 52, 117, 106, 116, 107, 116, 106, 115,
];
include!(concat!(env!("OUT_DIR"), "/rules_obfuscated.rs"));
const MAX_TITLE_LENGTH: usize = 100;
const MAX_RESPONSE_BODY_BYTES: usize = 2 * 1024 * 1024;
const NO_TITLE_TEXT: &str = "无标题";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebScanResult {
    pub original_target: String,
    pub requested_url: String,
    pub final_url: String,
    pub status_code: u16,
    pub title: String,
    pub length: String,
    pub headers: BTreeMap<String, String>,
    pub fingerprints: Vec<String>,
}

pub fn scan_target(target: &str, config: &WebConfig) -> Result<WebScanResult> {
    WebScanner::new(config)?.scan_target(target)
}

#[derive(Debug, Clone)]
pub struct WebScanner {
    config: WebConfig,
    client: Client,
}

impl WebScanner {
    pub fn new(config: &WebConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            client: build_client(config)?,
        })
    }

    pub fn scan_target(&self, target: &str) -> Result<WebScanResult> {
        let candidates = build_candidate_urls(target);
        let mut last_error = None;

        for candidate in candidates {
            match fetch_target(
                &self.client,
                target,
                &candidate,
                self.config.cookie.as_deref(),
            ) {
                Ok(result) => return Ok(result),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("failed to scan web target: {target}")))
    }
}

fn build_client(config: &WebConfig) -> Result<Client> {
    let mut builder = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .gzip(true)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(Duration::from_secs(config.web_timeout_secs.max(1)));

    if let Some(proxy) = &config.http_proxy {
        builder =
            builder.proxy(Proxy::all(proxy).with_context(|| format!("invalid proxy: {proxy}"))?);
    }
    if let Some(proxy) = &config.socks5_proxy {
        builder = builder
            .proxy(Proxy::all(proxy).with_context(|| format!("invalid socks5 proxy: {proxy}"))?);
    }

    builder.build().context("failed to build web client")
}

fn fetch_target(
    client: &Client,
    original_target: &str,
    url: &str,
    cookie: Option<&str>,
) -> Result<WebScanResult> {
    let mut request = client
        .get(url)
        .header(reqwest::header::USER_AGENT, decode_obfuscated(USER_AGENT));
    if let Some(cookie) = cookie.filter(|cookie| !cookie.is_empty()) {
        request = request.header(reqwest::header::COOKIE, cookie);
    }

    let response = request
        .send()
        .with_context(|| format!("failed to request {url}"))?;

    let status_code = response.status().as_u16();
    let final_url = response.url().to_string();
    let content_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let headers = collect_headers(response.headers());
    let mut body = Vec::new();
    response
        .take((MAX_RESPONSE_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .with_context(|| format!("failed to read response body for {url}"))?;
    if body.len() > MAX_RESPONSE_BODY_BYTES {
        body.truncate(MAX_RESPONSE_BODY_BYTES);
    }
    let body_text = decode_body(&body);
    let title = extract_title(&body_text);
    let fingerprints = match_fingerprints(&body_text, &headers);

    Ok(WebScanResult {
        original_target: original_target.to_string(),
        requested_url: url.to_string(),
        final_url,
        status_code,
        title,
        length: content_length.unwrap_or_else(|| body.len().to_string()),
        headers,
        fingerprints,
    })
}

fn decode_obfuscated(bytes: &[u8]) -> String {
    let decoded = bytes
        .iter()
        .map(|byte| byte ^ OBFUSCATION_KEY)
        .collect::<Vec<_>>();
    String::from_utf8(decoded).expect("obfuscated string must be valid utf-8")
}

fn build_candidate_urls(target: &str) -> Vec<String> {
    if target.contains("://") {
        return vec![target.to_string()];
    }

    if target.ends_with(":80") {
        return vec![format!("http://{target}")];
    }
    if target.ends_with(":443") {
        return vec![format!("https://{target}")];
    }

    vec![format!("https://{target}"), format!("http://{target}")]
}

fn collect_headers(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn extract_title(body: &str) -> String {
    static TITLE_RE: OnceLock<Regex> = OnceLock::new();
    let regex =
        TITLE_RE.get_or_init(|| Regex::new("(?is)<title[^>]*>(.*?)</title>").expect("title regex"));

    if let Some(capture) = regex.captures(body).and_then(|captures| captures.get(1)) {
        let title = normalize_whitespace(capture.as_str());
        if title.is_empty() {
            "\"\"".to_string()
        } else {
            title
        }
    } else {
        NO_TITLE_TEXT.to_string()
    }
}

fn normalize_whitespace(value: &str) -> String {
    value
        .trim()
        .replace('\n', "")
        .replace('\r', "")
        .replace("&nbsp;", " ")
        .chars()
        .take(MAX_TITLE_LENGTH)
        .collect()
}

fn decode_body(body: &[u8]) -> String {
    match std::str::from_utf8(body) {
        Ok(text) => text.to_string(),
        Err(_) => {
            let (decoded, _, _) = GBK.decode(body);
            decoded.into_owned()
        }
    }
}

fn match_fingerprints(body: &str, headers: &BTreeMap<String, String>) -> Vec<String> {
    let headers_blob = headers
        .iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut matches = BTreeSet::new();

    for rule in fingerprint_rules() {
        let haystack = match rule.location {
            MatchLocation::Body => body,
            MatchLocation::Headers => &headers_blob,
        };
        if rule.regex.is_match(haystack) {
            matches.insert(rule.name.clone());
        }
    }

    matches.into_iter().collect()
}

fn fingerprint_rules() -> &'static [FingerprintRule] {
    static RULES: OnceLock<Vec<FingerprintRule>> = OnceLock::new();
    RULES.get_or_init(parse_rules)
}

fn parse_rules() -> Vec<FingerprintRule> {
    rules_source()
        .lines()
        .filter_map(parse_rule_line)
        .filter_map(|(name, kind, rule)| {
            let location = match kind.as_str() {
                "code" | "index" => MatchLocation::Body,
                "headers" | "header" | "cookie" => MatchLocation::Headers,
                _ => return None,
            };
            let regex = Regex::new(&rule).ok()?;
            Some(FingerprintRule {
                name,
                location,
                regex,
            })
        })
        .collect()
}

fn rules_source() -> &'static str {
    static DECODED: OnceLock<String> = OnceLock::new();
    DECODED.get_or_init(|| decode_obfuscated(RULES_SOURCE))
}

fn parse_rule_line(line: &str) -> Option<(String, String, String)> {
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    static RAW: OnceLock<Regex> = OnceLock::new();
    let trimmed = line.trim();
    if !trimmed.starts_with("{\"") {
        return None;
    }

    let quoted = QUOTED.get_or_init(|| {
        Regex::new(r#"^\{"([^"]+)",\s*"([^"]+)",\s*"((?:[^"\\]|\\.)*)"\},?$"#)
            .expect("quoted rule regex")
    });
    if let Some(captures) = quoted.captures(trimmed) {
        return Some((
            captures[1].to_string(),
            captures[2].to_string().to_ascii_lowercase(),
            unescape_go_string(&captures[3]),
        ));
    }

    let raw = RAW.get_or_init(|| {
        Regex::new(r#"^\{"([^"]+)",\s*"([^"]+)",\s*`([^`]*)`\},?$"#).expect("raw rule regex")
    });
    raw.captures(trimmed).map(|captures| {
        (
            captures[1].to_string(),
            captures[2].to_string().to_ascii_lowercase(),
            captures[3].to_string(),
        )
    })
}

fn unescape_go_string(value: &str) -> String {
    value.replace("\\\"", "\"").replace("\\\\", "\\")
}

#[derive(Debug)]
struct FingerprintRule {
    name: String,
    location: MatchLocation,
    regex: Regex,
}

#[derive(Debug, Clone, Copy)]
enum MatchLocation {
    Body,
    Headers,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn scans_http_target_and_matches_fingerprint() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = "<html><title>RabbitMQ Console</title>RabbitMQ Management</html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: rememberMe=deleteMe\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        });

        let result = scan_target(&format!("http://127.0.0.1:{port}"), &WebConfig::default())
            .expect("web scan should succeed");

        server.join().expect("server thread should exit");

        assert_eq!(result.status_code, 200);
        assert_eq!(result.title, "RabbitMQ Console");
        assert_eq!(result.length, "63");
        assert!(result.fingerprints.iter().any(|item| item == "RabbitMQ"));
        assert!(result.fingerprints.iter().any(|item| item == "Shiro"));
    }

    #[test]
    fn returns_no_title_text_when_title_tag_is_missing() {
        assert_eq!(extract_title("<html><body>hello</body></html>"), "无标题");
    }

    #[test]
    fn returns_empty_quotes_when_title_tag_is_blank() {
        assert_eq!(extract_title("<html><title>   </title></html>"), "\"\"");
    }

    #[test]
    fn normalizes_nbsp_like_go_webtitle() {
        assert_eq!(
            extract_title("<html><title> Admin&nbsp;Console </title></html>"),
            "Admin Console"
        );
    }

    #[test]
    fn decodes_gbk_body_before_extracting_title() {
        let (encoded, _, _) = GBK.encode("<html><title>后台管理</title></html>");
        let decoded = decode_body(&encoded);
        assert_eq!(extract_title(&decoded), "后台管理");
    }
}
