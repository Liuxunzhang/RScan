use anyhow::{Context, Result, anyhow};
use encoding_rs::GBK;
use regex::Regex;
use reqwest::Proxy;
use reqwest::blocking::{Client, ClientBuilder};
use rscan_config::WebConfig;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Duration;

const USER_AGENT: &str = "Mozilla/5.0 (compatible; rscan/0.1.0)";
const MAX_TITLE_LENGTH: usize = 100;
const NO_TITLE_TEXT: &str = "无标题";

mod rules_asset {
    include!("../assets/rules.rs");
}

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

pub fn poc_aliases_for_fingerprints(fingerprints: &[String]) -> Vec<String> {
    let mut aliases = BTreeSet::new();
    for fingerprint in fingerprints {
        for mapping in poc_alias_rules() {
            if fingerprint.contains(&mapping.name) {
                aliases.insert(mapping.alias.clone());
            }
        }
    }
    aliases.into_iter().collect()
}

pub fn scan_target(target: &str, config: &WebConfig) -> Result<WebScanResult> {
    let candidates = build_candidate_urls(target);
    let client = build_client(config)?;
    let mut last_error = None;

    for (index, candidate) in candidates.iter().enumerate() {
        match fetch_target(&client, target, &candidate, config.cookie.as_deref()) {
            Ok(result) => {
                if should_retry_http_400_as_https(
                    candidate,
                    result.status_code,
                    &candidates[..index],
                ) {
                    let https_target = candidate.replacen("http://", "https://", 1);
                    match fetch_target(&client, target, &https_target, config.cookie.as_deref()) {
                        Ok(upgraded) => return Ok(upgraded),
                        Err(_) => return Ok(result),
                    }
                }
                return Ok(result);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("failed to scan web target: {target}")))
}

fn should_retry_http_400_as_https(
    candidate: &str,
    status_code: u16,
    prior_candidates: &[String],
) -> bool {
    status_code == 400
        && candidate.starts_with("http://")
        && !prior_candidates
            .iter()
            .any(|prior| prior.starts_with("https://"))
}

fn build_client(config: &WebConfig) -> Result<Client> {
    let mut builder = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .gzip(true)
        .redirect(reqwest::redirect::Policy::none())
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
    let mut current_url = url.to_string();
    let mut responses = Vec::new();

    for _ in 0..10 {
        let response = send_request(client, &current_url, cookie)?;
        let redirect_url = redirect_target(&response);
        current_url = redirect_url.clone().unwrap_or_else(|| response.url.clone());
        responses.push(response);

        if redirect_url.is_none() {
            break;
        }
    }

    let response = responses
        .pop()
        .ok_or_else(|| anyhow!("failed to scan web target: {url}"))?;
    let title = extract_title(&response.body_text);
    let fingerprints = match_fingerprint_responses(&responses, &response);

    Ok(WebScanResult {
        original_target: original_target.to_string(),
        requested_url: url.to_string(),
        final_url: response.url,
        status_code: response.status_code,
        title,
        length: response
            .content_length
            .unwrap_or_else(|| response.body_len.to_string()),
        headers: response.headers,
        fingerprints,
    })
}

fn send_request(client: &Client, url: &str, cookie: Option<&str>) -> Result<ResponseSnapshot> {
    let mut request = client
        .get(url)
        .header(reqwest::header::USER_AGENT, USER_AGENT);
    if let Some(cookie) = cookie.filter(|cookie| !cookie.is_empty()) {
        request = request.header(reqwest::header::COOKIE, cookie);
    }

    let response = request
        .send()
        .with_context(|| format!("failed to request {url}"))?;

    let response_url = response.url().to_string();
    let status_code = response.status().as_u16();
    let content_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let headers = collect_headers(response.headers());
    let body = response
        .bytes()
        .with_context(|| format!("failed to read response body for {url}"))?;
    let body_len = body.len();
    let body_text = decode_body(&body);

    Ok(ResponseSnapshot {
        url: response_url,
        status_code,
        content_length,
        headers,
        body_text,
        body_len,
    })
}

fn redirect_target(response: &ResponseSnapshot) -> Option<String> {
    if !(300..400).contains(&response.status_code) {
        return None;
    }

    let location = response
        .headers
        .get("location")
        .or_else(|| response.headers.get("Location"))?;
    let base = reqwest::Url::parse(&response.url).ok()?;
    base.join(location).ok().map(|url| url.to_string())
}

fn build_candidate_urls(target: &str) -> Vec<String> {
    if target.starts_with("https://") {
        return vec![
            target.to_string(),
            target.replacen("https://", "http://", 1),
        ];
    }
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

fn match_fingerprint_responses(
    prior_responses: &[ResponseSnapshot],
    final_response: &ResponseSnapshot,
) -> Vec<String> {
    let mut matches = BTreeSet::new();

    for response in prior_responses
        .iter()
        .chain(std::iter::once(final_response))
    {
        for fingerprint in match_fingerprints(&response.body_text, &response.headers) {
            matches.insert(fingerprint);
        }
    }

    matches.into_iter().collect()
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

fn poc_alias_rules() -> &'static [PocAliasRule] {
    static RULES: OnceLock<Vec<PocAliasRule>> = OnceLock::new();
    RULES.get_or_init(parse_poc_alias_rules)
}

fn parse_rules() -> Vec<FingerprintRule> {
    rules_asset::RULES
        .iter()
        .filter_map(|(name, kind, rule)| {
            let location = match *kind {
                "code" | "index" => MatchLocation::Body,
                "headers" | "header" | "cookie" => MatchLocation::Headers,
                _ => return None,
            };
            let regex = Regex::new(rule).ok()?;
            Some(FingerprintRule {
                name: (*name).to_string(),
                location,
                regex,
            })
        })
        .collect()
}

fn parse_poc_alias_rules() -> Vec<PocAliasRule> {
    rules_asset::POC_ALIASES
        .iter()
        .map(|(name, alias)| PocAliasRule {
            name: (*name).to_string(),
            alias: (*alias).to_string(),
        })
        .collect()
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

#[derive(Debug)]
struct ResponseSnapshot {
    url: String,
    status_code: u16,
    content_length: Option<String>,
    headers: BTreeMap<String, String>,
    body_text: String,
    body_len: usize,
}

#[derive(Debug)]
struct PocAliasRule {
    name: String,
    alias: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::io::BufReader;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, OnceLock};
    use std::thread;

    const TEST_TLS_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDJTCCAg2gAwIBAgIUVsKefIIAEdhsupG7MpdeI4oOp+AwDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQyNDAxMTA0NloXDTI2MDQy\n\
NTAxMTA0NlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n\
AAOCAQ8AMIIBCgKCAQEA1b3LZDyq0OWkJIehkB15JDPenaRtJ85zNicdBQvGI5O4\n\
KNlYW/l/84rjp2EFMlB8zenT1HEqSe1K+P0UZqZ6+8QEY7EaHa+jw04ouuIF6cje\n\
OC2uPHYdPatjF5ayLZTL9Eyv2KMFJhYegxIdX3tkfCEHyN8ntIK6BhG1vBfh1e+P\n\
X2YRY+asTvxFeiiHggyCHPzO4qnd4aJWbTPbTsad8jDBaUBgOHbI7j3gBo0UZkwO\n\
QGcHsovCceGKcqfPDkFjfvBTXDMpA5NTAdYsThL2Lt5ylOQ/45IB4IvDmyZRBzrv\n\
GzF0xNUxKHptzdkJ5CtQbFW19Raon1Rx0nnYUGvQaQIDAQABo28wbTAdBgNVHQ4E\n\
FgQUBeJnXanldzZuzrp3p6PbDzxed64wHwYDVR0jBBgwFoAUBeJnXanldzZuzrp3\n\
p6PbDzxed64wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH\n\
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBADmYSfEQS/DIvwtKofg6VKGTe3UcVx1f\n\
f1XIQywqou5/dFG9cK/ChCWcIlIukmUHrhwbXQ0k/AzdFwjj1D2gBh8qxNXf/GQx\n\
cqx51ZiY+akmLd/lPkPFHCDL4tGl17boglGvW3T/u3FFfXXV8dQaJ9wNgetw7vUL\n\
VANxm+zndHkgzHgFAPuuIyq5iNWwnnWuB6CtR2FB2d+t40aa2D90Yysy8dMNCZfR\n\
BclVky6ChHmANe0JgMk7OApo2Pz7EBluXYFVrQMiGSwJbLlL8F7VyYXjLed76WU0\n\
a5J2UBJo0i+WVREmrnWhIuvCJIpBaqeaPG8KDsC8RHvBFbGUErV6gX0=\n\
-----END CERTIFICATE-----\n";
    const TEST_TLS_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDVvctkPKrQ5aQk\n\
h6GQHXkkM96dpG0nznM2Jx0FC8Yjk7go2Vhb+X/ziuOnYQUyUHzN6dPUcSpJ7Ur4\n\
/RRmpnr7xARjsRodr6PDTii64gXpyN44La48dh09q2MXlrItlMv0TK/YowUmFh6D\n\
Eh1fe2R8IQfI3ye0groGEbW8F+HV749fZhFj5qxO/EV6KIeCDIIc/M7iqd3holZt\n\
M9tOxp3yMMFpQGA4dsjuPeAGjRRmTA5AZweyi8Jx4Ypyp88OQWN+8FNcMykDk1MB\n\
1ixOEvYu3nKU5D/jkgHgi8ObJlEHOu8bMXTE1TEoem3N2QnkK1BsVbX1FqifVHHS\n\
edhQa9BpAgMBAAECggEAARQhBtCm1XsKd2EXHaIocW+ZkxbPspIXmO6LasOluCWy\n\
gpUsBkCdtq9IkKQ3ylBNTgYrg0/Zy7D7xvb7oEhCy1lfKKmiItVOcJ+DFAQstgKW\n\
w8UVyl/0w0Zc3jM+HvI4YC2ZcHxvNgkVcw/hnPmO+1lhgTi6taghDDIQ3aB/C3GD\n\
IyprnMxIE/sc1LyVdZhGTF9X6I3xp+jQP7VJpX91wjffUac8G0+pzR1B2Rw6ZF7V\n\
Yu4EhU5dptp0tCbLlpzKvnD2/X01jwk8WffpgeN/oM2fYggl4UNkgl0aLYEwJFZo\n\
/XYuXl5QszOTmb2ZX9u17U1h9BlctkAvvH9/bqu3IQKBgQDxv53WbiRxyPZpvB5A\n\
UAeE52pDyyQLVI1xdktrSdPpp+BKDwg4CQqh3kffpAOa2s57IH+0tO5mnfG7w5SK\n\
CLhGqutAMkMey58bMMnPOW4lZvGgEqoH97p59mjLya+mb3P1k1fg3h2ep6uIo+yr\n\
P1nencHSyBQKMuTcA1ciBD7IXQKBgQDiV4EebrvHwr5wehhXPegUfjA7g5T/+1Za\n\
65XnCZSQXrmsWuqn+UazMndwIHj4utCEG7h2RqypRkW31ippOiiApB0EmRsjgIWm\n\
oSJxXDQtkwZu2mkC5aZO9tJ4Q2NgprCyIr0jux9QBv9kNu16FdWNK5N6clw0C3oC\n\
fa3QWBg3fQKBgQDcnaHNLnbT4DIADE0PI/m4r/eqJpiePmtWQD5Tiux5L1rgOxel\n\
C5tIXTH6RhOEHmqQsvfYUcW+oCUa1UGZNpv04cYOr8/RKsHobn29Pwvl1ixriJzi\n\
6JCk/NpmH4jMuql4Ux6/d/RP9XP1HqO9I/M/1Xgsg6rGI+v3XJUH1hf1gQKBgGps\n\
mJKVoIex4teCITXMLvaLyuQA36tpI1aG1SoYEBm94HHRIeqvQ/X4Mb6wFhFlzauA\n\
WUCLxJ2nJBrngXOO3AJ4qAhEcUVFJhKOS2Kf5wzSx8CRw7SQBJ22YooXrX+BgS2R\n\
Nfu5/WQklispxImWAJ5rMeHuKbpy9wB61aJT+bcFAoGAOXuAvfFH34syYitB/XG6\n\
xHJFz2k4twxhE3RZVYnWkzZ6duRrUEKfYYMn+nG+7vsZ4xJLzqO4Ua7NiBw32+Do\n\
t4jVJls3AqAt63f2EkL2jUjSpIyEB8jnLUTsdWE8UiBXGIV9YqvYiE3ekZylgV2d\n\
zSzfRta6NR6ILTdj7W2rfKU=\n\
-----END PRIVATE KEY-----\n";

    fn tls_test_config() -> Arc<ServerConfig> {
        static CONFIG: OnceLock<Arc<ServerConfig>> = OnceLock::new();
        Arc::clone(CONFIG.get_or_init(|| {
            let mut cert_reader = BufReader::new(TEST_TLS_CERT.as_bytes());
            let certs = rustls_pemfile::certs(&mut cert_reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("TLS cert should parse");
            let mut key_reader = BufReader::new(TEST_TLS_KEY.as_bytes());
            let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
                .expect("TLS key should parse")
                .expect("TLS key should exist");
            Arc::new(
                ServerConfig::builder_with_provider(
                    rustls::crypto::aws_lc_rs::default_provider().into(),
                )
                .with_safe_default_protocol_versions()
                .expect("TLS protocol versions should be available")
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("TLS server config should build"),
            )
        }))
    }

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
    fn falls_back_from_explicit_https_to_http_like_go() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 1024];
                let size = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..size]);
                if !request.starts_with("GET ") {
                    continue;
                }
                let body = "<html><title>HTTPS Fallback</title></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should write");
                break;
            }
        });

        let result = scan_target(&format!("https://127.0.0.1:{port}"), &WebConfig::default())
            .expect("web scan should succeed");

        server.join().expect("server thread should exit");

        assert_eq!(result.status_code, 200);
        assert_eq!(result.title, "HTTPS Fallback");
        assert_eq!(result.requested_url, format!("http://127.0.0.1:{port}"));
    }

    #[test]
    fn retries_http_400_as_https_like_go() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();
        let config = tls_test_config();

        let server = thread::spawn(move || {
            let (mut plain, _) = listener.accept().expect("http request should arrive");
            let mut plain_buffer = [0u8; 1024];
            let _ = plain.read(&mut plain_buffer);
            plain
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("http 400 should write");

            let (stream, _) = listener.accept().expect("https request should arrive");
            let conn = ServerConnection::new(config).expect("server conn should build");
            let mut tls = StreamOwned::new(conn, stream);
            tls.conn
                .complete_io(&mut tls.sock)
                .expect("TLS handshake should complete");
            let mut tls_buffer = [0u8; 1024];
            let _ = tls.read(&mut tls_buffer);
            let body = "<html><title>HTTP400 HTTPS Retry</title></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            tls.write_all(response.as_bytes())
                .expect("https response should write");
            tls.flush().expect("https response should flush");
        });

        let result = scan_target(&format!("http://127.0.0.1:{port}"), &WebConfig::default())
            .expect("web scan should succeed");

        server.join().expect("server thread should exit");

        assert_eq!(result.status_code, 200);
        assert_eq!(result.title, "HTTP400 HTTPS Retry");
        assert_eq!(result.requested_url, format!("https://127.0.0.1:{port}"));
    }

    #[test]
    fn keeps_redirect_response_fingerprints_like_go() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buffer = [0u8; 1024];
                let size = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..size]);
                if request.starts_with("GET /login ") {
                    let body = "<html><title>Redirect Target</title></html>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("final response should write");
                    break;
                }

                let body = "<html>redirecting</html>";
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: /login\r\nSet-Cookie: rememberMe=deleteMe\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("redirect response should write");
            }
        });

        let result = scan_target(&format!("http://127.0.0.1:{port}"), &WebConfig::default())
            .expect("web scan should succeed");

        server.join().expect("server thread should exit");

        assert_eq!(result.final_url, format!("http://127.0.0.1:{port}/login"));
        assert_eq!(result.title, "Redirect Target");
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

    #[test]
    fn maps_fingerprints_to_poc_aliases_like_go() {
        let aliases =
            poc_aliases_for_fingerprints(&["weblogic".to_string(), "RabbitMQ".to_string()]);
        assert!(aliases.iter().any(|alias| alias == "weblogic"));
        assert!(!aliases.iter().any(|alias| alias == "RabbitMQ"));
    }
}
