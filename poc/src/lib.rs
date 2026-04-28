use anyhow::{Context, Result, anyhow};
use base64::Engine;
use include_dir::{Dir, include_dir};
use indexmap::IndexMap;
use rand::{Rng, distr::Alphanumeric, rng};
use regex::Regex;
use reqwest::Proxy;
use reqwest::blocking::{Client, ClientBuilder};
use rhai::{Blob, Dynamic, Engine as RhaiEngine, ImmutableString, Map, Scope};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::iter;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

static EMBEDDED_POCS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/embedded-pocs");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Poc {
    pub name: String,
    #[serde(default)]
    pub set: IndexMap<String, String>,
    #[serde(default)]
    pub sets: IndexMap<String, Vec<String>>,
    #[serde(default)]
    pub rules: Vec<PocRule>,
    #[serde(default)]
    pub groups: IndexMap<String, Vec<PocRule>>,
    #[serde(default)]
    pub detail: PocDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct PocRule {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default)]
    pub expression: String,
    #[serde(default, rename = "continue")]
    pub continue_scan: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
pub struct PocDetail {
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocExecutionOptions {
    pub timeout_secs: u64,
    pub cookie: Option<String>,
    pub http_proxy: Option<String>,
    pub socks5_proxy: Option<String>,
    pub workers: usize,
}

impl Default for PocExecutionOptions {
    fn default() -> Self {
        Self {
            timeout_secs: 5,
            cookie: None,
            http_proxy: None,
            socks5_proxy: None,
            workers: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocMatch {
    pub poc_name: String,
    pub target: String,
    pub group: Option<String>,
    pub variables: BTreeMap<String, String>,
}

pub fn load_embedded_pocs() -> Result<Vec<Poc>> {
    let mut pocs = EMBEDDED_POCS
        .files()
        .filter(|file| is_yaml(file.path().to_string_lossy().as_ref()))
        .map(|file| {
            serde_yaml::from_slice::<Poc>(file.contents())
                .with_context(|| format!("failed to parse embedded POC {}", file.path().display()))
        })
        .collect::<Result<Vec<_>>>()?;
    pocs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(pocs)
}

pub fn load_pocs_from_path(path: &Path) -> Result<Vec<Poc>> {
    let mut yaml_files = Vec::new();
    collect_yaml_files(path, &mut yaml_files)?;

    let mut pocs = yaml_files
        .into_iter()
        .map(|file| {
            let contents = fs::read(&file)
                .with_context(|| format!("failed to read POC {}", file.display()))?;
            serde_yaml::from_slice::<Poc>(&contents)
                .with_context(|| format!("failed to parse POC {}", file.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    pocs.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(pocs)
}

pub fn filter_pocs<'a>(pocs: &'a [Poc], name_filter: &str) -> Vec<&'a Poc> {
    if name_filter.trim().is_empty() {
        return pocs.iter().collect();
    }

    let filter = name_filter.to_ascii_lowercase();
    pocs.iter()
        .filter(|poc| poc.name.to_ascii_lowercase().contains(&filter))
        .collect()
}

pub fn execute_pocs(
    target: &str,
    pocs: &[Poc],
    options: &PocExecutionOptions,
) -> Result<Vec<PocMatch>> {
    let client_with_redirects = build_client(options, true)?;
    let client_without_redirects = build_client(options, false)?;
    let workers = options.workers.max(1).min(pocs.len().max(1));
    if workers == 1 {
        let mut matches = Vec::new();
        for poc in pocs {
            matches.extend(execute_poc(
                target,
                poc,
                &client_with_redirects,
                &client_without_redirects,
                options,
            )?);
        }
        return Ok(matches);
    }

    let chunk_size = pocs.len().div_ceil(workers);
    thread::scope(|scope| -> Result<Vec<PocMatch>> {
        let mut jobs = Vec::new();
        for chunk in pocs.chunks(chunk_size) {
            let redirect_client = client_with_redirects.clone();
            let no_redirect_client = client_without_redirects.clone();
            jobs.push(scope.spawn(move || -> Result<Vec<PocMatch>> {
                let mut matches = Vec::new();
                for poc in chunk {
                    matches.extend(execute_poc(
                        target,
                        poc,
                        &redirect_client,
                        &no_redirect_client,
                        options,
                    )?);
                }
                Ok(matches)
            }));
        }

        let mut matches = Vec::new();
        for job in jobs {
            let chunk_matches = job
                .join()
                .map_err(|_| anyhow!("POC worker thread panicked"))??;
            matches.extend(chunk_matches);
        }
        Ok(matches)
    })
}

fn execute_poc(
    target: &str,
    poc: &Poc,
    redirect_client: &Client,
    no_redirect_client: &Client,
    options: &PocExecutionOptions,
) -> Result<Vec<PocMatch>> {
    let base_target =
        reqwest::Url::parse(target).with_context(|| format!("invalid target url: {target}"))?;
    let sequences = rule_sequences(poc);
    let variable_sets = build_variable_sets(poc)?;
    let mut matches = Vec::new();

    for initial_vars in variable_sets {
        for (group_name, rules) in &sequences {
            let mut vars = initial_vars.clone();
            if execute_rule_sequence(
                &base_target,
                rules,
                &mut vars,
                redirect_client,
                no_redirect_client,
                options,
            )? {
                matches.push(PocMatch {
                    poc_name: poc.name.clone(),
                    target: target.to_string(),
                    group: group_name.clone(),
                    variables: vars,
                });
                if poc.sets.is_empty() {
                    return Ok(matches);
                }
            }
        }
    }

    Ok(matches)
}

fn build_client(options: &PocExecutionOptions, follow_redirects: bool) -> Result<Client> {
    let mut builder = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .gzip(true)
        .timeout(Duration::from_secs(options.timeout_secs.max(1)))
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        });

    if let Some(proxy) = &options.http_proxy {
        builder =
            builder.proxy(Proxy::all(proxy).with_context(|| format!("invalid proxy: {proxy}"))?);
    }
    if let Some(proxy) = &options.socks5_proxy {
        builder = builder
            .proxy(Proxy::all(proxy).with_context(|| format!("invalid socks5 proxy: {proxy}"))?);
    }

    builder.build().context("failed to build POC HTTP client")
}

fn rule_sequences(poc: &Poc) -> Vec<(Option<String>, Vec<PocRule>)> {
    if !poc.rules.is_empty() {
        vec![(None, poc.rules.clone())]
    } else {
        poc.groups
            .iter()
            .map(|(name, rules)| (Some(name.clone()), rules.clone()))
            .collect()
    }
}

fn build_variable_sets(poc: &Poc) -> Result<Vec<BTreeMap<String, String>>> {
    let base = evaluate_set_map(&poc.set, &BTreeMap::new())?;
    if poc.sets.is_empty() {
        return Ok(vec![base]);
    }

    let mut contexts = vec![base];
    for (key, values) in &poc.sets {
        let mut next = Vec::new();
        for context in &contexts {
            for value in values {
                let mut candidate = context.clone();
                let evaluated = evaluate_value(value, &candidate)?;
                candidate.insert(key.clone(), evaluated);
                next.push(candidate);
            }
        }
        contexts = next;
    }
    Ok(contexts)
}

fn evaluate_set_map(
    source: &IndexMap<String, String>,
    seed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut result = seed.clone();
    for (key, value) in source {
        let evaluated = evaluate_value(value, &result)?;
        result.insert(key.clone(), evaluated);
    }
    Ok(result)
}

fn evaluate_value(value: &str, vars: &BTreeMap<String, String>) -> Result<String> {
    if let Some((name, args)) = parse_function_call(value) {
        return evaluate_function(&name, &args, vars);
    }
    Ok(apply_template(value, vars))
}

fn execute_rule_sequence(
    base_target: &reqwest::Url,
    rules: &[PocRule],
    vars: &mut BTreeMap<String, String>,
    redirect_client: &Client,
    no_redirect_client: &Client,
    options: &PocExecutionOptions,
) -> Result<bool> {
    for rule in rules {
        let response = execute_rule(
            base_target,
            rule,
            vars,
            redirect_client,
            no_redirect_client,
            options,
        )?;
        if let Some(search) = (!rule.search.trim().is_empty()).then_some(rule.search.as_str()) {
            let captures = run_search(search, &response.raw_for_search)?;
            if captures.is_empty() {
                return Ok(false);
            }
            vars.extend(captures);
        }
        if !evaluate_expression(&rule.expression, vars, &response)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn execute_rule(
    base_target: &reqwest::Url,
    rule: &PocRule,
    vars: &BTreeMap<String, String>,
    redirect_client: &Client,
    no_redirect_client: &Client,
    options: &PocExecutionOptions,
) -> Result<RuleResponse> {
    let path = apply_template(&rule.path, vars);
    let url = build_rule_url(base_target, &path)?;
    let method = if rule.method.trim().is_empty() {
        reqwest::Method::GET
    } else {
        reqwest::Method::from_bytes(rule.method.trim().as_bytes())
            .with_context(|| format!("invalid method: {}", rule.method))?
    };
    let client = if rule.follow_redirects {
        redirect_client
    } else {
        no_redirect_client
    };

    let mut request = client.request(method, url.clone());
    if let Some(cookie) = options
        .cookie
        .as_deref()
        .filter(|cookie| !cookie.is_empty())
    {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    for (key, value) in &rule.headers {
        request = request.header(key, apply_template(value, vars));
    }
    if !rule.body.is_empty() {
        request = request.body(apply_template(&rule.body, vars));
    }

    let started = Instant::now();
    let response = request
        .send()
        .with_context(|| format!("failed to request {}", url.as_str()))?;
    let elapsed = started.elapsed();
    let final_url = response.url().to_string();
    let status = i64::from(response.status().as_u16());
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    let headers_text = headers
        .iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let body = response
        .bytes()
        .with_context(|| format!("failed to read body from {}", url.as_str()))?
        .to_vec();
    let mut raw_for_search = String::new();
    if !headers_text.is_empty() {
        raw_for_search.push_str(&headers_text);
        raw_for_search.push('\n');
    }
    raw_for_search.push_str(&String::from_utf8_lossy(&body));

    Ok(RuleResponse {
        status,
        headers,
        content_type,
        body,
        url: final_url,
        latency_ms: elapsed.as_secs_f64() * 1000.0,
        raw_for_search,
    })
}

fn build_rule_url(base: &reqwest::Url, path: &str) -> Result<reqwest::Url> {
    if let Ok(url) = reqwest::Url::parse(path) {
        return Ok(url);
    }
    base.join(path.trim_start_matches('/'))
        .or_else(|_| base.join(path))
        .with_context(|| format!("failed to join path: {path}"))
}

fn run_search(pattern: &str, body: &str) -> Result<BTreeMap<String, String>> {
    let regex = Regex::new(pattern).with_context(|| format!("invalid search regex: {pattern}"))?;
    let Some(captures) = regex.captures(body) else {
        return Ok(BTreeMap::new());
    };
    let mut result = BTreeMap::new();
    for name in regex.capture_names().flatten() {
        if let Some(value) = captures.name(name) {
            result.insert(name.to_string(), value.as_str().to_string());
        }
    }
    Ok(result)
}

fn evaluate_expression(
    expression: &str,
    vars: &BTreeMap<String, String>,
    response: &RuleResponse,
) -> Result<bool> {
    let expr = expression.trim();
    if expr.is_empty() || expr == "true" {
        return Ok(true);
    }
    if expr == "false" {
        return Ok(false);
    }

    let transformed = cached_preprocess_expression(expr);
    let mut scope = Scope::new();
    scope.push_dynamic("response", response.as_dynamic());
    for (key, value) in vars {
        scope.push_dynamic(key.clone(), parse_variable_value(value));
    }
    RHAI_ENGINE.with(|engine| {
        engine
            .eval_with_scope::<bool>(&mut scope, &transformed)
            .map_err(|error| anyhow!("failed to evaluate expression `{expr}`: {error}"))
    })
}

fn parse_variable_value(value: &str) -> Dynamic {
    if let Ok(number) = value.parse::<i64>() {
        Dynamic::from(number)
    } else {
        Dynamic::from(value.to_string())
    }
}

thread_local! {
    static RHAI_ENGINE: RhaiEngine = build_rhai_engine();
}

fn build_rhai_engine() -> RhaiEngine {
    let mut engine = RhaiEngine::new();
    engine.register_fn("bcontains", |left: Blob, right: Blob| {
        left.windows(right.len())
            .any(|window| window == right.as_slice())
    });
    engine.register_fn("bcontains", |left: Blob, right: Dynamic| {
        let right = dynamic_to_blob(&right);
        left.windows(right.len())
            .any(|window| window == right.as_slice())
    });
    engine.register_fn("bmatches", |pattern: ImmutableString, body: Blob| {
        Regex::new(pattern.as_str())
            .map(|regex| regex.is_match(&String::from_utf8_lossy(&body)))
            .unwrap_or(false)
    });
    engine.register_fn("blob", |value: ImmutableString| value.as_bytes().to_vec());
    engine.register_fn("bytes", |value: Dynamic| {
        dynamic_to_string(&value).into_bytes()
    });
    engine.register_fn("bytes", |value: ImmutableString| value.as_bytes().to_vec());
    engine.register_fn("bytes", |value: i64| value.to_string().into_bytes());
    engine.register_fn("string", |value: Dynamic| dynamic_to_string(&value));
    engine.register_fn("md5", |value: ImmutableString| {
        format!("{:x}", md5::compute(value.as_bytes()))
    });
    engine.register_fn("substr", |value: ImmutableString, start: i64, len: i64| {
        let chars = value.chars().collect::<Vec<_>>();
        let start = start.max(0) as usize;
        let len = len.max(0) as usize;
        chars.into_iter().skip(start).take(len).collect::<String>()
    });
    engine.register_fn(
        "contains",
        |value: ImmutableString, needle: ImmutableString| value.contains(needle.as_str()),
    );
    engine.register_fn(
        "icontains",
        |value: ImmutableString, needle: ImmutableString| {
            value
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        },
    );
    engine.register_fn("startsWith", |value: Blob, prefix: Blob| {
        value.starts_with(prefix.as_slice())
    });
    engine.register_fn(
        "istartsWith",
        |value: ImmutableString, prefix: ImmutableString| {
            value
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
        },
    );
    engine.register_fn("has_key", |map: Map, key: ImmutableString| {
        map.contains_key(key.as_str())
    });
    engine.register_fn("wait", |_reverse: Dynamic, _seconds: i64| false);
    engine
}

fn cached_preprocess_expression(expression: &str) -> String {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    if let Some(transformed) = cache
        .lock()
        .expect("expression cache lock poisoned")
        .get(expression)
        .cloned()
    {
        return transformed;
    }

    let transformed = preprocess_expression(expression);
    cache
        .lock()
        .expect("expression cache lock poisoned")
        .insert(expression.to_string(), transformed.clone());
    transformed
}

fn preprocess_expression(expression: &str) -> String {
    let mut output = expression.replace('\n', " ");
    output = in_headers_regex()
        .replace_all(&output, r#"has_key(response.headers, "$1")"#)
        .into_owned();
    output = bytes_literal_regex()
        .replace_all(&output, |captures: &regex::Captures<'_>| {
            format!(r#"blob("{}")"#, escape_rhai_string(&captures[1]))
        })
        .into_owned();
    output
}

fn in_headers_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#""([^"]+)"\s+in\s+response\.headers"#).expect("in regex"))
}

fn bytes_literal_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"b"((?:[^"\\]|\\.)*)""#).expect("bytes literal regex"))
}

fn escape_rhai_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn dynamic_to_string(value: &Dynamic) -> String {
    if value.is::<i64>() {
        value.clone_cast::<i64>().to_string()
    } else if value.is::<bool>() {
        value.clone_cast::<bool>().to_string()
    } else if value.is::<ImmutableString>() {
        value.clone_cast::<ImmutableString>().to_string()
    } else if value.is::<String>() {
        value.clone_cast::<String>()
    } else if value.is::<Blob>() {
        String::from_utf8_lossy(&value.clone_cast::<Blob>()).to_string()
    } else {
        value.to_string()
    }
}

fn dynamic_to_blob(value: &Dynamic) -> Blob {
    if value.is::<Blob>() {
        value.clone_cast::<Blob>()
    } else {
        dynamic_to_string(value).into_bytes()
    }
}

fn parse_function_call(input: &str) -> Option<(String, Vec<String>)> {
    let input = input.trim();
    let open = input.find('(')?;
    if !input.ends_with(')') {
        return None;
    }
    let name = input[..open].trim();
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some((
        name.to_string(),
        split_args(&input[open + 1..input.len() - 1]),
    ))
}

fn split_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut quote = None;
    for ch in input.chars() {
        match ch {
            '"' | '\'' if quote.is_none() => {
                quote = Some(ch);
                current.push(ch);
            }
            '"' | '\'' if quote == Some(ch) => {
                quote = None;
                current.push(ch);
            }
            '(' if quote.is_none() => {
                depth += 1;
                current.push(ch);
            }
            ')' if quote.is_none() && depth > 0 => {
                depth -= 1;
                current.push(ch);
            }
            ',' if quote.is_none() && depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        args.push(current.trim().to_string());
    }
    args
}

fn evaluate_function(
    name: &str,
    args: &[String],
    vars: &BTreeMap<String, String>,
) -> Result<String> {
    match name {
        "randomInt" => {
            let start = resolve_numeric_arg(args.first(), vars)?;
            let end = resolve_numeric_arg(args.get(1), vars)?;
            Ok(rng().random_range(start..=end).to_string())
        }
        "randomLowercase" => Ok(random_string(
            resolve_numeric_arg(args.first(), vars)? as usize,
            "abcdefghijklmnopqrstuvwxyz",
        )),
        "randomUppercase" => Ok(random_string(
            resolve_numeric_arg(args.first(), vars)? as usize,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        )),
        "randomString" => Ok(rng()
            .sample_iter(Alphanumeric)
            .take(resolve_numeric_arg(args.first(), vars)? as usize)
            .map(char::from)
            .collect()),
        "base64" => Ok(base64::engine::general_purpose::STANDARD
            .encode(resolve_string_arg(args.first(), vars)?)),
        "base64Decode" => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(resolve_string_arg(args.first(), vars)?)
                .context("failed to decode base64")?;
            Ok(String::from_utf8_lossy(&decoded).to_string())
        }
        "md5" => Ok(format!(
            "{:x}",
            md5::compute(resolve_string_arg(args.first(), vars)?.as_bytes())
        )),
        "substr" => {
            let value = resolve_string_arg(args.first(), vars)?;
            let start = resolve_numeric_arg(args.get(1), vars)? as usize;
            let len = resolve_numeric_arg(args.get(2), vars)? as usize;
            Ok(value.chars().skip(start).take(len).collect())
        }
        "urlencode" => {
            Ok(urlencoding::encode(&resolve_string_arg(args.first(), vars)?).into_owned())
        }
        "urldecode" => Ok(
            urlencoding::decode(&resolve_string_arg(args.first(), vars)?)
                .context("failed to decode url")?
                .into_owned(),
        ),
        "hexdecode" => {
            let bytes = hex::decode(resolve_string_arg(args.first(), vars)?)
                .context("failed to decode hex")?;
            Ok(String::from_utf8_lossy(&bytes).to_string())
        }
        "TDdate" => Ok("2026".to_string()),
        "shirokey" => Ok(String::new()),
        "newReverse" => Ok(String::new()),
        _ => Ok(apply_template(name, vars)),
    }
}

fn resolve_string_arg(input: Option<&String>, vars: &BTreeMap<String, String>) -> Result<String> {
    let input = input.ok_or_else(|| anyhow!("missing function argument"))?;
    if let Some((name, args)) = parse_function_call(input) {
        return evaluate_function(&name, &args, vars);
    }
    let value = input.trim();
    if let Some(stripped) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        return Ok(stripped.to_string());
    }
    if let Some(stripped) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        return Ok(stripped.to_string());
    }
    if let Some(found) = vars.get(value) {
        return Ok(found.clone());
    }
    if value.contains('+') {
        let mut output = String::new();
        for part in value.split('+') {
            output.push_str(&resolve_string_arg(Some(&part.trim().to_string()), vars)?);
        }
        return Ok(output);
    }
    Ok(apply_template(value, vars))
}

fn resolve_numeric_arg(input: Option<&String>, vars: &BTreeMap<String, String>) -> Result<i64> {
    resolve_string_arg(input, vars)?
        .parse::<i64>()
        .map_err(|error| anyhow!("failed to parse numeric argument: {error}"))
}

fn random_string(len: usize, alphabet: &str) -> String {
    let mut rng = rng();
    let chars = alphabet.chars().collect::<Vec<_>>();
    iter::repeat_with(|| {
        let index = rng.random_range(0..chars.len());
        chars[index]
    })
    .take(len)
    .collect()
}

fn apply_template(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut output = template.to_string();
    for (key, value) in vars {
        let token = format!("{{{{{key}}}}}");
        if output.contains(&token) {
            output = output.replace(&token, value);
        }
    }
    output
}

fn is_yaml(path: &str) -> bool {
    path.ends_with(".yml") || path.ends_with(".yaml")
}

fn collect_yaml_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect POC path {}", path.display()))?;
    if metadata.is_file() {
        if is_yaml(path.to_string_lossy().as_ref()) {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }

    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to read POC directory {}", path.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to iterate POC directory {}", path.display()))?;
        let entry_path = entry.path();
        let entry_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry_path.display()))?;
        if entry_type.is_dir() {
            collect_yaml_files(&entry_path, files)?;
        } else if entry_type.is_file() && is_yaml(entry_path.to_string_lossy().as_ref()) {
            files.push(entry_path);
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct RuleResponse {
    status: i64,
    headers: BTreeMap<String, String>,
    content_type: String,
    body: Vec<u8>,
    url: String,
    latency_ms: f64,
    raw_for_search: String,
}

impl RuleResponse {
    fn as_dynamic(&self) -> Dynamic {
        let mut map = Map::new();
        map.insert("status".into(), Dynamic::from(self.status));
        map.insert(
            "content_type".into(),
            Dynamic::from(self.content_type.clone()),
        );
        map.insert("url".into(), Dynamic::from(self.url.clone()));
        map.insert("latency".into(), Dynamic::from_float(self.latency_ms));
        map.insert("body".into(), Dynamic::from(self.body.clone()));

        let mut headers = Map::new();
        for (key, value) in &self.headers {
            headers.insert(key.clone().into(), Dynamic::from(value.clone()));
        }
        map.insert("headers".into(), Dynamic::from(headers));
        Dynamic::from(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::{env, fs};

    #[test]
    fn loads_embedded_pocs() {
        let pocs = load_embedded_pocs().expect("embedded POCs should load");
        assert!(pocs.len() > 300);
        assert!(pocs.iter().any(|poc| poc.name == "poc-yaml-kibana-unauth"));
    }

    #[test]
    fn filters_embedded_pocs_by_name() {
        let pocs = load_embedded_pocs().expect("embedded POCs should load");
        let filtered = filter_pocs(&pocs, "wordpress-ext-mailpress-rce");

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "poc-yaml-wordpress-ext-mailpress-rce");
        assert_eq!(filtered[0].rules.len(), 2);
        assert!(filtered[0].set.contains_key("r"));
        assert!(filtered[0].set.contains_key("r1"));
    }

    #[test]
    fn loads_custom_pocs_from_directory() {
        let root = env::temp_dir().join(format!("rscan-poc-test-{}", std::process::id()));
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("temp poc dir should exist");
        fs::write(
            nested.join("custom.yaml"),
            "name: poc-yaml-custom\nrules:\n  - method: GET\n    path: /\n    expression: response.status == 200\n",
        )
        .expect("custom poc should write");

        let pocs = load_pocs_from_path(&root).expect("custom pocs should load");

        assert_eq!(pocs.len(), 1);
        assert_eq!(pocs[0].name, "poc-yaml-custom");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn executes_simple_poc_rule() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).expect("request should read");
            let body = "tomcat manager";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).expect("response");
        });

        let poc = Poc {
            name: "poc-yaml-test".to_string(),
            set: IndexMap::new(),
            sets: IndexMap::from([
                ("username".to_string(), vec!["admin".to_string()]),
                ("password".to_string(), vec!["admin".to_string()]),
                ("payload".to_string(), vec!["base64(username+\":\"+password)".to_string()]),
            ]),
            rules: vec![PocRule {
                method: "GET".to_string(),
                path: "/manager/html".to_string(),
                headers: BTreeMap::from([("Authorization".to_string(), "Basic {{payload}}".to_string())]),
                body: String::new(),
                search: String::new(),
                follow_redirects: false,
                expression:
                    "response.status == 200 && response.body.bcontains(b\"tomcat\") && response.body.bcontains(b\"manager\")"
                        .to_string(),
                continue_scan: false,
            }],
            groups: IndexMap::new(),
            detail: PocDetail::default(),
        };

        let matches = execute_pocs(
            &format!("http://127.0.0.1:{port}/"),
            &[poc],
            &PocExecutionOptions::default(),
        )
        .expect("poc should execute");

        server.join().expect("server thread should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].poc_name, "poc-yaml-test");
        assert_eq!(matches[0].variables["username"], "admin");
    }

    #[test]
    fn executes_search_and_variable_capture() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            for idx in 0..2 {
                let (mut stream, _) = listener.accept().expect("request should arrive");
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let body = if idx == 0 {
                    "<autosave id='abc123'>ok</autosave>"
                } else {
                    "value:abc123"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).expect("response");
            }
        });

        let poc = Poc {
            name: "poc-yaml-search".to_string(),
            set: IndexMap::new(),
            sets: IndexMap::new(),
            rules: vec![
                PocRule {
                    method: "GET".to_string(),
                    path: "/a".to_string(),
                    headers: BTreeMap::new(),
                    body: String::new(),
                    search: "<autosave id='(?P<id>.+?)'".to_string(),
                    follow_redirects: false,
                    expression: "response.status == 200".to_string(),
                    continue_scan: false,
                },
                PocRule {
                    method: "GET".to_string(),
                    path: "/{{id}}".to_string(),
                    headers: BTreeMap::new(),
                    body: String::new(),
                    search: String::new(),
                    follow_redirects: false,
                    expression: "response.body.bcontains(bytes(id))".to_string(),
                    continue_scan: false,
                },
            ],
            groups: IndexMap::new(),
            detail: PocDetail::default(),
        };

        let matches = execute_pocs(
            &format!("http://127.0.0.1:{port}/"),
            &[poc],
            &PocExecutionOptions::default(),
        )
        .expect("poc should execute");

        server.join().expect("server thread should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].variables["id"], "abc123");
    }

    #[test]
    fn executes_pocs_with_worker_parallelism() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();
        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let server = {
            let current = Arc::clone(&current);
            let max_seen = Arc::clone(&max_seen);
            thread::spawn(move || {
                let mut handlers = Vec::new();
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().expect("request should arrive");
                    let current = Arc::clone(&current);
                    let max_seen = Arc::clone(&max_seen);
                    handlers.push(thread::spawn(move || {
                        let mut buf = [0u8; 2048];
                        let _ = stream.read(&mut buf).expect("request should read");
                        let concurrent = current.fetch_add(1, Ordering::SeqCst) + 1;
                        let _ = max_seen.fetch_max(concurrent, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(150));
                        let body = "parallel";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("response should write");
                        current.fetch_sub(1, Ordering::SeqCst);
                    }));
                }

                for handler in handlers {
                    handler.join().expect("handler should finish");
                }
            })
        };

        let make_poc = |name: &str, path: &str| Poc {
            name: name.to_string(),
            set: IndexMap::new(),
            sets: IndexMap::new(),
            rules: vec![PocRule {
                method: "GET".to_string(),
                path: path.to_string(),
                headers: BTreeMap::new(),
                body: String::new(),
                search: String::new(),
                follow_redirects: false,
                expression: "response.status == 200".to_string(),
                continue_scan: false,
            }],
            groups: IndexMap::new(),
            detail: PocDetail::default(),
        };

        let matches = execute_pocs(
            &format!("http://127.0.0.1:{port}/"),
            &[make_poc("parallel-a", "/a"), make_poc("parallel-b", "/b")],
            &PocExecutionOptions {
                workers: 2,
                ..PocExecutionOptions::default()
            },
        )
        .expect("pocs should execute");

        server.join().expect("server thread should finish");

        assert_eq!(matches.len(), 2);
        assert!(max_seen.load(Ordering::SeqCst) >= 2);
    }
}
