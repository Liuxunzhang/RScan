use anyhow::{Context, Result};
use regex::bytes::{Captures, Regex, RegexBuilder};
use regex::Regex as TextRegex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

const MAX_FAILURES: usize = 10;
const PROBES_SOURCE: &str = include_str!("../assets/nmap-service-probes.txt");
const GO_CONFIG_SOURCE: &str = include_str!("../assets/Config.go");
const GO_FINGERPRINT_RECONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const GO_DEFAULT_TCP_PROBES: &[&str] = &[
    "GenericLines",
    "GetRequest",
    "TLSSessionReq",
    "SSLSessionReq",
    "ms-sql-s",
    "JavaRMI",
    "LDAPSearchReq",
    "LDAPBindReq",
    "oracle-tns",
    "Socks5",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFingerprintTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFingerprint {
    pub host: String,
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub banner: String,
    pub extras: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct Probe {
    name: String,
    protocol: String,
    data: Vec<u8>,
    ports: Vec<PortRange>,
    ssl_ports: Vec<PortRange>,
    total_wait_ms: Option<u64>,
    rarity: u16,
    fallback: Option<String>,
    matches: Vec<MatchRule>,
}

#[derive(Debug, Clone)]
struct MatchRule {
    is_soft: bool,
    service: String,
    regex: Regex,
    version_info: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Debug)]
struct ProbeDatabase {
    probes: Vec<Probe>,
    probes_by_name: HashMap<String, usize>,
    default_tcp_probes: Vec<usize>,
    go_port_map: HashMap<u16, Vec<usize>>,
    tls_ports: HashSet<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FingerprintTransport {
    Plain,
    Tls,
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn fingerprint_services(
    targets: &[ServiceFingerprintTarget],
    timeout: Duration,
    concurrency: usize,
) -> Result<Vec<ServiceFingerprint>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(targets.to_vec())));
    let matches = Arc::new(Mutex::new(Vec::new()));
    let worker_count = concurrency.max(1).min(targets.len());

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let matches = Arc::clone(&matches);

            scope.spawn(move || {
                loop {
                    let next = {
                        let mut queue = queue.lock().expect("queue lock poisoned");
                        queue.pop_front()
                    };
                    let Some(target) = next else {
                        break;
                    };

                    match fingerprint_target(&target, timeout) {
                        Ok(Some(service)) => {
                            matches.lock().expect("matches lock poisoned").push(service);
                        }
                        Ok(None) => {}
                        Err(_) => {}
                    }
                }
            });
        }
    });

    let mut matches = Arc::try_unwrap(matches)
        .expect("all workers should exit")
        .into_inner()
        .expect("matches lock poisoned");
    matches.sort_by(|left, right| {
        left.host
            .cmp(&right.host)
            .then_with(|| left.port.cmp(&right.port))
            .then_with(|| left.service.cmp(&right.service))
    });
    Ok(matches)
}

fn fingerprint_target(
    target: &ServiceFingerprintTarget,
    timeout: Duration,
) -> Result<Option<ServiceFingerprint>> {
    let database = probe_database()?;
    if let Some(result) = fingerprint_target_with_transport(
        target,
        timeout,
        database,
        FingerprintTransport::Plain,
    )? {
        return Ok(Some(result));
    }

    if database.prefers_tls(target.port) {
        return fingerprint_target_with_transport(target, timeout, database, FingerprintTransport::Tls);
    }

    Ok(None)
}

fn fingerprint_target_with_transport(
    target: &ServiceFingerprintTarget,
    timeout: Duration,
    database: &ProbeDatabase,
    transport: FingerprintTransport,
) -> Result<Option<ServiceFingerprint>> {
    let mut used = HashSet::new();
    let mut provisional = None;
    let mut last_banner = None;
    let mut reached_target = false;
    let mut plain_stream = None;
    let initial = match read_initial_banner(target, timeout, transport, &mut plain_stream) {
        Ok(response) => {
            reached_target = true;
            response
        }
        Err(_) => Vec::new(),
    };
    if !initial.is_empty() {
        last_banner = Some(trim_banner(&initial));
        if let Some(result) = match_banner_response(target, &initial, database, &mut used) {
            if is_generic_tls_result(&result, transport) {
                provisional = Some(result);
            } else {
                return Ok(Some(result));
            }
        }
        if let Some(result) = identify_manual_response(target, &initial) {
            return Ok(Some(result));
        }
    }

    let mut failures = 0usize;
    for probe_index in database.candidate_probes(target.port) {
        let probe = &database.probes[probe_index];
        if probe.data.is_empty() || !used.insert(probe.name.clone()) {
            continue;
        }

        let probe_timeout = probe_timeout(timeout, probe.total_wait_ms);
        let response = match execute_probe(
            target,
            probe,
            probe_timeout,
            transport,
            &mut plain_stream,
        ) {
            Ok(response) => {
                reached_target = true;
                response
            }
            Err(_) => Vec::new(),
        };
        if response.is_empty() {
            failures += 1;
            if failures > MAX_FAILURES {
                break;
            }
            continue;
        }
        last_banner = Some(trim_banner(&response));

        if let Some(result) = match_probe_response(target, probe, &response, database, &mut used) {
            if is_generic_tls_result(&result, transport) {
                provisional.get_or_insert(result);
            } else {
                return Ok(Some(result));
            }
        }
        if GO_DEFAULT_TCP_PROBES.contains(&probe.name.as_str()) {
            if let Some(result) =
                match_mapped_probe_response(target, probe, &response, database, &mut used)
            {
                if is_generic_tls_result(&result, transport) {
                    provisional.get_or_insert(result);
                } else {
                    return Ok(Some(result));
                }
            }
        }
    }

    Ok(provisional.or_else(|| {
        reached_target.then(|| unknown_result(target, last_banner.unwrap_or_default()))
    }))
}

fn probe_database() -> Result<&'static ProbeDatabase> {
    static DATABASE: OnceLock<Result<ProbeDatabase>> = OnceLock::new();
    DATABASE
        .get_or_init(parse_probe_database)
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn parse_probe_database() -> Result<ProbeDatabase> {
    let mut current = Vec::new();
    let mut probes = Vec::new();

    for raw_line in PROBES_SOURCE.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(ports) = line.strip_prefix("Exclude ") {
            let _ = parse_port_ranges(ports)?;
            continue;
        }
        if line.starts_with("Probe ") && !current.is_empty() {
            probes.push(parse_probe_block(&current)?);
            current.clear();
        }
        current.push(line.to_string());
    }
    if !current.is_empty() {
        probes.push(parse_probe_block(&current)?);
    }

    let mut probes_by_name = HashMap::new();
    for (index, probe) in probes.iter().enumerate() {
        probes_by_name.insert(probe.name.clone(), index);
    }

    let default_tcp_probes = GO_DEFAULT_TCP_PROBES
        .iter()
        .filter_map(|name| probes_by_name.get(*name).copied())
        .collect::<Vec<_>>();

    let mut port_map: HashMap<u16, Vec<usize>> = HashMap::new();
    let mut go_port_map: HashMap<u16, Vec<usize>> = HashMap::new();
    let mut tls_ports = HashSet::new();
    for (index, probe) in probes.iter().enumerate() {
        if !probe.protocol.eq_ignore_ascii_case("tcp") {
            continue;
        }
        for range in &probe.ports {
            for port in range.start..=range.end {
                port_map.entry(port).or_default().push(index);
            }
        }
        for range in &probe.ssl_ports {
            for port in range.start..=range.end {
                tls_ports.insert(port);
                port_map.entry(port).or_default().push(index);
            }
        }
    }
    for (port, names) in parse_go_port_map()? {
        let mapped = names
            .into_iter()
            .filter_map(|name| probes_by_name.get(&name).copied())
            .collect::<Vec<_>>();
        if !mapped.is_empty() {
            go_port_map.insert(port, mapped);
        }
    }

    Ok(ProbeDatabase {
        probes,
        probes_by_name,
        default_tcp_probes,
        go_port_map,
        tls_ports,
    })
}

fn parse_probe_block(lines: &[String]) -> Result<Probe> {
    let header = lines
        .first()
        .context("probe block should contain a header line")?;
    let header = header
        .strip_prefix("Probe ")
        .context("probe block header must start with Probe")?;
    let (protocol, remainder) = header
        .split_once(' ')
        .context("probe header missing protocol separator")?;
    let (name, remainder) = remainder
        .split_once(' ')
        .context("probe header missing name separator")?;
    let (payload, _) = parse_delimited_payload(remainder)?;

    let mut probe = Probe {
        name: name.to_string(),
        protocol: protocol.to_string(),
        data: decode_data(payload)?,
        ports: Vec::new(),
        ssl_ports: Vec::new(),
        total_wait_ms: None,
        rarity: 5,
        fallback: None,
        matches: Vec::new(),
    };

    for line in &lines[1..] {
        if let Some(spec) = line.strip_prefix("ports ") {
            probe.ports = parse_port_ranges(spec)?;
        } else if let Some(spec) = line.strip_prefix("sslports ") {
            probe.ssl_ports = parse_port_ranges(spec)?;
        } else if let Some(value) = line.strip_prefix("totalwaitms ") {
            probe.total_wait_ms = value.trim().parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix("rarity ") {
            probe.rarity = value.trim().parse::<u16>().unwrap_or(5);
        } else if let Some(value) = line.strip_prefix("fallback ") {
            probe.fallback = Some(value.trim().to_string());
        } else if let Some(rule) = line.strip_prefix("match ") {
            if let Ok(rule) = parse_match_rule(rule, false) {
                probe.matches.push(rule);
            }
        } else if let Some(rule) = line.strip_prefix("softmatch ") {
            if let Ok(rule) = parse_match_rule(rule, true) {
                probe.matches.push(rule);
            }
        }
    }

    Ok(probe)
}

fn parse_match_rule(rule: &str, is_soft: bool) -> Result<MatchRule> {
    let (service, remainder) = rule
        .split_once(' ')
        .context("match rule missing service separator")?;
    let (pattern, version_info) = parse_delimited_payload(remainder)?;
    let decoded = decode_pattern(pattern)?;
    let regex = RegexBuilder::new(&decoded)
        .unicode(false)
        .build()
        .with_context(|| format!("failed to compile pattern for service {service}: {decoded:?}"))?;

    Ok(MatchRule {
        is_soft,
        service: service.to_string(),
        regex,
        version_info: version_info.to_string(),
    })
}

fn parse_delimited_payload(value: &str) -> Result<(&str, &str)> {
    let mut chars = value.chars();
    chars.next().context("directive is missing flag")?;
    let delimiter = chars.next().context("directive is missing delimiter")?;
    let remainder = &value[2..];
    let end = remainder
        .find(delimiter)
        .with_context(|| format!("directive payload is missing closing delimiter {delimiter}"))?;
    Ok((&remainder[..end], &remainder[end + delimiter.len_utf8()..]))
}

fn parse_port_ranges(spec: &str) -> Result<Vec<PortRange>> {
    let mut ranges = Vec::new();
    for token in spec
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let token = token
            .rsplit_once(':')
            .map(|(_, value)| value)
            .unwrap_or(token)
            .trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start, end)) = token.split_once('-') {
            let start = start.trim().parse::<u16>()?;
            let end = end.trim().parse::<u16>()?;
            let (start, end) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            ranges.push(PortRange { start, end });
        } else {
            let port = token.parse::<u16>()?;
            ranges.push(PortRange {
                start: port,
                end: port,
            });
        }
    }
    Ok(ranges)
}

fn parse_go_port_map() -> Result<HashMap<u16, Vec<String>>> {
    static NAME_RE: OnceLock<TextRegex> = OnceLock::new();

    let mut map = HashMap::new();
    let mut in_port_map = false;

    for line in GO_CONFIG_SOURCE.lines() {
        let trimmed = line.trim();
        if trimmed == "var PortMap = map[int][]string{" {
            in_port_map = true;
            continue;
        }
        if !in_port_map {
            continue;
        }
        if trimmed == "}" {
            break;
        }
        let Some((port, rest)) = trimmed.split_once(':') else {
            continue;
        };
        let port = port.trim().parse::<u16>()?;
        let names = NAME_RE
            .get_or_init(|| TextRegex::new(r#""([^"]+)""#).expect("port map regex should compile"))
            .captures_iter(rest)
            .filter_map(|captures| captures.get(1).map(|value| value.as_str().to_string()))
            .collect::<Vec<_>>();
        map.insert(port, names);
    }

    Ok(map)
}

fn decode_pattern(pattern: &str) -> Result<String> {
    let mut output = String::new();
    let bytes = pattern.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'\\' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }

        if index + 1 >= bytes.len() {
            output.push('\\');
            break;
        }

        match bytes[index + 1] {
            b'x' if index + 3 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 2..index + 4])?;
                let value = u8::from_str_radix(hex, 16)?;
                push_literal_byte(&mut output, value);
                index += 4;
            }
            b'0'..=b'7' => {
                let mut end = index + 1;
                while end < bytes.len() && end < index + 4 && (b'0'..=b'7').contains(&bytes[end]) {
                    end += 1;
                }
                let octal = std::str::from_utf8(&bytes[index + 1..end])?;
                let value = u8::from_str_radix(octal, 8)?;
                push_literal_byte(&mut output, value);
                index = end;
            }
            b'a' => {
                push_literal_byte(&mut output, 0x07);
                index += 2;
            }
            b'f' => {
                push_literal_byte(&mut output, 0x0c);
                index += 2;
            }
            b't' => {
                push_literal_byte(&mut output, b'\t');
                index += 2;
            }
            b'n' => {
                push_literal_byte(&mut output, b'\n');
                index += 2;
            }
            b'r' => {
                push_literal_byte(&mut output, b'\r');
                index += 2;
            }
            b'v' => {
                push_literal_byte(&mut output, 0x0b);
                index += 2;
            }
            next => {
                output.push('\\');
                output.push(next as char);
                index += 2;
            }
        }
    }

    Ok(output)
}

fn decode_data(data: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let bytes = data.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'\\' {
            output.push(bytes[index]);
            index += 1;
            continue;
        }

        if index + 1 >= bytes.len() {
            output.push(b'\\');
            break;
        }

        match bytes[index + 1] {
            b'x' if index + 3 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 2..index + 4])?;
                output.push(u8::from_str_radix(hex, 16)?);
                index += 4;
            }
            b'0'..=b'7' => {
                let mut end = index + 1;
                while end < bytes.len() && end < index + 4 && (b'0'..=b'7').contains(&bytes[end]) {
                    end += 1;
                }
                let octal = std::str::from_utf8(&bytes[index + 1..end])?;
                output.push(u8::from_str_radix(octal, 8)?);
                index = end;
            }
            b'a' => {
                output.push(0x07);
                index += 2;
            }
            b'f' => {
                output.push(0x0c);
                index += 2;
            }
            b't' => {
                output.push(b'\t');
                index += 2;
            }
            b'n' => {
                output.push(b'\n');
                index += 2;
            }
            b'r' => {
                output.push(b'\r');
                index += 2;
            }
            b'v' => {
                output.push(0x0b);
                index += 2;
            }
            next => {
                output.push(next);
                index += 2;
            }
        }
    }

    Ok(output)
}

fn push_literal_byte(output: &mut String, byte: u8) {
    if !(0x20..=0x7e).contains(&byte) {
        output.push_str(&format!("\\x{byte:02x}"));
        return;
    }
    if matches!(
        byte,
        b'.' | b'*'
            | b'+'
            | b'?'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
            | b'|'
            | b'\\'
    ) {
        output.push('\\');
    }
    output.push(byte as char);
}

fn read_initial_banner(
    target: &ServiceFingerprintTarget,
    timeout: Duration,
    transport: FingerprintTransport,
    plain_stream: &mut Option<TcpStream>,
) -> Result<Vec<u8>> {
    match transport {
        FingerprintTransport::Plain => {
            let stream = ensure_plain_stream(target, timeout, plain_stream)?;
            read_available(stream)
        }
        FingerprintTransport::Tls => {
            let mut stream = connect_tls_stream(&target.host, target.port, timeout)?;
            read_available(&mut stream)
        }
    }
}

fn execute_probe(
    target: &ServiceFingerprintTarget,
    probe: &Probe,
    timeout: Duration,
    transport: FingerprintTransport,
    plain_stream: &mut Option<TcpStream>,
) -> Result<Vec<u8>> {
    match transport {
        FingerprintTransport::Plain => {
            let stream = write_plain_probe(target, timeout, plain_stream, &probe.data)
                .with_context(|| format!("failed to write probe {}", probe.name))?;
            read_available(stream)
        }
        FingerprintTransport::Tls => {
            let mut stream = connect_tls_stream(&target.host, target.port, timeout)?;
            stream
                .write_all(&probe.data)
                .with_context(|| format!("failed to write TLS probe {}", probe.name))?;
            stream
                .flush()
                .with_context(|| format!("failed to flush TLS probe {}", probe.name))?;
            read_available(&mut stream)
        }
    }
}

fn connect_stream(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let socket_addrs = format!("{host}:{port}")
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {host}:{port}"))?;

    for socket in socket_addrs {
        if let Ok(stream) = TcpStream::connect_timeout(&socket, timeout) {
            return Ok(stream);
        }
    }

    anyhow::bail!("failed to connect to {host}:{port}")
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<()> {
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set fingerprint read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set fingerprint write timeout")?;
    Ok(())
}

fn ensure_plain_stream<'a>(
    target: &ServiceFingerprintTarget,
    timeout: Duration,
    stream: &'a mut Option<TcpStream>,
) -> Result<&'a mut TcpStream> {
    if stream.is_none() {
        let connected = connect_stream(&target.host, target.port, timeout)?;
        configure_stream(&connected, timeout)?;
        *stream = Some(connected);
    }
    Ok(stream
        .as_mut()
        .expect("plain fingerprint stream should exist after connect"))
}

fn write_plain_probe<'a>(
    target: &ServiceFingerprintTarget,
    timeout: Duration,
    stream: &'a mut Option<TcpStream>,
    payload: &[u8],
) -> Result<&'a mut TcpStream> {
    let first_attempt = ensure_plain_stream(target, timeout, stream)?
        .write_all(payload)
        .map_err(anyhow::Error::from);
    match first_attempt {
        Ok(()) => ensure_plain_stream(target, timeout, stream),
        Err(error) if should_reconnect_plain_stream(&error) => {
            *stream = None;
            let connected = ensure_plain_stream(target, GO_FINGERPRINT_RECONNECT_TIMEOUT, stream)?;
            connected.write_all(payload)?;
            Ok(connected)
        }
        Err(error) => Err(error),
    }
}

fn should_reconnect_plain_stream(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .map(|io_error| {
            matches!(
                io_error.kind(),
                ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::NotConnected
            )
        })
        .unwrap_or(false)
}

fn connect_tls_stream(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let socket = connect_stream(host, port, timeout)?;
    configure_stream(&socket, timeout)?;
    let server_name = tls_server_name(host)?;
    let connection = ClientConnection::new(tls_client_config(), server_name)
        .with_context(|| format!("failed to create TLS client for {host}:{port}"))?;
    let mut stream = StreamOwned::new(connection, socket);
    stream
        .conn
        .complete_io(&mut stream.sock)
        .with_context(|| format!("failed to complete TLS handshake for {host}:{port}"))?;
    Ok(stream)
}

fn tls_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        Arc::new(
            ClientConfig::builder_with_provider(
                rustls::crypto::aws_lc_rs::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions should be available")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth(),
        )
    }))
}

fn tls_server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).context("invalid TLS server name")
}

fn read_available<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                buffer.extend_from_slice(&chunk[..count]);
                if count < chunk.len() {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            Err(_error) if !buffer.is_empty() => break,
            Err(error) => return Err(error).context("failed to read fingerprint response"),
        }
    }
    Ok(buffer)
}

fn probe_timeout(base_timeout: Duration, probe_wait_ms: Option<u64>) -> Duration {
    probe_wait_ms
        .map(Duration::from_millis)
        .map(|probe_timeout| probe_timeout.min(base_timeout))
        .unwrap_or(base_timeout)
}

fn match_banner_response(
    target: &ServiceFingerprintTarget,
    response: &[u8],
    database: &ProbeDatabase,
    _used: &mut HashSet<String>,
) -> Option<ServiceFingerprint> {
    for probe_name in ["NULL", "GenericLines"] {
        let Some(index) = database.probes_by_name.get(probe_name).copied() else {
            continue;
        };
        let probe = &database.probes[index];
        if let Some(result) = match_probe(target, probe, response, database) {
            return Some(result);
        }
    }
    None
}

fn match_probe_response(
    target: &ServiceFingerprintTarget,
    probe: &Probe,
    response: &[u8],
    database: &ProbeDatabase,
    used: &mut HashSet<String>,
) -> Option<ServiceFingerprint> {
    if let Some(result) = match_probe(target, probe, response, database) {
        return Some(result);
    }

    match probe.name.as_str() {
        "GenericLines" => {
            if let Some(index) = database.probes_by_name.get("NULL").copied() {
                used.insert("NULL".to_string());
                if let Some(result) = match_probe(target, &database.probes[index], response, database) {
                    return Some(result);
                }
            }
        }
        "NULL" => {}
        _ => {
            if let Some(index) = database.probes_by_name.get("GenericLines").copied() {
                used.insert("GenericLines".to_string());
                if let Some(result) = match_probe(target, &database.probes[index], response, database)
                {
                    return Some(result);
                }
            }
        }
    }

    identify_manual_response(target, response)
}

fn match_mapped_probe_response(
    target: &ServiceFingerprintTarget,
    current_probe: &Probe,
    response: &[u8],
    database: &ProbeDatabase,
    used: &mut HashSet<String>,
) -> Option<ServiceFingerprint> {
    let mapped = database.go_port_map.get(&target.port)?;

    for index in mapped {
        let probe = &database.probes[*index];
        if probe.name == current_probe.name || !used.insert(probe.name.clone()) {
            continue;
        }
        if let Some(result) = match_probe(target, probe, response, database) {
            return Some(result);
        }
    }

    None
}

fn match_probe(
    target: &ServiceFingerprintTarget,
    probe: &Probe,
    response: &[u8],
    database: &ProbeDatabase,
) -> Option<ServiceFingerprint> {
    let mut soft_match = None;

    for rule in &probe.matches {
        let Some(captures) = rule.regex.captures(response) else {
            continue;
        };
        let result = build_match_result(target, rule, &captures, response);
        if !rule.is_soft {
            return Some(result);
        }
        if soft_match.is_none() {
            soft_match = Some(result);
        }
    }

    if let Some(fallback_name) = &probe.fallback {
        if let Some(index) = database.probes_by_name.get(fallback_name).copied() {
            for rule in &database.probes[index].matches {
                let Some(captures) = rule.regex.captures(response) else {
                    continue;
                };
                let result = build_match_result(target, rule, &captures, response);
                if !rule.is_soft {
                    return Some(result);
                }
                if soft_match.is_none() {
                    soft_match = Some(result);
                }
            }
        }
    }

    soft_match
}

fn build_match_result(
    target: &ServiceFingerprintTarget,
    rule: &MatchRule,
    captures: &Captures<'_>,
    response: &[u8],
) -> ServiceFingerprint {
    let version_info = expand_version_info(&rule.version_info, captures);
    let mut extras = parse_version_fields(&version_info);
    let version = extras.remove("version");
    let banner = trim_banner(response);
    if rule.service == "microsoft-ds" && !banner.is_empty() {
        extras.insert("hostname".to_string(), banner.clone());
    }

    ServiceFingerprint {
        host: target.host.clone(),
        port: target.port,
        service: rule.service.clone(),
        version,
        banner,
        extras,
    }
}

fn expand_version_info(template: &str, captures: &Captures<'_>) -> String {
    let mut expanded = template.to_string();
    for index in 1..captures.len() {
        let replacement = captures
            .get(index)
            .map(|item| String::from_utf8_lossy(item.as_bytes()).to_string())
            .unwrap_or_default();
        expanded = expanded.replace(&format!("${index}"), &replacement);
    }
    expanded
}

fn parse_version_fields(version_info: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for (token, key) in [
        (" p", "vendor_product"),
        (" v", "version"),
        (" i", "info"),
        (" h", "hostname"),
        (" o", "os"),
        (" d", "device_type"),
        (" cpe:", "cpe"),
    ] {
        if let Some(value) = extract_delimited_field(version_info, token) {
            fields.insert(key.to_string(), value);
        }
    }
    fields
}

fn extract_delimited_field(version_info: &str, token: &str) -> Option<String> {
    let start = version_info.find(token)?;
    let after = &version_info[start + token.len()..];
    let mut chars = after.chars();
    let delimiter = chars.next()?;
    let remainder = &after[delimiter.len_utf8()..];
    let end = remainder.find(delimiter)?;
    let value = remainder[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn identify_manual_response(
    target: &ServiceFingerprintTarget,
    response: &[u8],
) -> Option<ServiceFingerprint> {
    let banner = trim_banner(response);
    if banner.is_empty() {
        return None;
    }

    if banner.contains("HTTP/") || banner.contains("html") {
        return Some(ServiceFingerprint {
            host: target.host.clone(),
            port: target.port,
            service: "http".to_string(),
            version: None,
            banner,
            extras: BTreeMap::new(),
        });
    }

    None
}

fn is_generic_tls_result(
    result: &ServiceFingerprint,
    transport: FingerprintTransport,
) -> bool {
    matches!(transport, FingerprintTransport::Tls) && result.service == "ssl"
}

fn unknown_result(target: &ServiceFingerprintTarget, banner: String) -> ServiceFingerprint {
    ServiceFingerprint {
        host: target.host.clone(),
        port: target.port,
        service: "unknown".to_string(),
        version: None,
        banner,
        extras: BTreeMap::new(),
    }
}

fn trim_banner(response: &[u8]) -> String {
    static WHITESPACE: OnceLock<TextRegex> = OnceLock::new();

    if let Some(smb_banner) = trim_smb_banner(response) {
        return smb_banner;
    }

    let mut compact = String::new();
    for ch in String::from_utf8_lossy(response).chars() {
        if ('!'..'}').contains(&ch) {
            compact.push(ch);
        } else {
            compact.push(' ');
        }
    }

    WHITESPACE
        .get_or_init(|| TextRegex::new(r"\s{2,}").expect("banner whitespace regex should compile"))
        .replace_all(&compact, ".")
        .trim()
        .to_string()
}

fn trim_smb_banner(response: &[u8]) -> Option<String> {
    if !response.windows(3).any(|window| window == b"SMB") {
        return None;
    }
    if response.len() <= 81 || response.get(5..8) != Some(b"SMB") {
        return None;
    }

    let data = &response[81..];
    let mut domain = String::new();
    let mut index = None;

    for (i, byte) in data.iter().enumerate() {
        if *byte != 0 {
            domain.push(*byte as char);
        } else if data.get(i + 1) == Some(&0) {
            index = Some(i + 2);
            break;
        }
    }

    let start = index?;
    let mut hostname = String::new();
    for (i, byte) in data[start..].iter().enumerate() {
        if *byte != 0 {
            hostname.push(*byte as char);
        }
        if data.get(start + i + 1) == Some(&0) {
            break;
        }
    }

    Some(format!("hostname: {hostname} domain: {domain}"))
}

impl ProbeDatabase {
    fn prefers_tls(&self, port: u16) -> bool {
        self.tls_ports.contains(&port)
    }

    fn candidate_probes(&self, port: u16) -> Vec<usize> {
        let mut seen = HashSet::new();
        let mut probes = Vec::new();

        if let Some(mapped) = self.go_port_map.get(&port) {
            for probe in mapped {
                if seen.insert(*probe) {
                    probes.push(*probe);
                }
            }
        }

        for probe in &self.default_tcp_probes {
            if seen.insert(*probe) {
                probes.push(*probe);
            }
        }

        probes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::io::{BufReader, ErrorKind};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::time::Instant;

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
    fn fingerprints_http_response() {
        let _ = probe_database().expect("probe database should parse");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut request = [0u8; 1024];
                        let _ = stream.read(&mut request);
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .expect("response should write");
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "http");
        assert_eq!(
            matches[0].banner,
            "HTTP/1.1 200 OK.Server: nginx/1.24.0.Content-Length: 0.Connection: close."
        );
    }

    #[test]
    fn reads_tls_banner_on_ssl_port() {
        let _ = probe_database().expect("probe database should parse");
        let listener = [8443_u16, 9443, 10443]
            .into_iter()
            .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
            .expect("listener should bind on known SSL port");
        let port = listener.local_addr().expect("addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");
        let config = tls_test_config();

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .expect("read timeout should set");
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .expect("write timeout should set");
                        let conn =
                            ServerConnection::new(config.clone()).expect("server conn should build");
                        let mut tls = StreamOwned::new(conn, stream);
                        if tls.conn.complete_io(&mut tls.sock).is_err() {
                            continue;
                        }
                        tls.write_all(b"220 mail.example ESMTP ready\r\n")
                            .expect("banner should write");
                        tls.flush().expect("response should flush");
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
        });

        let banner = read_initial_banner(
            &ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            },
            Duration::from_secs(1),
            FingerprintTransport::Tls,
            &mut None,
        )
        .expect("TLS banner should be readable");

        server.join().expect("server should finish");

        assert!(String::from_utf8_lossy(&banner).contains("ESMTP"));
    }

    #[test]
    fn loads_probe_database() {
        let database = probe_database().expect("probe database should parse");
        assert!(database.probes_by_name.contains_key("NULL"));
        assert!(database.probes_by_name.contains_key("GenericLines"));
    }

    #[test]
    fn matches_probe_database_banner_directly() {
        let database = probe_database().expect("probe database should parse");
        let mut used = HashSet::new();
        let result = match_banner_response(
            &ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port: 5038,
            },
            b"Asterisk Call Manager/18.5.0\r\n",
            database,
            &mut used,
        );

        assert!(result.is_some());
        let result = result.expect("probe rule should match");
        assert_eq!(result.service, "asterisk");
        assert_eq!(result.version.as_deref(), Some("18.5.0"));
        assert_eq!(result.extras["vendor_product"], "Asterisk Call Manager");
    }

    #[test]
    fn fingerprints_probe_database_banner() {
        let _ = probe_database().expect("probe database should parse");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();
        listener
            .set_nonblocking(true)
            .expect("listener should be nonblocking");

        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .write_all(b"Asterisk Call Manager/18.5.0\r\n")
                            .expect("banner should write");
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "asterisk");
        assert_eq!(matches[0].version.as_deref(), Some("18.5.0"));
        assert_eq!(matches[0].extras["vendor_product"], "Asterisk Call Manager");
    }

    #[test]
    fn continues_when_one_fingerprint_target_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .write_all(b"SSH-2.0-OpenSSH_9.6\r\n")
                .expect("banner should write");
        });

        let matches = fingerprint_services(
            &[
                ServiceFingerprintTarget {
                    host: "bad host name".to_string(),
                    port: 22,
                },
                ServiceFingerprintTarget {
                    host: "127.0.0.1".to_string(),
                    port,
                },
            ],
            Duration::from_secs(1),
            2,
        )
        .expect("fingerprint batch should continue");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].host, "127.0.0.1");
        assert_eq!(matches[0].service, "ssh");
    }

    #[test]
    fn returns_unknown_when_no_fingerprint_matches() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .write_all(b"mystery service banner\r\n")
                .expect("banner should write");
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "unknown");
        assert_eq!(matches[0].banner, "mystery service banner.");
    }

    #[test]
    fn does_not_manually_label_non_http_banners_like_go() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .write_all(b"$89\r\n# Server\r\nredis_version:7.2.5\r\n")
                .expect("banner should write");
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "unknown");
        assert_eq!(matches[0].banner, "$89.# Server.redis_version:7.2.5.");
    }

    #[test]
    fn fingerprints_ports_listed_in_probe_exclude_directive() {
        let listener = [9100_u16, 9101, 9102, 9103, 9104, 9105, 9106, 9107]
            .into_iter()
            .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
            .expect("listener should bind on known excluded port");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .write_all(b"raw printer banner\r\n")
                .expect("banner should write");
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "unknown");
        assert_eq!(matches[0].banner, "raw printer banner.");
    }

    #[test]
    fn fingerprints_html_body_as_http() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .write_all(b"<html><title>hello</title></html>\r\n")
                .expect("banner should write");
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "http");
        assert_eq!(matches[0].banner, "<html><title>hello</title></html>.");
    }

    #[test]
    fn normalizes_banner_whitespace_like_go() {
        assert_eq!(
            trim_banner(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"),
            "HTTP/1.1 200 OK.Server: nginx."
        );
    }

    #[test]
    fn decodes_smb_banner_like_go() {
        let mut response = vec![0u8; 81];
        response[5..8].copy_from_slice(b"SMB");
        response.extend_from_slice(b"WORKGROUP\0\0FILESRV\0\0");

        assert_eq!(
            trim_banner(&response),
            "hostname: FILESRV domain: WORKGROUP"
        );
    }

    #[test]
    fn copies_banner_into_microsoft_ds_hostname_like_go() {
        let rule = MatchRule {
            is_soft: false,
            service: "microsoft-ds".to_string(),
            regex: Regex::new("SMB").expect("regex should compile"),
            version_info: String::new(),
        };
        let response = b"SMB banner\r\n";
        let captures = rule
            .regex
            .captures(response)
            .expect("response should match");

        let result = build_match_result(
            &ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port: 445,
            },
            &rule,
            &captures,
            response,
        );

        assert_eq!(result.extras["hostname"], "SMB banner.");
        assert_eq!(result.banner, "SMB banner.");
    }

    #[test]
    fn retries_probe_responses_with_generic_lines_like_go() {
        let database = probe_database().expect("probe database should parse");
        let get_request = database.probes_by_name["GetRequest"];
        let mut used = HashSet::new();

        let result = match_probe_response(
            &ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port: 80,
            },
            &database.probes[get_request],
            b"ERROR\r\n",
            database,
            &mut used,
        )
        .expect("generic lines retry should match");

        assert_eq!(result.service, "achat");
    }

    #[test]
    fn retries_default_probe_responses_with_mapped_probes_like_go() {
        let database = probe_database().expect("probe database should parse");
        let generic_lines = database.probes_by_name["GenericLines"];
        let mut used = HashSet::from(["GenericLines".to_string()]);

        let result = match_mapped_probe_response(
            &ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port: 23,
            },
            &database.probes[generic_lines],
            b"\xff\xfd\x18\xff\xfa\x18\x01\xff\xf0\xff\xfd\x19",
            database,
            &mut used,
        )
        .expect("mapped probe retry should match");

        assert_eq!(result.service, "tn3270");
    }

    #[test]
    fn reuses_plain_connection_across_initial_read_and_probes_like_go() {
        let listener = TcpListener::bind("127.0.0.1:505").expect("listener should bind");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout should set");

            let mut seen = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(count) => {
                        seen.extend_from_slice(&buf[..count]);
                        if String::from_utf8_lossy(&seen).contains("GET / HTTP/1.0") {
                            stream
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .expect("response should write");
                            break;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::TimedOut => continue,
                    Err(error) => panic!("read failed: {error}"),
                }
            }
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port: 505,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "http");
    }

    #[test]
    fn passive_banner_check_does_not_skip_active_generic_lines_probe() {
        let listener = [110_u16, 119, 214, 264, 449]
            .into_iter()
            .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
            .expect("listener should bind on a GenericLines port");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .write_all(b"ignored banner\r\n")
                .expect("initial banner should write");

            let mut seen = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(count) => {
                        seen.extend_from_slice(&buf[..count]);
                        if seen.windows(4).any(|window| window == b"\r\n\r\n") {
                            stream.write_all(b"ERROR\r\n").expect("probe reply should write");
                            break;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::TimedOut => continue,
                    Err(error) => panic!("read failed: {error}"),
                }
            }
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "achat");
    }

    #[test]
    fn does_not_send_extra_head_fallback_requests_like_go() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let port = listener.local_addr().expect("addr").port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout should set");
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(count) => {
                        request.extend_from_slice(&buf[..count]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            let request_text = String::from_utf8_lossy(&request);
                            if request_text.contains("HEAD / HTTP/1.0") {
                                stream
                                    .write_all(
                                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                    )
                                    .expect("head response should write");
                            }
                            break;
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::TimedOut => break,
                    Err(error) => panic!("read failed: {error}"),
                }
            }
        });

        let matches = fingerprint_services(
            &[ServiceFingerprintTarget {
                host: "127.0.0.1".to_string(),
                port,
            }],
            Duration::from_secs(1),
            1,
        )
        .expect("fingerprint should succeed");

        server.join().expect("server should finish");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].service, "unknown");
    }

    #[test]
    fn matches_go_default_probe_order() {
        let database = probe_database().expect("probe database should parse");
        let candidates = database.candidate_probes(65000);
        let names = candidates
            .iter()
            .map(|index| database.probes[*index].name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            &names[..GO_DEFAULT_TCP_PROBES.len()],
            GO_DEFAULT_TCP_PROBES
        );
    }

    #[test]
    fn prioritizes_go_port_map_probe_order_for_common_ports() {
        let database = probe_database().expect("probe database should parse");
        let names = database
            .candidate_probes(80)
            .into_iter()
            .map(|index| database.probes[index].name.as_str().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            &names[..5],
            &[
                "GetRequest".to_string(),
                "HTTPOptions".to_string(),
                "RTSPRequest".to_string(),
                "X11Probe".to_string(),
                "FourOhFourRequest".to_string(),
            ]
        );
    }

    #[test]
    fn ignores_probe_file_only_port_mappings_for_active_probe_order() {
        let database = probe_database().expect("probe database should parse");
        let names = database
            .candidate_probes(4740)
            .into_iter()
            .map(|index| database.probes[index].name.as_str().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            &names[..GO_DEFAULT_TCP_PROBES.len()],
            &GO_DEFAULT_TCP_PROBES
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
        );
        assert!(!names.iter().any(|name| name == "mqtt"));
    }

    #[test]
    fn does_not_cap_default_probe_count_like_go() {
        let database = ProbeDatabase {
            probes: (0..64)
                .map(|index| Probe {
                    name: format!("Probe{index}"),
                    protocol: "TCP".to_string(),
                    data: Vec::new(),
                    ports: Vec::new(),
                    ssl_ports: Vec::new(),
                    total_wait_ms: None,
                    rarity: 1,
                    fallback: None,
                    matches: Vec::new(),
                })
                .collect(),
            probes_by_name: HashMap::new(),
            default_tcp_probes: (0..64).collect(),
            go_port_map: HashMap::new(),
            tls_ports: HashSet::new(),
        };

        let candidates = database.candidate_probes(65000);

        assert_eq!(candidates.len(), 64);
        assert_eq!(candidates[0], 0);
        assert_eq!(candidates[63], 63);
    }
}
