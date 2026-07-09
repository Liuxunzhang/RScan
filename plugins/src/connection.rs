use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::OpenService;
use crate::protocol_assets::TLS_FALLBACK_PLAINTEXT_PROBE_TIMEOUT;
use crate::runtime::current_connection_runtime_options;

#[derive(Debug)]
struct NoCertificateVerification;

type ClientTlsStream = StreamOwned<ClientConnection, TcpStream>;

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

pub(crate) fn connect_stream(target: &OpenService, timeout: Duration) -> Result<TcpStream> {
    let address = format!("{}:{}", target.host, target.port);
    let socket = address
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {address}"))?
        .next()
        .with_context(|| format!("no socket addresses for {address}"))?;
    connect_stream_with(&socket, timeout, &address, TcpStream::connect_timeout)
}

pub(crate) fn tls_fallback_plaintext_probe_timeout(timeout: Duration) -> Duration {
    timeout.min(TLS_FALLBACK_PLAINTEXT_PROBE_TIMEOUT)
}

pub(crate) fn connect_stream_with<F>(
    socket: &std::net::SocketAddr,
    timeout: Duration,
    address: &str,
    mut connect: F,
) -> Result<TcpStream>
where
    F: FnMut(&std::net::SocketAddr, Duration) -> std::io::Result<TcpStream>,
{
    let max_retries = usize::from(current_connection_runtime_options().max_retries);
    let mut last_error = None;

    for attempt in 0..=max_retries {
        match connect(socket, timeout) {
            Ok(stream) => return configure_stream(stream, timeout, address),
            Err(error) => {
                last_error = Some(error);
                if attempt == max_retries {
                    break;
                }
            }
        }
    }

    let error =
        anyhow::Error::from(last_error.expect("connect_stream_with should record an error"));
    Err(error).with_context(|| format!("failed to connect to {address}"))
}

pub(crate) fn configure_stream(
    stream: TcpStream,
    timeout: Duration,
    address: &str,
) -> Result<TcpStream> {
    stream
        .set_read_timeout(Some(timeout))
        .with_context(|| format!("failed to set read timeout for {address}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .with_context(|| format!("failed to set write timeout for {address}"))?;
    Ok(stream)
}

pub(crate) fn tls_client_config() -> Arc<ClientConfig> {
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

pub(crate) fn tls_server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).context("invalid TLS server name")
}

pub(crate) fn connect_tls_stream(
    target: &OpenService,
    timeout: Duration,
) -> Result<ClientTlsStream> {
    let address = format!("{}:{}", target.host, target.port);
    let stream = connect_stream(target, timeout)?;
    let connection = ClientConnection::new(tls_client_config(), tls_server_name(&target.host)?)
        .with_context(|| format!("failed to create TLS client for {address}"))?;
    let mut tls = StreamOwned::new(connection, stream);
    tls.conn
        .complete_io(&mut tls.sock)
        .with_context(|| format!("failed to complete TLS handshake for {address}"))?;
    Ok(tls)
}

pub(crate) fn write_and_flush_io<S>(stream: &mut S, payload: &[u8]) -> Result<()>
where
    S: Write,
{
    stream
        .write_all(payload)
        .context("failed to write request")?;
    stream.flush().context("failed to flush request")
}

pub(crate) fn write_and_flush(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    write_and_flush_io(stream, payload)
}

pub(crate) fn send_tcp_command(
    target: &OpenService,
    command: &[u8],
    timeout_secs: u64,
) -> Result<String> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let mut stream = connect_stream(target, timeout)?;
    write_and_flush(&mut stream, command)?;
    read_available(&mut stream)
}

pub(crate) fn send_tcp_payload(
    target: &OpenService,
    payload: &[u8],
    timeout_secs: u64,
) -> Result<String> {
    send_tcp_command(target, payload, timeout_secs)
}

pub(crate) fn read_line_io<S>(stream: &mut S) -> Result<String>
where
    S: Read,
{
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buffer.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            Err(error) => return Err(error).context("failed to read line"),
        }
    }
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

pub(crate) fn read_line(stream: &mut TcpStream) -> Result<String> {
    read_line_io(stream)
}

pub(crate) fn read_available_io<S>(stream: &mut S) -> Result<String>
where
    S: Read,
{
    Ok(String::from_utf8_lossy(&read_available_bytes_io(stream)?).to_string())
}

pub(crate) fn read_available(stream: &mut TcpStream) -> Result<String> {
    read_available_io(stream)
}

pub(crate) fn read_available_bytes_io<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: Read,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

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
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if buffer.is_empty() && error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            Err(error) => return Err(error).context("failed to read response"),
        }
    }

    Ok(buffer)
}

pub(crate) fn read_available_bytes(stream: &mut TcpStream) -> Result<Vec<u8>> {
    read_available_bytes_io(stream)
}
