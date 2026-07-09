//! Shared helpers for the rscan CLI integration tests.
//!
//! This module is compiled separately into each integration-test binary
//! (`end_to_end`, `service_plugins`), so any helper used by only one of them
//! would otherwise be reported as dead code in the other. Allow dead code
//! crate-wide to keep the shared helper pool usable from both binaries.
#![allow(dead_code)]

use rustls::pki_types::PrivateKeyDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::fs;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::thread;

pub(crate) fn temp_output(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rscan-e2e-{}-{}.json", name, std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

pub(crate) fn temp_input(name: &str, extension: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rscan-e2e-{}-{}.{}",
        name,
        std::process::id(),
        extension
    ));
    let _ = fs::remove_file(&path);
    path
}

pub(crate) fn read_output_compact(path: &PathBuf) -> String {
    let content = fs::read_to_string(path).expect("output file should exist");
    let mut compact = String::new();
    let stream = serde_json::Deserializer::from_str(&content).into_iter::<serde_json::Value>();
    for value in stream {
        compact.push_str(
            &serde_json::to_string(&value.expect("output should contain valid json records"))
                .expect("json record should serialize"),
        );
    }
    compact
}

pub(crate) const TEST_SSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAQEApsV6z4Qb/kgByFhg/Ive9nyAL01i3FOhIeA9VCR+CofpDm3cV/3j\n\
nbKhDDHyD5/E4jsJ8YTXbvHCaCMUZ02/sFYEmqFiKhURZLz8W5gTi3q/EWFN6RF0Cxch/n\n\
4ayR/f0+wun8L4ZMvEfSLgNa8wqHu/pC0zMuWtam+fg95G6X2miTSa0e+HJUX216k77VuG\n\
/+GfqQg5oxva17qRoRbrxuzW1dCURULEiegDYGviCl4/3MhIxCxisi8wfKrNZcjWiEB1lc\n\
H7s8wlI0Qpafa9aGO7oEIe1kiN/LChhYSSDUcH69/+Kp5rbA6b5i9uJS4gJx/2J3yqiFzh\n\
B2Lnlvyw5QAAA9iRPt3bkT7d2wAAAAdzc2gtcnNhAAABAQCmxXrPhBv+SAHIWGD8i972fI\n\
AvTWLcU6Eh4D1UJH4Kh+kObdxX/eOdsqEMMfIPn8TiOwnxhNdu8cJoIxRnTb+wVgSaoWIq\n\
FRFkvPxbmBOLer8RYU3pEXQLFyH+fhrJH9/T7C6fwvhky8R9IuA1rzCoe7+kLTMy5a1qb5\n\
+D3kbpfaaJNJrR74clRfbXqTvtW4b/4Z+pCDmjG9rXupGhFuvG7NbV0JRFQsSJ6ANga+IK\n\
Xj/cyEjELGKyLzB8qs1lyNaIQHWVwfuzzCUjRClp9r1oY7ugQh7WSI38sKGFhJINRwfr3/\n\
4qnmtsDpvmL24lLiAnH/YnfKqIXOEHYueW/LDlAAAAAwEAAQAAAP9gACvLnnyg7H0rRfkX\n\
I49PVI8gRUE0k5pHiAmjoeaoGC4qKL5QtYlI8U9MRut/vaOP7J+iClZfwtyVJs+ghcMwpU\n\
J4r9RBQyO3jPCE/JcQd9P8rUJ48IqPk4WxRtVGnHB4DdsvYJ3PiknNWLUeurHqBqe50eTA\n\
tJg4tW83YCvHPA44lcA5BlnfWaw7uLOUyASQKh7kiOWSx/yHvaCwHFzxih2GIr3rmPWNq1\n\
ASAYVVqaxQD0dMCJVGpyY0D2/KgiQ2RE6/vk5LR9wMRjMR1vZN1kmQaObyHLeN/h1F2GMS\n\
Kslm81jplV88LUcWMWYs4NrrrAHUny2OcsOgWq1NeZMAAACBAL7PzjYTTn//2XYid5TBKZ\n\
kqcUNiH8UUOLVzyAKaCD39OIs+elOoAVOT9FYSdzqMFap8kAqmv+eBYZyEoX3Z40NcuzmC\n\
xpI9d5kDWundiOM4108Wb4rraj49TyJrvln22+2ep09Ms5LL0DFR3qmiYeGYjjNmSRRuMZ\n\
OS9HmUsf/gAAAAgQDZGY+MZmFwwOHiSanlVeKaPB9CrDrJI0picTPuziXeZusEH4mmSx1+\n\
EVCFnjCDMnMdaTb9KG8ENr8TwvHdorf1BeyCKmZ+aQrpCIKu43sPd8ipm1v8upvZEKdnVv\n\
wlUV2NAaJHXQ5JFcoClASYORU5uETWHrS78L/8Eys/JoRLlwAAAIEAxKdWWo1p//zLtdmS\n\
784MleMd4cf0T/E8QodPpBskCUkDobrDT9sZCPHpi0w++dgBPbWjfi1Z3Th+mkhTtMhuSK\n\
lIruPFIShEPVQjqWkOlpX8MVgOYNbM2d2K/URu9U4HfaHLYXTqB8i4VGs7xMeKSLNPo/8e\n\
T+lFmFTFlBLc5uMAAAAccm9vdEBpWjBqbDdlMTBycndsczk4dXhoZjdoWgECAwQFBgc=\n\
-----END OPENSSH PRIVATE KEY-----\n";
pub(crate) const TEST_TLS_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
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
pub(crate) const TEST_TLS_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
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

pub(crate) fn tls_test_config() -> Arc<ServerConfig> {
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

pub(crate) fn complete_server_tls_handshake(
    tls: &mut StreamOwned<ServerConnection, TcpStream>,
    deadline: std::time::Instant,
) -> bool {
    let connection_deadline =
        (std::time::Instant::now() + std::time::Duration::from_secs(1)).min(deadline);
    while std::time::Instant::now() < connection_deadline {
        match tls.conn.complete_io(&mut tls.sock) {
            Ok(_) if !tls.conn.is_handshaking() => {
                let _ = tls.sock.set_nonblocking(false);
                return true;
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if error.kind() != ErrorKind::Interrupted {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            Err(_) => return false,
        }
    }
    false
}

pub(crate) struct TestSshHandler {
    username: String,
    password: Option<String>,
    authorized_key: Option<russh::keys::PublicKey>,
}

impl russh::server::Handler for TestSshHandler {
    type Error = russh::Error;

    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl std::future::Future<Output = std::result::Result<russh::server::Auth, Self::Error>> + Send
    {
        let accepted = self.username == user
            && self
                .password
                .as_deref()
                .is_some_and(|expected| expected == password);
        async move {
            Ok(if accepted {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }
    }

    fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = std::result::Result<russh::server::Auth, Self::Error>> + Send
    {
        let accepted = self.username == user && self.authorized_key.is_some();
        async move {
            Ok(if accepted {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }
    }

    fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = std::result::Result<russh::server::Auth, Self::Error>> + Send
    {
        let accepted = self.username == user && self.authorized_key.is_some();
        async move {
            Ok(if accepted {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

pub(crate) fn write_test_ssh_key(prefix: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("rscan-{prefix}-{}-{nonce}.key", std::process::id()));
    fs::write(&path, TEST_SSH_PRIVATE_KEY).expect("ssh private key should write");
    path
}

pub(crate) fn spawn_ssh_server(
    expected_sessions: usize,
    username: &'static str,
    password: Option<&'static str>,
    allow_publickey: bool,
) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime should build");
        let host_key = russh::keys::PrivateKey::from_openssh(TEST_SSH_PRIVATE_KEY)
            .expect("host key should parse");
        let authorized_key = host_key.public_key().clone();

        let mut config = russh::server::Config {
            keys: vec![host_key],
            ..Default::default()
        };
        config.auth_rejection_time = std::time::Duration::from_millis(10);
        config.auth_rejection_time_initial = Some(std::time::Duration::from_millis(10));
        let config = Arc::new(config);

        let mut served = 0usize;
        while served < expected_sessions {
            let (stream, _) = listener.accept().expect("connection should accept");
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .expect("probe timeout should set");
            let mut probe = [0u8; 4];
            let peeked = match stream.peek(&mut probe) {
                Ok(size) => size,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    continue;
                }
                Err(error) => panic!("failed to inspect ssh test connection: {error}"),
            };
            if peeked == 0 {
                continue;
            }

            stream
                .set_nonblocking(true)
                .expect("stream should become nonblocking");
            let session = runtime
                .block_on(async {
                    let stream =
                        tokio::net::TcpStream::from_std(stream).expect("tokio stream should wrap");
                    russh::server::run_stream(
                        config.clone(),
                        stream,
                        TestSshHandler {
                            username: username.to_string(),
                            password: password.map(ToString::to_string),
                            authorized_key: allow_publickey.then(|| authorized_key.clone()),
                        },
                    )
                    .await
                })
                .expect("ssh session should start");
            let _ = runtime.block_on(session);
            served += 1;
        }
    });

    (port, handle)
}

pub(crate) fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(2 + value.len());
    encoded.push(tag);
    if value.len() < 0x80 {
        encoded.push(value.len() as u8);
    } else {
        encoded.push(0x81);
        encoded.push(value.len() as u8);
    }
    encoded.extend_from_slice(value);
    encoded
}

pub(crate) fn ber_integer(value: i32) -> Vec<u8> {
    ber_tlv(0x02, &[(value & 0xff) as u8])
}

pub(crate) fn ber_octet_string(value: &[u8]) -> Vec<u8> {
    ber_tlv(0x04, value)
}

pub(crate) fn snmp_response(community: &str, system: &str) -> Vec<u8> {
    let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    let varbind = ber_tlv(
        0x30,
        &[ber_tlv(0x06, &oid), ber_octet_string(system.as_bytes())].concat(),
    );
    let varbinds = ber_tlv(0x30, &varbind);
    let pdu = ber_tlv(
        0xa2,
        &[ber_integer(1), ber_integer(0), ber_integer(0), varbinds].concat(),
    );
    ber_tlv(
        0x30,
        &[ber_integer(1), ber_octet_string(community.as_bytes()), pdu].concat(),
    )
}

pub(crate) fn neo4j_success_frame() -> Vec<u8> {
    vec![0x00, 0x03, 0xB1, 0x70, 0xA0, 0x00, 0x00]
}

pub(crate) fn cassandra_frame(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + body.len());
    frame.push(0x84);
    frame.push(0x00);
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.push(opcode);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

pub(crate) fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len();
    let mut packet = Vec::with_capacity(length + 4);
    packet.push((length & 0xff) as u8);
    packet.push(((length >> 8) & 0xff) as u8);
    packet.push(((length >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    packet
}

pub(crate) fn mysql_handshake() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x0a);
    payload.extend_from_slice(b"8.0.36\0");
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(b"12345678");
    payload.push(0x00);
    payload.extend_from_slice(&0xffffu16.to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&0x0002u16.to_le_bytes());
    payload.extend_from_slice(&0x0008u16.to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0u8; 10]);
    payload.extend_from_slice(b"abcdefghijklm");
    payload.push(0x00);
    payload.extend_from_slice(b"mysql_native_password\0");
    payload
}

pub(crate) fn postgres_read_startup(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .expect("postgres startup header should read");
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length.saturating_sub(4)];
    stream
        .read_exact(&mut payload)
        .expect("postgres startup payload should read");
    payload
}

pub(crate) fn postgres_message(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(payload.len() + 5);
    message.push(tag);
    message.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

pub(crate) fn kafka_read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .expect("kafka frame header should read");
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .expect("kafka frame payload should read");
    payload
}

pub(crate) fn kafka_response_frame(correlation_id: i32, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(body.len() + 4);
    payload.extend_from_slice(&correlation_id.to_be_bytes());
    payload.extend_from_slice(body);
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

pub(crate) fn kafka_request_api_key(payload: &[u8]) -> Option<i16> {
    let bytes: [u8; 2] = payload.get(0..2)?.try_into().ok()?;
    Some(i16::from_be_bytes(bytes))
}

pub(crate) fn mssql_prelogin_message() -> Vec<u8> {
    const VERSION: u8 = 0x00;
    const ENCRYPTION: u8 = 0x01;
    const THREAD_ID: u8 = 0x03;
    const MARS: u8 = 0x04;
    const TERMINATOR: u8 = 0xFF;

    let fields = [
        (VERSION, 6u16),
        (ENCRYPTION, 1u16),
        (THREAD_ID, 4u16),
        (MARS, 1u16),
    ];
    let mut payload = Vec::with_capacity(64);
    let mut offset = (fields.len() * 5 + 1) as u16;
    for (token, length) in fields {
        payload.push(token);
        payload.extend_from_slice(&offset.to_be_bytes());
        payload.extend_from_slice(&length.to_be_bytes());
        offset += length;
    }
    payload.push(TERMINATOR);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.push(0x00);
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.push(0x00);
    payload
}

pub(crate) fn mssql_read_message(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut payload = vec![0u8; length.saturating_sub(8)];
        stream.read_exact(&mut payload)?;
        message.extend_from_slice(&payload);
        if header[1] & 0x01 != 0 {
            break;
        }
    }
    Ok(message)
}

pub(crate) fn mssql_write_packet(
    stream: &mut TcpStream,
    packet_type: u8,
    packet_id: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let length = (payload.len() + 8) as u16;
    let mut packet = Vec::with_capacity(payload.len() + 8);
    packet.push(packet_type);
    packet.push(0x01);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, packet_id, 0x00]);
    packet.extend_from_slice(payload);
    stream.write_all(&packet)
}

pub(crate) fn mssql_login_ack_payload() -> Vec<u8> {
    vec![
        0xAD, 0x12, 0x00, 0x01, 0x74, 0x00, 0x00, 0x04, 0x05, b'r', 0, b's', 0, b'c', 0, b'a', 0,
        b'n', 0, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ]
}

pub(crate) fn mssql_login_username(payload: &[u8]) -> Option<String> {
    mssql_login_field(payload, 40)
}

pub(crate) fn mssql_login_password(payload: &[u8]) -> Option<String> {
    let offset = u16::from_le_bytes(payload.get(44..46)?.try_into().ok()?) as usize;
    let len = u16::from_le_bytes(payload.get(46..48)?.try_into().ok()?) as usize;
    let bytes = payload.get(offset..offset + len * 2)?;
    let decoded = bytes
        .iter()
        .map(|byte| (byte ^ 0xA5).rotate_left(4))
        .collect::<Vec<_>>();
    let units = decoded
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).ok()
}

pub(crate) fn mssql_login_field(payload: &[u8], offset_index: usize) -> Option<String> {
    let offset = u16::from_le_bytes(
        payload
            .get(offset_index..offset_index + 2)?
            .try_into()
            .ok()?,
    ) as usize;
    let len = u16::from_le_bytes(
        payload
            .get(offset_index + 2..offset_index + 4)?
            .try_into()
            .ok()?,
    ) as usize;
    let bytes = payload.get(offset..offset + len * 2)?;
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).ok()
}

pub(crate) fn redis_read_command(stream: &mut TcpStream) -> std::io::Result<String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("read timeout should set");
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        buffer.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

pub(crate) fn ms17010_negotiate_request() -> Vec<u8> {
    hex::decode("00000085ff534d4272000000001853c80000000000000000000000000000fffe00000000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200").expect("valid request")
}

pub(crate) fn ms17010_session_setup_request() -> Vec<u8> {
    hex::decode("00000088ff534d4273000000001807c80000000000000000000000000000fffe000040000cff000a01044132000000000000004a0000000000d40000a0cf00604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000078208a200000000000000000000000000000000000502ce0e0000000f00").expect("valid request")
}

pub(crate) fn ms17010_tree_connect_request(host: &str, user_id: [u8; 2]) -> Vec<u8> {
    let ipc_path = format!(r"\\{}\IPC$", host);
    let byte_count = 1 + ipc_path.len() + 1 + 6;
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(b"\xFFSMB");
    packet.push(0x75);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x20, 0x00, 0x00]);
    packet.extend_from_slice(&[0x00; 8]);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x2F, 0x4B]);
    packet.extend_from_slice(&user_id);
    packet.extend_from_slice(&[0xC5, 0x5E]);
    packet.extend_from_slice(&[0x04, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    packet.extend_from_slice(&(byte_count as u16).to_le_bytes());
    packet.push(0x00);
    packet.extend_from_slice(ipc_path.as_bytes());
    packet.push(0x00);
    packet.extend_from_slice(b"?????\0");
    let length = (packet.len() - 4) as u32;
    packet[1..4].copy_from_slice(&length.to_be_bytes()[1..4]);
    packet
}

pub(crate) fn ms17010_trans_named_pipe_request() -> Vec<u8> {
    hex::decode("0000004aff534d42250000000018012800000000000000000000000088ea30108529810000000000ffffffff0000000000000000000000004a0000004a000200230000000070005c504950455c00").expect("valid request")
}

pub(crate) fn ms17010_trans2_session_setup_request() -> Vec<u8> {
    hex::decode("0000004eff534d4232000000001807c00000000000000000000000008fffe0000841000f0c0000000010000000000000000a6d9a400000000c00420000004e0001000e000d0000000000000000000000000000").expect("valid request")
}

pub(crate) fn findnet_test_payload(hostname: &str, addresses: &[&str]) -> Vec<u8> {
    let mut payload = utf16le_bytes(hostname);
    payload.extend_from_slice(&[0, 0]);
    for address in addresses {
        payload.extend_from_slice(b"\x07\x00");
        payload.extend_from_slice(address.as_bytes());
        payload.extend_from_slice(&[0, 0, 0]);
    }
    payload.extend_from_slice(&[0, 0, 0, 0, 0x09, 0x00, 0xff, 0xff, 0x00, 0x00]);
    payload
}

pub(crate) fn utf16le_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

pub(crate) const NETBIOS_UDP_PROBE: &[u8] = b"\x66\x66\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01";

pub(crate) fn netbios_udp_response(domain: &str, host: &str) -> Vec<u8> {
    let mut response = vec![0u8; 57];
    response[56] = 2;
    let mut domain_entry = [b' '; 18];
    domain_entry[..domain.len().min(15)]
        .copy_from_slice(&domain.as_bytes()[..domain.len().min(15)]);
    domain_entry[15] = 0x00;
    domain_entry[16] = 0x80;
    let mut host_entry = [b' '; 18];
    host_entry[..host.len().min(15)].copy_from_slice(&host.as_bytes()[..host.len().min(15)]);
    host_entry[15] = 0x20;
    response.extend_from_slice(&domain_entry);
    response.extend_from_slice(&host_entry);
    response
}

pub(crate) fn netbios_ntlm_response() -> Vec<u8> {
    let target_info_length = 106usize;
    let mut response = vec![0u8; 47 + target_info_length];
    response[43] = target_info_length as u8;
    response[44] = (target_info_length >> 8) as u8;

    let start = 60usize;
    response[start..start + 7].copy_from_slice(b"NTLMSSP");
    response[start + 40] = 48;
    response[start + 41] = 0;
    response[start + 44] = 45;
    let items = [
        0x03, 0x00, 0x12, 0x00, b'D', 0, b'E', 0, b'S', 0, b'K', 0, b'T', 0, b'O', 0, b'P', 0,
        b'0', 0, b'1', 0, 0x04, 0x00, 0x12, 0x00, b'W', 0, b'O', 0, b'R', 0, b'K', 0, b'G', 0,
        b'R', 0, b'O', 0, b'U', 0, b'P', 0, 0x00, 0x00, 0x00, 0x00,
    ];
    let items_start = start + 45;
    response[items_start..items_start + items.len()].copy_from_slice(&items);
    response.extend_from_slice(&utf16le_bytes("Windows Server 2022|"));
    response
}

pub(crate) fn ms17010_negotiate_response() -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x72");
    response
}

pub(crate) fn ms17010_session_response(user_id: [u8; 2], os: &str) -> Vec<u8> {
    let byte_count = os.len() + 2;
    let mut response = vec![0u8; 45 + byte_count];
    response[4..8].copy_from_slice(b"SMB\x73");
    response[32..34].copy_from_slice(&user_id);
    response[36] = 1;
    response[43..45].copy_from_slice(&(byte_count as u16).to_le_bytes());
    response[46..46 + os.len()].copy_from_slice(os.as_bytes());
    response
}

pub(crate) fn ms17010_tree_response(tree_id: [u8; 2]) -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x75");
    response[28..30].copy_from_slice(&tree_id);
    response
}

pub(crate) fn ms17010_named_pipe_response(vulnerable: bool) -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x25");
    if vulnerable {
        response[9..13].copy_from_slice(&[0x05, 0x02, 0x00, 0xC0]);
    }
    response
}

pub(crate) fn ms17010_backdoor_response(backdoor: bool) -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x32");
    if backdoor {
        response[34] = 0x51;
    }
    response
}

pub(crate) fn ms17010_tree_connect_request_for(host: &str, user_id: [u8; 2]) -> Vec<u8> {
    ms17010_tree_connect_request(host, user_id)
}

pub(crate) fn ms17010_trans_named_pipe_request_for(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
    let mut request = ms17010_trans_named_pipe_request();
    request[28..30].copy_from_slice(&tree_id);
    request[32..34].copy_from_slice(&user_id);
    request
}

pub(crate) fn ms17010_trans2_session_setup_request_for(
    tree_id: [u8; 2],
    user_id: [u8; 2],
) -> Vec<u8> {
    let mut request = ms17010_trans2_session_setup_request();
    request[28..30].copy_from_slice(&tree_id);
    request[32..34].copy_from_slice(&user_id);
    request
}
