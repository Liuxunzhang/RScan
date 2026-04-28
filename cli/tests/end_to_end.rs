use rustls::pki_types::PrivateKeyDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::fs;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::thread;

fn temp_output(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rscan-e2e-{}-{}.json", name, std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

fn temp_input(name: &str, extension: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rscan-e2e-{}-{}.{}",
        name,
        std::process::id(),
        extension
    ));
    let _ = fs::remove_file(&path);
    path
}

fn read_output_compact(path: &PathBuf) -> String {
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

const TEST_SSH_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
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

fn complete_server_tls_handshake(
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

struct TestSshHandler {
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

    fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> impl std::future::Future<Output = std::result::Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}

fn write_test_ssh_key(prefix: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("rscan-{prefix}-{}-{nonce}.key", std::process::id()));
    fs::write(&path, TEST_SSH_PRIVATE_KEY).expect("ssh private key should write");
    path
}

fn spawn_ssh_server(
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

fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
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

fn ber_integer(value: i32) -> Vec<u8> {
    ber_tlv(0x02, &[(value & 0xff) as u8])
}

fn ber_octet_string(value: &[u8]) -> Vec<u8> {
    ber_tlv(0x04, value)
}

fn snmp_response(community: &str, system: &str) -> Vec<u8> {
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

fn neo4j_success_frame() -> Vec<u8> {
    vec![0x00, 0x03, 0xB1, 0x70, 0xA0, 0x00, 0x00]
}

fn cassandra_frame(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + body.len());
    frame.push(0x84);
    frame.push(0x00);
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.push(opcode);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len();
    let mut packet = Vec::with_capacity(length + 4);
    packet.push((length & 0xff) as u8);
    packet.push(((length >> 8) & 0xff) as u8);
    packet.push(((length >> 16) & 0xff) as u8);
    packet.push(sequence);
    packet.extend_from_slice(payload);
    packet
}

fn mysql_handshake() -> Vec<u8> {
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

fn postgres_read_startup(stream: &mut TcpStream) -> Vec<u8> {
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

fn postgres_message(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(payload.len() + 5);
    message.push(tag);
    message.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

fn kafka_read_frame(stream: &mut TcpStream) -> Vec<u8> {
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

fn kafka_response_frame(correlation_id: i32, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(body.len() + 4);
    payload.extend_from_slice(&correlation_id.to_be_bytes());
    payload.extend_from_slice(body);
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn kafka_request_api_key(payload: &[u8]) -> Option<i16> {
    let bytes: [u8; 2] = payload.get(0..2)?.try_into().ok()?;
    Some(i16::from_be_bytes(bytes))
}

fn mssql_prelogin_message() -> Vec<u8> {
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

fn mssql_read_message(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
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

fn mssql_write_packet(
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

fn mssql_login_ack_payload() -> Vec<u8> {
    vec![
        0xAD, 0x12, 0x00, 0x01, 0x74, 0x00, 0x00, 0x04, 0x05, b'r', 0, b's', 0, b'c', 0, b'a', 0,
        b'n', 0, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ]
}

fn mssql_login_username(payload: &[u8]) -> Option<String> {
    mssql_login_field(payload, 40)
}

fn mssql_login_password(payload: &[u8]) -> Option<String> {
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

fn mssql_login_field(payload: &[u8], offset_index: usize) -> Option<String> {
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

fn redis_read_command(stream: &mut TcpStream) -> std::io::Result<String> {
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

fn ms17010_negotiate_request() -> Vec<u8> {
    hex::decode("00000085ff534d4272000000001853c80000000000000000000000000000fffe00000000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200").expect("valid request")
}

fn ms17010_session_setup_request() -> Vec<u8> {
    hex::decode("00000088ff534d4273000000001807c80000000000000000000000000000fffe000040000cff000a01044132000000000000004a0000000000d40000a0cf00604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000078208a200000000000000000000000000000000000502ce0e0000000f00").expect("valid request")
}

fn ms17010_tree_connect_request(host: &str, user_id: [u8; 2]) -> Vec<u8> {
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

fn ms17010_trans_named_pipe_request() -> Vec<u8> {
    hex::decode("0000004aff534d42250000000018012800000000000000000000000088ea30108529810000000000ffffffff0000000000000000000000004a0000004a000200230000000070005c504950455c00").expect("valid request")
}

fn ms17010_trans2_session_setup_request() -> Vec<u8> {
    hex::decode("0000004eff534d4232000000001807c00000000000000000000000008fffe0000841000f0c0000000010000000000000000a6d9a400000000c00420000004e0001000e000d0000000000000000000000000000").expect("valid request")
}

fn findnet_test_payload(hostname: &str, addresses: &[&str]) -> Vec<u8> {
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

fn utf16le_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

const NETBIOS_UDP_PROBE: &[u8] = b"\x66\x66\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01";

fn netbios_udp_response(domain: &str, host: &str) -> Vec<u8> {
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

fn netbios_ntlm_response() -> Vec<u8> {
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

fn ms17010_negotiate_response() -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x72");
    response
}

fn ms17010_session_response(user_id: [u8; 2], os: &str) -> Vec<u8> {
    let byte_count = os.len() + 2;
    let mut response = vec![0u8; 45 + byte_count];
    response[4..8].copy_from_slice(b"SMB\x73");
    response[32..34].copy_from_slice(&user_id);
    response[36] = 1;
    response[43..45].copy_from_slice(&(byte_count as u16).to_le_bytes());
    response[46..46 + os.len()].copy_from_slice(os.as_bytes());
    response
}

fn ms17010_tree_response(tree_id: [u8; 2]) -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x75");
    response[28..30].copy_from_slice(&tree_id);
    response
}

fn ms17010_named_pipe_response(vulnerable: bool) -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x25");
    if vulnerable {
        response[9..13].copy_from_slice(&[0x05, 0x02, 0x00, 0xC0]);
    }
    response
}

fn ms17010_backdoor_response(backdoor: bool) -> Vec<u8> {
    let mut response = vec![0u8; 36];
    response[4..8].copy_from_slice(b"SMB\x32");
    if backdoor {
        response[34] = 0x51;
    }
    response
}

fn ms17010_tree_connect_request_for(host: &str, user_id: [u8; 2]) -> Vec<u8> {
    ms17010_tree_connect_request(host, user_id)
}

fn ms17010_trans_named_pipe_request_for(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
    let mut request = ms17010_trans_named_pipe_request();
    request[28..30].copy_from_slice(&tree_id);
    request[32..34].copy_from_slice(&user_id);
    request
}

fn ms17010_trans2_session_setup_request_for(tree_id: [u8; 2], user_id: [u8; 2]) -> Vec<u8> {
    let mut request = ms17010_trans2_session_setup_request();
    request[28..30].copy_from_slice(&tree_id);
    request[32..34].copy_from_slice(&user_id);
    request
}

#[test]
fn scans_open_port_and_writes_port_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("request should arrive");
    });

    let output = temp_output("port");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""status":"open""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_web_and_named_poc_and_writes_results() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 4096];
            let size = stream.read(&mut buffer).expect("request should read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            let body = if request.contains("GET /app/kibana ") {
                "<html><body>.kibanaWelcomeView</body></html>"
            } else {
                "<html><title>Kibana</title></html>"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        }
    });

    let output = temp_output("web-poc");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-u",
            &format!("http://127.0.0.1:{port}"),
            "-pocname",
            "kibana-unauth",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"SERVICE""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"http""#));
    assert!(content.contains(&format!(r#""Url":"http://127.0.0.1:{port}/""#)));
    assert!(content.contains(r#""fingerprints":["#));
    assert!(content.contains(r#""server_info":{"#));
    assert!(content.contains(r#""poc":"poc-yaml-kibana-unauth""#));
    let _ = fs::remove_file(output);
}

#[test]
fn prints_scan_plan_when_requested() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut buffer = [0u8; 4096];
            let size = stream.read(&mut buffer).expect("request should read");
            let request = String::from_utf8_lossy(&buffer[..size]);
            let body = if request.contains("GET /app/kibana ") {
                "<html><body>.kibanaWelcomeView</body></html>"
            } else {
                "<html><title>Kibana</title></html>"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
        }
    });

    let output = temp_output("scan-plan");
    let command = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-u",
            &format!("http://127.0.0.1:{port}"),
            "-pocname",
            "kibana-unauth",
            "-sp",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("command should run");
    assert!(command.status.success());

    server.join().expect("server should finish");

    let stdout = String::from_utf8_lossy(&command.stdout);
    assert!(stdout.contains("scan plan:"));
    assert!(stdout.contains("selected_pocs: 1 (poc-yaml-kibana-unauth)"));

    let _ = fs::remove_file(output);
}

#[test]
fn records_alive_host_results_in_output() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let _ = listener.accept();
    });

    let output = temp_output("alive-host");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1,198.51.100.1",
            "-p",
            &port.to_string(),
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"HOST""#));
    assert!(content.contains(r#""status":"alive""#));
    assert!(content.contains(r#""protocol":"ICMP""#));
    assert!(content.contains(r#""type":"PORT""#));

    let _ = TcpStream::connect(("127.0.0.1", port));
    server.join().expect("server should finish");
    let _ = fs::remove_file(output);
}

#[test]
fn prints_help_in_requested_language() {
    let zh = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .arg("-help")
        .output()
        .expect("help command should run");
    assert!(zh.status.success());
    assert!(String::from_utf8_lossy(&zh.stdout).contains("用法: rscan"));

    let en = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args(["-help", "-lang", "en"])
        .output()
        .expect("help command should run");
    assert!(en.status.success());
    assert!(String::from_utf8_lossy(&en.stdout).contains("Usage: rscan"));
}

#[test]
fn rejects_missing_runtime_target() {
    let command = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .output()
        .expect("command should run");
    assert!(!command.status.success());

    let stderr = String::from_utf8_lossy(&command.stderr);
    assert!(stderr.contains("error: specify scan parameters"));
    assert!(stderr.contains("用法: rscan"));
}

#[test]
fn rejects_conflicting_runtime_modes() {
    let command = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args(["-h", "127.0.0.1", "-u", "http://127.0.0.1"])
        .output()
        .expect("command should run");
    assert!(!command.status.success());

    let stderr = String::from_utf8_lossy(&command.stderr);
    assert!(stderr.contains("error: scan target modes conflict"));
    assert!(stderr.contains("用法: rscan"));
}

#[test]
fn prefixes_output_with_progress_when_requested() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("request should arrive");
    });

    let output = temp_output("progress");
    let command = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-pg",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("command should run");
    assert!(command.status.success());

    server.join().expect("server should finish");

    let stdout = String::from_utf8_lossy(&command.stdout);
    assert!(stdout.contains("[1/1] discovered PORT 127.0.0.1 open"));

    let _ = fs::remove_file(output);
}

#[test]
fn disables_color_when_requested() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("request should arrive");
    });

    let output = temp_output("nocolor");
    let colored = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("command should run");
    assert!(colored.status.success());
    assert!(String::from_utf8_lossy(&colored.stdout).contains("\u{1b}[33m"));

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();
    let server_plain = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("request should arrive");
    });

    let plain = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-nocolor",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("command should run");
    assert!(plain.status.success());
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("\u{1b}["));

    server.join().expect("server should finish");
    server_plain.join().expect("server should finish");
    let _ = fs::remove_file(output);
}

#[test]
fn suppresses_stdout_in_silent_mode() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("request should arrive");
    });

    let output = temp_output("silent");
    let command = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-silent",
            "-nocolor",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("command should run");
    assert!(command.status.success());
    assert!(String::from_utf8_lossy(&command.stdout).trim().is_empty());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    let _ = fs::remove_file(output);
}

#[test]
fn suppresses_stdout_for_error_log_level() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("request should arrive");
    });

    let output = temp_output("log-error");
    let command = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-log",
            "error",
            "-nocolor",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("command should run");
    assert!(command.status.success());
    assert!(String::from_utf8_lossy(&command.stdout).trim().is_empty());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_discovered_web_port_and_runs_named_poc() {
    let listener = [18080_u16, 18082, 18088, 19001]
        .into_iter()
        .find_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
        .expect("listener should bind on known web port");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("listener should become nonblocking");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                        .expect("stream timeout should set");
                    let mut buffer = [0u8; 4096];
                    let size = stream.read(&mut buffer).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    if !request.contains("GET ") {
                        continue;
                    }
                    let body = if request.contains("GET /app/kibana ") {
                        "<html><body>.kibanaWelcomeView</body></html>"
                    } else {
                        "<html><title>Kibana</title></html>"
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("response should write");
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => panic!("request should arrive: {error}"),
            }
        }
    });

    let output = temp_output("auto-web-poc");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-pocname",
            "kibana-unauth",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"SERVICE""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"http""#));
    assert!(content.contains(&format!(r#""Url":"http://127.0.0.1:{port}/""#)));
    assert!(content.contains(r#""fingerprints":["#));
    assert!(content.contains(r#""poc":"poc-yaml-kibana-unauth""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_memcached_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("request should arrive");
            let mut data = [0u8; 1024];
            let size = stream.read(&mut data).expect("request should read");
            let request = String::from_utf8_lossy(&data[..size]);
            if request.starts_with("stats") {
                stream
                    .write_all(b"STAT pid 1\r\nEND\r\n")
                    .expect("stats should write");
            } else {
                stream
                    .write_all(b"VERSION 1.6.9\r\n")
                    .expect("banner should write");
            }
        }
    });

    let output = temp_output("plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "memcached",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"memcached""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_ftp_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        let _ = probe_stream.write_all(b"220 FTP ready\r\n");

        let (mut auth_stream, _) = listener.accept().expect("ftp auth should arrive");
        auth_stream
            .write_all(b"220 FTP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];
        let size = auth_stream.read(&mut buffer).expect("user should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        if request.contains("USER anonymous") {
            auth_stream
                .write_all(b"230 Login successful\r\n")
                .expect("login should write");
        }
    });

    let output = temp_output("ftp-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "ftp",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"ftp""#));
    assert!(content.contains(r#""type":"anonymous-login""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_smtp_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        let _ = probe_stream.write_all(b"220 mail.example ESMTP ready\r\n");

        let (mut smtp_stream, _) = listener.accept().expect("smtp request should arrive");
        smtp_stream
            .write_all(b"220 mail.example ESMTP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];

        let size = smtp_stream.read(&mut buffer).expect("ehlo should read");
        assert!(String::from_utf8_lossy(&buffer[..size]).contains("EHLO rscan"));
        smtp_stream
            .write_all(b"250-mail.example\r\n250 AUTH PLAIN\r\n")
            .expect("ehlo response should write");

        let size = smtp_stream.read(&mut buffer).expect("mail should read");
        assert!(String::from_utf8_lossy(&buffer[..size]).contains("MAIL FROM"));
        smtp_stream
            .write_all(b"250 Sender OK\r\n")
            .expect("mail response should write");
    });

    let output = temp_output("smtp-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "smtp",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"smtp""#));
    assert!(content.contains(r#""type":"anonymous-access""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_smtp_plugin_from_hosts_file_host_port_entry() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut smtp_stream, _) = listener.accept().expect("smtp request should arrive");
        smtp_stream
            .write_all(b"220 mail.example ESMTP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];

        let size = smtp_stream.read(&mut buffer).expect("ehlo should read");
        assert!(String::from_utf8_lossy(&buffer[..size]).contains("EHLO rscan"));
        smtp_stream
            .write_all(b"250-mail.example\r\n250 AUTH PLAIN\r\n")
            .expect("ehlo response should write");

        let size = smtp_stream.read(&mut buffer).expect("mail should read");
        assert!(String::from_utf8_lossy(&buffer[..size]).contains("MAIL FROM"));
        smtp_stream
            .write_all(b"250 Sender OK\r\n")
            .expect("mail response should write");
    });

    let hosts_file = temp_input("smtp-hostport", "txt");
    fs::write(&hosts_file, format!("127.0.0.1:{port}\n")).expect("hosts file should write");

    let output = temp_output("smtp-hostport-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-hf",
            hosts_file.to_string_lossy().as_ref(),
            "-m",
            "smtp",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"smtp""#));
    assert!(content.contains(r#""type":"anonymous-access""#));
    let _ = fs::remove_file(output);
    let _ = fs::remove_file(hosts_file);
}

#[test]
fn scans_smtp_tls_fallback_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();
    listener
        .set_nonblocking(true)
        .expect("listener should become nonblocking");
    let config = tls_test_config();

    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                        .expect("read timeout should set");
                    stream
                        .set_write_timeout(Some(std::time::Duration::from_secs(1)))
                        .expect("write timeout should set");
                    let conn =
                        ServerConnection::new(config.clone()).expect("server conn should build");
                    let mut tls = StreamOwned::new(conn, stream);
                    if !complete_server_tls_handshake(&mut tls, deadline) {
                        continue;
                    }

                    tls.write_all(b"220 mail.example ESMTP ready\r\n")
                        .expect("banner should write");
                    let mut buffer = [0u8; 1024];

                    let size = tls.read(&mut buffer).expect("ehlo should read");
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    assert!(request.contains("EHLO rscan"));
                    tls.write_all(b"250-mail.example\r\n250 AUTH PLAIN\r\n")
                        .expect("ehlo response should write");

                    let size = tls.read(&mut buffer).expect("mail should read");
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    assert!(request.contains("MAIL FROM:<test@test.com>"));
                    tls.write_all(b"250 Sender OK\r\n")
                        .expect("mail response should write");
                    tls.flush().expect("response should flush");
                    return;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        panic!("timed out waiting for TLS SMTP request");
    });

    let output = temp_output("smtp-tls-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "smtp",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"smtp""#));
    assert!(content.contains(r#""type":"anonymous-access""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_imap_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        let _ = probe_stream.write_all(b"* OK IMAP ready\r\n");

        let (mut imap_stream, _) = listener.accept().expect("imap request should arrive");
        imap_stream
            .write_all(b"* OK IMAP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];
        let size = imap_stream.read(&mut buffer).expect("login should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("a001 LOGIN \"admin\" \"123456\""));
        imap_stream
            .write_all(b"a001 OK LOGIN completed\r\n")
            .expect("login response should write");
    });

    let output = temp_output("imap-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "imap",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"imap""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_pop3_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        let _ = probe_stream.write_all(b"+OK POP3 ready\r\n");

        let (mut pop3_stream, _) = listener.accept().expect("pop3 request should arrive");
        pop3_stream
            .write_all(b"+OK POP3 ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];

        let size = pop3_stream.read(&mut buffer).expect("user should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("USER admin"));
        pop3_stream
            .write_all(b"+OK user accepted\r\n")
            .expect("user response should write");

        let size = pop3_stream.read(&mut buffer).expect("pass should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("PASS 123456"));
        pop3_stream
            .write_all(b"+OK mailbox locked and ready\r\n")
            .expect("pass response should write");
    });

    let output = temp_output("pop3-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "pop3",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"pop3""#));
    assert!(content.contains(r#""type":"weak-password""#));
    assert!(content.contains(r#""tls":false"#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_activemq_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        let _ = probe_stream.write_all(b"CONNECTED\nversion:1.2\n\n\x00");

        let (mut mq_stream, _) = listener.accept().expect("activemq request should arrive");
        let mut buffer = [0u8; 2048];
        let size = mq_stream.read(&mut buffer).expect("frame should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("login:admin"));
        assert!(request.contains("passcode:admin"));
        mq_stream
            .write_all(b"CONNECTED\nversion:1.2\n\n\x00")
            .expect("response should write");
    });

    let output = temp_output("activemq-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "activemq",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"activemq""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_rabbitmq_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        let _ = probe_stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");

        let (mut mq_stream, _) = listener.accept().expect("rabbitmq request should arrive");
        let mut buffer = [0u8; 4096];
        let size = mq_stream.read(&mut buffer).expect("request should read");
        let request = String::from_utf8_lossy(&buffer[..size]).to_ascii_lowercase();
        assert!(request.contains("get /api/overview "));
        assert!(request.contains("authorization: basic z3vlc3q6z3vlc3q="));
        let body = r#"{"management_version":"3.13"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        mq_stream
            .write_all(response.as_bytes())
            .expect("response should write");
    });

    let output = temp_output("rabbitmq-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "rabbitmq",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"rabbitmq""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_mongodb_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut mongo_stream, _) = listener.accept().expect("mongodb request should arrive");
        let mut buffer = [0u8; 4096];
        let size = mongo_stream.read(&mut buffer).expect("request should read");
        assert!(size > 16);
        assert_eq!(&buffer[12..16], &[0xdd, 0x07, 0x00, 0x00]);
        mongo_stream
            .write_all(b"\x7f\x00\x00\x00totalLinesWritten")
            .expect("response should write");
    });

    let output = temp_output("mongodb-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "mongodb",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"mongodb""#));
    assert!(content.contains(r#""type":"unauthorized-access""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_modbus_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut modbus_stream, _) = listener.accept().expect("modbus request should arrive");
        let mut buffer = [0u8; 64];
        let size = modbus_stream
            .read(&mut buffer)
            .expect("request should read");
        assert_eq!(
            &buffer[..size],
            &[
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01
            ]
        );
        modbus_stream
            .write_all(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01])
            .expect("response should write");
    });

    let output = temp_output("modbus-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "modbus",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"modbus""#));
    assert!(content.contains(r#""type":"unauthorized-access""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_ldap_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut ldap_stream, _) = listener.accept().expect("ldap request should arrive");
        let mut buffer = [0u8; 2048];
        let size = ldap_stream.read(&mut buffer).expect("bind should read");
        assert!(String::from_utf8_lossy(&buffer[..size]).contains("\u{2}\u{1}\u{3}"));
        ldap_stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ])
            .expect("bind response should write");

        let size = ldap_stream.read(&mut buffer).expect("search should read");
        assert_eq!(buffer[5], 0x63);
        let _ = size;
        ldap_stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ])
            .expect("search response should write");
    });

    let output = temp_output("ldap-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "ldap",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"ldap""#));
    assert!(content.contains(r#""type":"anonymous-access""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_ldap_tls_fallback_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();
    listener
        .set_nonblocking(true)
        .expect("listener should become nonblocking");
    let config = tls_test_config();

    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                        .expect("read timeout should set");
                    stream
                        .set_write_timeout(Some(std::time::Duration::from_secs(1)))
                        .expect("write timeout should set");
                    let conn =
                        ServerConnection::new(config.clone()).expect("server conn should build");
                    let mut tls = StreamOwned::new(conn, stream);
                    if !complete_server_tls_handshake(&mut tls, deadline) {
                        continue;
                    }

                    let mut buffer = [0u8; 2048];
                    let size = tls.read(&mut buffer).expect("bind should read");
                    let request = &buffer[..size];
                    assert!(request.windows(3).any(|window| window == b"\x02\x01\x03"));
                    tls.write_all(&[
                        0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
                        0x04, 0x00,
                    ])
                    .expect("bind response should write");

                    let size = tls.read(&mut buffer).expect("search should read");
                    assert_eq!(buffer[5], 0x63);
                    let _ = size;
                    tls.write_all(&[
                        0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
                        0x04, 0x00,
                    ])
                    .expect("search response should write");
                    tls.flush().expect("response should flush");
                    return;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        panic!("timed out waiting for TLS LDAP request");
    });

    let output = temp_output("ldap-tls-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "ldap",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"ldap""#));
    assert!(content.contains(r#""type":"anonymous-access""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_snmp_plugin_and_writes_vuln_result() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket should bind");
    let port = socket.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let (size, peer) = socket
            .recv_from(&mut buffer)
            .expect("request should arrive");
        assert!(size > 0);
        socket
            .send_to(&snmp_response("public", "Mock SNMP"), peer)
            .expect("response should write");
    });

    let output = temp_output("snmp-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "snmp",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"snmp""#));
    assert!(content.contains(r#""type":"weak-community""#));
    assert!(content.contains(r#""community":"public""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_neo4j_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        probe_stream
            .write_all(b"\x00\x00\x04\x04")
            .expect("probe should write");

        let (mut noauth_stream, _) = listener.accept().expect("noauth request should arrive");
        let mut handshake = [0u8; 20];
        noauth_stream
            .read_exact(&mut handshake)
            .expect("handshake should read");
        noauth_stream
            .write_all(&[0x00, 0x00, 0x04, 0x04])
            .expect("version should write");
        let mut frame = [0u8; 256];
        let size = noauth_stream.read(&mut frame).expect("hello should read");
        let text = String::from_utf8_lossy(&frame[..size]);
        assert!(text.contains("scheme"));
        noauth_stream
            .write_all(&[0x00, 0x03, 0xB1, 0x7F, 0xA0, 0x00, 0x00])
            .expect("failure should write");

        let (mut default_stream, _) = listener.accept().expect("default request should arrive");
        default_stream
            .read_exact(&mut handshake)
            .expect("handshake should read");
        default_stream
            .write_all(&[0x00, 0x00, 0x04, 0x04])
            .expect("version should write");
        let size = default_stream.read(&mut frame).expect("hello should read");
        let text = String::from_utf8_lossy(&frame[..size]);
        assert!(text.contains("neo4j"));
        default_stream
            .write_all(&neo4j_success_frame())
            .expect("success should write");
    });

    let output = temp_output("neo4j-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "neo4j",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"neo4j""#));
    assert!(content.contains(r#""type":"default-credentials""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_cassandra_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        probe_stream
            .write_all(&cassandra_frame(0x02, &[]))
            .expect("probe should write");

        let (mut anonymous_stream, _) = listener.accept().expect("anonymous request should arrive");
        let mut frame = [0u8; 256];
        let _ = anonymous_stream
            .read(&mut frame)
            .expect("startup should read");
        anonymous_stream
            .write_all(&cassandra_frame(0x03, &[]))
            .expect("authenticate should write");

        let (mut weak_stream, _) = listener.accept().expect("weak request should arrive");
        let _ = weak_stream.read(&mut frame).expect("startup should read");
        weak_stream
            .write_all(&cassandra_frame(0x03, &[]))
            .expect("authenticate should write");
        let size = weak_stream.read(&mut frame).expect("auth should read");
        let text = String::from_utf8_lossy(&frame[..size]);
        assert!(text.contains("cassandra"));
        assert!(text.contains("123456"));
        weak_stream
            .write_all(&cassandra_frame(0x10, &[]))
            .expect("auth success should write");
    });

    let output = temp_output("cassandra-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "cassandra",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"cassandra""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_mysql_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("port probe should arrive");
        probe_stream
            .write_all(&mysql_packet(0, &mysql_handshake()))
            .expect("probe should write");

        let (mut mysql_stream, _) = listener.accept().expect("mysql request should arrive");
        mysql_stream
            .write_all(&mysql_packet(0, &mysql_handshake()))
            .expect("handshake should write");
        let mut buffer = [0u8; 512];
        let size = mysql_stream
            .read(&mut buffer)
            .expect("response should read");
        let text = String::from_utf8_lossy(&buffer[..size]);
        assert!(text.contains("root"));
        mysql_stream
            .write_all(&[
                0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            ])
            .expect("ok should write");
    });

    let output = temp_output("mysql-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "mysql",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"mysql""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_mssql_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut mssql_stream, _) = listener.accept().expect("mssql request should arrive");
        let prelogin = mssql_read_message(&mut mssql_stream).expect("prelogin should read");
        assert_eq!(prelogin, mssql_prelogin_message());
        mssql_write_packet(&mut mssql_stream, 0x04, 1, &mssql_prelogin_message())
            .expect("prelogin response should write");

        let login = mssql_read_message(&mut mssql_stream).expect("login should read");
        assert_eq!(mssql_login_username(&login), Some("sa".to_string()));
        assert_eq!(mssql_login_password(&login), Some("123456".to_string()));
        mssql_write_packet(&mut mssql_stream, 0x04, 1, &mssql_login_ack_payload())
            .expect("login ack should write");
    });

    let output = temp_output("mssql-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "mssql",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"mssql""#));
    assert!(content.contains(r#""type":"weak-password""#));
    assert!(content.contains(r#""username":"sa""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_redis_plugin_and_executes_custom_file_write() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut detect_stream, _) = listener.accept().expect("redis detect should arrive");
        assert_eq!(
            redis_read_command(&mut detect_stream).expect("info should read"),
            "INFO\r\n"
        );
        detect_stream
            .write_all(b"$12\r\nredis_version\r\n")
            .expect("response should write");

        let (mut exploit_stream, _) = listener.accept().expect("redis exploit should arrive");
        assert_eq!(
            redis_read_command(&mut exploit_stream).expect("dbfilename should read"),
            "CONFIG GET dbfilename\r\n"
        );
        exploit_stream
            .write_all(b"*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n")
            .expect("dbfilename should write");

        assert_eq!(
            redis_read_command(&mut exploit_stream).expect("dir should read"),
            "CONFIG GET dir\r\n"
        );
        exploit_stream
            .write_all(b"*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n")
            .expect("dir should write");

        assert_eq!(
            redis_read_command(&mut exploit_stream).expect("set dir should read"),
            "CONFIG SET dir /tmp\r\n"
        );
        exploit_stream
            .write_all(b"+OK\r\n")
            .expect("ok should write");

        assert_eq!(
            redis_read_command(&mut exploit_stream).expect("set file should read"),
            "CONFIG SET dbfilename owned.txt\r\n"
        );
        exploit_stream
            .write_all(b"+OK\r\n")
            .expect("ok should write");

        let write_command =
            redis_read_command(&mut exploit_stream).expect("set content should read");
        assert!(write_command.contains("set x \"hello\\nworld\""));
        exploit_stream
            .write_all(b"+OK\r\n")
            .expect("ok should write");

        assert_eq!(
            redis_read_command(&mut exploit_stream).expect("save should read"),
            "save\r\n"
        );
        exploit_stream
            .write_all(b"+OK\r\n")
            .expect("ok should write");

        assert_eq!(
            redis_read_command(&mut exploit_stream).expect("restore filename should read"),
            "CONFIG SET dbfilename dump.rdb\r\n"
        );
        exploit_stream
            .write_all(b"+OK\r\n")
            .expect("ok should write");

        assert_eq!(
            redis_read_command(&mut exploit_stream).expect("restore dir should read"),
            "CONFIG SET dir /tmp\r\n"
        );
        exploit_stream
            .write_all(b"+OK\r\n")
            .expect("ok should write");
    });

    let output = temp_output("redis-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "redis",
            "-rwp",
            "/tmp/owned.txt",
            "-rwc",
            "hello\nworld",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"redis""#));
    assert!(content.contains(r#""type":"unauthorized""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_ssh_plugin_and_writes_vuln_result() {
    let (port, server) = spawn_ssh_server(1, "root", Some("123456"), false);

    let output = temp_output("ssh-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "ssh",
            "-user",
            "root",
            "-pwd",
            "123456",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"ssh""#));
    assert!(content.contains(r#""username":"root""#));
    assert!(content.contains(r#""password":"123456""#));
    assert!(content.contains(r#""auth_type":"password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_fingerprint_and_writes_unknown_service_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("connection should arrive");
            let _ = stream.write_all(b"mystery service banner\r\n");
        }
    });

    let output = temp_output("fingerprint-unknown");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-fingerprint",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"SERVICE""#));
    assert!(content.contains(r#""status":"identified""#));
    assert!(content.contains(r#""service":"unknown""#));
    assert!(content.contains(r#""banner":"mystery service banner.""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_ssh_plugin_with_key_and_writes_vuln_result() {
    let (port, server) = spawn_ssh_server(1, "root", None, true);
    let key_path = write_test_ssh_key("ssh-cli");

    let output = temp_output("ssh-key-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "ssh",
            "-user",
            "root",
            "-sshkey",
            key_path.to_string_lossy().as_ref(),
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"ssh""#));
    assert!(content.contains(r#""username":"root""#));
    assert!(content.contains(r#""auth_type":"key""#));
    let _ = fs::remove_file(output);
    let _ = fs::remove_file(key_path);
}

#[test]
fn scans_postgres_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut postgres_stream, _) = listener.accept().expect("postgres request should arrive");
        let startup = postgres_read_startup(&mut postgres_stream);
        let text = String::from_utf8_lossy(&startup);
        assert!(text.contains("user\0postgres\0"));
        postgres_stream
            .write_all(&postgres_message(
                b'R',
                &[5u32.to_be_bytes().as_slice(), &[1, 2, 3, 4]].concat(),
            ))
            .expect("auth should write");
        let mut response = [0u8; 256];
        let size = postgres_stream
            .read(&mut response)
            .expect("password should read");
        let password = String::from_utf8_lossy(&response[..size]);
        assert!(password.contains("md5"));
        postgres_stream
            .write_all(&postgres_message(b'R', &0u32.to_be_bytes()))
            .expect("auth ok should write");
        postgres_stream
            .write_all(&postgres_message(b'Z', b"I"))
            .expect("ready should write");
    });

    let output = temp_output("postgres-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "postgres",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"postgresql""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_netbios_plugin_and_writes_service_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();
    let udp = match UdpSocket::bind("127.0.0.1:137") {
        Ok(udp) => udp,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("udp should bind: {error}"),
    };

    let udp_server = thread::spawn(move || {
        let mut request = [0u8; 128];
        let (size, peer) = udp
            .recv_from(&mut request)
            .expect("udp request should arrive");
        assert_eq!(&request[..size], NETBIOS_UDP_PROBE);
        udp.send_to(&netbios_udp_response("WORKGROUP", "DESKTOP01"), peer)
            .expect("udp response should send");
    });

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut netbios_stream, _) = listener.accept().expect("netbios request should arrive");
        let mut session = [0u8; 128];
        let _ = netbios_stream
            .read(&mut session)
            .expect("session request should read");
        netbios_stream
            .write_all(b"\x82")
            .expect("session ack should write");

        let mut negotiate = [0u8; 512];
        let _ = netbios_stream
            .read(&mut negotiate)
            .expect("negotiate one should read");
        netbios_stream
            .write_all(b"ok")
            .expect("negotiate one ack should write");
        let _ = netbios_stream
            .read(&mut negotiate)
            .expect("negotiate two should read");
        netbios_stream
            .write_all(&netbios_ntlm_response())
            .expect("ntlm response should write");
    });

    let output = temp_output("netbios-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "netbios",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    udp_server.join().expect("udp server should finish");
    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"SERVICE""#));
    assert!(content.contains(r#""computer_name":"DESKTOP01""#));
    assert!(content.contains(r#""domain_name":"WORKGROUP""#));
    assert!(content.contains(r#""os_version":"Windows Server 2022""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_kafka_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut unauth_stream, _) = listener.accept().expect("unauth request should arrive");
        let request = kafka_read_frame(&mut unauth_stream);
        assert_eq!(kafka_request_api_key(&request), Some(18));

        let (mut auth_stream, _) = listener.accept().expect("auth request should arrive");
        let handshake = kafka_read_frame(&mut auth_stream);
        assert_eq!(kafka_request_api_key(&handshake), Some(17));
        auth_stream
            .write_all(&kafka_response_frame(
                1,
                &[
                    0i16.to_be_bytes().as_slice(),
                    &1i32.to_be_bytes(),
                    &[0, 5],
                    b"PLAIN",
                ]
                .concat(),
            ))
            .expect("handshake response should write");
        let auth = kafka_read_frame(&mut auth_stream);
        assert!(auth.windows(7).any(|window| window == b"\0admin\0"));
        assert!(auth.windows(6).any(|window| window == b"123456"));

        let request = kafka_read_frame(&mut auth_stream);
        assert_eq!(kafka_request_api_key(&request), Some(18));
        auth_stream
            .write_all(&kafka_response_frame(2, &[0, 0, 0, 0]))
            .expect("api versions response should write");
    });

    let output = temp_output("kafka-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "kafka",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"kafka""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_vnc_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut vnc_stream, _) = listener.accept().expect("vnc request should arrive");
        vnc_stream
            .write_all(b"RFB 003.008\n")
            .expect("version should write");
        let mut version = [0u8; 12];
        vnc_stream
            .read_exact(&mut version)
            .expect("version should read");
        vnc_stream
            .write_all(&[1, 2])
            .expect("security should write");

        let mut selected = [0u8; 1];
        vnc_stream
            .read_exact(&mut selected)
            .expect("selection should read");
        assert_eq!(selected[0], 2);

        vnc_stream
            .write_all(b"0123456789abcdef")
            .expect("challenge should write");
        let mut response = [0u8; 16];
        vnc_stream
            .read_exact(&mut response)
            .expect("response should read");
        vnc_stream
            .write_all(&0u32.to_be_bytes())
            .expect("status should write");
    });

    let output = temp_output("vnc-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "vnc",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"vnc""#));
    assert!(content.contains(r#""type":"weak-password""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_smbghost_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut smb_stream, _) = listener.accept().expect("smb request should arrive");
        let mut request = [0u8; 256];
        let size = smb_stream.read(&mut request).expect("probe should read");
        assert!(size >= 4);

        let mut response = vec![0u8; 96];
        response[16..22].copy_from_slice(b"Public");
        response[72..74].copy_from_slice(&[0x11, 0x03]);
        response[74..76].copy_from_slice(&[0x02, 0x00]);
        smb_stream
            .write_all(&response)
            .expect("response should write");
    });

    let output = temp_output("smbghost-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "smbghost",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"smb""#));
    assert!(content.contains(r#""type":"cve-2020-0796""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_ms17010_plugin_and_writes_vuln_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut smb_stream, _) = listener.accept().expect("ms17010 request should arrive");

        let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
        smb_stream
            .read_exact(&mut negotiate)
            .expect("negotiate should read");
        assert_eq!(negotiate, ms17010_negotiate_request());
        smb_stream
            .write_all(&ms17010_negotiate_response())
            .expect("negotiate response should write");

        let mut session = vec![0u8; ms17010_session_setup_request().len()];
        smb_stream
            .read_exact(&mut session)
            .expect("session should read");
        assert_eq!(session, ms17010_session_setup_request());
        let user_id = [0x34, 0x12];
        smb_stream
            .write_all(&ms17010_session_response(user_id, "Windows Server 2012 R2"))
            .expect("session response should write");

        let mut tree = vec![0u8; ms17010_tree_connect_request("127.0.0.1", user_id).len()];
        smb_stream.read_exact(&mut tree).expect("tree should read");
        assert_eq!(tree, ms17010_tree_connect_request_for("127.0.0.1", user_id));
        let tree_id = [0x78, 0x56];
        smb_stream
            .write_all(&ms17010_tree_response(tree_id))
            .expect("tree response should write");

        let mut pipe = vec![0u8; ms17010_trans_named_pipe_request().len()];
        smb_stream.read_exact(&mut pipe).expect("pipe should read");
        assert_eq!(pipe, ms17010_trans_named_pipe_request_for(tree_id, user_id));
        smb_stream
            .write_all(&ms17010_named_pipe_response(true))
            .expect("pipe response should write");

        let mut trans2 = vec![0u8; ms17010_trans2_session_setup_request().len()];
        smb_stream
            .read_exact(&mut trans2)
            .expect("trans2 should read");
        assert_eq!(
            trans2,
            ms17010_trans2_session_setup_request_for(tree_id, user_id)
        );
        smb_stream
            .write_all(&ms17010_backdoor_response(true))
            .expect("backdoor response should write");
    });

    let output = temp_output("ms17010-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "ms17010",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"VULN""#));
    assert!(content.contains(r#""service":"smb""#));
    assert!(content.contains(r#""vulnerability":"MS17-010""#));
    assert!(content.contains(r#""backdoor":"DOUBLEPULSAR""#));
    let _ = fs::remove_file(output);
}

#[test]
fn scans_findnet_plugin_and_writes_service_result() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("addr").port();

    let server = thread::spawn(move || {
        let (_probe_stream, _) = listener.accept().expect("port probe should arrive");

        let (mut rpc_stream, _) = listener.accept().expect("rpc request should arrive");
        let mut probe = [0u8; 72];
        let _ = rpc_stream.read(&mut probe).expect("probe one should read");
        rpc_stream
            .write_all(b"ok")
            .expect("probe one response should write");

        let _ = rpc_stream.read(&mut probe).expect("probe two should read");
        let mut response = vec![0u8; 42];
        response.extend(findnet_test_payload("DESKTOP01", &["10.0.0.5", "fe80::1"]));
        rpc_stream
            .write_all(&response)
            .expect("probe two response should write");
    });

    let output = temp_output("findnet-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-m",
            "findnet",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    server.join().expect("server should finish");

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"PORT""#));
    assert!(content.contains(r#""type":"SERVICE""#));
    assert!(content.contains(r#""status":"identified""#));
    assert!(content.contains(r#""hostname":"DESKTOP01""#));
    let _ = fs::remove_file(output);
}

#[test]
fn runs_named_localinfo_mode_and_writes_service_result() {
    let output = temp_output("localinfo-plugin");
    let status = Command::new(env!("CARGO_BIN_EXE_rscan"))
        .args([
            "-m",
            "localinfo",
            "-f",
            "json",
            "-o",
            output.to_string_lossy().as_ref(),
        ])
        .status()
        .expect("command should run");
    assert!(status.success());

    let content = read_output_compact(&output);
    assert!(content.contains(r#""type":"SERVICE""#));
    assert!(content.contains(r#""status":"local-info""#));
    assert!(content.contains(r#""hostname":"#));
    let _ = fs::remove_file(output);
}
