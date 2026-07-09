//! End-to-end tests for the per-service plugin scan path.
//!
//! Each test spawns a minimal mock server for one protocol, invokes the rscan
//! CLI against it, and asserts the resulting JSON output. Shared helpers (mock
//! server frames, TLS/SSH scaffolding, temp output paths) live in `support`.

use rustls::{ServerConnection, StreamOwned};
use std::fs;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::Command;
use std::thread;

mod support;
use support::*;

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
