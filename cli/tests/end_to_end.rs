use std::fs;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;

mod support;
use support::*;

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
    assert!(stdout.contains(&format!("[1/1] PORT    127.0.0.1:{port}")));

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
        // Cover port-scan + HTTPS probe + HTTP webtitle + POC (and retries).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut http_gets = 0usize;
        while std::time::Instant::now() < deadline && http_gets < 2 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Accepted sockets inherit nonblocking on some platforms;
                    // force blocking so small HTTP responses always complete.
                    stream
                        .set_nonblocking(false)
                        .expect("stream should become blocking");
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                        .expect("stream timeout should set");
                    stream
                        .set_write_timeout(Some(std::time::Duration::from_millis(500)))
                        .expect("stream write timeout should set");
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
                    http_gets += 1;
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
