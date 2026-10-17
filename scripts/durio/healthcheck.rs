//! Tiny healthcheck probe for distroless images (no shell, no curl).
//!
//!   healthcheck http <host:port> [path]   GET over HTTP/1.0, healthy on 2xx/3xx
//!   healthcheck tcp <host:port>           healthy if a TCP connection opens
//!
//! Std only, built with plain `rustc` in the base image (see Dockerfile).

use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(3);

fn connect(addr: &str) -> Result<TcpStream, String> {
    let target = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolve {addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("resolve {addr}: no address"))?;
    let stream =
        TcpStream::connect_timeout(&target, TIMEOUT).map_err(|e| format!("connect {addr}: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    Ok(stream)
}

fn http(addr: &str, path: &str) -> Result<(), String> {
    let mut stream = connect(addr)?;
    let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host);
    write!(stream, "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("write: {e}"))?;

    let mut head = [0u8; 64];
    let read = stream.read(&mut head).map_err(|e| format!("read: {e}"))?;
    let status_line = String::from_utf8_lossy(&head[..read]);
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("bad response: {status_line:?}"))?;

    if (200..400).contains(&code) {
        Ok(())
    } else {
        Err(format!("status {code}"))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["http", addr] => http(addr, "/"),
        ["http", addr, path] => http(addr, path),
        ["tcp", addr] => connect(addr).map(|_| ()),
        _ => Err("usage: healthcheck http <host:port> [path] | tcp <host:port>".into()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("unhealthy: {error}");
            ExitCode::FAILURE
        }
    }
}
