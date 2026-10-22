//! The provider response-size cap also holds when the provider sends no
//! `Content-Length` (chunked transfer): the body is counted while it streams
//! and the read stops at the cap, instead of buffering the whole reply.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use citrate_gateway::provider::{dispatch_to_provider, ProviderProtocolRequest};
use citrate_gateway::ProviderInfo;

const CAP: usize = 2 * 1024 * 1024;

/// Read the whole request (head + `Content-Length` body) so that closing the
/// socket later is a clean FIN rather than a reset.
async fn drain_request(stream: &mut tokio::net::TcpStream) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let body_len = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < head_end + body_len {
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

/// Serve one chunked 200 response of `total` bytes in 64 KiB chunks.
async fn spawn_chunked_provider(total: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        drain_request(&mut stream).await;
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                    Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let chunk = vec![b' '; 64 * 1024];
        let mut sent = 0;
        while sent < total {
            let n = chunk.len().min(total - sent);
            let frame = format!("{n:x}\r\n");
            if stream.write_all(frame.as_bytes()).await.is_err()
                || stream.write_all(&chunk[..n]).await.is_err()
                || stream.write_all(b"\r\n").await.is_err()
            {
                return; // client stopped reading at the cap
            }
            sent += n;
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
        let _ = stream.flush().await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    address
}

fn provider(address: SocketAddr) -> ProviderInfo {
    ProviderInfo {
        address: ethereum_types::H160::from([0xb1; 20]),
        endpoint: format!("http://{address}/infer"),
        reputation_bps: 9_500,
        current_load: 0,
        max_concurrent: 10,
    }
}

fn request() -> ProviderProtocolRequest {
    ProviderProtocolRequest {
        model: "stream-cap-model".into(),
        prompt: "ping".into(),
        max_tokens: 1,
    }
}

#[tokio::test]
async fn chunked_response_over_the_cap_is_refused_while_streaming() {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let address = spawn_chunked_provider(CAP + 512 * 1024).await;
    let error = dispatch_to_provider(
        &reqwest::Client::new(),
        &provider(address),
        &request(),
        std::time::Duration::from_secs(10),
    )
    .await
    .expect_err("an over-cap streamed response must fail closed");
    assert!(
        error.to_string().contains("response too large"),
        "must report the bounded-response failure, got: {error}"
    );
}

#[tokio::test]
async fn chunked_response_under_the_cap_is_read_in_full() {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    // Whitespace-only body: read completely, then rejected as malformed JSON,
    // which proves the cap did not trip on an in-bounds stream.
    let address = spawn_chunked_provider(CAP - 1024).await;
    let error = dispatch_to_provider(
        &reqwest::Client::new(),
        &provider(address),
        &request(),
        std::time::Duration::from_secs(10),
    )
    .await
    .expect_err("whitespace is not a provider response");
    assert!(
        error.to_string().contains("malformed response"),
        "an in-bounds body must be read to the end, got: {error}"
    );
}
