//! IGW-B-008 tripwire: the provider response-size cap must be checked before
//! the client buffers a response body.

use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use citrate_gateway::provider::{dispatch_to_provider, ProviderProtocolRequest};
use citrate_gateway::ProviderInfo;

#[tokio::test]
async fn oversized_content_length_is_rejected_before_body_read() {
    const CAP: usize = 2 * 1024 * 1024;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address: SocketAddr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nx",
            CAP + 1
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    });
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");

    let provider = ProviderInfo {
        address: ethereum_types::H160::from([0xb1; 20]),
        endpoint: format!("http://{address}/infer"),
        reputation_bps: 9_500,
        current_load: 0,
        max_concurrent: 10,
    };
    let request = ProviderProtocolRequest {
        model: "b008-model".into(),
        prompt: "ping".into(),
        max_tokens: 1,
    };
    let error = dispatch_to_provider(
        &reqwest::Client::new(),
        &provider,
        &request,
        std::time::Duration::from_secs(2),
    )
    .await
    .expect_err("oversized response must fail closed");
    assert!(
        error.to_string().contains("response too large"),
        "must report the bounded-response failure, got: {error}"
    );
}
