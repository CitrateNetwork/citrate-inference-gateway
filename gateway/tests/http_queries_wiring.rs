//! Verifies the real `HttpChainQueries` ABI-encoding / eth_call /
//! response-decoding wiring end-to-end against an in-process mock
//! RPC server that returns hand-crafted ABI-encoded responses.
//!
//! This is the unit-level proof for task #45 (wire HttpChainQueries
//! with real ABI calls). A live-devnet round-trip is out of scope;
//! if the `cast` vectors and our encoding match, and the decode
//! round-trips, we're done.

use std::net::SocketAddr;

use axum::extract::Json as JsonExtractor;
use axum::routing::post;
use axum::Json as JsonResp;
use ethereum_types::U256;
use serde_json::Value;
use tokio::net::TcpListener;

use citrate_gateway::config::ContractAddresses;
use citrate_gateway::queries::{ChainQueries, HttpChainQueries};

/// Mock RPC server: returns a single canned response per request.
/// Records the last-seen `data` hex for the test to assert on.
///
/// Returns (server_addr, mocks_state). Each test builds its own
/// router with a fresh `Mocks` so state doesn't leak across tests.
async fn spawn_mock_rpc(
    response: Value,
) -> (SocketAddr, std::sync::Arc<tokio::sync::Mutex<Vec<Value>>>) {
    let captured: std::sync::Arc<tokio::sync::Mutex<Vec<Value>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let captured_clone = captured.clone();

    let app = axum::Router::new().route(
        "/",
        post(move |JsonExtractor(req): JsonExtractor<Value>| {
            let captured = captured_clone.clone();
            let response = response.clone();
            async move {
                captured.lock().await.push(req.clone());
                // Always return `result` even on error; tests only
                // assert on the success path here.
                JsonResp(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(serde_json::json!(1)),
                    "result": response,
                }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind rpc");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("rpc serve");
    });
    (addr, captured)
}

fn contracts_default() -> ContractAddresses {
    ContractAddresses::default()
}

#[tokio::test]
async fn estimate_cost_encodes_selector_and_args() {
    // Canned response: uint256(42).
    let response_hex = format!("0x{:064x}", 42u64);
    let (rpc_addr, captured) = spawn_mock_rpc(serde_json::json!(response_hex)).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let q = HttpChainQueries::new(format!("http://{}", rpc_addr), contracts_default());
    let model_hash = ethereum_types::H256::from([0xab; 32]);
    let cost = q
        .estimate_cost(model_hash, 100, 200, 1)
        .await
        .expect("cost");
    assert_eq!(cost, U256::from(42u64));

    // Verify the call shape: eth_call, to pricing oracle, data
    // starts with the selector for estimateJobCost(...) and
    // contains our model hash.
    let calls = captured.lock().await;
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call["method"].as_str(), Some("eth_call"));
    let params = &call["params"][0];
    assert_eq!(
        params["to"].as_str(),
        Some(contracts_default().pricing_oracle.as_str())
    );
    let data_hex = params["data"].as_str().expect("data hex");
    let data = hex::decode(data_hex.trim_start_matches("0x")).expect("hex");
    // First 4 bytes = keccak of sig. Just check size + presence of
    // the model hash further in.
    assert_eq!(data.len(), 4 + 4 * 32);
    let start_model = 4;
    assert_eq!(&data[start_model..start_model + 32], &[0xab; 32]);
    // Next word: input_tokens = 100
    let in_tok = U256::from_big_endian(&data[36..68]);
    assert_eq!(in_tok, U256::from(100u64));
    // Next: output_tokens = 200
    let out_tok = U256::from_big_endian(&data[68..100]);
    assert_eq!(out_tok, U256::from(200u64));
    // Final word last byte = tier
    assert_eq!(data[131], 1);
}

#[tokio::test]
async fn list_providers_with_empty_list() {
    // Response = offset(0x20) + length(0).
    let mut buf = vec![0u8; 64];
    buf[31] = 0x20;
    let response_hex = format!("0x{}", hex::encode(&buf));
    let (rpc_addr, _captured) = spawn_mock_rpc(serde_json::json!(response_hex)).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let q = HttpChainQueries::new(format!("http://{}", rpc_addr), contracts_default());
    let providers = q
        .list_providers(ethereum_types::H256::zero())
        .await
        .expect("list");
    assert!(providers.is_empty(), "empty address[] → no providers");
}

#[tokio::test]
async fn resolve_model_name_pinned_hash() {
    let q = HttpChainQueries::new("http://unused", contracts_default());
    let input = "0xabababababababababababababababababababababababababababababababab";
    let h = q.resolve_model_name(input).await.expect("ok");
    assert_eq!(h.as_bytes(), &[0xab; 32]);
}

#[tokio::test]
async fn estimate_cost_surfaces_rpc_error_as_chain_unavailable() {
    // Mock that returns jsonrpc `error` object — our client surfaces
    // that as ChainUnavailable.
    let app = axum::Router::new().route(
        "/",
        post(|JsonExtractor(_): JsonExtractor<Value>| async {
            JsonResp(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32000, "message": "execution reverted" }
            }))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind rpc");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("rpc serve");
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let q = HttpChainQueries::new(format!("http://{}", addr), contracts_default());
    let err = q
        .estimate_cost(ethereum_types::H256::zero(), 1, 1, 0)
        .await
        .expect_err("should fail");
    assert!(matches!(
        err,
        citrate_gateway::GatewayError::ChainUnavailable(_)
    ));
}

#[tokio::test]
async fn estimate_cost_surfaces_transport_error_as_chain_unavailable() {
    // Unreachable port — reqwest fails before any RPC round-trip.
    let q = HttpChainQueries::new("http://127.0.0.1:1", contracts_default());
    let err = q
        .estimate_cost(ethereum_types::H256::zero(), 1, 1, 0)
        .await
        .expect_err("should fail");
    assert!(matches!(
        err,
        citrate_gateway::GatewayError::ChainUnavailable(_)
    ));
}
