//! Chain-interaction trait + default HTTP implementation.
//!
//! `ChainClient` abstracts the four RPC operations the paid path needs:
//!
//! 1. [`ChainClient::verify_offline`] — call precompile `0x0201` via
//!    `eth_call` to verify an EIP-3009 authorization without paying
//!    gas.
//! 2. [`ChainClient::get_nonce`] — fetch the operator wallet's next
//!    transaction nonce.
//! 3. [`ChainClient::send_raw_tx`] — submit a signed settlement tx.
//! 4. [`ChainClient::wait_for_receipt`] — poll `eth_getTransactionReceipt`
//!    until success, revert, or timeout.
//!
//! The default implementation [`HttpChainClient`] is a thin reqwest
//! wrapper. Tests inject a mock by implementing the trait directly.

use std::time::Duration;

use async_trait::async_trait;
use ethereum_types::{H160, H256};
use serde_json::{json, Value};

use crate::error::X402Error;

/// Decoded transaction receipt with the fields x402 layer cares about.
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// `true` if the tx succeeded (status = 0x1), `false` on revert.
    pub status: bool,
    /// Block number the tx landed in. Zero means pending.
    pub block_number: u64,
    /// Event logs emitted by the tx. x402 layer parses these for
    /// `PaymentSettled`.
    pub logs: Vec<RawLog>,
}

/// Minimal event-log representation the receipt parser uses.
#[derive(Debug, Clone)]
pub struct RawLog {
    /// Contract address that emitted the log.
    pub address: H160,
    /// Topics (topic[0] is the event signature hash).
    pub topics: Vec<H256>,
    /// Non-indexed event data (ABI-encoded).
    pub data: Vec<u8>,
}

/// Trait for talking to the chain.
///
/// All methods are `async`; implementations should NOT panic on
/// transient network failures — return an `X402Error::RpcTransport`
/// instead so the layer can map it to a clean 500.
#[async_trait]
pub trait ChainClient: Send + Sync {
    /// Verify an EIP-3009 authorization via precompile `0x0201`.
    /// Input is the 265-byte layout the precompile expects
    /// (32-byte domain separator prepended to the 233-byte payload).
    /// Returns `Some(recovered_signer)` on valid signature, `None`
    /// on invalid.
    async fn verify_offline(
        &self,
        precompile_input: &[u8],
    ) -> Result<Option<H160>, X402Error>;

    /// Get the next tx nonce for an address (pending block tag).
    async fn get_nonce(&self, address: H160) -> Result<u64, X402Error>;

    /// Submit a signed raw tx via `eth_sendRawTransaction`. Returns
    /// the tx hash.
    async fn send_raw_tx(&self, raw_tx: &[u8]) -> Result<H256, X402Error>;

    /// Poll `eth_getTransactionReceipt` every 500 ms until the tx
    /// lands or `timeout` elapses. Returns [`X402Error::SettlePendingTimeout`]
    /// on timeout.
    async fn wait_for_receipt(
        &self,
        tx_hash: H256,
        timeout: Duration,
    ) -> Result<TxReceipt, X402Error>;
}

/// Precompile address `0x0000…0201` — TransferAuthVerify.
pub const TRANSFER_AUTH_VERIFY_PRECOMPILE: H160 = H160(const_addr_0201());

const fn const_addr_0201() -> [u8; 20] {
    let mut a = [0u8; 20];
    a[19] = 0x01;
    a[18] = 0x02;
    a
}

/// Reqwest-backed default [`ChainClient`].
#[derive(Debug, Clone)]
pub struct HttpChainClient {
    rpc_url: String,
    client: reqwest::Client,
}

impl HttpChainClient {
    /// Create a new client targeting `rpc_url` (e.g.
    /// `http://127.0.0.1:18545` or `https://rpc.citrate.ai`).
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            client: reqwest::Client::new(),
        }
    }

    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, X402Error> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| X402Error::RpcTransport(e.to_string()))?;
        let json: Value = resp
            .json()
            .await
            .map_err(|e| X402Error::RpcTransport(format!("decode: {}", e)))?;
        if let Some(err) = json.get("error") {
            return Err(X402Error::RpcError(err.to_string()));
        }
        Ok(json.get("result").cloned().unwrap_or(Value::Null))
    }
}

#[async_trait]
impl ChainClient for HttpChainClient {
    async fn verify_offline(
        &self,
        precompile_input: &[u8],
    ) -> Result<Option<H160>, X402Error> {
        let to_hex = format!("0x{}", hex::encode(TRANSFER_AUTH_VERIFY_PRECOMPILE.as_bytes()));
        let data_hex = format!("0x{}", hex::encode(precompile_input));
        let params = json!([
            { "to": to_hex, "data": data_hex },
            "latest"
        ]);
        let result = self.rpc_call("eth_call", params).await?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| X402Error::RpcError("eth_call returned non-string".into()))?;
        let bytes = hex::decode(hex_str.trim_start_matches("0x"))
            .map_err(|e| X402Error::RpcError(format!("hex decode: {}", e)))?;
        if bytes.len() != 32 {
            return Err(X402Error::RpcError(format!(
                "precompile output should be 32 bytes, got {}",
                bytes.len()
            )));
        }
        // Output layout: bytes[0] = validity flag; bytes[12..32] =
        // recovered signer address. This matches the precompile
        // impl at core/execution/src/precompiles/x402.rs:258-261.
        if bytes[0] != 1 {
            return Ok(None);
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes[12..32]);
        Ok(Some(H160::from(addr)))
    }

    async fn get_nonce(&self, address: H160) -> Result<u64, X402Error> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let params = json!([addr_hex, "pending"]);
        let result = self.rpc_call("eth_getTransactionCount", params).await?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| X402Error::RpcError("non-string nonce".into()))?;
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|e| X402Error::RpcError(format!("bad nonce hex: {}", e)))
    }

    async fn send_raw_tx(&self, raw_tx: &[u8]) -> Result<H256, X402Error> {
        let data_hex = format!("0x{}", hex::encode(raw_tx));
        let result = self.rpc_call("eth_sendRawTransaction", json!([data_hex])).await?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| X402Error::RpcError("non-string tx hash".into()))?;
        let bytes = hex::decode(hex_str.trim_start_matches("0x"))
            .map_err(|e| X402Error::RpcError(format!("hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(X402Error::RpcError(format!(
                "tx hash should be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(H256::from_slice(&bytes))
    }

    async fn wait_for_receipt(
        &self,
        tx_hash: H256,
        timeout: Duration,
    ) -> Result<TxReceipt, X402Error> {
        let tx_hex = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let result = self
                .rpc_call("eth_getTransactionReceipt", json!([tx_hex]))
                .await?;
            if !result.is_null() {
                return parse_receipt(&result);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(X402Error::SettlePendingTimeout);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

fn parse_receipt(v: &Value) -> Result<TxReceipt, X402Error> {
    let status_str = v
        .get("status")
        .and_then(|s| s.as_str())
        .ok_or_else(|| X402Error::RpcError("receipt missing status".into()))?;
    let status = matches!(status_str, "0x1" | "0x01");

    let bn_str = v
        .get("blockNumber")
        .and_then(|s| s.as_str())
        .ok_or_else(|| X402Error::RpcError("receipt missing blockNumber".into()))?;
    let block_number = u64::from_str_radix(bn_str.trim_start_matches("0x"), 16)
        .map_err(|e| X402Error::RpcError(format!("bad blockNumber: {}", e)))?;

    let logs_val = v.get("logs").and_then(|l| l.as_array()).cloned().unwrap_or_default();
    let mut logs = Vec::with_capacity(logs_val.len());
    for log in logs_val {
        let addr_str = log
            .get("address")
            .and_then(|a| a.as_str())
            .ok_or_else(|| X402Error::RpcError("log missing address".into()))?;
        let addr_bytes = hex::decode(addr_str.trim_start_matches("0x"))
            .map_err(|e| X402Error::RpcError(format!("log addr hex: {}", e)))?;
        if addr_bytes.len() != 20 {
            return Err(X402Error::RpcError("log address not 20 bytes".into()));
        }
        let address = H160::from_slice(&addr_bytes);

        let topics_arr = log
            .get("topics")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        let mut topics = Vec::with_capacity(topics_arr.len());
        for t in topics_arr {
            let ts = t
                .as_str()
                .ok_or_else(|| X402Error::RpcError("topic not string".into()))?;
            let tb = hex::decode(ts.trim_start_matches("0x"))
                .map_err(|e| X402Error::RpcError(format!("topic hex: {}", e)))?;
            if tb.len() != 32 {
                return Err(X402Error::RpcError("topic not 32 bytes".into()));
            }
            topics.push(H256::from_slice(&tb));
        }

        let data_str = log.get("data").and_then(|d| d.as_str()).unwrap_or("0x");
        let data = hex::decode(data_str.trim_start_matches("0x"))
            .map_err(|e| X402Error::RpcError(format!("data hex: {}", e)))?;

        logs.push(RawLog { address, topics, data });
    }

    Ok(TxReceipt { status, block_number, logs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precompile_address_is_0x0201() {
        let addr = TRANSFER_AUTH_VERIFY_PRECOMPILE;
        let mut expected = [0u8; 20];
        expected[18] = 0x02;
        expected[19] = 0x01;
        assert_eq!(addr.as_bytes(), &expected);
    }

    #[test]
    fn parse_receipt_success_with_logs() {
        let v = json!({
            "status": "0x1",
            "blockNumber": "0xa",
            "logs": [{
                "address": "0x1111111111111111111111111111111111111111",
                "topics": [
                    "0x2222222222222222222222222222222222222222222222222222222222222222",
                ],
                "data": "0x1234",
            }]
        });
        let r = parse_receipt(&v).expect("parse");
        assert!(r.status);
        assert_eq!(r.block_number, 10);
        assert_eq!(r.logs.len(), 1);
        assert_eq!(r.logs[0].topics.len(), 1);
        assert_eq!(r.logs[0].data, vec![0x12, 0x34]);
    }

    #[test]
    fn parse_receipt_revert() {
        let v = json!({
            "status": "0x0",
            "blockNumber": "0x7",
            "logs": []
        });
        let r = parse_receipt(&v).expect("parse");
        assert!(!r.status);
        assert_eq!(r.block_number, 7);
        assert!(r.logs.is_empty());
    }

    #[test]
    fn parse_receipt_rejects_missing_status() {
        let v = json!({"blockNumber": "0x1", "logs": []});
        let err = parse_receipt(&v).expect_err("should fail");
        assert!(matches!(err, X402Error::RpcError(_)));
    }

    #[test]
    fn parse_receipt_rejects_bad_address_length() {
        let v = json!({
            "status": "0x1",
            "blockNumber": "0x1",
            "logs": [{
                "address": "0x1234",  // too short
                "topics": [],
                "data": "0x"
            }]
        });
        let err = parse_receipt(&v).expect_err("should fail");
        assert!(matches!(err, X402Error::RpcError(m) if m.contains("20 bytes")));
    }
}
