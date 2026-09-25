//! INFER-S1 / WP-C — LIVE AWS KMS round-trip check (feature `aws-kms`).
//!
//! This is the operator's validation tool: with real AWS credentials + a KMS
//! secp256k1 key configured, it loads the signer, signs a digest via KMS, and
//! asserts the signature recovers the operator address — proving the whole
//! SigV4 → KMS Sign → DER → recover-id assembly works end to end against AWS.
//! It SKIPS (passes) when the env isn't set, so default CI is unaffected.
//!
//! Run it (with your AWS creds + key):
//!
//! ```text
//! AWS_REGION=us-east-1 \
//! AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
//! CITRATE_GATEWAY_KMS_KEY_ID=arn:aws:kms:...:key/... \
//! cargo test -p citrate-inference-gateway --features aws-kms \
//!   --test infer_wpc_kms_live -- --nocapture
//! ```
#![cfg(feature = "aws-kms")]

use citrate_gateway::signer::AwsKmsSigner;
use x402_axum::sign_tx::{ecrecover, Signer};

#[tokio::test]
async fn kms_live_sign_recovers_operator_address() {
    let key_id = match std::env::var("CITRATE_GATEWAY_KMS_KEY_ID") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!(
                "SKIP: set AWS_REGION + AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + \
                 CITRATE_GATEWAY_KMS_KEY_ID to run the live KMS check"
            );
            return;
        }
    };

    let signer = AwsKmsSigner::from_env(key_id)
        .await
        .expect("load AWS KMS signer (check creds + kms:GetPublicKey on the key)");
    let address = signer.address();
    eprintln!(
        "KMS operator address: 0x{}",
        hex::encode(address.as_bytes())
    );

    let hash = [0x11u8; 32];
    let sig = signer
        .sign_hash(&hash)
        .await
        .expect("KMS sign (check kms:Sign on the key + ECC_SECG_P256K1 SIGN_VERIFY)");

    // The full round-trip works iff the KMS signature recovers the operator.
    assert_eq!(
        ecrecover(&hash, &sig.r, &sig.s, sig.recovery_id),
        Some(address),
        "KMS signature must recover the operator address"
    );
    eprintln!("✓ live KMS round-trip OK (signature recovers the operator)");
}
