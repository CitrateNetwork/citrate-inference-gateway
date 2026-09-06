//! IGW-B-011 tripwire: provider-controlled token counts must not overflow the
//! client-visible usage total.

use citrate_gateway::openai::Usage;

#[test]
fn provider_token_counts_cannot_overflow_usage_total() {
    for (prompt, completion) in [
        (0, 0),
        (u32::MAX, 0),
        (0, u32::MAX),
        (u32::MAX, 1),
        (u32::MAX, u32::MAX),
    ] {
        let usage = Usage::new(prompt, completion);
        assert_eq!(usage.total_tokens, prompt.saturating_add(completion));
        assert!(usage.total_tokens >= prompt.max(completion));
    }
}
