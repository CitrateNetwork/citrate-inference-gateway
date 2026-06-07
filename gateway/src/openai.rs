//! OpenAI-compatible request/response types.
//!
//! These match the on-the-wire shape OpenAI's API uses so that
//! drop-in SDK callers (the official `openai` Python lib, the
//! `openai` Node lib, etc.) work without modification.
//!
//! We use `serde(deny_unknown_fields = false)` (the default) on
//! requests to be permissive about new fields the SDK may send;
//! responses use the exact shape SDKs expect.

use serde::{Deserialize, Serialize};

/// Incoming `/v1/chat/completions` request body. Matches a useful
/// subset of OpenAI's shape — extra fields the SDK sends (top_p,
/// presence_penalty, etc.) are tolerated by serde's default.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatCompletionRequest {
    /// Model name (e.g. "llama-3.1-8b") or pinned hash
    /// ("llama-3.1-8b@0xabcd..."). Resolved via ModelRegistry.
    pub model: String,
    /// Conversation messages.
    pub messages: Vec<ChatMessage>,
    /// Hard cap on output tokens. Defaults handled by gateway if unset.
    #[serde(default)]
    pub max_tokens: Option<u32>,
    /// `true` enables SSE streaming (planned WP-03.2 follow-up).
    #[serde(default)]
    pub stream: bool,
}

/// One message in a chat conversation. `role` is "system", "user",
/// or "assistant" per OpenAI convention.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    /// Sender role — "user", "system", "assistant".
    pub role: String,
    /// Message text.
    pub content: String,
}

/// `/v1/chat/completions` response body. OpenAI shape:
/// `{ id, object: "chat.completion", created, model, choices, usage }`.
#[derive(Debug, Clone, Serialize)]
pub struct ChatCompletionResponse {
    /// Server-generated unique ID for this completion.
    pub id: String,
    /// OpenAI shape constant — always `"chat.completion"`.
    pub object: &'static str,
    /// Unix seconds when the completion was generated.
    pub created: u64,
    /// Model name (echoed from request).
    pub model: String,
    /// Returned choices. We always return exactly one (n=1) in v1.
    pub choices: Vec<Choice>,
    /// Token accounting — visible to clients for billing.
    pub usage: Usage,
}

/// One choice in a chat completion response.
#[derive(Debug, Clone, Serialize)]
pub struct Choice {
    /// Position in the choices list (always 0 for n=1).
    pub index: u32,
    /// The completion message.
    pub message: ChatMessage,
    /// Why generation stopped — "stop", "length", etc.
    pub finish_reason: &'static str,
}

/// Token-count breakdown.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Usage {
    /// Input tokens consumed.
    pub prompt_tokens: u32,
    /// Output tokens produced.
    pub completion_tokens: u32,
    /// Sum of the two — convenience for clients.
    pub total_tokens: u32,
}

impl Usage {
    /// Construct with auto-computed total.
    pub fn new(prompt: u32, completion: u32) -> Self {
        Self {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parses_minimal_openai_shape() {
        let body = r#"{
            "model": "llama-3.1-8b",
            "messages": [{"role": "user", "content": "hi"}]
        }"#;
        let req: ChatCompletionRequest = serde_json::from_str(body).expect("parse");
        assert_eq!(req.model, "llama-3.1-8b");
        assert_eq!(req.messages.len(), 1);
        assert!(!req.stream);
        assert!(req.max_tokens.is_none());
    }

    #[test]
    fn request_tolerates_extra_fields() {
        // OpenAI SDK sends top_p, presence_penalty, etc. — we accept.
        let body = r#"{
            "model": "x",
            "messages": [],
            "top_p": 0.9,
            "presence_penalty": 0.1,
            "stream": true
        }"#;
        let req: ChatCompletionRequest = serde_json::from_str(body).expect("parse");
        assert!(req.stream);
    }

    #[test]
    fn response_serializes_with_required_fields() {
        let r = ChatCompletionResponse {
            id: "chatcmpl-abc".into(),
            object: "chat.completion",
            created: 1_714_000_000,
            model: "llama-3.1-8b".into(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".into(),
                    content: "hello".into(),
                },
                finish_reason: "stop",
            }],
            usage: Usage::new(2, 1),
        };
        let s = serde_json::to_string(&r).expect("ser");
        assert!(s.contains(r#""object":"chat.completion""#));
        assert!(s.contains(r#""finish_reason":"stop""#));
        assert!(s.contains(r#""total_tokens":3"#));
    }

    #[test]
    fn usage_total_is_sum() {
        let u = Usage::new(7, 13);
        assert_eq!(u.total_tokens, 20);
    }
}
