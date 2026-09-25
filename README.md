# citrate-inference-gateway

*Part of the **[Citrate Network](https://citrate.ai)** — own the means of computation. · [Docs](https://docs.citrate.ai) · [Run a node](https://citrate.ai/download) · [Contribute → free membership](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)*

> An OpenAI-compatible HTTP gateway for the Citrate Network — serve
> `/v1/chat/completions`, `/v1/embeddings`, and `/v1/batch` either by proxying a
> local model server or by dispatching x402-gated jobs onto the on-chain compute
> marketplace (chain 40204).

## What it is

`citrate-inference-gateway` is an axum server that speaks the OpenAI HTTP API and
runs in one of two modes, selected by `CITRATE_GATEWAY_MODE`:

- **`local-proxy`** — proxies `/v1/*` to one or more local model backends
  (llama-server / any OpenAI-compatible endpoint), with `cgk_` bearer auth and an
  encrypted money-store. This is the mode most local setups want.
- **`marketplace`** (default) — translates requests into x402 (HTTP 402) payment-
  gated `InferenceRouter` / `ComputeMarketplace` dispatches against the chain.

It also ships `x402-axum`, the reusable HTTP-402 payment middleware crate.

- Concept docs: https://docs.citrate.ai/gateway · x402: https://docs.citrate.ai/x402
- Depends (marketplace mode) on a [citrate-chain](https://github.com/CitrateNetwork/citrate-chain)
  RPC + the deployed ModelRegistry / InferenceRouter contracts.

## Prerequisites

```bash
# Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# System packages (Debian/Ubuntu) — RocksDB (money store) needs a C toolchain
sudo apt-get update && sudo apt-get install -y build-essential clang cmake pkg-config git curl

# For local-proxy mode: a local model server, e.g. llama-server on 127.0.0.1:8181
```

**Chain dependency (interim):** this repo consumes `citrate-wallet-core` from
`CitrateNetwork/citrate-chain` as a git dependency. During the federation
transition it is pinned via SSH; Cargo uses your SSH agent, so you need a GitHub
SSH key with read access to `citrate-chain`. (When the chain publishes to
crates.io this becomes a normal semver dep.)

## Build from source

```bash
git clone https://github.com/CitrateNetwork/citrate-inference-gateway
cd citrate-inference-gateway

cargo build --release            # produces target/release/citrate-inference-gateway
cargo test --workspace --locked
```

## Run locally

Both modes default their listen address to `127.0.0.1:9800`.

**local-proxy mode** — front a local llama-server:

```bash
CITRATE_GATEWAY_MODE=local-proxy \
CITRATE_GATEWAY_UPSTREAM_URL=http://127.0.0.1:8181 \
CITRATE_GATEWAY_KEYSTORE_PATH=./gateway-keystore \
CITRATE_GATEWAY_LISTEN_ADDR=127.0.0.1:9800 \
./target/release/citrate-inference-gateway
```

**marketplace mode** — dispatch on a local chain:

```bash
CITRATE_GATEWAY_MODE=marketplace \
CITRATE_GATEWAY_RPC_URL=http://localhost:8545 \
CITRATE_GATEWAY_CHAIN_ID=40204 \
CITRATE_GATEWAY_MODEL_REGISTRY=0x<ModelRegistry> \
CITRATE_GATEWAY_INFERENCE_ROUTER=0x<InferenceRouter> \
CITRATE_GATEWAY_PRICING_ORACLE=0x<PricingOracle> \
./target/release/citrate-inference-gateway
```

Verify it's up:

```bash
curl -s http://127.0.0.1:9800/health              # liveness
curl -s http://127.0.0.1:9800/v1/models           # advertised models (marketplace mode)
```

Marketplace routes served by this binary: `/health`, `/v1/models`, `/metrics`
(plus the unpaid open-chat pilot routes, only under the dev profile on a loopback
bind). local-proxy routes: `/health`, and the allowlisted `/v1/chat/completions`,
`/v1/completions`, `/v1/embeddings`, `/v1/models`, `/v1/audio/transcriptions`
forwarded to the upstream (any other path is 404; a path with `\`, an encoded
`.`/`/`/`\` or a dot segment is 400). Both bind loopback by default — a
non-loopback bind logs a warning; front it with a TLS reverse proxy.

> **Paid routes are not served (PBA-L3b-I03).** The x402 payment router
> (`build_router_with`, `x402-axum`) and the API-key debit/refund router
> (`build_router_with_auth`) are library code exercised by tests; the shipped
> binary mounts neither. Issues in that code are latent until a release wires
> them into `main.rs`, and bounty scope should treat them that way.

## Connect it locally  ← the differentiator

- **local-proxy mode** needs a **local model server** upstream. Start a
  llama-server (or any OpenAI-compatible endpoint) on `127.0.0.1:8181`, then point
  `CITRATE_GATEWAY_UPSTREAM_URL` at it (comma-separate several for failover).
  Optionally set `CITRATE_GATEWAY_EMBED_UPSTREAM_URL` to a dedicated embeddings
  model (e.g. bge-m3) — the chat model does not answer `/v1/embeddings`.
- **marketplace mode** needs a **local chain RPC + deployed contracts**:
  1. Start a devnet node from
     [citrate-chain](https://github.com/CitrateNetwork/citrate-chain):
     `./target/release/citrate devnet` → `http://localhost:8545`.
  2. Deploy the book (`forge script script/Deploy.s.sol …`) and record the
     `ModelRegistry` / `InferenceRouter` / `PricingOracle` addresses.
  3. Set `CITRATE_GATEWAY_RPC_URL=http://localhost:8545` and the contract env
     vars, then start the gateway and confirm it logs `chain_id=40204`.

Minimal end-to-end check (local-proxy): with a model server up and the gateway
running, `curl http://127.0.0.1:9800/v1/chat/completions` with an OpenAI-shaped
body returns a completion.

See the full multi-repo bring-up: https://docs.citrate.ai/local-stack

## Configuration

- `CITRATE_GATEWAY_MODE` — `local-proxy` | `marketplace` (default `marketplace`).
- `CITRATE_GATEWAY_LISTEN_ADDR` — bind (default `127.0.0.1:9800`).
- local-proxy: `CITRATE_GATEWAY_UPSTREAM_URL` (default `http://127.0.0.1:8181`, comma-list),
  `CITRATE_GATEWAY_EMBED_UPSTREAM_URL`, `CITRATE_GATEWAY_KEYSTORE_PATH`
  (default `/var/lib/citrate-gateway/keystore`), `GATEWAY_STORE_KEY` /
  `GATEWAY_STORE_KEY_FILE` (money-store master key; encrypted at rest, ENCRYPT-S1),
  `CITRATE_GATEWAY_MAX_TOKENS` (generation ceiling, default 2048),
  `CITRATE_GATEWAY_MAX_CONCURRENT_PER_KEY` (default 4; the next request is 429),
  `CITRATE_GATEWAY_MAX_CONCURRENT_UPSTREAM` (fair shared queue, default 32).
- marketplace: `CITRATE_GATEWAY_RPC_URL` (default `http://127.0.0.1:8545`),
  `CITRATE_GATEWAY_CHAIN_ID` (default 40204), `CITRATE_GATEWAY_MODEL_REGISTRY`,
  `CITRATE_GATEWAY_INFERENCE_ROUTER`, `CITRATE_GATEWAY_PRICING_ORACLE`.
- `RUST_LOG`, `LOG_FORMAT` (`json|pretty|compact`).
- Systemd example: `packaging/citrate-inference-gateway-local-proxy.service`.

## Links

- Docs: https://docs.citrate.ai/gateway
- Depends on: [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) ·
  Consumed by: SDKs, comms-web, buyer apps (any OpenAI-compatible client)
- Contributing (DCO): CONTRIBUTING.md · Security: SECURITY.md · License: LICENSE

## License

Source-available under the Business Source License 1.1 (see [`LICENSE`](LICENSE)); converts to Apache-2.0 on the Change Date stated in the license. This is the commercial application-layer / core tier of Citrate's open-core model; the infrastructure tier is Apache-2.0. Licensor: Citrate Inc.
