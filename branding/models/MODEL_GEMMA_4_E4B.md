---
created: 2026-05-28T21:30:00Z
branch: main
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.7 (1M context)
status: active
purpose: provenance + redistribution + bundling notes for the wallet's default AI model
canonical_docs:
  - https://ai.google.dev/gemma/docs/core
  - https://huggingface.co/ggml-org/gemma-4-E4B-it-GGUF
---

# Gemma 4 E4B-it — bundled default AI model

The Citrate Wallet ships this model inside the installer so the AI chat works
**out of the box** — no manual download, no Ollama, no registry lookup. Every
fresh wallet copy has a working assistant the moment it launches.

This file documents what the model is, why it was chosen, what license terms
ride along, where the file came from, and how it's wired into the build.

## At a glance

| Field | Value |
|---|---|
| Family | Gemma 4 (Google, released 2025-Q3) |
| Variant | **E4B-it** — *Effective 4B parameters, Instruction-Tuned, edge/mobile profile* |
| Quantisation | **Q4_K_M** GGUF (4-bit, K-quant medium) |
| File | `gemma-4-E4B-it-Q4_K_M.gguf` |
| File size | **4.96 GB** (5,335,289,824 bytes) |
| Context window | **128K tokens** (small-model tier; the 31B and 26B-A4B tiers go to 256K) |
| Modalities | Text + images + **native audio** + video understanding |
| Tool use | Native function-calling support |
| Reasoning | Configurable "thinking modes" (per Google's Gemma 4 doc) |
| Decoding | Multi-Token Prediction (speculative decoding) supported |
| Engine compatibility | llama.cpp ≥ ggml-org's gemma4 architecture support (the wallet ships llama.cpp) |
| RAM at runtime | ~5 GB (4-bit). 8-bit is ~7.5 GB; bf16 is ~15 GB. We ship 4-bit only. |

## Why this model

Selection criteria, in priority order:

1. **Works on the user's CPU/GPU without a server.** E4B is Google's
   explicitly-edge-tier variant — designed to run on phones and laptops.
   Apple Silicon with Metal backend hits real-time-ish token rates.
2. **Open weights, commercial-use OK.** Gemma's terms permit responsible
   commercial redistribution and tuning. We legally ship the weights inside a
   commercial wallet installer.
3. **US origin, large-vendor trust.** Google Research; well-established
   provenance, regular safety reviews, broad community vetting.
4. **Multimodal upside.** Even though the wallet's chat UI is text-only
   today, the model supports images and audio natively — once the UI exposes
   image upload, no model swap needed.
5. **Native function-calling.** The wallet's chat already uses
   `send_message_with_tools_streaming` (see
   `citrate-gui-native/gui/citrate_desktop_app/src/services/chat_service.rs`).
   E4B's native function-calling slots directly into that path.
6. **128K context.** Enough to feed a long blockchain transcript, a code file,
   or a multi-block ledger window without truncation.

## Why specifically the ggml-org GGUF (vs bartowski / unsloth / lmstudio)

GGUF source: **[`ggml-org/gemma-4-E4B-it-GGUF`](https://huggingface.co/ggml-org/gemma-4-E4B-it-GGUF)**.

- `ggml-org` is the llama.cpp project's own organization. The GGUF emitted by
  ggml-org tracks the llama.cpp `master` tokenizer/architecture
  implementation **exactly**, with the lowest chance of a runtime mismatch
  inside the bundled inference engine.
- bartowski's GGUF is also high-quality and offers more Q4 variants
  (Q4_0, Q4_K_S, Q4_K_M, Q4_K_L), but we pin to the canonical-team build.
- unsloth's is ~4.98 GB (slightly smaller) but their quantisation pipeline
  is independent from llama.cpp upstream; using ggml-org avoids the rare
  "quant block ordering changed under us" footgun.
- lmstudio-community's is the LM Studio team's repackage. Fine, but adds an
  unnecessary intermediary.

Backup mirror, if `ggml-org` ever delists or rate-limits during a CI build:
`bartowski/google_gemma-4-E4B-it-GGUF`.

## License

Gemma weights are released under the **Gemma Terms of Use**
(<https://ai.google.dev/gemma/terms>). Key points relevant to bundling in
Citrate Wallet:

| Term | Our status |
|---|---|
| Responsible commercial use permitted | ✅ — the wallet is a commercial product; permitted. |
| Redistribution of the weights | ✅ — including bundling inside our installer. |
| Prohibited uses (deceptive content at scale, illegal activity, …) | We disclose the prohibited-uses policy to end users in Settings → AI → "About this model" (TODO when the Settings audit lands). |
| Attribution requirement | ✅ — this file + the wallet's About panel both name Gemma 4 + Google. |
| Modification + tuning | ✅ permitted — we may distribute LoRAs and finetunes registered through `ModelRegistry`. |

We are not a derivative-of-a-derivative. The bundled file is the verbatim
ggml-org GGUF as fetched, unmodified, byte-equal to upstream.

## Provenance / integrity

The downloaded file is fixed at:
```
branding/models/gemma-4-E4B-it-Q4_K_M.gguf
branding/models/gemma-4-E4B-it-Q4_K_M.gguf.sha256
```

Verify upstream-equality with:
```bash
shasum -a 256 -c branding/models/gemma-4-E4B-it-Q4_K_M.gguf.sha256
```

The `.gguf` header magic is `0x47475546` ("GGUF"), version 3, confirmed at
download time. The header inventory + tensor layout match
`unsloth/gemma-4-E4B-it-GGUF/blob/main/gemma-4-E4B-it-Q4_K_M.gguf` to within
quantization granularity.

## How it ends up in the installer

Build path:

1. `branding/models/gemma-4-E4B-it-Q4_K_M.gguf` is a tracked file at the
   citrate-labs root.
2. `branding/templates/apply-tier2.sh` copies it into each repo's
   `<repo>/branding/models/` on every render, alongside `branding/icons/`
   and `branding/templates/entitlements.plist`.
3. `branding/templates/packager.toml.template` lists the model in
   `resources = [ "${REPO_PREFIX}branding/models/*.gguf" ]`, so cargo-packager
   embeds it in `<app>/Contents/Resources/branding/models/` (macOS) / the
   `.deb` data tree (Linux) / the WiX MSI cab (Windows).
4. On first run the wallet copies the bundled GGUF to
   `~/.citrate/models/gemma-4-E4B-it-Q4_K_M.gguf` (or the OS equivalent) and
   marks it as the default chat model. Subsequent launches read from the
   user's dir, leaving the bundled copy as a recovery seed.

## Replacement / upgrade policy

This file documents the **current pin**. When a better
American-origin commercial-OK open-weights model appears — or when Gemma
itself ships a successor — bump the file by:

1. Downloading the new GGUF into `branding/models/`.
2. Updating this doc's "At a glance" table + the Why section.
3. Removing the old GGUF so installer size doesn't double.
4. Re-rendering all 4 binary repos via `apply-tier2.sh`.
5. Re-tagging `v*-tier2` to ship the new model.

The wallet's first-run code keys off the *filename*, not a hard-coded
checksum, so the bump is one config edit + one CI fire.

## Why we don't ship the larger Gemma 4 variants

| Variant | Memory @ 4-bit | Why not (yet) |
|---|---|---|
| E2B (2B effective) | ~3 GB | Smaller installer (~2.5 GB GGUF) but materially less capable on tool use + reasoning. Reasonable fallback to add later as "fast mode". |
| 31B dense | ~17.4 GB | Won't fit in unified memory on most user machines; needs server-class GPU. |
| 26B A4B (MoE) | ~15.6 GB | Same memory issue, plus MoE adds activation-routing overhead llama.cpp's gemma4 backend handles inconsistently as of writing. |

E4B is the only Gemma 4 variant that ships as the default-bundled model. The
larger tiers can be served via the `InferenceRouter` contract (off-wallet,
on-network), pinned by operators with the GPU budget.
