# Patent Rights — Citrate Network

**Status:** active · **Owner:** Citrate Inc. · **Effective:** 2026

This document describes Citrate Inc. patent posture for the Citrate Network and
its federated repositories. It supplements, and is incorporated by reference into, the
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) files at the root of this federation.

## Reservation of patent rights

Citrate Inc. reserves all patent rights in the Licensed Work. No express or implied
patent license is granted to any party except:

1. as expressly required by applicable law;
2. as explicitly granted in writing by Citrate Inc. under a separate executed
   patent license agreement; or
3. to the limited extent necessary for Permitted Community Use under the Additional
   Use Grant in the [`LICENSE`](LICENSE) — which is non-commercial, capped, and
   non-public.

For the avoidance of doubt: the BUSL-1.1 license **does not** grant a patent license
for production, commercial, hosted, managed, white-labeled, or revenue-generating
use of any technology covered by Citrate Inc. patent claims.

## Subject matter

The following classes of mechanism, design, protocol, architecture, and interface are
embodied in the Licensed Work and are the subject of filed, pending, or contemplated
patent applications by Citrate Inc. or its affiliates. The list is illustrative,
not exhaustive:

1. **Consensus mechanisms.** GhostDAG-based BlockDAG ordering variants, including
   tie-breaking, finality acceleration, and finality-with-bridging procedures used in
   `citrate-chain`.

2. **AI-native precompile interfaces.** EVM precompiles that expose model-inference,
   embedding, and vector-search primitives to on-chain contracts, including the
   gas-metering, sandboxing, and result-attestation flows that bridge between the
   execution layer and `citrate-inference-gateway` / `citrate-compute-pool`.

3. **Zero-knowledge verifiable compute.** Proof systems, circuit templates, and
   commitment schemes used to attest inference and training results on-chain,
   together with the verifier-precompile interfaces.

4. **Embedded-node application architecture.** Designs for embedding a full node
   inside end-user GUI applications (e.g., `citrate-native`,
   `citrate-learning-center`), including lifecycle management, sandboxing, key
   isolation, and the IPC bridge between GUI and node.

5. **Agent harness architecture.** Capsule-based execution, capability scoping,
   memory model, and the wire protocols used in `citrate-agent-runtime` and the
   x402-compatible payment flows in `citrate-inference-gateway`.

6. **Federation-wide drift control.** Manifest-driven cross-repository dependency
   pinning, automated drift detection, and the federated-commit fan-out mechanism
   described in [`docs/SYNC.md`](docs/SYNC.md).

7. **Marketplace SDK and x402-paid inference flows.** End-to-end protocols for
   metered, pay-per-call AI inference where settlement occurs on the Citrate chain.

## Defensive posture

Citrate Inc. will pursue patent claims defensively to protect the integrity of
the Citrate Network, its contributors, and its licensed deployers. Defensive use
includes — but is not limited to — counter-asserting patents against parties who
initiate patent litigation, trademark infringement, or unauthorized commercial use
against the Licensed Work, against Citrate Inc., or against a downstream
licensee in good standing.

## Anti-patent-litigation termination

A patent infringement claim asserted by any party against the Licensed Work, against
Citrate Inc., or against any contributor to the Licensed Work (in their capacity
as a contributor) **automatically terminates all rights** of the asserting party
under the [`LICENSE`](LICENSE) — including the Additional Use Grant and any
sublicenses — as of the date the claim is filed.

This termination applies to the asserter and to any entity that controls, is
controlled by, or is under common control with the asserter.

## Commercial patent licensing

Production, commercial, institutional, hosted, managed, and white-labeled use of the
Licensed Work — and any technology covered by the patent claims described above —
requires a separate written agreement.

**Contact:** Partnerships@Citrate.ai

Include in your inquiry: the entity name, intended deployment scale, jurisdictions,
expected revenue model, and the specific Citrate components involved.

## Notice of changes

This document may be updated as additional applications are filed. The most recent
version published in this repository is authoritative.

---

© 2026 Citrate Inc. All rights reserved.
