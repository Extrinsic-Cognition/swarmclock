# conformance-v1.md

Status: Canonical v1
Version: 2026-03-29

## Scope

Defines mandatory security conformance gates for envelope, membrane, and sync behavior.

## Suite A: Schema and Signature Invariants

Required checks:

1. schema validation for `agent.mail.v1` and `mesh.heartbeat.v1`
2. canonical hash recomputation matches transmitted hash
3. Ed25519 signature verifies over canonical preimage
4. label fields are present and signed (`integrity_label`, `confidentiality_label`)

## Suite B: Replay and Causality

Required checks:

1. nonce replay rejection
2. seq monotonicity enforcement
3. lamport monotonicity enforcement
4. idempotent delta apply by `op_id` and `text_hash+bank_id`

## Suite C: Directional Membrane Enforcement

Each gate must be tested independently:

1. IngressInspector
2. EgressSanitizer
3. LateralProjector
4. DownwardProjector
5. UpwardPromoter

For each gate: allow/transform/block decisions must emit signed receipts with reason codes.

## Suite D: Explicit-Flow Enforcement

Tests must demonstrate that low-integrity inputs cannot directly trigger high-integrity actions without authorized declassification.

## Suite E: Implicit-Flow Residual Controls

This suite does not claim full mechanical prevention.

Required checks:

1. selective hiding policy applied in sensitive paths
2. summarize transforms are policy-gated and integrity-downgraded
3. governance/approval gates required for high-impact promotions

## Suite F: Injection Short-Circuit

Required tests:

1. prompt-injection payload in tool return is blocked or transformed before privileged action
2. tool-output poisoning payload cannot cross upward promotion gate unsanitized
3. blocked payloads are quarantined with receipts

## Suite G: Non-Interference Test Cases

Target property: explicit low-integrity perturbations must not change protected high-integrity sinks when policies forbid that flow.

Minimum tests:

1. vary tainted inbound payloads under same policy
2. verify canonical protected sink state remains unchanged
3. verify receipt reasons and decision hashes remain deterministic

## Suite H: Classify-Step Quality (Trace Privacy Recognition)

The classify step is tracked as a first-class risk metric.

Required metrics:

1. privacy element recall
2. false negative rate on sensitive elements
3. risk/category/necessity classification accuracy
4. leakage rate after transform

Pass criteria MUST define maximum tolerated false negatives before release.

Recommended benchmark style:

- GUIGuard-like evaluation dimensions: detection, localization, risk/category classification, and task necessity
- report both binary detection performance and full-chain classification performance

## Suite I: Partition and Heal

Required checks:

1. partitioned nodes buffer and replay in causal order
2. dedupe on replay preserves idempotency
3. convergence window meets declared SLO after heal

## Suite J: Control-Tower Policy Enforcement

Required checks:

1. extension-origin policy toggles are accepted only when signed and epoch-valid
2. stale `policy_epoch` deltas are rejected
3. program/context/outbound toggle changes alter gate outcomes deterministically
4. unsigned UI-only state cannot alter runtime enforcement
5. emergency `deny_all_egress` blocks external sinks and emits receipts

## Suite K: Seat Trust and Revocation

Required checks:

1. valid majority assignment grants seat trust to new occupant key
2. revoked assignment is blocked immediately at privileged intents
3. replaced occupant key cannot regain authority without new assignment mandate
4. revocation and reassignment increment assignment epoch monotonically
5. runtime denies privileged actions from orphaned/unknown wallets with no active seat assignment

## Suite L: Module Ecosystem and Widget Runtime

Required checks:

1. module manifest validates against strict schema with unknown-field rejection
2. unsigned or signature-mismatched module bundles are rejected
3. frontend bundle installs require sanitization receipt with source/sanitized hash linkage
4. iframe direct daemon API access attempts are blocked
5. extension bridge enforces manifest permission contract on widget-originated intents
6. revoked module versions are disabled at runtime until re-authorized

## Release Gate

A build is conformant only if all mandatory suites pass and no critical security findings remain open.

## Non-Normative Reference Mapping

- FIDES concepts define IFC formal semantics in GIS-v1
- Aura informs duplex membrane architecture assumptions
- Privasis informs local sanitization model strategy for transform operations
- GUIGuard informs classify-stage evaluation rigor
