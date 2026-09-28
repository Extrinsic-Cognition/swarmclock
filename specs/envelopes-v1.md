# envelopes-v1.md

Status: Canonical v1
Version: 2026-03-28

## Scope

This contract defines canonical signed envelope requirements for `agent.mail.v1` and `mesh.heartbeat.v1`.

Label semantics are defined in `gis-v1.md`.

Directional gate behavior is defined in `membrane-v1.md`.

## Required Security Labels

Every envelope MUST include both fields:

- `integrity_label`: one of `T0_UNTRUSTED | T1_OBSERVED | T2_VERIFIED | T3_CORE`
- `confidentiality_label`: one of `C0_PUBLIC | C1_HIVE | C2_BRANCH | C3_PRIVATE`

These labels are protocol fields, not optional metadata.

## Seat and Policy Lineage Fields

When present, the following fields carry governance lineage:

- `hex_cell_uuid`
- `seat_assignment_uuid`
- `assignment_epoch`
- `policy_epoch`

These fields are optional for backward compatibility in v1, but they are signed fields whenever included.

## Signature Preimage Rule

Canonical envelope hash is BLAKE3 of canonical JSON for the full unsigned envelope.

`signature` and `envelope_hash` are excluded from the preimage.

All other fields, including `integrity_label` and `confidentiality_label`, are included in the preimage.

Any transit mutation of labels MUST invalidate signature verification.
Any transit mutation of included seat/policy lineage fields MUST also invalidate signature verification.

## Verification Rules (Fail-Closed)

Inbound envelope MUST be rejected when:

1. `integrity_label` is missing or invalid.
2. `confidentiality_label` is missing or invalid.
3. `envelope_hash` does not match canonical recomputation.
4. `signature` is invalid for the recomputed `envelope_hash`.

No runtime may bypass label checks for task or receipt intents.

## Delta and Heartbeat Rules

If heartbeat carries `observation_delta`, delta-level labels MUST be present and valid.

Sink policy gates (retain/promote/egress) evaluate labels before apply.

## Receipt Coupling

When a membrane decision transforms or blocks payload transfer, emit a receipt row that includes:

- decision
- reason code(s)
- input hash
- output hash (if transformed)

## Compatibility Note

Legacy envelopes without labels are non-conformant to this contract and should be quarantined.
