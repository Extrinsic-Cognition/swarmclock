# state-machines-v1.md

Status: Canonical v1
Version: 2026-03-28

## Scope

Defines lifecycle states for runtime entities required by v1 conformance.

## Agent Heartbeat Lifecycle

States:

1. `woken`
2. `lease_verified`
3. `projection_loaded`
4. `lock_acquired`
5. `executing`
6. `retaining`
7. `reflecting`
8. `delta_proposed`
9. `membrane_checked`
10. `emitted`
11. `sleeping`
12. `failed`

Transitions to `failed` require signed receipt with reason code.

## Lease Lifecycle

States:

1. `issued`
2. `active`
3. `expiring`
4. `revoked`
5. `expired`

Only `active` permits execution.

## Seat Assignment Lifecycle

States:

1. `summoned`
2. `active`
3. `suspended`
4. `revoked`
5. `reassigned`

Rules:

- only `active` seat assignments can produce binding votes or execute privileged intents
- `revoked` blocks privileged intents immediately
- `reassigned` requires new occupant key and incremented assignment epoch

## Branch Lifecycle

States:

1. `draft`
2. `active`
3. `blocked`
4. `in_review`
5. `sealed`
6. `published`

`sealed` and `published` are immutable except by governance mandate.

## Delta Lifecycle

States:

1. `proposed`
2. `validated`
3. `applied`
4. `rejected`
5. `quarantined`

Rules:

- replay duplicate => remain `applied` with dedupe receipt
- invalid signature/hash/labels => `rejected` or `quarantined`

## Membrane Decision Lifecycle

States:

1. `received`
2. `labeled`
3. `checked`
4. `transformed` | `blocked` | `allowed`
5. `receipted`

No terminal decision without receipt.

## Recovery Lifecycle

States:

1. `reap_orphaned`
2. `resume_queued`
3. `replay_safe`
4. `steady`

Recovery transitions must preserve idempotency and replay safety.
