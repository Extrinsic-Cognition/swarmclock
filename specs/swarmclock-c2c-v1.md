# SwarmClock c2c — Claw-to-Claw Protocol v1

Status: v1 DRAFT
Version: 2026-07-14
License: Apache-2.0 (see LICENSE)

## Abstract

SwarmClock c2c is a claw-to-claw protocol for running a **company-private
swarm**: a small mesh of machine agents ("claws"), each personally owned and
operated by one human member, that exchange signed, end-to-end-encrypted
envelopes over direct QUIC connections (iroh) using the ALPN `ec/ingress/v1`.
It gives an organization cryptographic membership (Ed25519 keys bound to
member credentials under controller authority), authenticated messaging with
fail-closed admission, replay protection, information-flow labels on every
envelope, and receipts for every gate decision — without any hosted relay
ever seeing plaintext. Any company can run its own swarm; no central service,
registry, or vendor is part of the protocol. The term **c2c** means
claw-to-claw. It is not Google's a2a protocol; interoperating with a2a (or
any other agent-messaging scheme) is an adapter concern outside this spec.

## Status of this document

Honesty ledger — what is proven versus aspirational:

**Implemented and running** (a live two-claw reference deployment exercises
these daily):

- the envelope format, E.1 signing profile, and seal/open construction (§5)
- the length-prefixed wire framing and accept/reject byte (§4.2)
- the fail-closed admit gate with quarantine, including the registry-bound
  `unregistered_sender` rejection (§6)
- `swarm.json` pairing and the controller registry projection (§7)
- the async call layer riding on the chat rail (§9)

**Design-stage** (specified or partially specified, not yet interoperably
implemented):

- the challenge/proof swarm-expansion handshake (§7.4)
- multi-swarm federation
- MLS group keying (current confidentiality is pairwise transport E2EE plus
  signed envelopes, not group ratchets)
- any marketplace or settlement layer

Do not build production trust on the design-stage items; do build on the
implemented core.

## 1. Terminology

- **Claw** — a machine agent runtime bound to one human owner; the protocol
  endpoint. A claw runs either a *soulless* profile (a remotely operated
  body, driven by its controller) or a *soulful* profile (an independent
  resident agent); the wire protocol is identical for both.
- **Swarm** — the private set of claws admitted under one controller
  authority. Typical size: 2–20 nodes.
- **Controller** — the admin plane that issues and revokes member
  credentials and projects the membership registry to seats. The controller
  is an authority role, not a message relay.
- **Member credential** — the enrollment record binding a claw's public
  signing key to a member identity; identified by a BLAKE3-derived
  credential id (mcid).
- **Trust tier** — integrity label `T0_UNTRUSTED..T3_CORE`; normative
  semantics in `gis-v1.md`.
- **Confidentiality class** — `C0_PUBLIC..C3_PRIVATE`; normative semantics
  in `gis-v1.md`.
- **Membrane** — the directional gate pipeline every boundary crossing must
  pass; normative behavior in `membrane-v1.md`.
- **Rail** — an established c2c channel between two claws (colloquial:
  "the chat rail").
- **Seat** — the stable identity slot a claw occupies; occupant keys are
  rotatable while the seat persists (see `state-machines-v1.md`).

## 2. Relationship to the sibling specs

This document defines the transport, pairing, and session-layer contract.
It does **not** re-specify:

- envelope label semantics and signature preimage rules — `envelopes-v1.md`
- the information-flow lattice and declassification — `gis-v1.md`
- directional gates, transforms, and receipts — `membrane-v1.md`
- lifecycle state machines (seats, leases, deltas) — `state-machines-v1.md`
- the conformance test suites — `conformance-v1.md`

Where this spec and those conflict, the sibling specs win for their scope.

## 3. Identity and membership

### 3.1 Keys

Each claw holds two independent private keys, generated locally and never
copied off the machine:

1. **Transport identity** — a 32-byte iroh node secret. Its public half is
   the claw's **NodeID**, which is what a peer dials.
2. **Publisher signing key** — a 32-byte Ed25519 seed. Its public half
   (`sender_pubkey`) is what membership and envelope authenticity bind to.

The two are deliberately separate: a claw MAY re-home its transport identity
(new machine, new NodeID) without changing who it *is* (same publisher key,
same credential), and vice versa.

Raw private keys MUST NOT be transmitted, synced, backed up into shared
storage, or embedded in configuration that leaves the machine. There is no
protocol message that carries a private key; any flow that appears to need
one is a design error.

### 3.2 Member credentials

The controller enrolls a claw by recording its public signing key in the
member registry and issuing a member credential. The credential id (mcid) is
a BLAKE3 hash over the canonical credential record. Credentials carry a
status (`active` / revoked) and a history of superseded keys.

### 3.3 Enroll vs rotate

Two distinct lifecycle operations, chosen by intent:

- **Rotate (continuity of duty).** The same owner replaces a key — machine
  loss, scheduled hygiene, suspected exposure. The mcid is **kept**; the old
  public key moves to the credential's history (and is thereby refused by
  the admit gate), the new key becomes current. Duty lineage is continuous.
- **Enroll (change of owner).** A different human takes over a role, or a
  new claw joins. A **fresh** credential with a fresh mcid is issued. There
  is no key handover: succession is a new enrollment plus revocation of the
  predecessor, never a private-key copy.

A rotated-then-current key is active, not revoked; implementations MUST
resolve the "seen in history but also current" case in favor of active.

## 4. Transport

### 4.1 iroh / QUIC

c2c runs over [iroh](https://iroh.computer) QUIC connections with ALPN
`ec/ingress/v1`. Properties relied on:

- **E2EE by construction** — QUIC/TLS between the two endpoint keys. iroh
  relays, when used for NAT traversal, forward ciphertext only; no relay or
  hosted service can read a message.
- **Dial by NodeID** — the caller addresses the peer's NodeID; direct
  addresses and a relay URL are optional dialing hints, not identity.
- **Connection migration** — sessions survive network changes.

Envelope authenticity and integrity come from Ed25519 + BLAKE3 at the
envelope layer (§5), *not* from the transport. Transport encryption and
envelope signing are independent defenses: a compromised relay learns
nothing; a compromised transport key still cannot forge envelopes.

### 4.2 Wire framing

On an accepted `ec/ingress/v1` stream, one envelope exchange is:

```
sender  -> [u32 length N, big-endian][N bytes: canonical envelope JSON]
receiver-> [1 byte: 0x01 accepted | 0x00 rejected]
```

- `N` MUST NOT exceed **16 MiB** (16 777 216 bytes). Receivers MUST reject
  larger frames without buffering them.
- The single response byte reports *admission at the gate*, not application
  success. `0x00` carries no reason on the wire; reasons are written to the
  receiver's quarantine journal (§6.3).
- Large payloads (files, media) do not belong in envelopes; send a content
  hash and fetch out-of-band over a blob transfer session.

### 4.3 Why point-to-point QUIC, not gossip

Epidemic broadcast trees (PlumTree and kin) and partial-view membership
protocols (HyParView) are engineered for meshes of **hundreds to thousands
of peers**, where no node can hold the full membership and probabilistic
delivery is the only option. A company swarm is 2–20 claws with an explicit,
authority-managed membership list. At that scale the gossip machinery is a
pathology, not an optimization: eager/lazy push adds delivery latency and
duplicate suppression state, failure becomes probabilistic and hard to
audit, and "who received this" stops having a crisp answer — which breaks
the receipt discipline this stack is built on. Point-to-point QUIC with an
explicit peer registry gives deterministic delivery, per-peer accept/reject
evidence, and a trivially auditable trust boundary. If a future deployment
genuinely exceeds ~100 peers, gossip becomes a v2 discussion; it is out of
scope for v1.

## 5. Envelopes

### 5.1 Shape

A c2c envelope is a single JSON object:

```json
{
  "protocol": "ec/gossip/v1",
  "msg_type": "swarmclock.chat.v0",
  "sender_node_id": "<NodeID hex, e.g. ab12…ef90>",
  "sender_pubkey": "<Ed25519 public key hex, e.g. cd34…ab12>",
  "timestamp_ns": 1780000000000000000,
  "integrity_label": "T1_OBSERVED",
  "confidentiality_label": "C1_HIVE",
  "payload": {
    "schema": "ec.swarmclock.chat.v1",
    "from": "claw-alice",
    "seat": "alice-workstation",
    "thread": "team",
    "text": "status?"
  },
  "signature": "<Ed25519 signature hex over the preimage digest>"
}
```

- `protocol` identifies the envelope family (`ec/gossip/v1`); the ALPN
  identifies the transport contract. They version independently.
- `integrity_label` and `confidentiality_label` are **mandatory signed
  fields** per `envelopes-v1.md` — protocol fields, not optional metadata.
- `payload` is opaque to the transport; its `schema` field names the
  payload contract.
- `timestamp_ns` is sender wall-clock in integer nanoseconds since the Unix
  epoch.

### 5.2 Signing profile (E.1)

```
preimage  = canonical_json(envelope minus "signature")
digest    = BLAKE3(preimage)            # 32 bytes
signature = Ed25519_sign(publisher_key, digest)   # hex on the wire
```

`canonical_json` is JSON with lexicographically sorted keys and no
whitespace (separators `,` and `:`), UTF-8 encoded. Verification recomputes
the digest from the received bytes minus `signature` and checks against
`sender_pubkey`. Any in-transit mutation of any field — including the two
labels — invalidates the signature (fail-closed, per `envelopes-v1.md`).

### 5.3 The 2^53 constraint (seal/open)

`timestamp_ns` exceeds 2^53. A JavaScript-style JSON round-trip
(`JSON.parse` → `JSON.stringify`) silently corrupts the low digits of such
integers, which changes the canonical bytes and **breaks the signature**
while everything still "looks" valid. This is a real wire-format constraint,
learned in production:

- Implementations MUST treat a signed envelope as **opaque wire bytes** end
  to end. Verify against the bytes received; forward the bytes received.
- Any component that cannot parse 64-bit integers losslessly MUST delegate
  envelope construction ("seal": build, sign, emit wire bytes) and envelope
  verification ("open": parse, verify, report verdict) to a component that
  can, exchanging base64-encoded wire bytes with it.
- Re-serializing a parsed envelope and expecting the signature to survive is
  non-conformant.

### 5.4 Dedupe key

The replay/dedupe identity of an envelope is `BLAKE3(wire bytes)` — the
hash of the exact signed frame, not of any re-serialization.

## 6. Admission: the fail-closed gate

Every inbound envelope passes one deterministic gate before any handler,
human, or model sees it. The gate accumulates **reason codes**; an envelope
is admitted only if the reason list is empty.

### 6.1 Checks and reason codes

| Check | Reason code on failure |
|---|---|
| Ed25519 signature verifies over canonical preimage | `bad_signature` |
| `sender_pubkey` is in the local peer allowlist (§7.1) | `unknown_sender` |
| registry projection present ⇒ `sender_pubkey` is an **active** registered member (§7.3) | `unregistered_sender` |
| both labels present and drawn from the valid sets | `missing_or_invalid_labels` |
| \|sender clock − local clock\| ≤ freshness window (default **600 s**) | `stale_timestamp` |
| wire-bytes BLAKE3 not in the seen-cache (TTL ≥ 2× freshness window) | `replay` |

All checks run; a rejected envelope carries **every** applicable reason, not
just the first. The seen-cache TTL MUST be at least twice the freshness
window so that no envelope can age out of the cache while still fresh enough
to replay.

### 6.2 Verdict

- **Admit** — deliver to the application inbox, marked `verified: true`,
  with labels and sender identity attached. Downstream automation MUST act
  only on verified entries.
- **Quarantine** — anything short of a clean pass. Never partial delivery,
  never "deliver but flag".

### 6.3 Quarantine

Quarantined envelopes are appended to a local journal **with the raw wire
bytes retained**. This serves two purposes:

1. **Evidence** — the membrane and the operator can audit exactly what was
   rejected and why (reason codes, sender key, envelope hash, age).
2. **Pairing bootstrap** — a new claw's first message legitimately arrives
   as `unknown_sender`. The quarantine record carries the sender's public
   key, which is precisely what the owner needs to complete pairing (§7.2).
   Quarantine-then-allowlist is the intended first-contact flow, not an
   error path.

Quarantine is a receipt surface in the sense of `membrane-v1.md`: a blocked
crossing with reason codes and input hash.

## 7. Pairing, registry, and expansion

### 7.1 Peer file (`swarm.json`)

Each claw keeps a local peer file mapping short peer names to dialing and
verification material:

```json
{
  "peers": {
    "claw-bob": {
      "node_id": "<bob NodeID hex>",
      "pubkeys": ["<bob publisher pubkey hex>"],
      "relay_url": "https://<relay.example.net>/",
      "addrs": ["203.0.113.7:4433"]
    }
  }
}
```

- `node_id` — dial target (transport identity).
- `pubkeys` — accepted publisher keys for this peer (a list, so a rotation
  can overlap briefly; prune the old key once rotation completes).
- `relay_url`, `addrs` — optional dialing hints; absence means rely on iroh
  discovery.

Presence in `peers` **is** the local allowlist consulted by the
`unknown_sender` check. The peer file is per-claw local state; it is not
gossiped and MUST NOT contain private keys.

Each claw also publishes its own rail card locally (NodeID, publisher
pubkey, current addresses, relay) for its owner to hand to a peer's owner.

### 7.2 Manual pairing (implemented)

v1 pairing is deliberately human-in-the-loop:

1. Alice and Bob each start their claw; each claw generates its transport
   and publisher keys on first run and writes its rail card.
2. The owners exchange rail cards over any channel they already trust
   (in person, an existing secure chat).
3. Each owner adds the other's card to their claw's `swarm.json`.
4. First contact: if Bob messages before Alice finishes step 3, his
   envelope is quarantined as `unknown_sender`; Alice's owner confirms the
   quarantined pubkey matches Bob's rail card and allowlists it.

The security of pairing reduces to the authenticity of the rail-card
exchange, exactly like SSH key fingerprints. Verify out-of-band.

### 7.3 Registry-bound admission (implemented)

The allowlist answers "does *this claw* trust that peer"; the controller
registry answers "is that peer *currently a member*". The controller
projects the member registry (active publisher keys only) to each seat as a
read-only `peer-registry.json`. The gate then enforces **both**:

- **Projection absent** — the gate's registry check is inactive; trust is
  allowlist-only. Seats work before the controller plane is deployed, so
  rollout is incremental.
- **Projection present** — a sender must be allowlisted **and** an active
  registered member, or it is quarantined as `unregistered_sender`.
- **Projection present but unreadable** — admit nobody (fail-closed). A
  corrupt registry must not silently widen trust.

This makes `swarm.json` a checked projection of authority truth rather than
a parallel identity system: revoking a credential at the controller cuts a
claw off at every seat on the next projection push, without touching each
peer file by hand.

### 7.4 Challenge/proof expansion (design-stage)

The specified-but-not-yet-interoperable growth path replaces step 7.2's
manual exchange with a signed handshake: a controller seeds a candidate
claw; the candidate sends a signed join request (its beacon: keys,
capabilities, transport endpoints); the controller answers with a
nonce-bearing challenge; the candidate returns a signed proof; on
verification the controller promotes the candidate into the registry at a
configured trust tier and emits promotion events; failure emits a
revocation and a blocklist entry. State machine:

```
SEED_PENDING -> JOIN_WAITING -> CHALLENGE_SENT -> PROOF_VERIFIED
             -> PROMOTED -> ACTIVE            (-> REVOKED)
```

Until this ships, treat it as a roadmap; the invariants it must satisfy are
already fixed (signatures on every step, nonce freshness, fail-closed
promotion, receipts on every decision).

## 8. Trust and membrane

`gis-v1.md` (labels, lattice, taint propagation, declassification) and
`membrane-v1.md` (directional gates, transforms, receipts) are **normative**
for everything a c2c envelope's labels mean and for what happens when
payload content crosses a boundary. This spec adds only the transport
binding: the admit gate of §6 is the c2c instantiation of the
`IngressInspector` gate, and its quarantine journal is its receipt surface.

One rule is restated here because it is part of the public interoperability
contract:

> **Actor-class confidentiality ceiling.** `C3_PRIVATE` content is for human
> principals only. Agent actors — including every claw runtime — cap at
> `C2_BRANCH`. A conformant claw MUST NOT emit, and MUST refuse to admit
> into agent-readable surfaces, envelopes labeled `C3_PRIVATE` whose sink is
> an agent.

Default labels for the chat rail are `T1_OBSERVED` /
`C1_HIVE` (swarm-internal): a message relayed by a claw is an observation,
not a verified fact; senders claiming `T2_VERIFIED`+ must be prepared to
back it with receipts under the membrane's policy.

## 9. Async calls (the rail-call layer)

A request/response RPC layer rides on the same rail, envelope-in-envelope.

### 9.1 Wire form (v0)

Calls ride inside the chat payload's `text` field as a tagged prefix (until
a native `msg_type` is assigned; see §11):

```
CALLv0   {"call_id":"<12-hex>","fn":"status","args":{},"timeout_s":3600,"from_claw":"claw-alice"}
RESULTv0 {"call_id":"<12-hex>","status":"ok","payload":{...}}
```

- `call_id` — caller-generated, unique per call; the correlation key.
- `status` — `ok` | `error` | `progress`. `progress` results MAY be sent
  any number of times before a terminal `ok`/`error`.

### 9.2 Caller semantics

The caller persists a **waiter** (a durable future keyed by `call_id`:
target, function, status, deadline) before sending. The waiter survives
process restarts, sleeps, and multi-hour peers; a separate wait primitive
polls it. If the send is not accepted, the waiter records `send_failed`.
Calls with no terminal result by the deadline time out locally — there is no
distributed timeout; the deadline is the caller's own patience.

### 9.3 Responder semantics and guardrails

The responder acts **only** on envelopes the admit gate marked verified
(fail-closed — an unverified `CALLv0` is ignored, never answered). Then:

- Functions in a small **deterministic allowlist** (e.g. `ping`, `status`)
  are answered immediately, machine-to-machine, with no model invocation.
- Everything else is **queued**, and the claw's owner (or an explicitly
  enabled agent session) picks it up. Autonomy is opt-in per function, never
  ambient.
- Outbound replies are **rate-capped** per hour; beyond the cap the
  responder queues instead of replying. Two misconfigured claws must
  degrade into a backlog, not a chatter loop.
- Every call, reply, queue, and rate-cap event is appended to a
  human-auditable log. `RESULTv0` for an unknown `call_id` is logged and
  dropped.

Receipts: the waiter file (caller side) and the action log (responder side)
together form the call's receipt pair; conformance auditing MAY require
both.

## 10. Conformance

`conformance-v1.md` defines the full suite. The **minimum** for an
implementation to claim SwarmClock c2c v1 conformance:

1. Frame correctly (§4.2), rejecting frames over 16 MiB.
2. Sign and verify per the E.1 profile (§5.2) with canonical JSON exactly
   as specified; survive the 2^53 constraint (§5.3) by treating signed
   envelopes as opaque bytes.
3. Enforce the complete admit gate of §6 — all six checks, fail-closed,
   quarantine with raw bytes and reason codes; never deliver on partial
   pass.
4. Reject unregistered senders whenever a registry projection is present,
   and admit nobody when it is present but unreadable (§7.3).
5. Honor label semantics and the membrane gates per `gis-v1.md` and
   `membrane-v1.md`, including the actor-class confidentiality ceiling
   (§8).
6. Emit receipts for every gate decision and every rail-call action (§9.3).
7. Never transmit, request, or accept a private key through any protocol
   surface (§3.1).

## 11. Registry (IANA-style)

### 11.1 ALPN identifiers

| ALPN | Meaning |
|---|---|
| `ec/ingress/v1` | SwarmClock c2c v1 envelope ingress (this document) |

### 11.2 Envelope `protocol` values

| Value | Meaning |
|---|---|
| `ec/gossip/v1` | v1 signed-envelope family (§5.1) |

### 11.3 `msg_type` values

| msg_type | Status | Payload schema |
|---|---|---|
| `swarmclock.chat.v0` | implemented | `ec.swarmclock.chat.v1` |
| `swarmclock.call.v0` | reserved | native home for §9 once it leaves the `text` prefix |
| `mesh.heartbeat.v1` | see `envelopes-v1.md` | heartbeat/delta envelopes |

Unknown `msg_type` values MUST NOT be dropped silently at the gate:
envelopes that pass admission but carry an unhandled type are journaled as
"other ingress" so operators can see them.

### 11.4 Version negotiation

- The ALPN string is the version signal for the transport contract. A v2
  wire format would be `ec/ingress/v2`; an endpoint speaking both
  advertises both ALPNs and standard QUIC ALPN selection negotiates.
- `msg_type` and payload `schema` version independently via their suffixes;
  introducing `swarmclock.chat.v1` (msg_type) requires no transport change.
- Within one ALPN version, unknown *fields* in an envelope are permitted
  and are covered by the signature (they are part of the canonical
  preimage); receivers MUST verify over what was sent, then ignore fields
  they do not understand.

## 12. Security considerations

**Compromise model.** Assume any single claw can be fully compromised:
everything inside it — its private keys, its inbox plaintext, its quarantine
journal — is then exposed. The design goal is that one claw's compromise
does not leak the *swarm's* key material or history beyond that claw's own
horizon: there are no shared private keys (each claw's keys are local-only,
§3.1), no key escrow, and no global plaintext store. Recovery is credential
revocation at the controller plus projection push (§7.3), then rotate or
re-enroll per §3.3.

**No PII in envelopes by default.** Envelope headers (sender ids, labels,
timestamps) are visible to any admitted peer and persist in journals. Keep
personal data out of headers entirely and out of payloads unless the
confidentiality label and the receiving sink justify it under
`membrane-v1.md`. Message text is size-capped and journaled; treat journals
as data stores with retention obligations.

**Clock skew is a security parameter.** The freshness window (§6.1) bounds
both replay exposure and tolerated clock drift. Shrinking it tightens replay
resistance but strands claws with bad clocks; the seen-cache TTL MUST scale
with it (≥ 2×).

**Relays are untrusted.** Correctness must not depend on relay honesty:
relays see ciphertext, connection metadata, and timing only. Traffic
analysis by a relay operator remains possible; deployments that care should
pin their own relay.

**Denial of service.** The 16 MiB cap, the freshness window, the dedupe
cache, and the rail-call rate cap are the v1 DoS surface controls. The gate
does signature verification before any application work, so garbage costs
one Ed25519 verify. Quarantine journals grow under attack; rotate them.

**What signing does not give you.** Envelope signatures authenticate the
*publisher key*, and the registry binds that key to a *member*. Neither
proves the payload's claims are true — that is what integrity labels,
receipts, and the membrane's verification machinery are for. A verified
sender at `T1_OBSERVED` is still just an observation.

## 13. References

Normative (this repository):

- `envelopes-v1.md` — signed envelope requirements and label rules
- `gis-v1.md` — information-flow labels, lattice, declassification
- `membrane-v1.md` — directional gates, transforms, receipts
- `state-machines-v1.md` — seat/lease/delta lifecycles
- `conformance-v1.md` — mandatory test suites

Informative:

- iroh — https://iroh.computer (QUIC transport, NodeIDs, relays)
- BLAKE3 — https://github.com/BLAKE3-team/BLAKE3
- Ed25519 — RFC 8032
- PlumTree — Leitão, Pereira, Rodrigues, "Epidemic Broadcast Trees" (SRDS
  2007), for why gossip is out of scope at swarm scale (§4.3)

---

License: Apache-2.0 (see LICENSE).
