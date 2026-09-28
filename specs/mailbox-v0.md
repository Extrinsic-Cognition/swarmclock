# Mailbox v0 — store-and-forward on the master claw (work order)

Status: IMPLEMENTED 2026-07-21 (local E2E green, deploy pending). Origin,
alice's question: "can the master claw hold an important message for bob
and deliver it to his pill when he comes online?" Before this component the
answer was no — delivery was live-peer-only.

Implementation map:
- `tools/chat_crypto.py` — `seal_to` / `unseal` ops (sealed box to the
  recipient's Ed25519 key via curve25519 conversion; wire bytes preserved).
- `tools/mailboxd.py` — the master-side daemon (standalone sibling of
  swarmclock-chatd, own sidecar identity + signing key, `$EC_MAILBOX_HOME`,
  ops API on 127.0.0.1:7779).
- `bin/antimirror` — sealed-put fallback in `chatSend` (status `mailboxed`),
  `mailbox-pending.ndjson` retry, drain on rail-up + 15-min timer,
  `handleMailboxItem` delivery through the existing gate → inbox + ◔ floor,
  persistent `mailbox-seen.json` dedup, `GET /api/mailbox` +
  `POST /api/mailbox/drain`.
- `tests/test_mailboxd_e2e.py` — protocol-level E2E (put → blind hold →
  fail-closed stranger refusal → drain → unseal → admit → ack → delete).
- `tests/test_daemon_mailbox_e2e.py` — full-loop E2E through two sandboxed
  real daemons: offline recipient, `mailboxed` send, rebirth, inbox +
  "(held for you)" notification, acked-empty store.

One deviation from the first draft: the mailbox messages are **payload
schemas riding the standard `swarmclock.chat.v0` envelope**
(`ec.swarmclock.mailbox.put/item/drain/ack/refusal.v1`), not new msg_types —
same pattern as `ec.enroll.v1` / `ec.app.publish.v1`, so every existing
peek-router and admit gate applies unchanged. The daemon knows the mailbox
as the swarm peer named **`mailbox`**.

## Ground truth first (corrects the 2026-07-20 audit)

Two facts changed / were wrong in the audit this spec descends from:

1. **bob HAS a rail identity.** `~/.antimirror/swarm.json` now carries a
   `bob` peer (kind `necromancer`, node_id, pubkey, relay_url, 3 addrs).
   `chatSend('bob', …)` is addressable today. Gap 1 of the audit is closed
   on this seat; what remains is whether his daemon is *running* when we send.
2. **The master is not "a box that runs nothing."** The DO VPS is Device B of
   `ec-claw-handoff-sfo3`: `run_daemon.py` owns the iroh endpoint on
   `ec/ingress/v1`, stores inbound source packets durably under
   `~/.ec-daemon/`, and already has a **durable, signed, daemon-drained
   outbox** (`downlink_outbox/`, written by `tools_master_downlink.py`,
   sent by the resident daemon). What it lacks is exactly one thing: a
   *recipient-addressed* mailbox with a drain protocol. The Mac daemon
   already best-effort unicasts `ec.enroll.v1` to `master`, so the
   Mac↔master rail path is proven code, not theory.

The remaining gap is therefore precisely: **no offline delivery**.
`chatSend` is fire-and-fail — on `unreachable`/`timeout` it writes the
failure to the inbox and gives up. Both endpoints must be online at the same
moment. Everything downstream of delivery already exists: an envelope that
passes the admit gate lands in `inbox.ndjson` AND fires the notification
floor (`notifyMac` → `notifications.ndjson` → the ◔ widget with working
clicks and unread badge).

## Thesis

Give the fleet one durable mailbox on the always-on master, holding only
**ciphertext sealed to the recipient**. Sender seals, master stores blindly,
recipient drains on rail-up and pushes the recovered envelope through the
*existing* admit gate → inbox → notification floor. No new UI, no new trust:
the mailbox is a dumb, blind, quota-capped holding tank.

**Doctrinal note (GATE).** c2c-protocol-draft §1 commits to "no hosted
message store, no cloud inbox". A plaintext mailbox would break that
commitment; a sealed one refines it to what it always meant: **no third
party ever holds plaintext**. The same section already marks
application-layer sealing ("encrypting the payload to the recipient's key
independent of the transport session") as `STATUS: planned` — the mailbox is
the feature that forces that plan to ship. alice ratifies the wording change
before this lands.

## Anatomy

### 1. Message family — `ec.swarmclock.mailbox.*.v1`

Payload schemas riding standard E.1-signed `swarmclock.chat.v0` envelopes
(same seal/open helper, same labels, same admit gate):

- `mailbox.put.v1` — sender → master.
  Payload: `{ to_pubkey, blob_b64, blob_hash, ttl_s, hint }`.
  `blob_b64` = the ORIGINAL signed chat envelope (raw wire bytes, never
  re-serialized — the 2^53 timestamp rule), sealed with `crypto_box_seal`
  to the recipient's curve25519 key derived from their allowlisted Ed25519
  pubkey. `hint` is a short plaintext label for quotas/ops
  (`"chat"`), never content.
- `mailbox.item.v1` — master → recipient, one per stored blob.
  Payload: `{ id, blob_b64, blob_hash, stored_ts, from_pubkey }`.
  Sent in response to a drain (below). Outer envelope is master-signed and
  fresh, so it passes the recipient's gate; the recipient unseals and then
  runs the INNER envelope through the full admit gate before delivery.
- `mailbox.drain.v1` — recipient → master: "send me my mail."
  `mailbox.ack.v1` — recipient → master: `{ ids }` → master deletes.
  Un-acked items are re-sent on the next drain (at-least-once; dedup is the
  recipient's job, see §4).

### 2. Master side (`ec-claw-handoff-sfo3`)

A mailbox handler in the resident daemon (or a sibling of the downlink
worker — same pattern, inverted direction):

- Store: `~/.ec-daemon/mailbox/<recipient_pubkey>/<id>.json`
  (id = hash of the sealed blob → idempotent puts, free replay dedup).
- Fail-closed admit on `put`: outer signature valid, sender pubkey in the
  claw registry / swarm allowlist, labels present, fresh. Same physics as
  every other envelope.
- Quotas: per-recipient cap (v0: 200 items / 25 MB), per-sender rate cap,
  TTL sweep (v0 default 30 days). Over-quota put → signed refusal, receipted.
- The master can not read a blob and never tries. Receipts record ids,
  sizes, pubkeys — never payloads.

### 3. Sender side (Mac daemon `bin/antimirror`)

- `chatSend` grows a mailbox fallback: when a send to a peer fails with
  `unreachable`/`timeout`, seal the already-signed envelope to the
  recipient's pubkey and `mailbox.put.v1` it to `master`. Inbox entry status
  becomes `mailboxed` (not `delivered` — never lie about delivery; the ✦
  widget renders it as "held for <peer>").
- If the master is ALSO unreachable, append to local
  `~/.antimirror/mailbox-pending.ndjson`; a timer retries puts until the
  master takes them. (This file is the successor of the append-only
  `outbox.ndjson` idea — but consumed, not aspirational.)
- v0 scope: fallback applies to direct chat to `necromancer`/`claw` peers.
  No new send UI; the existing chat composer just stops failing.

### 4. Recipient side (Mac daemon — this is where bob's pill lights up)

- On sidecar `ready` (rail-up) and every 15 min: `mailbox.drain.v1` → master.
- Each `mailbox.item.v1`: unseal with own key → recover inner raw envelope →
  run it through the NORMAL admit gate (`chat_crypto open`: signature,
  allowlist, labels, replay) with ONE amendment: the freshness check applies
  to the outer (master) envelope, not the inner one — mailbox mail is stale
  by definition. Inner `timestamp_ns` becomes the displayed sent-time; the
  entry carries `via_mailbox: true`.
- Replay: the in-memory seen-cache (20 min TTL) cannot dedup redelivered
  un-acked items. Persist delivered inner envelope hashes in
  `~/.antimirror/mailbox-seen.json` (bounded, TTL = master's mailbox TTL).
- Delivery = `inboxAppend` + `notifyMac('✦ <from> (while you were away)',
  text, 'chat')`. That is the whole point: it reuses the notification floor,
  so history, unread badge, and click-through come for free.

## Trust & floor compliance

- Master stores ciphertext only; sealing is to the recipient's allowlisted
  key, so a compromised master can delay or drop mail (already true of any
  relay) but never read or forge it — forgery dies at the inner signature.
- Both hops are fail-closed admit gates; the mailbox adds zero new trust in
  the master beyond availability.
- Labels ride inside the inner signed envelope untouched; C3 handling on
  render is unchanged.
- At-least-once + persistent dedup, never at-most-once silently: a message
  is either delivered, held (visible as `mailboxed`), or refused with a
  receipt. No void.

## v0 cut (smallest lovable thing)

1. Master: mailbox handler (put/item/drain/ack) + disk store + quotas + TTL.
2. Mac daemon: sealed-put fallback in `chatSend` + `mailbox-pending` retry.
3. Mac daemon: drain on rail-up + 15-min timer; inner envelope through the
   existing gate → inbox + ◔ floor; persistent mailbox-seen dedup.
4. E2E proof: send bob a message while his laptop is closed; he opens it;
   the message lands in his pill with a notification and a working click.
   The scenario that asked the question becomes the acceptance test.

## Deployment (operator runbook — the remaining act)

On the DO master box (Device B, Ubuntu):

1. Sidecar binary: build `ec-claw-handoff-sfo3/iroh_sidecar` on the box
   (`cargo build --release`) or reuse the binary the master smoke already
   proved there; point `EC_IROH_SIDECAR` at it.
2. `python3 tools/mailboxd.py` under systemd (deps: `pynacl blake3` in a
   venv; same pattern as `ec-master-supervisord.service`). First boot prints
   the mailbox pubkey and writes `~/.ec-mailbox/mailbox-rail.json`
   (node_id + dial addrs). Open the sidecar's UDP port in the firewall.
3. Allowlist the fleet in `~/.ec-mailbox/swarm.json`: one peer entry per
   seat (name, node_id, pubkeys, addrs/relay_url) — start with alice, bob,
   carol, seat-a. mailboxd re-reads it per envelope; no restart needed.
4. On EVERY seat: add the `mailbox` peer to `~/.antimirror/swarm.json`
   (node_id + pubkey + `<do-ip>:<udp-port>` from mailbox-rail.json), then
   restart the daemon (it drains on rail-up).
5. Real-world acceptance test: message bob while his laptop is closed —
   his pill must notify "(held for you)" when he opens it.

## GATEs (human acts, not mine)

- alice ratifies the doctrine wording: "no hosted message store" → "no third
  party ever holds plaintext" (c2c draft §1 update rides this spec).
- The deployment runbook above — every step is an operator act on Device B
  or a seat owner's machine.
- bob's seat: confirm his daemon+pill actually run on his Mac (his
  swarm.json entry proves enrollment, not liveness).

## Relation to canon

`c2c-protocol-draft.md` — mailbox.put/item/drain/ack join the same message
family as chat and CALLv0; application-layer sealing graduates from
`planned` to `implemented` here. `swarmsync-drops-v0.md` — drop/v1 announces
gain offline delivery for free once they ride the same fallback (rail =
doorbell, and now the doorbell has a memory). ENFORCEMENT-FLOOR — receipts
at every boundary; the mailbox is receipt-dense by construction.
`tools_master_downlink.py` — the master-side pattern this generalizes
(durable job dir, resident daemon sends); the mailbox is its inbound twin.
