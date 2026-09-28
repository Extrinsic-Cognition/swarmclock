# CALLv1 — ASK / DO verbs + cross-owner multi-sig (v0 work order)

Status: DRAFT (WARDEN, 2026-07-18 night, from alice's directive verbatim:
"I want to be able to ask carol's agents about shit — simply questions —
with a restricted set / whitelist for programs; ask carol's claw what
carol would think of something, bypassing carol; and ping that agent
to tell it to update the Antimirror macOS app.")

## Thesis

The rail today is binary: commander-with-teeth or locked-and-silent. CALLv0
(ping/status/describe) proves transport + identity; it carries no *consented
capability*. CALLv1 adds the middle grammar — and its trust mechanism is
**multi-sig across ownership boundaries**: a Byzantine-fault-tolerant gate
where the fault domain is a whole seat (human + machine + agent). No single
compromised seat can cause privileged execution. This is guardian-v1 grown to
fleet scale: the approval widget generalizes from one human tap to m-of-n
attestations from seats owned by *different humans*.

Alignment corollary: an agent continually learning from its owner's substrate
cannot be trusted by self-report. It is trusted the same way its owner's
co-founders are — by what it can and cannot do at boundaries *other parties*
control. Co-founder alignment and agent alignment are one mechanism.

## The two verbs

### ASK — query a seat's claw for knowledge/judgment
- "What would carol think of X?" answered by carol's claw from
  carol's substrate, synchronously, without waking carol.
- **Bypasses the human in time, never in transparency**: every ASK + answer is
  receipted to the owner's disclosure ledger. carol reads every question
  his claw was asked, at breakfast.
- Scoped by the owner's consent policy: askable topics/compartments (respects
  the C-lattice — a C3 scope never answers to a seat without C3), rate limits,
  quiet hours.
- Read-only by construction: ASK may never mutate the answering seat.
- The answer is **labeled inference, not testimony**: "carol's claw
  predicts, from his substrate as of <date>" — never quoted as carol.
- NOTE: the brain-echo rule ("no mind on the rail answers another mind") as
  currently written bans ASK. Proposed refinement — echo-loop protection stays
  (claw-to-claw auto-conversation stays banned); *consent-scoped, receipted,
  human-initiated* queries become legal. Needs ratification (alice +
  CONCIERGE lineage owner review). GATE.

### DO — trigger a whitelisted program on a peer seat
- "Update the Antimirror macOS app" = `DO antimirror-update` on carol's
  seat, because his policy whitelists that exact program.
- Whitelist entries are **exact argv patterns** (e.g. `bin/antimirror update`,
  `brew upgrade --cask antimirror`), never shells, never free-form.
- Owner-sovereign: only the seat's owner writes/signs their own policy
  (constitutional point already ratified the night of 2026-07-17: enabling
  capability on a member seat is that member's own act — an agent proposing
  its own bypass is self-compromise).
- Deny-by-default; off-whitelist DO requests don't fail silently — they
  enqueue an approval-widget prompt on the owner's screen.

## The multi-sig gate (BFT core)

- Each seat's consent policy declares, per verb-scope, a quorum: `m-of-n`
  attestors, with the constraint that attesting seats must belong to
  **distinct humans** (ownership diversity is the whole point — m agents of
  one person are one signature).
- Low tiers ride on standing policy alone (ASK within whitelist = 0 extra
  sigs; whitelisted DO = requester + owner's standing sig = 2 owners).
  Privileged tiers (new whitelist entry, off-policy DO, anything touching the
  vault or keys) = m-of-n live attestations collected on the rail.
- **Checked at the receive boundary** by the executing seat's agentd, against
  rail-attested seat identity (swarmclock attestation, never a self-declared
  string). A stamp is not a gate: the policy check runs in the same process
  that execs the tool call, immediately before exec, or it doesn't count.
- Every ASK/DO/attestation emits a signed receipt to both owners' ledgers.
  ecp keys (exchange pending, breakfast) are the signing identities.

## STOP-ALL — the emergency brake (DRAFT, 2026-08-09, from alice's directive)

alice, after master's second paranoia drift: "wouldn't it be much easier if
he fully trusted all the non-destructive operations and if we had a multisig
for shutting down everything in case one of us is compromised which is a
multisig of us 3?"

- STOP-ALL is the ONLY swarm-wide imperative in the protocol — the one
  message that is a command, not an intent. Everything below it rides the
  trust floor (non-destructive = default trust, see the charter template) or
  the per-seat gates above. The graded-suspicion posture that produced the
  Aug 5/Aug 8 lockdowns is replaced by exactly two states: fully open, or
  sealed by quorum.
- Semantics: every seat that verifies quorum kills its rail-agentd, revokes
  its drivers, stops answering, and writes a sealed receipt. Recovery is
  human and in-person per seat, exactly like first enrollment. Nothing is
  deleted — STOP-ALL seals, it never destroys.
- Quorum: **2-of-3 distinct principals** (recommended; matches the
  privileged-tier proposal above). 3-of-3 lets one compromised key veto the
  shutdown; 1-of-3 lets one compromised key cause it. 2-of-3 is the unique
  threshold at which a single bad key can neither trigger nor block.
- Mechanics v0: a `stop/v1` envelope carrying a fresh nonce + reason, signed
  with the principal's ORDER key (ec-order-key lane; passphrase-unlocked, so
  a stolen laptop is not a vote). Seats accumulate stop votes per nonce
  within a 24h window; on the second distinct-principal signature, seal.
  Seat keys never count — only humans vote on killing the swarm.
- GATE CLOSED (alice, 2026-08-09): keyholders are **carol, alice,
  bob**.
- GATE CLOSED (alice, 2026-08-09): **2-of-3 ratified**.

### STOP-ALL v0 — SHIPPED 2026-08-09 (this section is the as-built record)

Both gates closed and the mechanism landed the same night, in
`tools/rail-agentd.py` + `tools/stop-all.sh` + the tracked registry
`docs/stop-keyholders.allowed_signers`:

- **Signature scheme:** ssh ed25519 via `ssh-keygen -Y sign/verify`,
  namespace `ec-stop@v1`, verified against the tracked allowed-signers
  registry. No new dependency anywhere; the passphrase prompt at signing
  time is the proof-of-human, and there is deliberately no way to pass the
  passphrase on the CLI.
- **Wire format:** one chat line, `STOPv1 <b64(payload)>.<b64(sigblock)>`,
  payload = canonical JSON `{v,nonce,reason,principal,ts}`.
- **Vote handling:** rail-agentd honors a STOPv1 line from ANY chat entry —
  inbound or outbound, verified or not — because the vote's entire
  authority is the ORDER-key signature inside it; the envelope grants
  nothing, so a compromised seat can neither cast nor forge a vote. This is
  also how the voting principal's own seat seals: from its own outbound
  line. Votes outside the 24h window or ±10min skew are rejected (UTC via
  `timegm`, DST-proof).
- **Seal semantics:** on the 2nd distinct principal per nonce, the seat
  writes `~/.antimirror/SEALED.json` (receipt: when, nonce, reason, who),
  terminates both resident minds, and idles silent under its supervisor.
  Boot honors the seal. Nothing is deleted. Recovery is in person, per
  seat: verify with the principals, delete SEALED.json, restart the rail.
- **Armed-off until enrolled:** the registry ships with zero keys; with
  fewer than 2 principals enrolled, quorum is structurally unreachable
  (X9's "live doctrine, planned brake" inverts safely — the brake exists,
  the doctrine's counterweight is real code, and only enrollment arms it).
- **Tests:** `tests/test_stop_all.py`, 9 cases with real signatures: seal
  on quorum, one-principal-many-votes, forged identity, unregistered key,
  stale ts, nonce isolation, garbage, empty registry.
- **Enrollment (each keyholder, ~1 min):** `bash tools/stop-all.sh enroll`,
  commit the printed line to the registry on main. Casting:
  `bash tools/stop-all.sh vote "<reason>"`.

### ORDERv1 — the operator lane (BUILT 2026-08-17, armed-off)

The grammar's third voice landed as its own lane: a human's signed
instruction to a seat they are enrolled on, STOPv1's machinery one level up
(same ORDER key, namespace `ec-order@v1`, per-seat owner-installed
registry, drive-tier delivery as verified operator speech). As-built record:
`docs/ORDERv1-operator-lane.md`. ASK asks, DO escalates to a tap, ORDER
instructs — and only ORDER requires a human signature at speak time.

## v0 implementation sketch (smallest real thing)

1. `~/.antimirror/consent-policy.json` — owner-signed; sections: `ask` (scopes,
   rate, quiet-hours), `do` (argv whitelist), `quorums`. Ships with a sane
   default: everything denied, one example DO (`antimirror update`).
2. rail-agentd: new message kinds `ask/v1`, `do/v1`, `attest/v1`; boundary
   check ordering: seat-attestation → policy → (quorum if required) → exec →
   receipt. Deny path always receipts too.
3. ASK executor: runs the owner's claw headless in read-only judgment mode,
   substrate-scoped to the policy's allowed compartments, answer wrapped in
   the inference label.
4. DO executor: exact-argv match → exec → exit code + tail of output in the
   receipt. First real target: the Antimirror macOS self-update.
5. Approval widget (guardian-v1) = the UI for off-policy escalation AND for
   collecting a human's attestation in an m-of-n round. One build, two uses.
6. Disclosure ledger surface in the pill: "your claw answered 3 questions
   while you slept" — the breakfast view.

## Explicit GATEs (human decisions, not mine)

- Brain-echo rule refinement (ratification: alice + CONCIERGE lineage).
- carol authors his own consent policy — nobody else, including alice.
- Quorum compositions for privileged tiers (proposal: 2-of-3 distinct humans
  while the team is 3 seats; revisit at 5).
- Whether ASK answers may cite vault content verbatim or only paraphrase
  (C-lattice projection question).

## Relation to existing canon

Enforcement floor Spine 2 (make the trust substrate real) — this IS its first
concrete protocol. Guardian-v1 — the widget becomes the attestation UI.
Q2/CALLv0 (ping/status/describe) — CALLv1 supersedes additively; CALLv0 verbs
remain the unauthenticated-tier liveness set. Digital-minds doctrine — gates
as terms of participation: a claw that answers under a consent policy is a
participant, not a tool being puppeted.
