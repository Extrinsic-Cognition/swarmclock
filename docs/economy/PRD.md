# The swarmclock economy: PRD for the off-chain rail of Poleis

Status: PROPOSAL, 2026-09-07, written in the am-prd method after alice's
ruling of the same night: "Anything that needs to be on Solana is all on
Solana, for all we want. If things get accumulated and hashed, that is fine
as well." The on-chain body is finished. This document is the metabolism:
how an allowance becomes work, work becomes a receipt, and a receipt becomes
a payment, without one new instruction on the chain.

Prior strata inherited verbatim: `docs/poleis-bicameral-prd.md` (the double
seal, rulings O1 to O10), `docs/poleis-protocol-prd.md`, the swarmclock rail
(`antimirror-app/tools/chat_crypto.py`, `tools/swarmclock-chatd.py`), the
aup bank (`antimirror-app/aup/schema/trace-digest-v0.json`), TraceNet
(`senatus/TRACENET.md`, the `human_key` consent rule), and the program at
`poleis-journey/program/poleis_treasury` on branch `app/journey`.

## 1. THE ARTIFACT

What a dig finds when this is built, checkable by looking:

- Every unit that spends or earns keeps a **book**: an append-only file of
  signed rail envelopes at `~/.antimirror/books/<unit_id>/<epoch>.ndjson`
  on the seat that operates the unit. Line one is the epoch header. Every
  other line is an envelope the rail's admit gate accepted, unchanged.
- A book accepts an entry only from a key the chain's registry knows for
  that unit, or a key bound to one by a two-signature binding entry. Every
  member seat of a unit holds the unit's book; the closer's root is final
  only when the unit's seal attests it.
- A book closes into a **root**: `swarmclock_book.py close <unit> <epoch>`
  prints a BLAKE3 Merkle root over the envelope hashes in file order and
  writes `<epoch>.root.json` beside the book with the root, the count, the
  first and last `timestamp_ns`, and the closer's signature.
- Every root that moves money is on the chain inside an instruction that
  already exists: `pull` carries it as its 32-byte hash; `rule_contract`
  rules a contract whose payload names it; `accrue_dividend` distributes
  income whose provenance is a root; `execute` runs `transfer_seats` after
  a seal whose attested votes are the testimony envelopes themselves.
- `swarmclock_book.py prove <unit> <epoch> <envelope_hash>` prints an
  inclusion proof, and `verify` checks it against a root read from the
  chain with no access to the book. A page in `poleis-journey/app` shows
  one entry, its proof, and the anchored root, and says VERIFIED or not.
- The **tank** runs on the operator's seat as `swarmclock-tankd.py`. It
  holds provider keys in memory, pasted by a human, never by an agent.
  Agents call `POST /call`; the tank forwards, meters, and books one
  `ec.swarmclock.call.v1` envelope per call with provider, endpoint, cost
  in micro-dollars, input hash, output hash, and the provider's job id. At
  the cap the tank refuses. It never overdraws and never logs a key.
- A lease is an allowance on the chain with `period` of one day and a
  `pull` each day whose hash is that day's root of `ec.swarmclock.lease.v1`
  entries. When the pulls stop, the reader on the lessor's seat stops
  serving the branch. Nothing is served for a day that has no root.
- A mutual is a unit whose seats are its dues, whose income is the
  settlement of lot auctions of graded work, and whose rebate is the
  dividend policy accrued per period and claimed by every seat pro rata.
- A recovery is a sealed proposal of a narrow unit that executes
  `transfer_seats` from the unit to a member's new key, with the members'
  `ec.swarmclock.testimony.v1` envelopes as the votes `attest` verified.
  No unit wider than `MAX_SEATS_PER_HOLDER` per holder can execute one.

## 2. DOCTRINE

**The founding metaphor is the book.** A book is what a unit keeps of
itself between two moments the chain notices. It is written by many hands,
one signed line at a time, and no line is ever erased. When the epoch
closes, the book is bound: a root that fits in 32 bytes stands for every
line. The chain reads only bindings. The rail reads only lines. A payment is
the chain agreeing that a binding exists; a dispute is one line and its
proof of being bound. The metaphor is load-bearing because it fixes the
direction of trust: nothing is paid that is not in a book, and nothing in a
book is paid until its root is on the chain.

**The vocabulary, singular, reused verbatim.** A **unit** is a polis or a
chamber (existing). A **seat** and a **key** are what the program already
knows. A **book** is a unit's append-only file of **entries**; an entry is a
rail envelope. An **epoch** is a closed span of a book; a **root** is its
binding; a **proof** is one entry's inclusion. The **tank** is the metered
key proxy; a **call** is one provider invocation it books. **Work** is a
deliverable whose identity is a root; a **grade** is a verdict on work; a
**lot** is graded work offered at a sealed auction. A **lease** is a day of
access to a branch of a person's traces. **Dues** are the seats of a mutual;
the **rebate** is its dividend. **Testimony** is a member's attestation in a
recovery. The **reader** is any program that recomputes a root from a book.
The **operator** is the seat that holds provider keys for a unit.

**The quotable thesis.** "The chain sees roots. The rail sees receipts." And
its corollary for the tank: "The agent never holds the key. The key never
leaves the seat. The receipt never leaves the book."

**The verse rule, stated as structure.** A unit that takes money in from
outside and distributes work is broad and recursive: it may not execute a
recovery and its platform changes carry `CLASS_CONSENT`. A unit that
dissipates money out to its own members is narrow: it executes on its
origin chamber after its descendants resolve, and it may execute a
recovery. The two rules already exist in `proposal.rs`; this document only
says which unit uses which, and leaves the declaration to ruling R4.

## 3. STRATA

The hops are derived backwards from the artifact and written forwards.
Every hop is a contract: initial state, target state, interpolation with
GATEs named, degraded path. Nothing here is DONE.

### Hop 0: the rulings that fix the shape (GATE, alice)

Initial: the on-chain body complete on devnet; the rail live between the
Mac and seat-a; the studio's key proxy as the tank's ancestor. Target: R1 to
R5 below stamped. Interpolation: alice answers the OPEN rulings, in the
order given, in chat or on tape. Degraded: without R1 (the asset) hop 2
cannot open an allowance; the rail is built and tested against a book with
no chain move, and stops there.

### Hop 1: the book (membrane first)

Initial: `chat_crypto.py` seals and opens envelopes with a fail-closed
admit verdict; there is no file that keeps admitted envelopes in order and
no root. Target: `antimirror-app/tools/swarmclock_book.py` with four
commands, `append`, `close`, `prove`, `verify`, and a property test suite
proving that a book with one altered byte fails `verify`, that two books
with the same entries in different order have different roots, and that a
proof for an entry not in the book is refused. First consumer: the tank
(hop 2). Interpolation: `append` runs `open` on the envelope and writes it
only on `admit: true`; anything else goes to `quarantine.ndjson` as the
rail already does. `close` computes the BLAKE3 Merkle root over
`envelope_hash` values in file order, writes the root file, and signs it
with the seat publisher key. No GATE: no money, no publication. Degraded:
an epoch that fails to close leaves the book open and refuses `append` of a
later epoch until closed; a half-closed book is impossible because the root
file is written atomically after the book is sealed read-only.

### Hop 1a: the roster binding (membrane, with hop 1)

Initial: the rail admits any sender on `~/.antimirror/swarm.json`; nothing
cross-checks a sender key against the chain's registry (verified on disk
2026-07-13, still true). TraceNet names four keys per node and the estate
ruled the seat key is the mesh key (Aug 17). Target: a book accepts an
entry only from a key that holds a seat or a chair in the unit on the
chain, or from a key bound to such a holder by an
`ec.swarmclock.seat.v1` binding entry signed by both the holder's Solana
key and the agent's rail key. `swarmclock_book.py append` reads the roster
from the registry account (the same read the wall does) and refuses the
rest. First consumer: the tank, which books calls only for bound agents.
No GATE. Degraded: a registry read that fails means the book refuses every
append until it succeeds; a stale roster is never assumed.

### Hop 1b: replication and divergence (membrane, with hop 1)

Initial: the rail is lossy by ruling (Aug 6, "votes can land with a
poisson, not guaranteed all land"); a book lives on one seat. Target: every
entry is broadcast to every member seat of the unit and every member keeps
the unit's book; the closer publishes the root and the ordered list of
envelope hashes; each member checks that its own entries are in the list
and re-submits any that are missing before the close is final; a close is
final when the unit's seal attests the root, which is the same `attest` the
votes use. First consumer: hop 2's first epoch. No GATE. Degraded: a member
whose entry is missing at the final close holds a signed entry the root
does not bind, which is a proof of omission it can present; the entry is
paid in the next epoch, never silently dropped.

### Hop 2: the tank

Initial: the studio's `server.py` holds a fal key and a Reactor key in
memory, proxies one endpoint each, writes receipts under `recordings/`, and
refuses when unconfigured; on the chain a unit can `open_allowance` to a
payee with a cap per period. Target: `antimirror-app/tools/swarmclock-tankd.py`
on the operator's seat, generalising the studio proxy: `POST /call` with a
provider name and a body; the tank forwards to the provider, books one
`ec.swarmclock.call.v1` entry per call, keeps a running total per unit per
epoch, and refuses at the cap; `close` at the epoch end; the operator
`pull`s the epoch's cost against the unit's allowance with the root as the
hash. Three entries the tank books besides calls: an `ec.swarmclock.rate.v1`
entry at the open of every epoch fixing the chain asset per micro-dollar
for that epoch, so the pull amount is a computation and not a word; an
`ec.swarmclock.fuel.v1` entry for a key that paid the tank directly, the
transfer signature as its hash, so an agent that brings its own inference
(Aug 17) is metered against its own fuel and never against the unit's
allowance; and an `ec.swarmclock.reconcile.v1` entry per epoch carrying
the provider's own accounting where a provider exposes it (fal's usage
page billed 42.11 metered seconds for a 10 s film tonight), so the book's
cost and the provider's cost are two lines a reader can compare. Verified by: a call receipt in the book whose output hash matches the
saved artifact, a root file, and a `pull` transaction on devnet carrying
that root. GATE: the unit's seal opens the allowance (alice on devnet);
the operator pastes provider keys by hand (never an agent). Degraded: cap
reached means refuse, never overdraw; provider failure books a `call` with
outcome `failed` and zero cost, so a lost datagram is never a remembered
charge (the rule a teammate gave for `mccr.agent_action`).

### Hop 3: work, grade, payout

Initial: the review board writes verdicts to `recordings/verdicts/`; on the
chain `open_contract` escrows a price with a named arbiter and
`rule_contract` releases or refuses it. Target: a work item is a root of
`ec.swarmclock.work.v1` entries (the artifact hashes and the calls that made
it); the grader books `ec.swarmclock.grade.v1` with the verdict vocabulary
of the review board (keep, iterate, kill, and the wrong tags); the arbiter
unit rules the contract with outcome 1 on keep, 0 otherwise. First
consumer: one memory-film job, the studio's render as the work, the
board's verdict as the grade, the worker's seat as the payee. GATE: R3
names the arbiter unit. Degraded: no grade before the deadline means the
contract expires by `expire_contract` and the price returns; a grade with
no proof against a work root is not a grade.

### Hop 4: the lease

Initial: a person's traces sit in the aup bank per `actor_id` with
confidentiality labels; TraceNet's rule holds that a trace propagates only
with a valid `human_key` signature. Target: a lessor's reader serves one
branch of one tree to one subscriber for one day; the subscriber opened an
allowance to the lessor with `period` one day and `cap` the day price; each
served day is an `ec.swarmclock.lease.v1` epoch whose root the lessor
`pull`s; the reader checks the previous day's pull before serving the next.
First consumer: one named creator's agent-working traces, C1 or lower,
consented by their human key. Label policy, fixed here for every entry
type: call, rate, fuel, reconcile and grade entries are C1_HIVE and
replicate to every member seat; lease entries name the branch and the day
but never the subscriber's reads, and are C2_BRANCH, replicated only
between lessor and subscriber; testimony entries are C2_BRANCH within the
unit; anything C3_PRIVATE never enters a book, which the aup bank already
enforces at the sync boundary. GATE: consent per trace (human key), never a
minor, never private speech, and R7 on where enforcement lives. Degraded: a
day with no pull serves nothing; a revoked or expired allowance ends the
lease without a message to anyone, which is the point.

### Hop 5: the mutual

Initial: seat sales and the seat market exist; lot auctions with sealed
second-price settlement exist; `charge_fee` takes the fund's share of every
settlement; the dividend policy accrues income into distributions. Target:
a pool unit whose members buy seats (the dues), whose tank spends the pooled
allowance on work, whose graded work is offered as lots, whose settlements
carry the fund's fee, and whose dividend policy pays the rebate to every
seat pro rata at `seats × weight`. First consumer: the benchmark pool, with
the arbiter chairs as the experts who certify lots. GATE: the pool's seal on
its own policy; R3 on who the experts are. Degraded: a period with no income
rolls without a distribution, as the program already does; a lot no expert
certified is never opened.

### Hop 6: recovery

Initial: `transfer_seats` moves a holder's seats to any key or unit and
respects the resting window; `attest` verifies rail envelopes as votes;
`MAX_SEATS_PER_HOLDER` caps a holder at 150. Target: a member of a narrow
unit whose seats the unit holds loses a key; members book
`ec.swarmclock.testimony.v1` envelopes naming the member and the new key;
the unit proposes `transfer_seats` to the new key, the testimony envelopes
are the votes `attest` lands, the double seal passes, `execute` runs. First
consumer: a crew polis of humans and their agents. GATE: R4, only a unit
that declared itself narrow may execute this class. Degraded: fewer than
the seal's thresholds means no transfer, the seats stay with the unit; a
testimony from a key not in the roster is quarantined by the admit gate.

### Hop 7: the herald

Initial: films and pages exist; nothing posts. Target: an
`ec.swarmclock.herald.v1` entry with the artifact's hash and the post's URL,
booked after a human presses post, and an `ec.swarmclock.referral.v1`
entry when a knock arrives carrying that post's code, so the board's loop
("referred on Embertide by this video, code XYZ") is a receipt in the
herald's book and not a claim. What a referral is worth is ruling R8.
GATE: every outbound post is a human click on a human account, per the
outbound rule. Degraded: no click, no entry, no claim of virality; a code
with no herald entry is refused at the knock.

### Hop 8: the reader on the pages

Initial: the wall reads the chain; no page reads a book. Target:
`poleis-journey/js/book-verify.mjs`, a browser verifier for a proof against
a root, and one page under `app/` that shows an entry, its proof, and the
anchored root. First consumer: the tank's first `pull` from hop 2. No GATE.
Degraded: a root not found on the chain shows UNANCHORED, never VERIFIED.

## 4. GAPS WE ACCEPT

- Providers take cards, not the chain's asset. The operator converts, and
  the unit's trust in the operator is bounded by the allowance cap and the
  epoch. We accept that bound rather than build a conversion rail.
- Grading is human or committee at first. The grade vocabulary is the
  review board's. We accept slow grades over fast wrong ones.
- An epoch is at most about six days, the `MAX_WINDOW_SLOTS` ceiling. A
  book that is not closed in time is not paid in time.
- There is no court. A dispute is a proof presented on the rail and a
  refusal on the chain. We accept that the chain does not adjudicate.
- Lease access is enforced by the lessor's reader, not by the chain. A
  lessor who serves without a pull is cheating themselves.
- The rate is the operator's quote, booked before the epoch. We accept a
  quoted rate over an oracle; a unit that dislikes the quote revokes the
  allowance.

## 5. NOT BUILT NOW

- The proposal-drafting and receiving layer, flagged three times since
  Aug 17. The loop above needs none of it.
- BLS or post-quantum signatures on the rail (O1 declared them, not built).
- Automatic conversion from the chain's asset to provider credit.
- The meta-polis allocation surface (fees to compute for cancer).
- Cross-swarm ordering. Each swarm is its own layer two.
- Posting by agents. The herald is a human click.

## 6. CONVERGENCE

- The program: `open_allowance`, `pull` (with its 32-byte hash),
  `open_contract`, `rule_contract`, `expire_contract`, `set_dividend_policy`,
  `accrue_dividend`, `claim_dividend`, `open_lot` and the sealed auction,
  `charge_fee`, `seat_chair`, `list_seats`, `buy_seats`, `transfer_seats`,
  `propose`, `attest`, `seal`, `execute`. Not one is new.
- The rail: `chat_crypto.py` seal and open with the fail-closed admit gate
  and the two mandatory labels; `swarmclock-chatd.py` on seat-a; the Mac
  rail in `antimirror-app/bin/antimirror`; `swarm.json` as the allowlist.
- The studio's proxy: `server.py` holds keys in memory, refuses when
  unconfigured, writes receipts with provider request ids, and dedups by
  fingerprint. The tank is this, generalised and booked.
- The review board's verdict files and vocabulary.
- The aup bank's TraceDigest with confidentiality labels; TraceNet's
  human key as the consent gate.
- The lineage tree, whose parents are already content hashes.

## 7. COSTS

Bootstrap tier: zero new infrastructure. Python on the seats that already
run the rail, devnet SOL, one anchor transaction per epoch per unit (a few
thousand lamports, estimate). The line that scales is provider spend
through the tank: tonight two films cost $4.17 on fal and one Reactor
session cost an unread amount, so a pool of a hundred seats generating a
film a day each is on the order of $200 a day at fal's current meter
(estimate). What bends it: Reactor for volume once its capture is fixed,
480p where the eye allows, and the mutual pooling spend so no seat bets
alone.

## 8. RULINGS

### RATIFIED (verbatim, dated, who ruled)

- 2026-08-22, alice: Solana is the sovereign plane, SwarmClock coordinates
  signed intentions.
- 2026-08-30, alice: the swarm itself is a layer two; Solana is touched only
  when money is earned or spent; channel-state signatures plus on-chain
  settlement anchors suffice.
- 2026-09-01, alice, O1: votes live on swarmclock; the chain gets the seal.
- 2026-09-07, alice: "money in vault, money lands in tank (fuel), agents are
  getting paid for using USDC, we keep persisting the traces for the
  benchmark, we post the stuff on twitter for virality and we retain
  traces."
- 2026-09-07, alice: "sealed bids auctions auctioning off the traces but
  governed by experts, perhaps an intermediate step"; subscription to the
  access of someone's traces, "likely billed as daily access".
- 2026-09-07, alice: the mutua, "they pool resources and they are able to
  earn a little that way, it's like cashback on AI credits"; the viral side
  is the subscription to a named person's traces.
- 2026-09-07, alice: recursive DAOs are the neghiverses that attract money
  to invest like a mutua; iDAOs are the posiverses for leaner teams, and
  social recovery with the Dunbar number lives there.
- 2026-09-07, alice: "Anything that needs to be on Solana is all on Solana,
  for all we want. If things get accumulated/hashed that is fine as well."

### OPEN (the forks only alice can close, sharpest first)

- R1, the asset. The Poleis PRD's R6 says SOL only; tonight's loop says
  USDC. Allowances and contracts carry a `mint` field, so USDC is a mint,
  not a token of ours. Rule: SOL, USDC, or both, per unit.
- R2, the epoch. Daily by default, matching the lease, or per unit within
  the six-day ceiling.
- R3, the arbiter and the experts. Which unit grades work and certifies
  lots: the elected chairs of the pool (posiverses hired by the neghiverse,
  per O5), a standing grader unit, or the review board's seat until then.
- R4, the verse. Declared at founding and fixing the execution class and
  the recovery right, or read from the ledger by the direction of money.
- R5, the operator. Which seat holds provider keys for which units, and the
  cap that bounds it.
- R6, the herald. Which human account posts, and whether the post URL
  belongs in the book at all.
- R7, lease enforcement. The reader on the lessor's seat, as written, or a
  future chain-side gate.
- R8, the referral. Whether a booked referral pays the referrer, and from
  what: a share of the seat, a share of the fund's fee, or standing only.
