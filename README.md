# swarmclock

Claw-to-claw: a peer-to-peer protocol for agents, over [iroh](https://iroh.computer), with one clock shared by every member of the swarm.

> "the protocol is called SwarmClock protocol it was designed to be Claw-2-Claw aka p2p for agent-to-agent" (Sept 6 2026)
>
> "swarmclock is the ALPN of iroh... thats it... no?" / "the entire point of swarmclock is to have an internal clock across all members of the swarm" (Sept 8 2026)
>
> "i think we can save money by using swarmclock as the consensus layer and then on solana we could post aggregate signatures" (Sept 1 2026)

## Status

> "you know swarmclock is not fully implemented or even tested... correct?" (Sept 9 2026)

That still holds. What exists, plainly:

| part | state |
|---|---|
| **the rail**: signed, fail-closed, end-to-end-encrypted messages and calls between agents' machines (`tools/`, `cli/am`) | runs: a live rail between machines since July 12 2026 |
| **the mailbox**: store-and-forward for a peer that is offline (`tools/mailboxd.py`) | built; its end-to-end test runs real iroh peers (`tests/test_mailboxd_e2e.py`) |
| **the iroh sidecar**: the native iroh I/O the Python rail speaks to over stdin/stdout (`sidecar/`, Rust, iroh 0.97) | built; one binary per machine |
| **the clock**: the book, an append-only, Merkle-rooted order of events with inclusion proofs, in Python (`tools/swarmclock_book.py`) and Node (`book/node/`), bound to each other by a shared vector | built and tested (Python 8/8, Node 6/6, same roots) |
| **the economy**: how work, grades and payouts ride the rail and settle on Solana (`docs/economy/`) | designed only |
| Byzantine tolerance, post-quantum signatures | not started |

## Layout

```
cli/am                    the CLI: status, whoami, join, send, tail, call, group, doctor
tools/swarmclock          legacy alias for cli/am
tools/swarmclock-chatd.py the rail daemon for a headless machine (HTTP on :7778)
tools/chat_crypto.py      envelope seal/open (Ed25519 over BLAKE3 of canonical JSON)
tools/vendored_ec_crypto.py
tools/rail_bridge.py      a local agent's door onto the rail
tools/mailboxd.py         the store-and-forward mailbox (HTTP on :7779)
tools/swarmclock_book.py  the clock (Python) + swarmclock_book_test.py
book/node/                the clock (Node) + the shared test vector
sidecar/                  ec-iroh-sidecar (Rust): stable NodeID, gossip, blobs, JSON-line IPC
specs/                    the protocol (c2c v1, envelopes, conformance, state machines, mailbox, calls)
docs/economy/             the economy PRD, its ledger, and the link to the Solana programs
```

## Run two peers

Requirements: Python 3.10+ with `pynacl` and `blake3`, Rust (stable), Node 20+ for the Node book.

```bash
pip install pynacl blake3
cargo build --release --manifest-path sidecar/Cargo.toml   # the CLI and daemons find sidecar/target/release/ec-iroh-sidecar
cli/am doctor                                              # what this machine still needs
```

On the first machine, `cli/am status` and `cli/am whoami` print its identity and an invite packet. On the second:

```bash
cli/am join '<packet>' --as bob     # TOFU -> knock -> receipt, one command
cli/am send alice "hello"           # or @group to fan out
cli/am tail --follow
cli/am call alice <fn> '{"x": 1}'   # a call to the other agent; replies come back through the inbox
```

Runtime state lives under `~/.antimirror/` (the peer table `swarm.json`, the inbox) and `~/.ec-claw/` (the signing key). Nothing there belongs in git. See [SECURITY.md](SECURITY.md).

Tests:

```bash
python3 tools/swarmclock_book_test.py
(cd book/node && node --test book.test.mjs)
python3 tests/test_mailboxd_e2e.py        # needs the sidecar built; runs three real iroh identities in a temp dir
```

## Solana

The rail carries signed intentions; settlement is on Solana. The economy PRD records the rule as "Solana is the sovereign plane, SwarmClock coordinates signed intentions" (Aug 22 2026) and adds "not one new instruction on the chain". The treasury program the economy settles against lives in its own repository; see [docs/economy/devnet-link.md](docs/economy/devnet-link.md).

## Where it came from

Cut on Sept 28 2026 from the working trees where it grew (the Antimirror app, the master claw, the July open-source kit, the workspace). Every file's source and commit is in [PROVENANCE.md](PROVENANCE.md). Names of people in the design notes are replaced by roles (alice, bob, carol).

## Licence

Apache-2.0 as drafted in the July 14 2026 open-source kit ([LICENSE](LICENSE), [NOTICE](NOTICE)). The licence is to be confirmed by the owner before the repository is made public.
