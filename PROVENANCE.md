# Provenance

This repository is a fresh cut (one genesis commit, no carried history) made on Sept 28 2026 from the private trees where the swarmclock grew. History is not carried on purpose: a subtree split would ship every value ever committed and later deleted. This file records where each file came from so the lineage stays checkable.

| file here | source repository | source path | at |
|---|---|---|---|
| `cli/am` | antimirror-app | `cli/am` | `18d7d00` (2026-09-21) |
| `tools/swarmclock` | antimirror-app | `tools/swarmclock` | `18d7d00` |
| `tools/swarmclock-chatd.py` | antimirror-app | `tools/swarmclock-chatd.py` | `18d7d00` |
| `tools/chat_crypto.py` | antimirror-app | `tools/chat_crypto.py` | `18d7d00` |
| `tools/vendored_ec_crypto.py` | antimirror-app | `tools/vendored_ec_crypto.py` | `18d7d00` |
| `tools/rail_bridge.py` | antimirror-app | `tools/rail_bridge.py` | `18d7d00` |
| `tools/mailboxd.py` | antimirror-app | `tools/mailboxd.py` | `18d7d00` |
| `tests/test_mailboxd_e2e.py` | antimirror-app | `tests/test_mailboxd_e2e.py` | `18d7d00` |
| `tools/swarmclock_book.py`, `tools/swarmclock_book_test.py` | antimirror-app | `tools/` on branch `tools/swarmclock-book` | `bc7e40d` (2026-09-07), never merged to main |
| `book/node/book.mjs`, `book.test.mjs`, `vector.json` | ec-workspace | `tools/swarmclock-book/` | `ce9f482` (2026-09-07) |
| `sidecar/Cargo.toml`, `Cargo.lock`, `src/main.rs` | ec-master-claw | `iroh_sidecar/` | `5939308` (2026-07-14, the open-source scrub) |
| `specs/swarmclock-c2c-v1.md`, `envelopes-v1.md`, `conformance-v1.md`, `state-machines-v1.md` | cyber-senate | `antimirror/antimirror-OSS/docs/specs/` | `691a8f2` (2026-07-14) |
| `specs/mailbox-v0.md` | antimirror-app | `docs/mailbox-v0.md` | `18d7d00` |
| `specs/call-ask-do-multisig-v1.md` | antimirror-app | `docs/CALLv1-ask-do-multisig-v0.md` | `18d7d00` |
| `docs/economy/PRD.md` | ec-workspace | `docs/poleis-swarmclock-economy-prd.md` | `936650b` (2026-09-07) |
| `docs/economy/ledger.md` | ec-workspace | `docs/swarmclock-economy-ledger.md` | `ce9f482` |
| `.github/workflows/secrets-scan.yml`, `text-hygiene.yml` | antimirror-app | `.github/workflows/` | `18d7d00` |
| `LICENSE`, `NOTICE` | cyber-senate | `antimirror/antimirror-OSS/` | `691a8f2` |
| `README.md`, `PROVENANCE.md`, `SECURITY.md`, `.gitignore`, `docs/economy/devnet-link.md` | new | | 2026-09-28 |

## Changes made in the cut

- **Names of people replaced by roles** (alice, bob, carol, dave; machines as seat-a, seat-b) in: `cli/am` (a comment), `tools/swarmclock-chatd.py` (two comments), `tests/test_mailboxd_e2e.py` (test strings), `specs/mailbox-v0.md`, `specs/call-ask-do-multisig-v1.md`, `docs/economy/PRD.md`, `docs/economy/ledger.md`. Quotes in those docs keep their words with the names replaced.
- **Paths made repo-relative**: the Python book test reads the shared vector from `book/node/vector.json`; `tools/swarmclock-chatd.py`, `tools/mailboxd.py` and `cli/am` also look for the sidecar at `sidecar/target/release/` (the mailbox's lookup into a private build folder was removed).
- Nothing else in the code was changed.

## Left out, and why

- `tools/rail_call.py`: superseded by `am call` (its own docstring says so) and bound to one machine's name.
- `tools/swarm-sync.py`: a controller-only tool that reads a private claw registry and member credentials; not portable.
- The Rust mesh crates (the Nest's engine): still moving, not in git, and placed by an earlier ruling inside the Nest's monorepo.
- The Poleis treasury program: already its own repository; linked from `docs/economy/devnet-link.md`, not copied.
- Internal briefs and audits that name people and machines.

## Checks run on the cut tree (Sept 28 2026)

- the July 14 open-source kit's `oss-safety-check.sh` (secret markers, personal paths, the private denylist) and `gitleaks`, inside `publish-fresh-cut.sh`
- `trufflehog filesystem --only-verified` as a second, independent scanner
- `python3 tools/swarmclock_book_test.py` (8/8), `node --test book/node/book.test.mjs` (6/6)
- `tests/test_mailboxd_e2e.py` with three real iroh identities: all checks passed
