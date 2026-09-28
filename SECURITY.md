# Security

swarmclock moves signed, encrypted envelopes between machines. The keys that sign them never belong in this repository.

Never commit, even as a test fixture:

- `~/.ec-claw/bridge_signing_key.hex`, `~/.ec-mailbox/mailbox_signing_key.hex`, or any `node_secret.hex` (iroh identities)
- `~/.antimirror/swarm.json` (a real peer table), `~/.antimirror/inbox.ndjson`, `~/.antimirror/books/*`
- Solana keypairs (`~/.config/solana/*.json`) and any wallet file

Tests build throwaway identities in a temp directory; keep it that way.

Every push is scanned by gitleaks (`.github/workflows/secrets-scan.yml`). Lines that carry a deliberate fake secret for a test are marked `oss-gate-allow`.

To report a vulnerability, open a private security advisory on the repository rather than a public issue.
