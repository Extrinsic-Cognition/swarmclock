#!/usr/bin/env python3
"""swarmclock_book: a unit's book, its roots, and the proofs that bind a line to a root.

A book is an append-only newline-JSON file of admitted lines for one unit and one
epoch: ~/.antimirror/books/<unit>/<epoch>.ndjson. Line one is the header. Every
other line is either a rail envelope the admit gate accepted (unchanged bytes) or,
for records that predate signing, a retro line that wraps the record and says so.

Closing an epoch computes a Merkle root over the exact line bytes (header included)
and writes <epoch>.root.json beside the book. The root is what the chain sees; the
lines are what the rail sees. A proof binds one line to one root and verifies with
no access to the book.

Algorithm (shared verbatim with tools/swarmclock-book/book.mjs in ec-workspace):
  leaf = sha256(0x00 || line_bytes)            line bytes exactly as stored, no newline
  node = sha256(0x01 || left || right)
  an odd node at any level is promoted unchanged (never duplicated)
  root of an empty book is sha256(0x00) so that "no lines" is still a value

Commands:
  open   <unit> <epoch>                          write the header if the book is new
  append <unit> <epoch> --retro KIND < record    book an unsigned record as a retro line
  append <unit> <epoch> --envelope < raw.json    book a rail envelope after the admit gate
  close  <unit> <epoch>                          write the root file, seal the book read-only
  prove  <unit> <epoch> <index|leafhex>          print an inclusion proof
  verify < proof.json [--root HEX]               recompute; exit 0 only on VERIFIED
  root   <unit> <epoch>                          print the root of the lines as they stand

Python 3 standard library only. The admit gate is tools/chat_crypto.py (same dir);
when it is missing, --envelope refuses instead of admitting blind.
"""
import argparse, hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path

BOOKS = Path(os.environ.get("SWARMCLOCK_BOOKS", Path.home() / ".antimirror" / "books"))
SCHEMA_BOOK, SCHEMA_ROOT, SCHEMA_PROOF = "swarmclock/book@v0", "swarmclock/book-root@v0", "swarmclock/book-proof@v0"
HERE = Path(__file__).resolve().parent


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def leaf_hash(line: bytes) -> bytes:
    return sha256(b"\x00", line)


def merkle_root(leaves):
    if not leaves:
        return sha256(b"\x00")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(sha256(b"\x01", level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def merkle_proof(leaves, index):
    """Path of (side, sibling) pairs from the leaf to the root; side is where the sibling sits.
    The parent index is always index // 2; a promoted odd node has no sibling at its level."""
    path, level, i = [], list(leaves), index
    while len(level) > 1:
        nxt = [sha256(b"\x01", level[j], level[j + 1]) for j in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        if i % 2 == 1:
            path.append(("left", level[i - 1]))
        elif i + 1 < len(level):
            path.append(("right", level[i + 1]))
        i //= 2
        level = nxt
    return path


def verify_proof(leaf, path, root):
    h = leaf
    for side, sibling in path:
        h = sha256(b"\x01", h, sibling) if side == "right" else sha256(b"\x01", sibling, h)
    return h == root


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def book_path(unit, epoch):
    return BOOKS / unit / f"{epoch}.ndjson"


def read_lines(path: Path):
    raw = path.read_bytes()
    return [l for l in raw.split(b"\n") if l]


def cmd_open(a):
    p = book_path(a.unit, a.epoch)
    if p.exists():
        print(json.dumps({"ok": True, "book": str(p), "existed": True}))
        return 0
    p.parent.mkdir(parents=True, exist_ok=True)
    header = {"type": "book.header", "schema": SCHEMA_BOOK, "unit": a.unit, "epoch": a.epoch,
              "opened_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "roster": a.roster or "unbound"}
    with p.open("xb") as f:
        f.write(canonical(header) + b"\n")
    print(json.dumps({"ok": True, "book": str(p), "existed": False}))
    return 0


def sealed(p: Path) -> bool:
    return p.with_suffix(".root.json").exists()


def cmd_append(a):
    p = book_path(a.unit, a.epoch)
    if not p.exists():
        print(json.dumps({"ok": False, "error": "book not open; run open first"})); return 2
    if sealed(p):
        print(json.dumps({"ok": False, "error": "epoch closed; open the next epoch"})); return 2
    raw = sys.stdin.buffer.read()
    if a.retro:
        try:
            record = json.loads(raw)
        except ValueError:
            print(json.dumps({"ok": False, "error": "retro record must be JSON"})); return 2
        line = canonical({"type": a.retro, "retro": True, "admitted": "retro",
                          "booked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "record": record})
    else:
        gate = HERE / "chat_crypto.py"
        if not gate.exists():
            print(json.dumps({"ok": False, "error": "admit gate tools/chat_crypto.py missing; refusing to admit blind"})); return 2
        import base64
        r = subprocess.run([sys.executable, str(gate)], input=json.dumps({"op": "open", "raw_b64": base64.b64encode(raw).decode()}),
                           capture_output=True, text=True)
        try:
            verdict = json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            print(json.dumps({"ok": False, "error": "admit gate gave no verdict", "stderr": r.stderr[-300:]})); return 2
        if not verdict.get("admit"):
            q = p.parent / "quarantine.ndjson"
            with q.open("ab") as f:
                f.write(canonical({"reasons": verdict.get("reasons"), "envelope_hash": verdict.get("envelope_hash")}) + b"\n")
            print(json.dumps({"ok": False, "error": "not admitted", "reasons": verdict.get("reasons")})); return 3
        if a.roster:
            allowed = set(json.loads(Path(a.roster).read_text()).get("keys", []))
            if verdict.get("sender_pubkey") not in allowed:
                print(json.dumps({"ok": False, "error": "sender not on the roster", "sender": verdict.get("sender_pubkey")})); return 3
        line = raw.strip().replace(b"\n", b"")  # the envelope's exact bytes, one line
    with p.open("ab") as f:
        f.write(line + b"\n")
    print(json.dumps({"ok": True, "leaf": leaf_hash(line).hex(), "index": len(read_lines(p)) - 1}))
    return 0


def cmd_root(a):
    p = book_path(a.unit, a.epoch)
    lines = read_lines(p)
    print(json.dumps({"ok": True, "root": merkle_root([leaf_hash(l) for l in lines]).hex(), "count": len(lines)}))
    return 0


def cmd_close(a):
    p = book_path(a.unit, a.epoch)
    if sealed(p):
        print(json.dumps({"ok": False, "error": "already closed", "root_file": str(p.with_suffix('.root.json'))})); return 2
    lines = read_lines(p)
    leaves = [leaf_hash(l) for l in lines]
    ts = []
    for l in lines[1:]:
        try:
            o = json.loads(l); ts.append(o.get("timestamp_ns") or o.get("booked_at") or o.get("record", {}).get("ts"))
        except ValueError:
            ts.append(None)
    root = {"schema": SCHEMA_ROOT, "unit": a.unit, "epoch": a.epoch, "count": len(lines),
            "root": merkle_root(leaves).hex(), "leaves": [x.hex() for x in leaves],
            "first_ts": next((t for t in ts if t), None), "last_ts": next((t for t in reversed(ts) if t), None),
            "closed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "closer": None, "signature": None}
    rp = p.with_suffix(".root.json"); tmp = rp.with_suffix(".tmp")
    tmp.write_text(json.dumps(root, indent=1) + "\n"); os.replace(tmp, rp)
    os.chmod(p, stat.S_IRUSR | stat.S_IRGRP)  # sealed read-only; the root file is the seal
    print(json.dumps({"ok": True, "root": root["root"], "count": len(lines), "root_file": str(rp)}))
    return 0


def cmd_prove(a):
    p = book_path(a.unit, a.epoch)
    lines = read_lines(p); leaves = [leaf_hash(l) for l in lines]
    if a.which.isdigit():
        idx = int(a.which)
    else:
        idx = next((i for i, x in enumerate(leaves) if x.hex() == a.which), -1)
    if not 0 <= idx < len(leaves):
        print(json.dumps({"ok": False, "error": "no such line in this book"})); return 3
    path = merkle_proof(leaves, idx)
    proof = {"schema": SCHEMA_PROOF, "unit": a.unit, "epoch": a.epoch, "index": idx, "leaf": leaves[idx].hex(),
             "path": [[s, h.hex()] for s, h in path], "root": merkle_root(leaves).hex(), "line": lines[idx].decode()}
    print(json.dumps(proof))
    return 0


def cmd_verify(a):
    proof = json.load(sys.stdin)
    root = bytes.fromhex(a.root or proof["root"])
    leaf = bytes.fromhex(proof["leaf"])
    if "line" in proof and leaf_hash(proof["line"].encode()) != leaf:
        print(json.dumps({"ok": True, "verified": False, "reason": "line does not hash to the leaf"})); return 1
    ok = verify_proof(leaf, [(s, bytes.fromhex(h)) for s, h in proof["path"]], root)
    print(json.dumps({"ok": True, "verified": ok, "root": root.hex()}))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="swarmclock_book")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("open", "append", "close", "prove", "root"):
        s = sub.add_parser(name); s.add_argument("unit"); s.add_argument("epoch")
        if name == "open":
            s.add_argument("--roster", help="what bound the roster for this epoch: 'chain:<registry>' or a note; default unbound")
        if name == "append":
            g = s.add_mutually_exclusive_group(required=True)
            g.add_argument("--retro", metavar="KIND", help="book an unsigned record under this kind, marked retro")
            g.add_argument("--envelope", action="store_true", help="book a rail envelope after the admit gate")
            s.add_argument("--roster", help="JSON file {keys:[pubkey hex]} the sender must be on")
        if name == "prove":
            s.add_argument("which", help="line index or leaf hex")
    v = sub.add_parser("verify"); v.add_argument("--root", help="root hex read from the chain; defaults to the proof's")
    a = ap.parse_args(argv)
    return {"open": cmd_open, "append": cmd_append, "close": cmd_close, "prove": cmd_prove, "root": cmd_root, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
