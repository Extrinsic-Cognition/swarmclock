#!/usr/bin/env python3
"""Property tests for swarmclock_book: one altered byte fails, order changes the root,
a foreign proof is refused, every index proves at every size, and the shared vector
(book/node/vector.json) binds this implementation to the Node one."""
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import swarmclock_book as B  # noqa: E402

VECTOR = HERE.parent / "book" / "node" / "vector.json"


def lines_of(n):
    return [json.dumps({"i": i, "text": "line %d" % i}, sort_keys=True, separators=(",", ":")).encode() for i in range(n)]


class MerkleTests(unittest.TestCase):
    def test_every_index_proves_at_every_size(self):
        for n in (1, 2, 3, 4, 5, 7, 8, 9, 16, 33):
            leaves = [B.leaf_hash(l) for l in lines_of(n)]
            root = B.merkle_root(leaves)
            for i in range(n):
                self.assertTrue(B.verify_proof(leaves[i], B.merkle_proof(leaves, i), root), (n, i))

    def test_one_altered_byte_fails(self):
        ls = lines_of(6); leaves = [B.leaf_hash(l) for l in ls]; root = B.merkle_root(leaves)
        bad = bytearray(ls[3]); bad[5] ^= 1
        self.assertFalse(B.verify_proof(B.leaf_hash(bytes(bad)), B.merkle_proof(leaves, 3), root))

    def test_order_changes_the_root(self):
        ls = lines_of(5)
        a = B.merkle_root([B.leaf_hash(l) for l in ls]); b = B.merkle_root([B.leaf_hash(l) for l in reversed(ls)])
        self.assertNotEqual(a, b)

    def test_foreign_proof_refused(self):
        la = [B.leaf_hash(l) for l in lines_of(5)]; lb = [B.leaf_hash(l) for l in lines_of(6)]
        self.assertFalse(B.verify_proof(la[2], B.merkle_proof(la, 2), B.merkle_root(lb)))

    def test_empty_book_has_a_value(self):
        self.assertEqual(B.merkle_root([]), B.sha256(b"\x00"))

    def test_shared_vector(self):
        if not VECTOR.exists():
            self.skipTest("vector not generated yet")
        v = json.loads(VECTOR.read_text())
        leaves = [B.leaf_hash(l.encode()) for l in v["lines"]]
        self.assertEqual(B.merkle_root(leaves).hex(), v["root"])
        for pr in v["proofs"]:
            self.assertTrue(B.verify_proof(bytes.fromhex(pr["leaf"]), [(s, bytes.fromhex(h)) for s, h in pr["path"]], bytes.fromhex(v["root"])))


class CliTests(unittest.TestCase):
    def run_cli(self, *args, stdin=b""):
        env = dict(os.environ, SWARMCLOCK_BOOKS=self.books)
        r = subprocess.run([sys.executable, str(HERE / "swarmclock_book.py"), *args], input=stdin, capture_output=True, env=env)
        return r.returncode, json.loads(r.stdout.decode().strip().splitlines()[-1]) if r.stdout.strip() else {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.books = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_open_append_close_prove_verify(self):
        code, out = self.run_cli("open", "u1", "e1"); self.assertEqual(code, 0)
        for i in range(4):
            code, out = self.run_cli("append", "u1", "e1", "--retro", "call.v1", stdin=json.dumps({"n": i}).encode())
            self.assertEqual(code, 0, out); self.assertEqual(out["index"], i + 1)
        code, out = self.run_cli("close", "u1", "e1"); self.assertEqual(code, 0, out); root = out["root"]
        self.assertEqual(out["count"], 5)  # header + 4
        code, proof = self.run_cli("prove", "u1", "e1", "2"); self.assertEqual(code, 0)
        code, ver = self.run_cli("verify", "--root", root, stdin=json.dumps(proof).encode()); self.assertEqual(code, 0); self.assertTrue(ver["verified"])
        proof["line"] = proof["line"].replace('"n":1', '"n":9')
        code, ver = self.run_cli("verify", "--root", root, stdin=json.dumps(proof).encode()); self.assertEqual(code, 1); self.assertFalse(ver["verified"])
        code, out = self.run_cli("append", "u1", "e1", "--retro", "call.v1", stdin=b"{}"); self.assertEqual(code, 2)  # sealed

    def test_envelope_without_gate_refuses(self):
        self.run_cli("open", "u2", "e1")
        gate = HERE / "chat_crypto.py"
        if gate.exists():
            code, out = self.run_cli("append", "u2", "e1", "--envelope", stdin=b'{"not":"an envelope"}')
            self.assertIn(code, (2, 3)); self.assertFalse(out.get("ok"))
        else:
            code, out = self.run_cli("append", "u2", "e1", "--envelope", stdin=b"{}"); self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
