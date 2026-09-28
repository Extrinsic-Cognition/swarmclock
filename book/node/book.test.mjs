import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { leafHash, merkleRoot, merkleProof, verifyProof, rootOfFile, proveLine, verify } from './book.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const lines = (n) => Array.from({ length: n }, (_, i) => JSON.stringify({ i, text: `line ${i}` }, Object.keys({ i: 0, text: 0 }).sort()));

test('every index proves at every size', () => {
  for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 16, 33]) {
    const leaves = lines(n).map(leafHash), root = merkleRoot(leaves);
    for (let i = 0; i < n; i++) assert.ok(verifyProof(leaves[i], merkleProof(leaves, i), root), `${n}/${i}`);
  }
});
test('one altered byte fails', () => {
  const ls = lines(6), leaves = ls.map(leafHash), root = merkleRoot(leaves);
  const bad = Buffer.from(ls[3]); bad[5] ^= 1;
  assert.equal(verifyProof(leafHash(bad), merkleProof(leaves, 3), root), false);
});
test('order changes the root', () => {
  const ls = lines(5);
  assert.notEqual(merkleRoot(ls.map(leafHash)).toString('hex'), merkleRoot(ls.slice().reverse().map(leafHash)).toString('hex'));
});
test('foreign proof refused', () => {
  const a = lines(5).map(leafHash), b = lines(6).map(leafHash);
  assert.equal(verifyProof(a[2], merkleProof(a, 2), merkleRoot(b)), false);
});
test('shared vector binds Node to Python', () => {
  const vf = join(here, 'vector.json');
  if (!existsSync(vf)) return;
  const v = JSON.parse(readFileSync(vf, 'utf8'));
  const leaves = v.lines.map((l) => leafHash(Buffer.from(l, 'utf8')));
  assert.equal(merkleRoot(leaves).toString('hex'), v.root);
  for (const pr of v.proofs) assert.ok(verifyProof(Buffer.from(pr.leaf, 'hex'), pr.path.map(([s, h]) => [s, Buffer.from(h, 'hex')]), Buffer.from(v.root, 'hex')));
});
test('a file is a book: root, prove, verify', () => {
  const dir = mkdtempSync(join(tmpdir(), 'book-')), file = join(dir, 'e1.ndjson');
  writeFileSync(file, lines(7).join('\n') + '\n');
  const { root, count } = rootOfFile(file); assert.equal(count, 7);
  const proof = proveLine(file, 4); assert.equal(proof.root, root); assert.ok(verify(proof));
  proof.line = proof.line.replace('"i":4', '"i":5'); assert.equal(verify(proof), false);
});
