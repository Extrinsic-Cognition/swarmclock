// The book, in Node, for the place file and the pages: the same algorithm as
// antimirror-app/tools/swarmclock_book.py, byte for byte. A book is an append-only
// newline-JSON file; a root binds its exact line bytes; a proof binds one line to a root.
//   leaf = sha256(0x00 || line)   node = sha256(0x01 || left || right)   odd nodes promote
//   root of an empty book = sha256(0x00)
// Zero dependencies (Node >= 18). Consumers: the MCCR recorder's place file (one file per
// place per UTC day, which is already a book) and the Poleis pages' verifier.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
export const leafHash = (line) => sha256(Buffer.from([0]), Buffer.isBuffer(line) ? line : Buffer.from(line));
const pair = (l, r) => sha256(Buffer.from([1]), l, r);

export function merkleRoot(leaves) {
  if (!leaves.length) return sha256(Buffer.from([0]));
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(pair(level[i], level[i + 1]));
    if (level.length % 2) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0];
}

export function merkleProof(leaves, index) {
  // The parent index is always floor(i / 2); a promoted odd node has no sibling at its level.
  const path = []; let level = leaves.slice(), i = index;
  while (level.length > 1) {
    const next = [];
    for (let j = 0; j + 1 < level.length; j += 2) next.push(pair(level[j], level[j + 1]));
    if (level.length % 2) next.push(level[level.length - 1]);
    if (i % 2 === 1) path.push(['left', level[i - 1]]);
    else if (i + 1 < level.length) path.push(['right', level[i + 1]]);
    i = Math.floor(i / 2);
    level = next;
  }
  return path;
}

export function verifyProof(leaf, path, root) {
  let h = leaf;
  for (const [side, sibling] of path) h = side === 'right' ? pair(h, sibling) : pair(sibling, h);
  return h.equals(root);
}

export function readLines(file) {
  // Exact bytes, split on 0x0a, no decoding: a line hashes as it was stored.
  const buf = readFileSync(file), out = []; let start = 0;
  for (let i = 0; i <= buf.length; i++) if (i === buf.length || buf[i] === 0x0a) { if (i > start) out.push(buf.subarray(start, i)); start = i + 1; }
  return out;
}

export function rootOfFile(file) {
  const lines = readLines(file);
  return { root: merkleRoot(lines.map(leafHash)).toString('hex'), count: lines.length };
}

export function proveLine(file, index) {
  const lines = readLines(file), leaves = lines.map(leafHash);
  if (index < 0 || index >= leaves.length) throw new Error('no such line in this book');
  return { schema: 'swarmclock/book-proof@v0', index, leaf: leaves[index].toString('hex'),
    path: merkleProof(leaves, index).map(([s, h]) => [s, h.toString('hex')]),
    root: merkleRoot(leaves).toString('hex'), line: lines[index].toString('utf8') };
}

export function verify(proof, rootHex = proof.root) {
  const leaf = Buffer.from(proof.leaf, 'hex');
  if (proof.line !== undefined && !leafHash(Buffer.from(proof.line, 'utf8')).equals(leaf)) return false;
  return verifyProof(leaf, proof.path.map(([s, h]) => [s, Buffer.from(h, 'hex')]), Buffer.from(rootHex, 'hex'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, file, which] = process.argv.slice(2);
  if (cmd === 'root') console.log(JSON.stringify(rootOfFile(file)));
  else if (cmd === 'prove') console.log(JSON.stringify(proveLine(file, Number(which))));
  else if (cmd === 'verify') { const proof = JSON.parse(readFileSync(file, 'utf8')); const ok = verify(proof, which); console.log(JSON.stringify({ verified: ok })); process.exit(ok ? 0 : 1); }
  else { console.error('usage: book.mjs root <file> | prove <file> <index> | verify <proof.json> [rootHex]'); process.exit(2); }
}
