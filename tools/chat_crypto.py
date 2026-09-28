#!/usr/bin/env python3
"""Swarmclock chat crypto helper — E.1 signing profile via ec-claw-sdk.

The antimirror daemon (zero-dep Node) shells out here for envelope
signing/verification so the bytes match every other claw on the rail:
canonical JSON (sorted keys, no whitespace) -> BLAKE3 -> Ed25519.

stdin:  one JSON command
  {"op":"sign",   "envelope":{...minus signature...}, "key_path":"~/.ec-claw/bridge_signing_key.hex"}
  {"op":"verify", "envelope":{...including signature...}}
  {"op":"pubkey", "key_path":"~/.ec-claw/bridge_signing_key.hex"}
  {"op":"seal",   "msg_type":"swarmclock.chat.v0", "sender_node_id":"<hex>",
                  "payload":{...}, "key_path":"..."}
  {"op":"open",   "raw_b64":"<base64 wire envelope>"}
  {"op":"seal_to","recipient_pubkey":"<ed25519 hex>", "raw_b64":"<wire bytes>"}
  {"op":"unseal", "blob_b64":"<sealed blob>", "key_path":"..."}
stdout: one JSON result
  sign   -> {"ok":true, "signature":"<hex>", "sender_pubkey":"<hex>"}
  verify -> {"ok":true, "valid":true|false, "sender_pubkey":"<hex>"}
  pubkey -> {"ok":true, "sender_pubkey":"<hex>"}
  seal   -> {"ok":true, "raw_b64":"<wire-ready envelope>", "sender_pubkey":"<hex>"}
  seal_to-> {"ok":true, "blob_b64":"<ciphertext>", "blob_hash":"<hex>"}
  unseal -> {"ok":true, "raw_b64":"<original wire bytes>", "blob_hash":"<hex>"}
  open   -> {"ok":true, "valid":bool, "admit":bool, "reasons":[...],
             "integrity_label":..., "confidentiality_label":..., "age_s":float,
             "envelope_hash":"<hex>", "msg_type":..., "sender_pubkey":...,
             "sender_node_id":..., "ts_sender":"<iso>", "payload":{...}}

Envelopes carry the two mandatory gis-v1 labels inside the signed preimage
(envelopes-v1: labels are protocol fields, fail-closed). `open` reports an
`admit` verdict — bad signature, missing/invalid labels, or a stale
timestamp (>10 min skew) each add a reason and the caller MUST quarantine,
not deliver. Sender-allowlist and replay dedup stay in the caller (it owns
swarm.json and the long-lived seen-cache).

seal/open exist because envelopes carry timestamp_ns as a >2^53 integer:
a JavaScript JSON round-trip silently corrupts the digits and breaks the
signature. The daemon therefore hands wire bytes in and out of this helper
and never re-serializes a signed envelope itself.
"""
import base64
import json
import os
import sys
import time

SDK = os.path.expanduser('~/code-ec/ec-claw-sdk')
if SDK not in sys.path:
    sys.path.insert(0, SDK)

import blake3  # noqa: E402
from nacl.public import SealedBox  # noqa: E402
from nacl.signing import SigningKey, VerifyKey  # noqa: E402
try:
    from ec_claw_sdk.crypto import sign_canonical, verify_canonical, pubkey_hex, canonical_json  # noqa: E402
except ImportError:  # member Mac with only antimirror-app cloned — use the vendored copy
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from vendored_ec_crypto import sign_canonical, verify_canonical, pubkey_hex, canonical_json  # noqa: E402

VALID_INTEGRITY = {'T0_UNTRUSTED', 'T1_OBSERVED', 'T2_VERIFIED', 'T3_CORE'}
VALID_CONFIDENTIALITY = {'C0_PUBLIC', 'C1_HIVE', 'C2_BRANCH', 'C3_PRIVATE'}
FRESH_WINDOW_S = 600  # max |sender clock - our clock| before an envelope is stale


def main() -> None:
    cmd = json.loads(sys.stdin.read())
    op = cmd.get('op')
    if op == 'sign':
        key_path = os.path.expanduser(cmd['key_path'])
        seed = bytes.fromhex(open(key_path).read().strip())
        sk = SigningKey(seed)
        env = dict(cmd['envelope'])
        env.pop('signature', None)
        sig = sign_canonical(env, sk)
        print(json.dumps({'ok': True, 'signature': sig, 'sender_pubkey': pubkey_hex(sk)}))
    elif op == 'pubkey':
        key_path = os.path.expanduser(cmd['key_path'])
        seed = bytes.fromhex(open(key_path).read().strip())
        print(json.dumps({'ok': True, 'sender_pubkey': pubkey_hex(SigningKey(seed))}))
    elif op == 'seal':
        key_path = os.path.expanduser(cmd['key_path'])
        seed = bytes.fromhex(open(key_path).read().strip())
        sk = SigningKey(seed)
        env = {
            'protocol': 'ec/gossip/v1',
            'msg_type': cmd.get('msg_type', 'swarmclock.chat.v0'),
            'sender_node_id': cmd.get('sender_node_id', ''),
            'sender_pubkey': pubkey_hex(sk),
            'timestamp_ns': int(time.time() * 1e9),
            'integrity_label': cmd.get('integrity_label', 'T1_OBSERVED'),
            'confidentiality_label': cmd.get('confidentiality_label', 'C1_HIVE'),
            'payload': cmd.get('payload') or {},
        }
        env['signature'] = sign_canonical(env, sk)
        wire = canonical_json(env)  # module-level import — vendored fallback covers virgin Macs
        print(json.dumps({'ok': True, 'raw_b64': base64.b64encode(wire).decode(), 'sender_pubkey': env['sender_pubkey']}))
    elif op == 'open':
        raw = base64.b64decode(cmd['raw_b64'])
        env = json.loads(raw)
        sig = env.pop('signature', None)
        pub = env.get('sender_pubkey', '')
        valid = False
        if sig and pub:
            try:
                valid = verify_canonical(env, sig, VerifyKey(bytes.fromhex(pub)))
            except Exception:
                valid = False
        ts = env.get('timestamp_ns')
        il = env.get('integrity_label')
        cl = env.get('confidentiality_label')
        age_s = abs(time.time() - ts / 1e9) if isinstance(ts, (int, float)) else None
        reasons = []
        if not valid:
            reasons.append('bad_signature')
        if il not in VALID_INTEGRITY or cl not in VALID_CONFIDENTIALITY:
            reasons.append('missing_or_invalid_labels')
        if age_s is None or age_s > FRESH_WINDOW_S:
            reasons.append('stale_timestamp')
        print(json.dumps({
            'ok': True, 'valid': bool(valid),
            'admit': not reasons, 'reasons': reasons,
            'integrity_label': il, 'confidentiality_label': cl,
            'age_s': age_s, 'envelope_hash': blake3.blake3(raw).hexdigest(),
            'msg_type': env.get('msg_type'), 'sender_pubkey': pub,
            'sender_node_id': env.get('sender_node_id'),
            'ts_sender': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts / 1e9)) if isinstance(ts, (int, float)) else None,
            'payload': env.get('payload') or {},
        }))
    elif op == 'seal_to':
        # mailbox-v0: seal wire bytes to a recipient's allowlisted Ed25519
        # pubkey (converted to curve25519) so the mailbox stores ciphertext it
        # can never read. Input is raw wire bytes — never a re-serialized
        # envelope (the 2^53 timestamp rule).
        raw = base64.b64decode(cmd['raw_b64'])
        vk = VerifyKey(bytes.fromhex(cmd['recipient_pubkey']))
        blob = SealedBox(vk.to_curve25519_public_key()).encrypt(raw)
        print(json.dumps({'ok': True, 'blob_b64': base64.b64encode(blob).decode(),
                          'blob_hash': blake3.blake3(blob).hexdigest()}))
    elif op == 'unseal':
        # mailbox-v0: recover the original wire bytes with our own signing
        # key. The caller MUST still run the result through op=open — the
        # sealed box proves only that the blob was addressed to us.
        key_path = os.path.expanduser(cmd['key_path'])
        seed = bytes.fromhex(open(key_path).read().strip())
        blob = base64.b64decode(cmd['blob_b64'])
        raw = SealedBox(SigningKey(seed).to_curve25519_private_key()).decrypt(blob)
        print(json.dumps({'ok': True, 'raw_b64': base64.b64encode(raw).decode(),
                          'blob_hash': blake3.blake3(blob).hexdigest()}))
    elif op == 'verify':
        env = dict(cmd['envelope'])
        sig = env.pop('signature', None)
        pub = env.get('sender_pubkey', '')
        if not sig or not pub:
            print(json.dumps({'ok': True, 'valid': False, 'reason': 'missing signature or sender_pubkey'}))
            return
        vk = VerifyKey(bytes.fromhex(pub))
        valid = verify_canonical(env, sig, vk)
        print(json.dumps({'ok': True, 'valid': bool(valid), 'sender_pubkey': pub}))
    else:
        print(json.dumps({'ok': False, 'error': f'unknown op {op!r}'}))
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:  # single-shot helper: any failure is a JSON error line
        print(json.dumps({'ok': False, 'error': str(e)}))
        sys.exit(1)
