#!/usr/bin/env python3
"""mailboxd — blind store-and-forward mailbox on the always-on master claw.

docs/mailbox-v0.md. A sibling of swarmclock-chatd: wraps ec-iroh-sidecar
with its own iroh identity + signing key, speaks standard swarmclock.chat.v0
envelopes on the rail, and dispatches on payload.schema:

    ec.swarmclock.mailbox.put.v1    {to_pubkey, blob_b64, blob_hash, ttl_s?, hint?}
    ec.swarmclock.mailbox.drain.v1  {}            (recipient = envelope sender)
    ec.swarmclock.mailbox.ack.v1    {ids: [...]}  (delete delivered items)

The blob is ciphertext sealed to the recipient's Ed25519 key (chat_crypto
op=seal_to) — this daemon can never read a message and never tries. Identity
is fail-closed: put/drain/ack are only honored from pubkeys allowlisted in
<home>/swarm.json, and a drain only ever returns items addressed to the
*verified* sender pubkey, so recipient identity is unspoofable by design.

State under $EC_MAILBOX_HOME (default ~/.ec-mailbox):
    swarm.json                 peer allowlist {peers:{name:{node_id,pubkeys,relay_url,addrs}}}
    store/<to_pubkey>/<id>.json  one held item (ciphertext + metadata)
    mailbox_signing_key.hex    this daemon's publisher key (minted on first run)
    sidecar-home/              private HOME for the iroh sidecar identity
    mailbox-rail.json          published rail coordinates (node_id, pubkey, relays)
    receipts.ndjson            ids/sizes/pubkeys only — never payloads

Ops API (localhost only): GET http://127.0.0.1:7779/api/mailbox
"""
import base64
import json
import os
import re
import secrets
import socket
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

import blake3
from nacl.signing import SigningKey, VerifyKey

HOME = os.path.expanduser('~')
MAILBOX_HOME = os.path.expanduser(os.environ.get('EC_MAILBOX_HOME', os.path.join(HOME, '.ec-mailbox')))
SIDECAR_HOME = os.path.join(MAILBOX_HOME, 'sidecar-home')
STORE = os.path.join(MAILBOX_HOME, 'store')
SWARM_FILE = os.path.join(MAILBOX_HOME, 'swarm.json')
SIGNING_KEY = os.path.join(MAILBOX_HOME, 'mailbox_signing_key.hex')
RAIL_FILE = os.path.join(MAILBOX_HOME, 'mailbox-rail.json')
RECEIPTS = os.path.join(MAILBOX_HOME, 'receipts.ndjson')
LOG = os.path.join(MAILBOX_HOME, 'mailboxd.log')
SIDECAR_NAME = 'ec-iroh-sidecar.exe' if os.name == 'nt' else 'ec-iroh-sidecar'
SIDECAR_CANDIDATES = (
    os.path.join(HOME, '.ec-claw', 'runtime', 'bin', SIDECAR_NAME),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'vendor', SIDECAR_NAME),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sidecar', 'target', 'release', SIDECAR_NAME),
)
SIDECAR_BIN = os.environ.get('EC_IROH_SIDECAR') or next(
    (p for p in SIDECAR_CANDIDATES if os.path.exists(p)), SIDECAR_CANDIDATES[0]
)
PORT = int(os.environ.get('EC_MAILBOX_PORT', '7779'))

MSG_TYPE = 'swarmclock.chat.v0'   # ride the chat family so peers' peek-routing delivers us
VALID_INTEGRITY = {'T0_UNTRUSTED', 'T1_OBSERVED', 'T2_VERIFIED', 'T3_CORE'}
VALID_CONFIDENTIALITY = {'C0_PUBLIC', 'C1_HIVE', 'C2_BRANCH', 'C3_PRIVATE'}
FRESH_WINDOW_S = 600
SEEN_TTL_S = 2 * FRESH_WINDOW_S

# quotas — docs/mailbox-v0.md §2
MAX_ITEMS_PER_RECIPIENT = 200
MAX_BYTES_PER_RECIPIENT = 25 * 1024 * 1024
MAX_ITEM_BYTES = 512 * 1024
DEFAULT_TTL_S = 30 * 86400
MAX_TTL_S = 30 * 86400
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def log(*a):
    line = time.strftime('%Y-%m-%dT%H:%M:%S ') + ' '.join(str(x) for x in a)
    print(line, flush=True)
    with open(LOG, 'a') as f:
        f.write(line + '\n')


def receipt(kind, **detail):
    with open(RECEIPTS, 'a') as f:
        f.write(json.dumps({'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                            'kind': kind, **detail}) + '\n')


# ── E.1 signing profile (canonical JSON → BLAKE3 → Ed25519) ──────────────
def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def sign_envelope(env: dict, sk: SigningKey) -> str:
    body = {k: v for k, v in env.items() if k != 'signature'}
    return sk.sign(blake3.blake3(canonical_json(body)).digest()).signature.hex()


def verify_envelope(env: dict) -> bool:
    sig, pub = env.get('signature'), env.get('sender_pubkey')
    if not sig or not pub:
        return False
    body = {k: v for k, v in env.items() if k != 'signature'}
    try:
        VerifyKey(bytes.fromhex(pub)).verify(blake3.blake3(canonical_json(body)).digest(), bytes.fromhex(sig))
        return True
    except Exception:
        return False


def swarm_peers() -> dict:
    try:
        with open(SWARM_FILE) as f:
            return json.load(f).get('peers', {})
    except Exception:
        return {}


def peer_for_pubkey(pubkey: str):
    for name, p in swarm_peers().items():
        if pubkey in (p.get('pubkeys') or []):
            return name, p
    return None, None


def allowlisted_pubkeys() -> set:
    keys = set()
    for p in swarm_peers().values():
        keys.update(p.get('pubkeys') or [])
    return keys


# ── the store (ciphertext only) ───────────────────────────────────────────
def item_dir(to_pubkey: str) -> str:
    return os.path.join(STORE, to_pubkey)


def recipient_items(to_pubkey: str) -> list:
    d = item_dir(to_pubkey)
    out = []
    try:
        names = sorted(os.listdir(d))
    except FileNotFoundError:
        return []
    for n in names:
        if not n.endswith('.json'):
            continue
        try:
            with open(os.path.join(d, n)) as f:
                out.append(json.load(f))
        except Exception:
            pass
    return out


def store_item(item: dict) -> str:
    d = item_dir(item['to_pubkey'])
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, item['id'] + '.json')
    if os.path.exists(path):
        return 'duplicate'  # idempotent put — same blob, same id
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(item, f)
    os.replace(tmp, path)
    return 'stored'


def delete_items(to_pubkey: str, ids: list) -> int:
    n = 0
    for i in ids:
        if not isinstance(i, str) or not HEX64.match(i):
            continue
        p = os.path.join(item_dir(to_pubkey), i + '.json')
        if os.path.exists(p):
            os.remove(p)
            n += 1
    return n


def sweep_expired():
    now = time.time()
    swept = 0
    try:
        recipients = os.listdir(STORE)
    except FileNotFoundError:
        return
    for r in recipients:
        for it in recipient_items(r):
            if now - it.get('stored_epoch', now) > min(it.get('ttl_s', DEFAULT_TTL_S), MAX_TTL_S):
                delete_items(r, [it['id']])
                swept += 1
    if swept:
        receipt('mailbox.swept', count=swept)
        log('ttl sweep removed', swept, 'items')


# ── sidecar rail ──────────────────────────────────────────────────────────
class Rail:
    def __init__(self):
        self.proc = None
        self.node_id = None
        self.up = False
        self.pending = {}
        self.seen = {}
        self.lock = threading.Lock()
        seed_path = os.path.join(SIDECAR_HOME, '.ec-daemon', 'iroh', 'node_secret.hex')
        os.makedirs(os.path.dirname(seed_path), exist_ok=True)
        if not os.path.exists(seed_path):
            with open(seed_path, 'w') as f:
                f.write(secrets.token_bytes(32).hex())
            os.chmod(seed_path, 0o600)
            log('mailbox rail identity created at', seed_path)
        if not os.path.exists(SIGNING_KEY):
            with open(SIGNING_KEY, 'w') as f:
                f.write(secrets.token_bytes(32).hex())
            os.chmod(SIGNING_KEY, 0o600)
            log('minted mailbox signing key at', SIGNING_KEY)
        self.sk = SigningKey(bytes.fromhex(open(SIGNING_KEY).read().strip()))
        self.pubkey = self.sk.verify_key.encode().hex()
        log('mailbox publisher pubkey:', self.pubkey)

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        backoff = 5
        while True:
            env = dict(os.environ, HOME=SIDECAR_HOME, EC_TOPIC='ec/swarmclock/chat')
            if os.name == 'nt':
                env['USERPROFILE'] = SIDECAR_HOME
            log('starting sidecar', SIDECAR_BIN)
            self.proc = subprocess.Popen([SIDECAR_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
            for line in self.proc.stdout:
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                try:
                    self._on_event(ev)
                except Exception as e:  # one bad envelope must not kill the reader loop
                    log('handler error:', repr(e))
            self.up = False
            self.node_id = None
            log('sidecar exited, respawn in', backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

    def _on_event(self, ev):
        kind = ev.get('event')
        if kind == 'ready':
            self.up = True
            self.node_id = ev['node_id']
            with open(RAIL_FILE, 'w') as f:
                json.dump({'node_id': ev['node_id'], 'pubkey': self.pubkey,
                           'ip_addrs': ev.get('ip_addrs', []), 'relay_urls': ev.get('relay_urls', []),
                           'updated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}, f, indent=2)
            log('rail up, node_id', ev['node_id'])
        elif kind == 'send_result':
            with self.lock:
                slot = self.pending.pop(ev.get('reply_id'), None)
            if slot:
                slot['result'] = ev
                slot['event'].set()
        elif kind == 'envelope':
            # NEVER handle inline: put/drain handlers send replies and block
            # on send_result, which arrives on THIS reader thread — inline
            # handling deadlocks the loop until the send times out (proven by
            # the E2E: the ack sat unread for 50s). Workers keep the loop hot.
            threading.Thread(target=self._on_envelope, args=(ev,), daemon=True).start()
        elif kind == 'error':
            log('rail error:', ev.get('context'), str(ev.get('detail'))[:160])

    def _on_envelope(self, ev):
        try:
            raw = base64.b64decode(ev['raw_b64'])
            env = json.loads(raw)
        except Exception:
            return
        # fail-closed admit gate — same physics as every rail consumer
        reasons = []
        if not verify_envelope(env):
            reasons.append('bad_signature')
        sender_pubkey = env.get('sender_pubkey')
        peer_name, _ = peer_for_pubkey(sender_pubkey)
        if peer_name is None:
            reasons.append('unknown_sender')
        if env.get('integrity_label') not in VALID_INTEGRITY or \
           env.get('confidentiality_label') not in VALID_CONFIDENTIALITY:
            reasons.append('missing_or_invalid_labels')
        ts = env.get('timestamp_ns')
        age_s = abs(time.time() - ts / 1e9) if isinstance(ts, (int, float)) else None
        if age_s is None or age_s > FRESH_WINDOW_S:
            reasons.append('stale_timestamp')
        env_hash = blake3.blake3(raw).hexdigest()
        now = time.time()
        with self.lock:
            self.seen = {h: t for h, t in self.seen.items() if now - t < SEEN_TTL_S}
            if env_hash in self.seen:
                reasons.append('replay')
            else:
                self.seen[env_hash] = now
        p = env.get('payload') or {}
        schema = str(p.get('schema') or '')
        if reasons:
            receipt('mailbox.refused_envelope', reasons=reasons, schema=schema,
                    sender_pubkey=(sender_pubkey or '')[:16])
            log('REFUSED', ','.join(reasons), 'schema', schema or '?', 'from', (sender_pubkey or '')[:8])
            return
        if schema == 'ec.swarmclock.mailbox.put.v1':
            self._handle_put(p, sender_pubkey, peer_name)
        elif schema == 'ec.swarmclock.mailbox.drain.v1':
            self._handle_drain(sender_pubkey, peer_name)
        elif schema == 'ec.swarmclock.mailbox.ack.v1':
            self._handle_ack(p, sender_pubkey, peer_name)
        else:
            receipt('mailbox.ignored', schema=schema, peer=peer_name)

    # ---- handlers (sender identity = verified envelope pubkey, always) ----
    def _handle_put(self, p, sender_pubkey, peer_name):
        to_pubkey = str(p.get('to_pubkey') or '').lower()
        blob_b64 = p.get('blob_b64')
        refuse = None
        blob = None
        if not HEX64.match(to_pubkey):
            refuse = 'bad_to_pubkey'
        elif to_pubkey not in allowlisted_pubkeys():
            refuse = 'unknown_recipient'
        else:
            try:
                blob = base64.b64decode(blob_b64, validate=True)
            except Exception:
                refuse = 'bad_blob'
        if blob is not None and len(blob) > MAX_ITEM_BYTES:
            refuse = 'item_too_big'
        if blob is not None and refuse is None:
            blob_hash = blake3.blake3(blob).hexdigest()
            if p.get('blob_hash') and p['blob_hash'] != blob_hash:
                refuse = 'hash_mismatch'
        if refuse is None:
            held = recipient_items(to_pubkey)
            if len(held) >= MAX_ITEMS_PER_RECIPIENT or \
               sum(i.get('bytes', 0) for i in held) + len(blob) > MAX_BYTES_PER_RECIPIENT:
                refuse = 'over_quota'
        if refuse:
            receipt('mailbox.put.refused', reason=refuse, from_pubkey=sender_pubkey[:16],
                    to_pubkey=to_pubkey[:16], peer=peer_name)
            log('put REFUSED', refuse, 'from', peer_name)
            self._send_to_pubkey(sender_pubkey, {'schema': 'ec.swarmclock.mailbox.refusal.v1',
                                                 'reason': refuse, 'to_pubkey': to_pubkey})
            return
        item = {
            'id': blob_hash, 'to_pubkey': to_pubkey, 'from_pubkey': sender_pubkey,
            'blob_b64': blob_b64, 'blob_hash': blob_hash, 'bytes': len(blob),
            'ttl_s': min(int(p.get('ttl_s') or DEFAULT_TTL_S), MAX_TTL_S),
            'hint': str(p.get('hint') or '')[:40],
            'stored_ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'stored_epoch': time.time(),
        }
        outcome = store_item(item)
        receipt('mailbox.put', outcome=outcome, id=blob_hash[:16], bytes=len(blob),
                from_pubkey=sender_pubkey[:16], to_pubkey=to_pubkey[:16], hint=item['hint'])
        log('put', outcome, blob_hash[:12], f'{len(blob)}B', peer_name, '->', to_pubkey[:8])

    def _handle_drain(self, sender_pubkey, peer_name):
        items = recipient_items(sender_pubkey)
        receipt('mailbox.drain', peer=peer_name, held=len(items))
        log('drain from', peer_name, '-', len(items), 'held')
        for it in items:
            self._send_to_pubkey(sender_pubkey, {
                'schema': 'ec.swarmclock.mailbox.item.v1',
                'id': it['id'], 'blob_b64': it['blob_b64'], 'blob_hash': it['blob_hash'],
                'stored_ts': it['stored_ts'], 'from_pubkey': it['from_pubkey'],
                'hint': it.get('hint', ''),
            })

    def _handle_ack(self, p, sender_pubkey, peer_name):
        ids = p.get('ids') if isinstance(p.get('ids'), list) else []
        n = delete_items(sender_pubkey, ids[:200])
        receipt('mailbox.ack', peer=peer_name, deleted=n)
        log('ack from', peer_name, '- deleted', n)

    # ---- outbound (dial back the allowlisted peer, never the wire address) --
    def _send_to_pubkey(self, pubkey, payload):
        name, peer = peer_for_pubkey(pubkey)
        if not peer or not peer.get('node_id'):
            receipt('mailbox.send.error', to_pubkey=pubkey[:16], reason='no peer entry')
            return False
        envelope = {
            'protocol': 'ec/gossip/v1', 'msg_type': MSG_TYPE,
            'sender_node_id': self.node_id, 'sender_pubkey': self.pubkey,
            'timestamp_ns': int(time.time() * 1e9),
            'integrity_label': 'T1_OBSERVED', 'confidentiality_label': 'C1_HIVE',
            'payload': payload,
        }
        envelope['signature'] = sign_envelope(envelope, self.sk)
        reply_id = secrets.token_hex(8)
        slot = {'event': threading.Event(), 'result': None}
        with self.lock:
            self.pending[reply_id] = slot
        cmd = {'op': 'send', 'reply_id': reply_id, 'target_node_id': peer['node_id'],
               'timeout_s': 45, 'raw_b64': base64.b64encode(json.dumps(envelope).encode()).decode()}
        if peer.get('addrs'):
            cmd['target_addrs'] = peer['addrs']
        if peer.get('relay_url'):
            cmd['relay_url'] = peer['relay_url']
        self.proc.stdin.write(json.dumps(cmd) + '\n')
        self.proc.stdin.flush()
        if not slot['event'].wait(50):
            with self.lock:
                self.pending.pop(reply_id, None)
            result = {'status': 'timeout'}
        else:
            result = slot['result']
        ok = result.get('status') == 'ok'
        if not ok:
            receipt('mailbox.send.error', to=name, schema=payload.get('schema'),
                    status=result.get('status'), detail=str(result.get('detail'))[:120])
            log('send', payload.get('schema'), '->', name, 'FAILED:', result.get('status'))
        return ok


rail = Rail()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith('/api/mailbox'):
            held = {}
            try:
                for r in os.listdir(STORE):
                    items = recipient_items(r)
                    if items:
                        held[r[:16]] = {'items': len(items), 'bytes': sum(i.get('bytes', 0) for i in items)}
            except FileNotFoundError:
                pass
            body = json.dumps({'rail': {'up': rail.up, 'node_id': rail.node_id, 'pubkey': rail.pubkey},
                               'peers': list(swarm_peers().keys()), 'held': held}).encode()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def main():
    os.makedirs(MAILBOX_HOME, exist_ok=True)
    os.makedirs(STORE, exist_ok=True)
    rail.start()

    def sweeper():
        while True:
            time.sleep(3600)
            try:
                sweep_expired()
            except Exception as e:
                log('sweep error:', repr(e))
    threading.Thread(target=sweeper, daemon=True).start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer(('127.0.0.1', PORT), Handler)
    log(f'mailboxd on http://127.0.0.1:{PORT} (home {MAILBOX_HOME})')
    srv.serve_forever()


if __name__ == '__main__':
    main()
