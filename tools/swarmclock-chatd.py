#!/usr/bin/env python3
"""swarmclock-chatd — claw-seat chat agent on the iroh E2EE rail.

The Linux/claw counterpart of the antimirror daemon's chat rail: wraps
ec-iroh-sidecar with a dedicated chat identity (never the ec-daemon's),
verifies inbound swarmclock.chat envelopes per the E.1 profile, appends
~/.antimirror/inbox.ndjson, and serves a local HTTP API claws use to talk:

    GET  http://127.0.0.1:7778/api/chat            rail state + messages
    POST http://127.0.0.1:7778/api/chat/send       {"to":"mac","text":"..."}

Peers live in ~/.antimirror/swarm.json:
    {"peers":{"mac":{"node_id":"...","pubkeys":["..."],"relay_url":"...","addrs":[]}}}

Identity: fresh iroh secret under ~/.antimirror/sidecar-home; envelopes are
signed with this seat's publisher key (~/.ec-claw/bridge_signing_key.hex),
already known to the fleet. E2EE: iroh QUIC endpoint-to-endpoint; relays
forward ciphertext only. No hosted service ever sees a message.
"""
import base64
import json
import os
import secrets
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler

import blake3
from nacl.signing import SigningKey, VerifyKey

HOME = os.path.expanduser('~')
IS_WIN = os.name == 'nt'
# a detached Windows chatd inherits a cp1252 stdout; '→'/'✦' in a log line
# would then raise UnicodeEncodeError mid-request (after the send succeeded)
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, 'reconfigure'):
        _stream.reconfigure(encoding='utf-8', errors='replace')
APP_HOME = os.path.join(HOME, '.antimirror')
SIDECAR_HOME = os.path.join(APP_HOME, 'sidecar-home')
INBOX = os.path.join(APP_HOME, 'inbox.ndjson')
QUARANTINE = os.path.join(APP_HOME, 'quarantine.ndjson')
SWARM_FILE = os.path.join(APP_HOME, 'swarm.json')
PEER_REGISTRY = os.path.join(APP_HOME, 'peer-registry.json')
RAIL_FILE = os.path.join(APP_HOME, 'chat-rail.json')
LOG = os.path.join(APP_HOME, 'chatd.log')
SIDECAR_NAME = 'ec-iroh-sidecar.exe' if IS_WIN else 'ec-iroh-sidecar'
SIDECAR_CANDIDATES = (
    os.path.join(HOME, '.ec-claw', 'runtime', 'bin', SIDECAR_NAME),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'vendor', SIDECAR_NAME),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'sidecar', 'target', 'release', SIDECAR_NAME),
)
SIDECAR_BIN = os.environ.get('EC_IROH_SIDECAR') or next(
    (p for p in SIDECAR_CANDIDATES if os.path.exists(p)), SIDECAR_CANDIDATES[0]
)
SIGNING_KEY = os.path.join(HOME, '.ec-claw', 'bridge_signing_key.hex')
PORT = int(os.environ.get('SWARMCLOCK_PORT', '7778'))
SEAT = socket.gethostname().split('.')[0]


def actor():
    # speaking identity, resolved per send: explicit env beats the name
    # `swarmclock join` recorded on admission (member.json) beats the
    # hostname fallback — so an admitted seat speaks as 'dave', not as
    # 'claw@host', from the moment the receipt lands, no restart needed
    if os.environ.get('SWARMCLOCK_ACTOR'):
        return os.environ['SWARMCLOCK_ACTOR']
    try:
        with open(os.path.join(APP_HOME, 'member.json')) as f:
            name = json.load(f).get('name')
        if name:
            return name
    except Exception:
        pass
    return 'claw@' + SEAT
MSG_TYPE = 'swarmclock.chat.v0'
VALID_INTEGRITY = {'T0_UNTRUSTED', 'T1_OBSERVED', 'T2_VERIFIED', 'T3_CORE'}
VALID_CONFIDENTIALITY = {'C0_PUBLIC', 'C1_HIVE', 'C2_BRANCH', 'C3_PRIVATE'}
FRESH_WINDOW_S = 600   # max |sender clock - our clock| before an envelope is stale
SEEN_TTL_S = 2 * FRESH_WINDOW_S  # replay cache horizon (must outlive the freshness window)
SEND_FAILURE_RESTART_THRESHOLD = max(2, int(os.environ.get('SWARMCLOCK_SEND_FAILURE_RESTART_THRESHOLD', '2')))
SEND_FAILURE_RESTART_COOLDOWN_S = max(0, int(os.environ.get('SWARMCLOCK_SEND_FAILURE_RESTART_COOLDOWN_S', '120')))


def log(*a):
    line = time.strftime('%Y-%m-%dT%H:%M:%S ') + ' '.join(str(x) for x in a)
    print(line, flush=True)
    with open(LOG, 'a') as f:
        f.write(line + '\n')


# ── E.1 signing profile (canonical JSON → BLAKE3 → Ed25519) ──────────────
def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def sign_envelope(env: dict, sk: SigningKey) -> str:
    body = {k: v for k, v in env.items() if k != 'signature'}
    return sk.sign(blake3.blake3(canonical_json(body)).digest()).signature.hex()


def verify_envelope(env: dict) -> bool:
    sig = env.get('signature')
    pub = env.get('sender_pubkey')
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


def registry_active_pubkeys():
    """Controller-projected member registry (tools_claw_registry.py
    export-peer-registry, deployed by tools/swarm-sync.py). Absent file →
    None: the gate is inactive and trust stays allowlist-only, so seats
    without controller state keep working. Present → a sender must ALSO be
    an active registered member; unreadable file admits nobody (fail-closed).
    This makes swarm.json a projection of authority truth, not parallel truth."""
    try:
        with open(PEER_REGISTRY) as f:
            agents = json.load(f).get('agents', {})
    except FileNotFoundError:
        return None
    except Exception:
        return set()
    keys = set()
    for a in agents.values():
        if a.get('status') != 'active':
            continue
        pk = str(a.get('pubkey_ed25519') or '')
        keys.add(pk.split(':', 1)[1] if ':' in pk else pk)
    return keys


def inbox_append(entry: dict) -> dict:
    entry = {'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **entry}
    os.makedirs(APP_HOME, exist_ok=True)
    with open(INBOX, 'a') as f:
        f.write(json.dumps(entry) + '\n')
    return entry


def quarantine_append(entry: dict) -> None:
    # Envelopes that fail the admit gate land here with the raw wire bytes:
    # evidence for the membrane, and the sender_pubkey a pairing flow needs
    # (a new seat's first message is quarantined as unknown_sender until its
    # pubkey is allowlisted in swarm.json).
    entry = {'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), **entry}
    os.makedirs(APP_HOME, exist_ok=True)
    with open(QUARANTINE, 'a') as f:
        f.write(json.dumps(entry) + '\n')


def inbox_tail(limit=200) -> list:
    try:
        with open(INBOX) as f:
            lines = [l for l in f.read().strip().split('\n') if l]
        out = []
        for l in lines[-limit:]:
            try:
                out.append(json.loads(l))
            except Exception:
                pass
        return out
    except FileNotFoundError:
        return []


# ── sidecar management ────────────────────────────────────────────────────
class Rail:
    def __init__(self):
        self.proc = None
        self.node_id = None
        self.up = False
        self.pending = {}  # reply_id -> threading.Event + slot
        self.seen = {}  # envelope_hash -> first-seen epoch (replay dedup)
        self.send_failures = {}  # peer -> consecutive completed send failures
        self.last_failure_restart_at = None
        self.lock = threading.Lock()
        seed_path = os.path.join(SIDECAR_HOME, '.ec-daemon', 'iroh', 'node_secret.hex')
        os.makedirs(os.path.dirname(seed_path), exist_ok=True)
        if not os.path.exists(seed_path):
            with open(seed_path, 'w') as f:
                f.write(secrets.token_bytes(32).hex())
            os.chmod(seed_path, 0o600)
            log('chat identity created at', seed_path)
        if not os.path.exists(SIGNING_KEY):
            # fresh seat (e.g. a Windows WSL seat): mint a gen-0 publisher key; peers
            # allowlist the printed pubkey to flip messages to verified.
            os.makedirs(os.path.dirname(SIGNING_KEY), exist_ok=True)
            with open(SIGNING_KEY, 'w') as f:
                f.write(secrets.token_bytes(32).hex())
            os.chmod(SIGNING_KEY, 0o600)
            log('minted new seat signing key at', SIGNING_KEY)
        self.sk = SigningKey(bytes.fromhex(open(SIGNING_KEY).read().strip()))
        self.pubkey = self.sk.verify_key.encode().hex()
        log('seat publisher pubkey:', self.pubkey)

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        backoff = 5
        while True:
            env = dict(os.environ, HOME=SIDECAR_HOME, EC_TOPIC='ec/swarmclock/chat')
            if IS_WIN:
                env['USERPROFILE'] = SIDECAR_HOME
            log('starting sidecar', SIDECAR_BIN)
            self.proc = subprocess.Popen([SIDECAR_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
            for line in self.proc.stdout:
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                self._on_event(ev)
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
            try:
                raw = base64.b64decode(ev['raw_b64'])
                env = json.loads(raw)
            except Exception:
                return
            if not str(env.get('msg_type', '')).startswith('swarmclock.chat'):
                inbox_append({'kind': 'ingress-other', 'from': ev.get('from'), 'msg_type': env.get('msg_type')})
                return
            # fail-closed admit gate (envelopes-v1): signature, sender allowlist,
            # mandatory gis labels, freshness, replay. Anything short → quarantine.
            peers = swarm_peers()
            peer_name = next((n for n, p in peers.items() if env.get('sender_pubkey') in (p.get('pubkeys') or [])), None)
            ts = env.get('timestamp_ns')
            age_s = abs(time.time() - ts / 1e9) if isinstance(ts, (int, float)) else None
            env_hash = blake3.blake3(raw).hexdigest()
            reasons = []
            if not verify_envelope(env):
                reasons.append('bad_signature')
            if peer_name is None:
                reasons.append('unknown_sender')
            reg = registry_active_pubkeys()
            if reg is not None and env.get('sender_pubkey') not in reg:
                reasons.append('unregistered_sender')
            if env.get('integrity_label') not in VALID_INTEGRITY or \
               env.get('confidentiality_label') not in VALID_CONFIDENTIALITY:
                reasons.append('missing_or_invalid_labels')
            if age_s is None or age_s > FRESH_WINDOW_S:
                reasons.append('stale_timestamp')
            now = time.time()
            with self.lock:
                self.seen = {h: t for h, t in self.seen.items() if now - t < SEEN_TTL_S}
                if env_hash in self.seen:
                    reasons.append('replay')
                else:
                    self.seen[env_hash] = now
            p = env.get('payload') or {}
            if reasons:
                quarantine_append({
                    'reasons': reasons, 'from': p.get('from'), 'seat': p.get('seat'),
                    'sender_pubkey': env.get('sender_pubkey'), 'sender_node_id': ev.get('from'),
                    'age_s': age_s, 'envelope_hash': env_hash, 'raw_b64': ev['raw_b64'],
                })
                log('chat QUARANTINED:', ','.join(reasons), 'from', p.get('from') or (env.get('sender_pubkey') or '')[:8])
                return
            entry = inbox_append({
                'kind': 'chat', 'dir': 'in',
                # pubkey-resolved name wins over self-declared 'from': a
                # delivered envelope's pubkey is a known peer (unknown_sender
                # is quarantined), so peer_name is the authoritative identity.
                'from': peer_name or p.get('from'),
                'seat': peer_name or p.get('seat'), 'text': str(p.get('text', ''))[:4000],
                'thread': p.get('thread', 'team'), 'verified': True,
                'integrity_label': env.get('integrity_label'),
                'confidentiality_label': env.get('confidentiality_label'),
                'sender_pubkey': env.get('sender_pubkey'), 'sender_node_id': ev.get('from'),
                'transport': ev.get('transport'),
            })
            log('chat in:', entry['from'], '—', entry['text'][:120])
        elif kind == 'error':
            log('rail error:', ev.get('context'), str(ev.get('detail'))[:160])

    def _record_send_health(self, peer_name: str, ok: bool) -> None:
        """Rotate a wedged sidecar after bounded, peer-specific failures.

        A successful send clears that peer's streak.  Rotation never retries
        the completed application message, so callers retain exactly-once
        responsibility and cannot create a duplicate host action.
        """
        proc = None
        failures = 0
        with self.lock:
            if ok:
                self.send_failures.pop(peer_name, None)
                return
            failures = self.send_failures.get(peer_name, 0) + 1
            self.send_failures[peer_name] = failures
            now = time.monotonic()
            cooldown_elapsed = self.last_failure_restart_at is None or \
                now - self.last_failure_restart_at >= SEND_FAILURE_RESTART_COOLDOWN_S
            if failures >= SEND_FAILURE_RESTART_THRESHOLD and cooldown_elapsed:
                self.last_failure_restart_at = now
                self.send_failures.clear()
                proc = self.proc
        if proc is not None and proc.poll() is None:
            log('rotating sidecar after consecutive send failures:', peer_name, failures)
            try:
                proc.terminate()
            except Exception as error:
                log('sidecar rotation failed:', str(error)[:160])

    def send(self, to: str, text: str, sender: str = None, thread: str = None) -> dict:
        peer = swarm_peers().get(to) or {}
        if not peer.get('node_id'):
            return {'error': f"unknown peer '{to}' — add it to ~/.antimirror/swarm.json"}
        if not self.up or not self.proc:
            return {'error': 'chat rail is down — sidecar not ready'}
        thread = str(thread or 'team')[:40]  # group sends stamp 'grp:<name>'
        envelope = {
            'protocol': 'ec/gossip/v1', 'msg_type': MSG_TYPE,
            'sender_node_id': self.node_id, 'sender_pubkey': self.pubkey,
            'timestamp_ns': int(time.time() * 1e9),
            'integrity_label': 'T1_OBSERVED', 'confidentiality_label': 'C1_HIVE',
            'payload': {'schema': 'ec.swarmclock.chat.v1', 'text': str(text)[:4000],
                        'from': sender or actor(), 'seat': SEAT, 'thread': thread},
        }
        envelope['signature'] = sign_envelope(envelope, self.sk)
        reply_id = uuid.uuid4().hex
        slot = {'event': threading.Event(), 'result': None}
        with self.lock:
            self.pending[reply_id] = slot
        cmd = {'op': 'send', 'reply_id': reply_id, 'target_node_id': peer['node_id'],
               'timeout_s': 45,
               'raw_b64': base64.b64encode(json.dumps(envelope).encode()).decode()}
        if peer.get('addrs'):
            cmd['target_addrs'] = peer['addrs']
        if peer.get('relay_url'):
            cmd['relay_url'] = peer['relay_url']
        self.proc.stdin.write(json.dumps(cmd) + '\n')
        self.proc.stdin.flush()
        if not slot['event'].wait(50):  # sidecar send timeout is 45s; first dial after a peer restart can take ~30s of rediscovery
            with self.lock:
                self.pending.pop(reply_id, None)
            result = {'status': 'timeout', 'detail': 'no send_result within 25s'}
        else:
            result = slot['result']
        ok = result.get('status') == 'ok'
        entry = inbox_append({'kind': 'chat', 'dir': 'out', 'from': sender or actor(), 'seat': SEAT,
                              'to': to, 'text': envelope['payload']['text'], 'thread': thread,
                              'verified': True, 'status': 'delivered' if ok else result.get('status'),
                              'detail': result.get('detail')})
        log('chat out:', 'ok' if ok else result.get('status'), '→', to, '—', entry['text'][:120])
        self._record_send_health(to, ok)
        return {'ok': True, 'status': 'delivered', 'entry': entry} if ok else \
               {'error': f"send {result.get('status')}: {result.get('detail') or 'peer unreachable'}", 'entry': entry}


rail = Rail()


# ── local HTTP API ────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith('/api/chat'):
            msgs = [m for m in inbox_tail() if m.get('kind') == 'chat']
            self._json(200, {'rail': {'up': rail.up, 'node_id': rail.node_id, 'pubkey': rail.pubkey},
                             'peers': swarm_peers(), 'messages': msgs})
        else:
            self._json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path == '/api/chat/send':
            try:
                body = json.loads(self.rfile.read(int(self.headers.get('content-length', 0))) or b'{}')
            except Exception:
                body = {}
            to, text = str(body.get('to', '')).strip(), str(body.get('text', '')).strip()
            if not to or not text:
                return self._json(400, {'error': 'to and text required'})
            r = rail.send(to, text, sender=body.get('from'), thread=body.get('thread'))
            self._json(502 if 'error' in r else 200, r)
        else:
            self._json(404, {'error': 'not found'})


def main():
    os.makedirs(APP_HOME, exist_ok=True)
    rail.start()
    socketserver.ThreadingTCPServer.allow_reuse_address = True  # must be set before bind
    srv = socketserver.ThreadingTCPServer(('127.0.0.1', PORT), Handler)
    log(f'swarmclock-chatd on http://127.0.0.1:{PORT} (seat {SEAT})')
    srv.serve_forever()


if __name__ == '__main__':
    main()
