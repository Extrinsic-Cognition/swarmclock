#!/usr/bin/env python3
"""mailbox-v0 E2E: put → durable hold → drain → unseal → admit → ack → delete.

Runs the REAL mailboxd (tools/mailboxd.py) and the REAL iroh sidecar with
three isolated identities (mailbox, sender, recipient) under a temp root.
Never touches ~/.antimirror or the live pill daemon.

Proves, in order:
  1. sender seals a signed chat envelope to the recipient's key and puts it
     to the mailbox over the rail;
  2. the item is durably on the mailbox disk as ciphertext (the plaintext
     text does NOT appear anywhere under the mailbox home);
  3. an unknown sender's put is refused (fail-closed allowlist);
  4. the recipient drains, receives the item, unseals it, and the INNER
     envelope still passes signature verification with the original bytes;
  5. ack deletes the item from the store; a re-drain delivers nothing.

Usage:  ~/.ec-claw/runtime/ecclaw_venv/bin/python3 tests/test_mailboxd_e2e.py
"""
import base64
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import blake3
from nacl.signing import SigningKey

APP_ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = APP_ROOT / 'tools'
SIDECAR = os.environ.get('EC_IROH_SIDECAR') or next((str(p) for p in [
    pathlib.Path.home() / '.ec-claw' / 'runtime' / 'bin' / 'ec-iroh-sidecar',
    APP_ROOT / 'vendor' / 'ec-iroh-sidecar',
    pathlib.Path.home() / 'code-ec' / 'ec-claw-handoff-sfo3' / 'iroh_sidecar' / 'target' / 'release' / 'ec-iroh-sidecar',
] if p.exists()), None)
assert SIDECAR, 'no ec-iroh-sidecar binary found'
PY = sys.executable
MB_PORT = 17779


def crypto(cmd: dict) -> dict:
    p = subprocess.run([PY, str(TOOLS / 'chat_crypto.py')], input=json.dumps(cmd).encode(),
                       capture_output=True, timeout=30)
    out = json.loads(p.stdout)
    assert out.get('ok'), f'chat_crypto {cmd["op"]} failed: {out}'
    return out


class Seat:
    """A raw rail endpoint: one sidecar + one signing key, isolated home."""

    def __init__(self, root: pathlib.Path, name: str):
        self.name = name
        self.home = root / name
        (self.home / '.ec-daemon' / 'iroh').mkdir(parents=True)
        (self.home / '.ec-daemon' / 'iroh' / 'node_secret.hex').write_text(secrets.token_bytes(32).hex())
        self.key_path = self.home / 'signing_key.hex'
        self.key_path.write_text(secrets.token_bytes(32).hex())
        self.pubkey = SigningKey(bytes.fromhex(self.key_path.read_text().strip())).verify_key.encode().hex()
        self.node_id = None
        self.addrs = []
        self.relays = []
        self.events = []
        self.pending = {}
        self.lock = threading.Lock()
        self.ready = threading.Event()
        env = dict(os.environ, HOME=str(self.home), EC_TOPIC='ec/swarmclock/chat')
        self.proc = subprocess.Popen([SIDECAR], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get('event') == 'ready':
                self.node_id = ev['node_id']
                self.addrs = ev.get('ip_addrs', [])
                self.relays = ev.get('relay_urls', [])
                self.ready.set()
            elif ev.get('event') == 'send_result':
                with self.lock:
                    slot = self.pending.pop(ev.get('reply_id'), None)
                if slot:
                    slot['result'] = ev
                    slot['done'].set()
            elif ev.get('event') == 'envelope':
                with self.lock:
                    self.events.append(ev)

    def send_payload(self, target: 'dict', payload: dict) -> dict:
        env = {
            'protocol': 'ec/gossip/v1', 'msg_type': 'swarmclock.chat.v0',
            'sender_node_id': self.node_id, 'sender_pubkey': self.pubkey,
            'timestamp_ns': int(time.time() * 1e9),
            'integrity_label': 'T1_OBSERVED', 'confidentiality_label': 'C1_HIVE',
            'payload': payload,
        }
        sk = SigningKey(bytes.fromhex(self.key_path.read_text().strip()))
        body = {k: v for k, v in env.items() if k != 'signature'}
        canon = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
        env['signature'] = sk.sign(blake3.blake3(canon).digest()).signature.hex()
        return self.send_raw(target, base64.b64encode(json.dumps(env).encode()).decode())

    def send_raw(self, target: dict, raw_b64: str) -> dict:
        reply_id = secrets.token_hex(8)
        slot = {'done': threading.Event(), 'result': None}
        with self.lock:
            self.pending[reply_id] = slot
        cmd = {'op': 'send', 'reply_id': reply_id, 'target_node_id': target['node_id'],
               'timeout_s': 30, 'raw_b64': raw_b64}
        if target.get('addrs'):
            cmd['target_addrs'] = target['addrs']
        self.proc.stdin.write(json.dumps(cmd) + '\n')
        self.proc.stdin.flush()
        assert slot['done'].wait(40), 'no send_result'
        return slot['result']

    def wait_envelopes(self, n: int, timeout: float = 30) -> list:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if len(self.events) >= n:
                    return list(self.events)
            time.sleep(0.2)
        with self.lock:
            return list(self.events)

    def stop(self):
        self.proc.terminate()


def main():
    root = pathlib.Path(tempfile.mkdtemp(prefix='mailbox-e2e-'))
    mb_home = root / 'mailbox-home'
    mb_home.mkdir()
    procs = []
    try:
        print('• starting seats (sender, recipient) …')
        sender = Seat(root, 'sender')
        recip = Seat(root, 'recipient')
        stranger = Seat(root, 'stranger')  # NOT in the mailbox allowlist
        for s in (sender, recip, stranger):
            assert s.ready.wait(30), f'{s.name} sidecar never came up'
        print(f'  sender    {sender.node_id[:12]}…  recipient {recip.node_id[:12]}…')

        # mailbox allowlists sender + recipient (with dial-back info), not the stranger
        (mb_home / 'swarm.json').write_text(json.dumps({'peers': {
            'sender': {'node_id': sender.node_id, 'pubkeys': [sender.pubkey], 'addrs': sender.addrs},
            'recipient': {'node_id': recip.node_id, 'pubkeys': [recip.pubkey], 'addrs': recip.addrs},
        }}))
        print('• starting mailboxd …')
        env = dict(os.environ, EC_MAILBOX_HOME=str(mb_home), EC_MAILBOX_PORT=str(MB_PORT),
                   EC_IROH_SIDECAR=SIDECAR)
        mb_proc = subprocess.Popen([PY, str(TOOLS / 'mailboxd.py')], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procs.append(mb_proc)
        rail_file = mb_home / 'mailbox-rail.json'
        for _ in range(150):
            if rail_file.exists():
                break
            time.sleep(0.2)
        assert rail_file.exists(), 'mailboxd rail never came up'
        mb = json.loads(rail_file.read_text())
        mb_target = {'node_id': mb['node_id'], 'addrs': mb.get('ip_addrs', [])}
        print(f'  mailboxd  {mb["node_id"][:12]}…')

        # 1. sender builds the inner signed chat envelope + seals it to the recipient
        secret_text = 'bob: the dinner moved to 21:30 — HOLD-THIS-PROOF'
        inner = crypto({'op': 'seal', 'msg_type': 'swarmclock.chat.v0', 'sender_node_id': sender.node_id,
                        'payload': {'schema': 'ec.swarmclock.chat.v1', 'text': secret_text,
                                    'from': 'alice', 'seat': 'test-mac', 'thread': 'team'},
                        'key_path': str(sender.key_path)})
        sealed = crypto({'op': 'seal_to', 'recipient_pubkey': recip.pubkey, 'raw_b64': inner['raw_b64']})

        # 2. put it (recipient is "offline" as far as this hop is concerned)
        r = sender.send_payload(mb_target, {'schema': 'ec.swarmclock.mailbox.put.v1',
                                            'to_pubkey': recip.pubkey,
                                            'blob_b64': sealed['blob_b64'],
                                            'blob_hash': sealed['blob_hash'], 'hint': 'chat'})
        assert r['status'] == 'ok', f'put transport failed: {r}'
        item_path = mb_home / 'store' / recip.pubkey / (sealed['blob_hash'] + '.json')
        for _ in range(50):
            if item_path.exists():
                break
            time.sleep(0.2)
        assert item_path.exists(), 'item not stored on mailbox disk'
        print('✓ put stored durably on the mailbox')

        # 3. blindness: plaintext must not exist anywhere under the mailbox home
        leak = subprocess.run(['grep', '-r', 'HOLD-THIS-PROOF', str(mb_home)], capture_output=True)
        assert leak.returncode != 0, 'PLAINTEXT LEAKED into the mailbox home!'
        print('✓ mailbox holds ciphertext only (plaintext grep is clean)')

        # 4. stranger's put is refused (fail-closed)
        r = stranger.send_payload(mb_target, {'schema': 'ec.swarmclock.mailbox.put.v1',
                                              'to_pubkey': recip.pubkey,
                                              'blob_b64': sealed['blob_b64'],
                                              'blob_hash': sealed['blob_hash']})
        time.sleep(1.5)
        stored = list((mb_home / 'store' / recip.pubkey).glob('*.json'))
        assert len(stored) == 1, f'stranger put must not be stored (found {len(stored)})'
        receipts = (mb_home / 'receipts.ndjson').read_text()
        assert 'refused_envelope' in receipts and 'unknown_sender' in receipts, 'no refusal receipt'
        print('✓ unknown sender refused, receipted')

        # 5. recipient drains → item arrives → unseal → inner gate
        r = recip.send_payload(mb_target, {'schema': 'ec.swarmclock.mailbox.drain.v1'})
        assert r['status'] == 'ok', f'drain transport failed: {r}'
        events = recip.wait_envelopes(1)
        assert events, 'no item envelope arrived on drain'
        outer = json.loads(base64.b64decode(events[0]['raw_b64']))
        assert outer['sender_pubkey'] == json.loads(rail_file.read_text())['pubkey'], 'item not signed by the mailbox'
        item = outer['payload']
        assert item['schema'] == 'ec.swarmclock.mailbox.item.v1', item['schema']
        back = crypto({'op': 'unseal', 'blob_b64': item['blob_b64'], 'key_path': str(recip.key_path)})
        assert back['raw_b64'] == inner['raw_b64'], 'inner wire bytes mutated in transit/storage'
        opened = crypto({'op': 'open', 'raw_b64': back['raw_b64']})
        assert opened['valid'], 'inner signature broken'
        assert opened['sender_pubkey'] == sender.pubkey, 'inner sender is not the original sender'
        assert opened['payload']['text'] == secret_text
        reasons = [x for x in opened['reasons'] if x != 'stale_timestamp']
        assert not reasons, f'inner envelope inadmissible: {reasons}'
        print('✓ drain delivered; unsealed; inner envelope intact and admissible (staleness forgiven)')

        # 6. ack deletes; re-drain delivers nothing new
        recip.send_payload(mb_target, {'schema': 'ec.swarmclock.mailbox.ack.v1', 'ids': [item['id']]})
        for _ in range(50):
            if not item_path.exists():
                break
            time.sleep(0.2)
        assert not item_path.exists(), 'ack did not delete the stored item'
        before = len(recip.wait_envelopes(0))
        recip.send_payload(mb_target, {'schema': 'ec.swarmclock.mailbox.drain.v1'})
        time.sleep(3)
        assert len(recip.wait_envelopes(0)) == before, 're-drain redelivered after ack'
        print('✓ ack deleted the item; re-drain is empty')

        # 7. ops endpoint answers
        with urllib.request.urlopen(f'http://127.0.0.1:{MB_PORT}/api/mailbox', timeout=5) as resp:
            status = json.loads(resp.read())
        assert status['rail']['up'] and not status['held'], status
        print('✓ ops endpoint healthy, store empty')
        print('\nALL MAILBOX E2E CHECKS PASSED')
    except BaseException:
        try:
            print('--- mailboxd.log tail ---')
            print('\n'.join((mb_home / 'mailboxd.log').read_text().splitlines()[-25:]))
            print('--- receipts tail ---')
            print('\n'.join((mb_home / 'receipts.ndjson').read_text().splitlines()[-10:]))
        except Exception:
            pass
        raise
    finally:
        for p in procs:
            p.terminate()
        try:
            sender.stop(); recip.stop(); stranger.stop()
        except Exception:
            pass
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    main()
