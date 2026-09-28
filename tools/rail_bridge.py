#!/usr/bin/env python3
"""rail-bridged — the listener that makes the swarmclock rail ring.

Tails ~/.antimirror/inbox.ndjson and:
  * RESULTv0 inbound  -> resolves the matching waiter in ~/.antimirror/calls/
                         and fires a macOS notification.
  * CALLv0 inbound    -> if fn is in the deterministic allowlist (ping, status),
                         answers immediately over the rail. Anything else is
                         queued to ~/.antimirror/calls/queue-inbound.ndjson and
                         notified — a human or an agent session picks it up.

Guardrails (deliberate, do not remove):
  * Acts ONLY on envelopes the rail gate marked verified=true. Fail-closed.
  * Outbound replies rate-capped (MAX_REPLIES_PER_HOUR). Beyond the cap it
    queues instead of replying — no chatter loops.
  * Every action appended to ~/.antimirror/rail-bridge.log (human-auditable).
  * No LLM invocation in v0 — deterministic handlers only. Waking an agent on
    queued calls is a separate, explicitly-enabled step.
"""
import json
import os
import platform
import subprocess
import time
import urllib.request
from pathlib import Path

HOME = Path.home()
INBOX = HOME / ".antimirror" / "inbox.ndjson"
CALLS_DIR = HOME / ".antimirror" / "calls"
QUEUE = CALLS_DIR / "queue-inbound.ndjson"
LOG = HOME / ".antimirror" / "rail-bridge.log"
SYNCTHING_API = "http://127.0.0.1:8384"
MAX_REPLIES_PER_HOUR = 12
POLL_S = 2


def _detect_rail_port() -> str:
    """SWARMCLOCK_PORT pins it; otherwise chatd (:7778, claw seats) wins over
    the app daemon (:7777, desktop seats) — same order as cli/am."""
    ports = [os.environ["SWARMCLOCK_PORT"]] if os.environ.get("SWARMCLOCK_PORT") else ["7778", "7777"]
    for p in ports:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{p}/api/chat", timeout=3) as r:
                if "rail" in json.load(r):
                    return p
        except Exception:
            continue
    return ports[-1]  # nothing up yet — the poll loop retries sends anyway


RAIL_PORT = _detect_rail_port()
RAIL_API = f"http://127.0.0.1:{RAIL_PORT}/api/chat/send"


def _self_claw() -> str:
    # membership name (written by `am join`) beats env beats hostname
    try:
        name = json.loads((HOME / ".antimirror" / "member.json").read_text()).get("name")
        if name:
            return name
    except Exception:
        pass
    return os.environ.get("SWARMCLOCK_ACTOR") or platform.node().split(".")[0]


SELF_CLAW = _self_claw()


def _peer_name_for(pubkey: str) -> str | None:
    """Resolve a sender_pubkey to its peer-table name — the correct reply
    address (replaces the old hostname-sniffing hack)."""
    try:
        peers = json.loads((HOME / ".antimirror" / "swarm.json").read_text()).get("peers", {})
    except Exception:
        return None
    return next((n for n, p in peers.items() if pubkey and pubkey in (p.get("pubkeys") or [])), None)


_reply_times: list[float] = []


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}\n"
    with LOG.open("a") as f:
        f.write(line)


def notify(title: str, text: str) -> None:
    cmd = (["osascript", "-e", f'display notification "{text}" with title "{title}"']
           if platform.system() == "Darwin" else ["notify-send", title, text])
    try:
        subprocess.run(cmd, capture_output=True, timeout=5)
    except Exception:
        pass  # headless seat — the log line is the notification


def send_rail(to: str, text: str) -> bool:
    now = time.time()
    _reply_times[:] = [t for t in _reply_times if now - t < 3600]
    if len(_reply_times) >= MAX_REPLIES_PER_HOUR:
        log(f"RATE-CAPPED reply to {to} (queued instead)")
        return False
    body = json.dumps({"to": to, "thread": "team", "text": text}).encode()
    req = urllib.request.Request(RAIL_API, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            ok = json.load(r).get("status") == "delivered"
        if ok:
            _reply_times.append(now)
        return ok
    except Exception as e:
        log(f"SEND ERROR to {to}: {e}")
        return False


def fn_ping(args: dict) -> dict:
    return {"pong": True, "claw": SELF_CLAW, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def fn_status(args: dict) -> dict:
    out = {"claw": SELF_CLAW, "rail": "up"}
    try:
        cfg = next(p for p in (
            HOME / "Library/Application Support/Syncthing/config.xml",   # macOS
            HOME / ".local/state/syncthing/config.xml",                  # Linux (new)
            HOME / ".config/syncthing/config.xml",                       # Linux (old)
        ) if p.exists()).read_text()
        key = cfg.split("<apikey>")[1].split("</apikey>")[0]
        req = urllib.request.Request(
            f"{SYNCTHING_API}/rest/db/status?folder=ec-vault", headers={"X-API-Key": key}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.load(r)
        out["syncthing"] = {"state": d.get("state"), "localFiles": d.get("localFiles"),
                            "localGB": round(d.get("localBytes", 0) / 1e9, 2)}
    except Exception as e:
        out["syncthing"] = f"unavailable: {e}"
    return out


def fn_describe(args: dict) -> dict:
    """AX: the rail describes itself so agents never read docs. One call
    returns who is here, what can be called, and the wire format."""
    out = {"claw": SELF_CLAW, "protocol": "c2c-call v0",
           "wire": {"call": 'CALLv0 {"call_id","fn","args","timeout_s","from_claw"}',
                    "result": 'RESULTv0 {"call_id","status":"ok|error|progress","payload"}'},
           "fns": sorted(ALLOWLIST.keys()),
           "guardrails": {"verified_envelopes_only": True, "rate_cap_per_hour": MAX_REPLIES_PER_HOUR,
                          "non_allowlisted": "queued for a human, no auto-reply"}}
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{RAIL_PORT}/api/chat?limit=1", timeout=5) as r:
            d = json.load(r)
        out["roster"] = {n: {"kind": p.get("kind") or ("claw" if "claw" in (p.get("label") or "").lower() else "necromancer"),
                             "soul": p.get("soul")} for n, p in (d.get("peers") or {}).items()}
    except Exception as e:
        out["roster"] = f"unavailable: {e}"
    return out


ALLOWLIST = {"ping": fn_ping, "status": fn_status, "describe": fn_describe}


def handle_call(entry: dict) -> None:
    try:
        env = json.loads(entry["text"][len("CALLv0 "):])
    except Exception:
        log(f"MALFORMED CALLv0 from {entry.get('from')}")
        return
    call_id, fn = env.get("call_id"), env.get("fn")
    # reply to the peer-table name bound to the sender's OWN key — the signed
    # envelope is the address, not whatever from_claw claims
    peer = _peer_name_for(entry.get("sender_pubkey")) or env.get("from_claw") or entry.get("from", "unknown")
    log(f"CALL {call_id} {fn} from {peer}")
    if fn in ALLOWLIST:
        payload = ALLOWLIST[fn](env.get("args") or {})
        result = {"call_id": call_id, "status": "ok", "payload": payload}
        if send_rail(peer, "RESULTv0 " + json.dumps(result)):
            log(f"REPLIED {call_id} {fn} -> ok")
            return
    with QUEUE.open("a") as f:
        f.write(json.dumps({"received": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **env}) + "\n")
    log(f"QUEUED {call_id} {fn} (not in allowlist or rate-capped)")
    notify("Rail call queued", f"{peer} -> {fn} ({call_id})")


def handle_result(entry: dict) -> None:
    try:
        env = json.loads(entry["text"][len("RESULTv0 "):])
    except Exception:
        log(f"MALFORMED RESULTv0 from {entry.get('from')}")
        return
    call_id = env.get("call_id")
    waiter_path = CALLS_DIR / f"{call_id}.json"
    if not waiter_path.exists():
        log(f"RESULT {call_id} with no waiter (ignored)")
        return
    w = json.loads(waiter_path.read_text())
    status = env.get("status", "ok")
    w["status"] = {"ok": "resolved", "error": "error", "progress": "progress"}.get(status, "resolved")
    w["payload"] = env.get("payload")
    w["resolved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    waiter_path.write_text(json.dumps(w, indent=2))
    log(f"RESOLVED {call_id} status={status}")
    if status != "progress":
        notify("Rail call resolved", f"{w['to']}.{w['fn']} -> {status}")


def main() -> None:
    CALLS_DIR.mkdir(parents=True, exist_ok=True)
    log("rail-bridged starting (allowlist: " + ", ".join(ALLOWLIST) + ")")
    pos = INBOX.stat().st_size if INBOX.exists() else 0
    while True:
        time.sleep(POLL_S)
        if not INBOX.exists():
            continue
        size = INBOX.stat().st_size
        if size < pos:  # rotated
            pos = 0
        if size == pos:
            continue
        with INBOX.open() as f:
            f.seek(pos)
            chunk = f.read()
            pos = f.tell()
        for line in chunk.splitlines():
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if entry.get("dir") != "in":
                continue
            if not entry.get("verified"):
                log(f"UNVERIFIED envelope from {entry.get('from')} — ignored (fail-closed)")
                continue
            text = entry.get("text", "")
            if text.startswith("CALLv0 "):
                handle_call(entry)
            elif text.startswith("RESULTv0 "):
                handle_result(entry)


if __name__ == "__main__":
    main()
