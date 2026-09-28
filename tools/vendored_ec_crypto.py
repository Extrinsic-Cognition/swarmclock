"""
EC Claw SDK — Cryptographic primitives.
(vendored verbatim from ec-claw-sdk/ec_claw_sdk/crypto.py so a member Mac
that only cloned antimirror-app can still speak the rail — keep in sync)

Implements Appendix E.1 signing profile:
  - Canonical JSON (sorted keys, no whitespace)
  - BLAKE3 unkeyed hash
  - Ed25519 signature over the BLAKE3 hash

Also provides keypair management for persistent claw identity.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Tuple

import blake3 as _blake3
import nacl.signing
import nacl.encoding


def canonical_json(obj: dict) -> bytes:
    """Canonical JSON per E.1: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')


def blake3_hash(data: bytes) -> str:
    """BLAKE3 unkeyed hash → 64-char hex string."""
    return _blake3.blake3(data).hexdigest()


def sign_canonical(obj_dict: dict, signing_key: nacl.signing.SigningKey) -> str:
    """Sign per E.1: canonical JSON → BLAKE3 hash → Ed25519 sig → hex."""
    cj = canonical_json(obj_dict)
    h = _blake3.blake3(cj).digest()  # 32 bytes
    signed = signing_key.sign(h)
    return signed.signature.hex()


def verify_canonical(obj_dict: dict, signature_hex: str, verify_key: nacl.signing.VerifyKey) -> bool:
    """Verify a canonical object signature per E.1."""
    cj = canonical_json(obj_dict)
    h = _blake3.blake3(cj).digest()
    sig = bytes.fromhex(signature_hex)
    try:
        verify_key.verify(h, sig)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


def generate_keypair() -> nacl.signing.SigningKey:
    """Generate a new Ed25519 signing keypair."""
    return nacl.signing.SigningKey.generate()


def save_keypair(signing_key: nacl.signing.SigningKey, path: str) -> None:
    """Save signing key to a file (hex-encoded seed).
    
    WARNING: This is the private key. Protect it accordingly.
    In production, use OS keychain or HSM.
    """
    seed = signing_key.encode().hex()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(seed)
    os.chmod(path, 0o600)


def load_keypair(path: str) -> nacl.signing.SigningKey:
    """Load signing key from a file (hex-encoded seed)."""
    seed_hex = Path(path).read_text().strip()
    seed = bytes.fromhex(seed_hex)
    return nacl.signing.SigningKey(seed)


def pubkey_hex(signing_key: nacl.signing.SigningKey) -> str:
    """Get the hex-encoded Ed25519 public key."""
    return signing_key.verify_key.encode().hex()
