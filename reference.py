#!/usr/bin/env python3
"""Voidbind / heyarr recovery, reimplemented from docs/RECOVERY-SPEC.md alone.

This file exists so a written recovery secret stays usable even if no voidbind or
heyarr code survives. It needs Python 3.9+ and the `cryptography` package
(`pip install cryptography`) for Ed25519, X25519 and ChaCha20-Poly1305. Everything
else (bech32m, HKDF, HChaCha20, the fingerprint, the blob format) is written out
here in full.

    python3 reference.py identity  < secret.txt        # user ID, recovery key, fingerprint
    python3 reference.py blob BLOB < secret.txt        # open a heyarr recovery blob, print the space keys
    python3 reference.py selftest VECTORS_DIR          # check against testvectors/vectors

The secret is read from stdin, so it never appears in argv or shell history.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- §2 the secret: bech32m (BIP-350), HRP "heyarr", 32 bytes ------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3
HRP = "heyarr"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def parse_secret(text):
    """The 32 secret bytes, or ValueError. Whitespace is ignored; case is folded
    (mixed case is refused)."""
    s = "".join(text.split())
    if s != s.lower() and s != s.upper():
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    hrp, data = s[:pos], s[pos + 1:]
    if hrp != HRP:
        raise ValueError("prefix is %r, expected %r" % (hrp, HRP))
    try:
        values = [CHARSET.index(c) for c in data]
    except ValueError:
        raise ValueError("a character is not in the bech32 alphabet")
    if len(values) != 52 + 6:
        raise ValueError("wrong length")
    if _polymod(_hrp_expand(hrp) + values) != BECH32M_CONST:
        raise ValueError("checksum does not verify: a transcription error")
    acc, bits, out = 0, 0, bytearray()
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc << (8 - bits)) & 0xFF:
        raise ValueError("non-zero padding")
    if len(out) != 32:
        raise ValueError("decodes to %d bytes" % len(out))
    return bytes(out)


def format_secret(entropy):
    acc, bits, values = 0, 0, []
    for b in entropy:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            values.append((acc >> bits) & 31)
    if bits:
        values.append((acc << (5 - bits)) & 31)
    poly = _polymod(_hrp_expand(HRP) + values + [0] * 6) ^ BECH32M_CONST
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return HRP + "1" + "".join(CHARSET[v] for v in values + checksum)


# --- §3 derivation: HKDF-SHA256 (RFC 5869) --------------------------------------

LABEL_USER_IDENTITY = b"heyarr/recovery/v1/user-identity-ed25519-seed"
LABEL_USER_ENCRYPTION = b"heyarr/recovery/v1/user-encryption-x25519-seed"


def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block, i = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def _raw(pub):
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def user_public_key(entropy):
    seed = hkdf_sha256(entropy, b"", LABEL_USER_IDENTITY)
    return _raw(Ed25519PrivateKey.from_private_bytes(seed).public_key())


def recovery_encryption_key(entropy):
    seed = hkdf_sha256(entropy, b"", LABEL_USER_ENCRYPTION)
    return X25519PrivateKey.from_private_bytes(seed)


# --- §4 the fingerprint ---------------------------------------------------------

FINGERPRINT_LABEL = b"voidbind/user-fingerprint/v1"


def fingerprint(user_pub):
    digest = hashlib.sha256(FINGERPRINT_LABEL + b"\x00" + user_pub).digest()[:10]
    text = base64.b32encode(digest).decode().rstrip("=")
    return " ".join(text[i:i + 4] for i in range(0, len(text), 4))


# --- §5 unwrapping a space key: X25519 + HKDF + XChaCha20-Poly1305 ---------------

WRAP_INFO = b"heyarr/space-key-wrap/v1"


def _rotl(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def hchacha20(key, nonce16):
    """HChaCha20 (draft-irtf-cfrg-xchacha): the subkey XChaCha20 derives."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))

    def qr(a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = _rotl(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = _rotl(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = _rotl(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = _rotl(state[b] ^ state[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<8I", *(state[0:4] + state[12:16]))


def xchacha20poly1305_open(key, nonce24, ciphertext, aad=b""):
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).decrypt(b"\x00" * 4 + nonce24[16:], ciphertext, aad)


def unwrap(wrapped, recipient_priv):
    """The 32-byte space key from wrapped = e_pub(32) ‖ nonce(24) ‖ AEAD(key)."""
    e_pub, nonce, sealed = wrapped[:32], wrapped[32:56], wrapped[56:]
    r_pub = _raw(recipient_priv.public_key())
    shared = recipient_priv.exchange(X25519PublicKey.from_public_bytes(e_pub))
    wrap_key = hkdf_sha256(shared, e_pub + r_pub, WRAP_INFO)
    return xchacha20poly1305_open(wrap_key, nonce, sealed, aad=e_pub + r_pub)


def decrypt_change(space_key, ciphertext):
    """A change or snapshot: nonce(24) ‖ XChaCha20-Poly1305(plaintext), no AAD."""
    return xchacha20poly1305_open(space_key, ciphertext[:24], ciphertext[24:])


# --- §6 the heyarr recovery blob ------------------------------------------------

BLOB_MAGIC = b"heyarr-recovery-blob-v1\x00"


def open_blob(data, recipient_priv):
    if not data.startswith(BLOB_MAGIC):
        raise ValueError("not a heyarr-recovery-blob-v1 file")
    rest = data[len(BLOB_MAGIC):]
    (n,) = struct.unpack(">I", rest[:4])
    blob_key = unwrap(rest[4:4 + n], recipient_priv)
    body = json.loads(decrypt_change(blob_key, rest[4 + n:]))
    spaces = {}
    for s in body["spaces"]:
        spaces[s["space_id"]] = unwrap(base64.b64decode(s["wrapped"]), recipient_priv)
    return body, spaces


# --- command line ---------------------------------------------------------------


def _identity(entropy):
    pub = user_public_key(entropy)
    enc = _raw(recovery_encryption_key(entropy).public_key())
    return "ed25519:" + pub.hex(), "x25519:" + enc.hex(), fingerprint(pub)


def selftest(vectors_dir):
    rec_dir = os.path.join(vectors_dir, "recovery")
    count = 0
    for name in sorted(os.listdir(rec_dir)):
        if not name.endswith(".json"):
            continue
        v = json.load(open(os.path.join(rec_dir, name)))
        entropy = bytes.fromhex(v["entropy"])
        assert format_secret(entropy) == v["secret"], name
        assert parse_secret(v["secret_upper"]) == entropy, name
        assert _identity(entropy) == (v["user_id"], v["encryption_recipient"], v["fingerprint"]), name
        count += 1
    wrap_dir = os.path.join(vectors_dir, "recovery-wrap")
    for name in sorted(os.listdir(wrap_dir)):
        if not name.endswith(".json"):
            continue
        v = json.load(open(os.path.join(wrap_dir, name)))
        priv = recovery_encryption_key(parse_secret(v["secret"]))
        key = unwrap(bytes.fromhex(v["wrapped"]), priv)
        assert key.hex() == v["space_key"], name
        assert decrypt_change(key, bytes.fromhex(v["change_ciphertext"])).hex() == v["change_plaintext"], name
        body, spaces = open_blob(bytes.fromhex(v["blob"]), priv)
        assert list(spaces.values()) == [key], name
        count += 1
    print("ok: %d vectors" % count)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] == "selftest":
        selftest(argv[2])
        return 0
    entropy = parse_secret(sys.stdin.read())
    if argv[1] == "identity":
        user, enc, fp = _identity(entropy)
        print("user          " + user)
        print("recovery key  " + enc)
        print("fingerprint   " + fp)
        return 0
    if argv[1] == "blob":
        body, spaces = open_blob(open(argv[2], "rb").read(), recovery_encryption_key(entropy))
        print("blob exported %s for %s" % (body.get("generated_at"), body.get("user_id", "?")))
        for space_id, key in spaces.items():
            print("space %s  key %s" % (space_id, key.hex()))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
