# Void-Which-Binds recovery: the complete format

This document is everything needed to recover a Void-Which-Binds identity, and the heyarr
vault data wrapped for it, from a written recovery secret, **without any voidbind or
heyarr code**. It is meant to outlive the software. A ~270-line reference
implementation that uses nothing beyond Python and the `cryptography` package is in
[`reference.py`](reference.py). It is checked against the
known-answer vectors listed in §9.

If you are an heir or an executor holding a sheet titled **Recovery secret**, read
§1 and then §7.

## 1. What a recovery secret is

A recovery secret is 32 random bytes (256 bits), written as a checksummed string
beginning `heyarr1` (§2). Every key of the identity is derived from those bytes
(§3), so the secret alone rebuilds the identity on any machine, offline.

- It is the identity's **root authority** ("genesis"). Anyone holding it can act as
  the user, so treat it like the key to everything.
- It may instead be held as **SLIP-39 shares**, where any *k* of *n* rebuild the
  32 bytes (§6).
- A person can check a written secret without using it, by comparing its
  **fingerprint** (§4) with the one printed on the sheet or shown by the user's apps.

## 2. The written form: bech32m

The secret is **bech32m** (BIP-350) with human-readable part `heyarr`.

- Data is the 32 bytes regrouped 8→5 bits with zero padding: 52 symbols. It is
  followed by the 6-symbol bech32m checksum (constant `0x2bc830a3`). The whole
  string is 65 characters: `heyarr1` plus 58 symbols.
- The alphabet is `qpzry9x8gf2tvdw0s3jn54khce6mua7l`. It contains no `1`, `b`, `i`
  or `o`.
- **Reading back:**
  - Ignore all whitespace. The secret is displayed and written in groups of four
    characters.
  - Fold case: an all-upper-case string is valid, and is what the QR code on a
    sheet carries (it keeps the code in QR alphanumeric mode). A string mixing
    upper and lower case is invalid.
  - Refuse a failed checksum. It catches any single-character transcription error,
    and a mistyped secret must never be treated as a different identity.

## 3. Derivation

Every key is HKDF-SHA256 (RFC 5869) over the 32 secret bytes:
- IKM = the 32 bytes;
- salt empty, which RFC 5869 treats as 32 zero bytes;
- output 32 bytes;
- the *info* string differs per key.

| Key | HKDF info | Output used as |
|---|---|---|
| User identity (signing) | `heyarr/recovery/v1/user-identity-ed25519-seed` | an Ed25519 private-key seed (RFC 8032). Its public key is the **user ID** |
| Recovery encryption key | `heyarr/recovery/v1/user-encryption-x25519-seed` | an X25519 private key (RFC 7748, clamped as usual). Its public key is the **recovery recipient** |

The labels say `heyarr` for historical reasons. They define the identity and never
change.

**Rendering.** A user ID is written `ed25519:` followed by the 32-byte public key in
lowercase hex. The recovery recipient is written `x25519:` followed by its 32-byte
public key in lowercase hex.

## 4. The fingerprint

```
fingerprint = base32( SHA-256( "voidbind/user-fingerprint/v1" ‖ 0x00 ‖ user_public_key )[0:10] )
```

- The encoding is RFC 4648 base32 (`A–Z`, `2–7`) with no padding, giving 16
  characters. They are shown in groups of four, for example `PYJI XGNZ K7ZH XHEJ`.
- It is for people, not software. If the fingerprint a written secret derives
  equals the one on record, the paper is the right paper.

## 5. heyarr vault data

heyarr encrypts each *space* (a vault, a set of personal records) under a random
32-byte **space key**.

### 5.1 How a space key is wrapped

A copy of each space key is **wrapped** for every authorised device and, always, for
the **recovery recipient** (§3). That last copy is what makes the data recoverable.

```
wrapped = e_pub (32) ‖ nonce (24) ‖ XChaCha20-Poly1305(wrap_key, nonce, space_key, aad = e_pub ‖ recipient_pub)
```

where

```
shared   = X25519(e_priv, recipient_pub)          -- recovered as X25519(recovery_priv, e_pub)
wrap_key = HKDF-SHA256(IKM = shared, salt = e_pub ‖ recipient_pub, info = "heyarr/space-key-wrap/v1", L = 32)
```

XChaCha20-Poly1305 is draft-irtf-cfrg-xchacha:
1. HChaCha20 of the key with the first 16 nonce bytes gives a subkey.
2. That subkey is used for ChaCha20-Poly1305 (RFC 8439) with the nonce
   `00 00 00 00 ‖ nonce[16:24]`.

### 5.2 How content is encrypted

Content (a change or a snapshot) is `nonce (24) ‖ XChaCha20-Poly1305(space_key, nonce, plaintext)`, with no associated data.

### 5.3 Where the wrapped copies live

The wrapped copies sit in two places:
- in the heyarr control database, table `wrapped_keys`, rows whose `recipient` is
  the recovery recipient;
- in an exported **recovery blob** (§5.4).

### 5.4 The recovery blob (heyarr ADR-0022 addendum)

A recovery blob is one file:

```
"heyarr-recovery-blob-v1" 0x00 ‖ uint32_be(len(sealed_key)) ‖ sealed_key ‖ body_ciphertext
```

- `sealed_key` is a fresh 32-byte key, wrapped for the recovery recipient exactly
  as in §5.1.
- `body_ciphertext` encrypts, as in §5.2 under that key, this JSON:

  ```json
  {"format": "heyarr-recovery-blob-v1", "user_id": "ed25519:…", "recovery_recipient": "x25519:…",
   "generated_at": "RFC 3339", "spaces": [{"space_id": "…", "kind": "…", "wrapped": "<base64 of a §5.1 wrapped key>"}]}
  ```

A blob is sealed to a *public* key, so anyone could make one. A key taken from a
blob is trusted for reading, and must decrypt the space's newest real content
before it is trusted for writing.

## 6. SLIP-39 shares

A secret may be split into SLIP-39 shares (<https://github.com/satoshilabs/slips/blob/master/slip-0039.md>, the "extendable" revision) so that any *k* of *n* rebuild it.

- **The master secret is the 32 bytes of §1.** Combining shares yields those bytes,
  and so the same identity.
- **The Void-Which-Binds profile:** one group, typically 2-of-3; iteration exponent 1;
  extendable; SLIP-39 passphrase empty unless the owner chose one. A forgotten
  passphrase loses the secret. The profile is recorded in
  `docs/adr/0011-recovery-secret-shares-are-slip-39.md`.
- Exactly *k* shares must be combined: supplying extra shares is refused, per
  the SLIP-39 specification.
- Any conforming SLIP-39 implementation, such as Trezor's `python-shamir-mnemonic`,
  recombines them. Its output is 32 bytes; render them with §2 or use them with §3
  directly.

## 7. Recovering, step by step

1. **Read the secret.** Type or scan it (§2). If you hold shares instead, combine
   *k* of them (§6).
2. **Check it.** Derive the user public key and fingerprint (§3, §4), and compare
   with the sheet or the user's records. With the reference:
   `python3 reference.py identity < secret.txt`.
3. **Rebuild access.**
   - If the Void-Which-Binds apps still exist, *Restore* in Cruciform, or
     `void-which-binds identity recover --secret-file -`, re-admits a device as the same
     identity.
   - If they don't, the keys of §3 are the identity.
4. **Reach vault data.**
   - Take the recovery-recipient wrapped copies from a recovery blob
     (`python3 reference.py blob FILE < secret.txt`) or from a heyarr
     database.
   - Unwrap them (§5.1), then decrypt content (§5.2).
   - The encrypted content itself is replicated across the heyarr peers; the
     recovery material is only the keys.

## 8. Getting the tools

Every void-which-binds-go release carries the following, and each release of this
public repository mirrors them unchanged:
- static `void-which-binds` binaries (named `voidbind` before v0.18.0, when the repo was `voidbind-go`) for Linux, macOS and Windows on amd64 and arm64; <!-- r1:keep -->
- this document and `reference.py`;
- a `SHA256SUMS` signed keyless with Sigstore cosign by the release workflow.

To check a download:

```
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/rarebit-one/(voidbind-go|void-which-binds-go)/\.github/workflows/release\.yml@refs/tags/v' \
  SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

The binaries are a convenience. This document and `reference.py` are enough on
their own.

## 9. Known-answer vectors

Every value above is pinned in `vectors/` (mirrored from void-which-binds-go's
`testvectors/vectors/`), and the reference implementation checks itself against them
(`python3 reference.py selftest vectors`):

- `recovery/*.json` holds, for fixed entropy:
  - the bech32m secret, in lower and upper case;
  - the user ID;
  - the recovery recipient;
  - the fingerprint.
- `recovery-wrap/*.json` holds:
  - a space key wrapped for a recovery recipient;
  - a change encrypted under it;
  - a recovery blob carrying it.
- `slip39/vectors.json` holds Trezor's official SLIP-39 vectors.

The Go implementation replays the same files (`go test ./recovery ./encryption`),
and void-which-binds-kmp copies them verbatim.
