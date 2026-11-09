# Void-Which-Binds recovery

This repository lets anyone recover a **Void-Which-Binds identity** from its written
recovery secret, and recover the **heyarr vault keys** wrapped for it, without
any other software from its authors. It exists so a recovery secret stays usable
for as long as the paper does.

This is **recovery-spec v2**, the generation-2 (gen2) format. A gen2 secret
begins `void-which-binds1`. A generation-1 secret begins `heyarr1`. It is
retired, and current software refuses it. RECOVERY-SPEC §10 says what that
means for a gen1 sheet still on paper.

Void-Which-Binds was called Voidbind, and this repository was
`rarebit-one/voidbind-recovery-spec` (the old URL redirects).

If you are holding a sheet titled **Recovery secret**, start with
[RECOVERY-SPEC.md](RECOVERY-SPEC.md) §1 and §7.

| File | What it is |
|---|---|
| [`RECOVERY-SPEC.md`](RECOVERY-SPEC.md) | The complete format: the secret (bech32m), key derivation (HKDF), the fingerprint, space-key wrapping (X25519 + XChaCha20-Poly1305), the heyarr recovery blob, SLIP-39 shares, and step-by-step recovery. |
| [`reference.py`](reference.py) | An independent implementation written from the spec alone: Python 3 plus `pip install cryptography`. |
| [`vectors/`](vectors) | Known-answer vectors. They use test-only keys, never anyone's secret. |

```
pip install cryptography
python3 reference.py selftest vectors            # check the reference against the vectors
python3 reference.py identity < secret.txt       # the identity and fingerprint a secret derives
python3 reference.py blob FILE < secret.txt      # open a heyarr recovery blob
```

The reference reads the secret from standard input, so it never lands in your
shell history. Run it on a machine you trust, ideally offline.

The Void-Which-Binds apps are open source too: the phone authenticator and the Kotlin
library, including a SLIP-39 implementation, live at
[rarebit-one/voidbind-kmp](https://github.com/rarebit-one/voidbind-kmp).
RECOVERY-SPEC §8 says how to get and verify the signed `void-which-binds`
command-line tools.

## Where this comes from

void-which-binds-go is the source of truth for the recovery format.
`RECOVERY-SPEC.md`, `reference.py` and `vectors/` are byte-for-byte copies of
its `docs/RECOVERY-SPEC.md`, `docs/recovery/reference.py` and
`testvectors/vectors/{recovery,recovery-wrap,slip39}` at the commit in
[`VOID_WHICH_BINDS_GO_REF`](VOID_WHICH_BINDS_GO_REF). CI fails if they drift
(`scripts/check-drift.sh`), and runs `reference.py selftest vectors` on every
change. Because the files are copied verbatim, the spec's relative links to
ADRs point into void-which-binds-go. They record provenance and are not needed
to recover anything.
