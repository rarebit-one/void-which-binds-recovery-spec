# Void-Which-Binds recovery

This repository lets anyone recover a **Void-Which-Binds identity** from its written
recovery secret, and recover the **heyarr vault keys** wrapped for it, without
any other software from its authors. It exists so a recovery secret stays usable
for as long as the paper does.

Void-Which-Binds was called Voidbind, and this repository was
`rarebit-one/voidbind-recovery-spec` (the old URL redirects). The rename
([ADR-0013](https://github.com/rarebit-one/void-which-binds-go/blob/main/docs/adr/0013-gen2-rename-to-void-which-binds-and-re-genesis.md)
R1) changes names only: every secret, label and vector here is unchanged, and
secrets printed before it recover exactly as before.

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
[Releases](../../releases) of this repository mirror the signed `void-which-binds`
command-line binaries (named `voidbind` before v0.18.0). RECOVERY-SPEC §8 shows how to verify them.
