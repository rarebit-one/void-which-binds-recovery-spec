# SLIP-39 test vectors (Trezor)

`vectors.json` is Trezor's official SLIP-39 test-vector file, copied **verbatim**
(no reformatting, no trailing newline added). `recovery/slip39` replays every
case (ADR-0011) and pins the file's SHA-256, so a change here fails the build.

| | |
|---|---|
| Source | <https://raw.githubusercontent.com/trezor/python-shamir-mnemonic/master/vectors.json> |
| Repository | [`trezor/python-shamir-mnemonic`](https://github.com/trezor/python-shamir-mnemonic) (MIT) |
| Fetched | 2026-09-25, `master` @ `17fcce14736afe498871d3018e4fa9330443471a` |
| Last change to the file | `1525df19df504b1f69b49179140119959f317f24` (2024-05-14) |
| SHA-256 | `13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4` |

Each entry is `[description, mnemonics, master_secret_hex, xprv]`. Every case
uses the passphrase `TREZOR`. An empty `master_secret_hex` means the mnemonics
must be refused. `xprv` is the BIP-32 root key of the master secret; it is a
wallet concern and voidbind does not check it.

The 45 cases cover 128- and 256-bit secrets, with and without the extendable
flag: single shares, 2-of-3 and multi-group sharing, and the refusals (bad
checksum, bad padding, mismatched identifiers, iteration exponents, group
thresholds and counts, duplicate indices, a bad digest, too few groups or
members, bad lengths), plus a case that catches errors in GF(256) arithmetic.

The SLIP-39 wordlist that `recovery/slip39` embeds is python-shamir-mnemonic's
`shamir_mnemonic/wordlist.txt` (MIT, same commit as above). It is byte-identical
to the spec's own copy,
<https://github.com/satoshilabs/slips/blob/master/slip-0039/wordlist.txt>
(`master` @ `570ed55b7fde158f1116be34fc2faa35dada5912`, CC-BY-SA-4.0). SHA-256
`bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3`, pinned by
`TestWordlistPinned`.
