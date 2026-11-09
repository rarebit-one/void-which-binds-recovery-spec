# Recovery known-answer vectors

For fixed secret entropy, every value a port must derive byte-for-byte (ADR-0004,
ADR-0010), in the gen2 spellings (ADR-0022). void-which-binds-go generates them with
`go test ./recovery -run TestRecoveryVectors -update` and replays them without
`-update`; void-which-binds-kmp copies the files verbatim.

```jsonc
{
  "name":                 "counting-entropy",           // == file stem
  "description":          "…",
  "entropy":              "<64 hex>",                    // the 32 secret bytes
  "secret":               "void-which-binds1…",          // bech32m, 75 characters, as displayed
  "secret_upper":         "VOID-WHICH-BINDS1…",          // the QR (alphanumeric) form; parses identically
  "user_id":              "ed25519:<hex>",               // HKDF(void-which-binds/recovery/v1/user-identity-ed25519-seed) → Ed25519
  "encryption_recipient": "x25519:<hex>",                // HKDF(void-which-binds/recovery/v1/user-encryption-x25519-seed) → X25519
  "fingerprint":          "XXXX XXXX XXXX XXXX"          // SHA-256(void-which-binds/user-fingerprint/v1 ‖ 0x00 ‖ key), ADR-0010
}
```

A gen1 secret (`heyarr1…`) is not a vector here: `recovery.ParseSecret` refuses
it with `ErrGenerationRetired`, and only the read-only `migrate/gen1` package
reads it, until v0.20.0. All entropy here is test-only.
