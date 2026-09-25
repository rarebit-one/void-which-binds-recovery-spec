# Recovery known-answer vectors

For fixed secret entropy, every value a port must derive byte-for-byte (ADR-0004,
ADR-0010). voidbind-go generates them with
`go test ./recovery -run TestRecoveryVectors -update` and replays them without
`-update`; voidbind-kmp copies the files verbatim.

```jsonc
{
  "name":                 "counting-entropy",           // == file stem
  "description":          "…",
  "entropy":              "<64 hex>",                    // the 32 secret bytes
  "secret":               "heyarr1…",                    // bech32m, as displayed
  "secret_upper":         "HEYARR1…",                    // the QR (alphanumeric) form; parses identically
  "user_id":              "ed25519:<hex>",               // HKDF(heyarr/recovery/v1/user-identity-ed25519-seed) → Ed25519
  "encryption_recipient": "x25519:<hex>",                // HKDF(heyarr/recovery/v1/user-encryption-x25519-seed) → X25519
  "fingerprint":          "XXXX XXXX XXXX XXXX"          // Fingerprint(user key), ADR-0010
}
```

All entropy here is test-only.
