#!/usr/bin/env bash
# Fails if this repo's recovery format has drifted from void-which-binds-go at
# the commit pinned in VOID_WHICH_BINDS_GO_REF.
#
# void-which-binds-go is the source of truth for the recovery format. This repo
# is its PUBLIC, standalone copy (void-which-binds-go is private), so an heir can
# recover with nothing from the authors. Each file below must equal upstream's
# byte for byte. Never edit one here: re-copy it from void-which-binds-go and
# bump the pin in the same change. (Mirrors void-which-binds-web's
# scripts/check-vector-drift.sh.)
#
#   RECOVERY-SPEC.md           <- docs/RECOVERY-SPEC.md
#   reference.py               <- docs/recovery/reference.py
#   vectors/{recovery,recovery-wrap,slip39}/  <- testvectors/vectors/<same>/
#
# Env:
#   VOID_WHICH_BINDS_GO_TOKEN  token that can read the (private) void-which-binds-go
#                              repo over HTTPS; optional when git already has
#                              credentials.
#   VOID_WHICH_BINDS_GO_URL    clone URL or local path (default: the GitHub repo).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
pin_file="$root/VOID_WHICH_BINDS_GO_REF"
url="${VOID_WHICH_BINDS_GO_URL:-https://github.com/rarebit-one/void-which-binds-go.git}"

ref="$(sed -e 's/#.*//' "$pin_file" | tr -d '[:space:]')"
if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error file=VOID_WHICH_BINDS_GO_REF::expected a full 40-char void-which-binds-go commit SHA, got '$ref'" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

auth=()
if [[ -n "${VOID_WHICH_BINDS_GO_TOKEN:-}" ]]; then
  basic="$(printf 'x-access-token:%s' "$VOID_WHICH_BINDS_GO_TOKEN" | base64 | tr -d '\n')"
  auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $basic")
fi

git -C "$work" init -q
git ${auth[@]+"${auth[@]}"} -C "$work" fetch -q --depth 1 "$url" "$ref"
git -C "$work" checkout -q FETCH_HEAD -- docs/RECOVERY-SPEC.md docs/recovery/reference.py testvectors/vectors

status=0
check() { # check <upstream path> <local path>
  if ! diff -r -u "$work/$1" "$root/$2"; then
    echo "::error file=$2::differs from void-which-binds-go@$ref $1" >&2
    status=1
  fi
}
check docs/RECOVERY-SPEC.md RECOVERY-SPEC.md
check docs/recovery/reference.py reference.py
for entry in "$root"/vectors/*; do
  name="$(basename "$entry")"
  if [[ ! -d "$work/testvectors/vectors/$name" ]]; then
    echo "::error file=vectors/$name::void-which-binds-go@$ref has no testvectors/vectors/$name" >&2
    status=1
    continue
  fi
  check "testvectors/vectors/$name" "vectors/$name"
done

if [[ $status -eq 0 ]]; then
  echo "spec, reference and vectors match void-which-binds-go@$ref"
else
  echo "::error::this repo has drifted from void-which-binds-go@$ref. Re-copy the files (never hand-edit them) and bump VOID_WHICH_BINDS_GO_REF in the same change." >&2
  exit 1
fi
