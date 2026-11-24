#!/bin/sh
# Generates the golden fixtures in ./golden.
#
# The fixtures are files in vault file format version 1, written by vault 1.0.31
# from commit 903988e. They were generated using a clean checkout of that commit:
#
#   git worktree add --detach <scratch>/vault-903988e 903988e
#   tests/fixtures/v1/generate.sh <scratch>/vault-903988e
#   git worktree remove <scratch>/vault-903988e
#
# The script verifies the checkout, builds it with `cargo build` and uses its debug binary.
# Never regenerate the fixtures with a newer vault, they pin what vault 1.0.31 wrote.
# The script refuses to run if ./golden already exists.
set -eu

REFERENCE_COMMIT=903988e7bd291d35acda7ab7003a2366b2dbe606

SRC=${1:?usage: generate.sh <path-to-a-checkout-of-903988e>}
SRC="$(cd "$SRC" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/golden"

if [ -e "$OUT" ]; then
    echo "$OUT already exists, golden fixtures must not be regenerated" >&2
    exit 1
fi

HEAD="$(git -C "$SRC" rev-parse HEAD)"
if [ "$HEAD" != "$REFERENCE_COMMIT" ]; then
    echo "$SRC is at $HEAD, expected $REFERENCE_COMMIT" >&2
    exit 1
fi

if [ -n "$(git -C "$SRC" status --porcelain)" ]; then
    echo "$SRC has local changes" >&2
    exit 1
fi

(cd "$SRC" && cargo build)
VAULT_BIN="$SRC/target/debug/vault"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/home" "$WORK/vault/.vault/keys" "$WORK/vault/.vault/private_keys" "$WORK/vault/.vault/secrets"
cd "$WORK/vault"

# Isolate from the ~/.vault/private_keys of the person running the script.
export HOME="$WORK/home"
export VAULT_FORCE_YES=1
unset VAULT_PRIVATE_KEY_PATH

"$VAULT_BIN" create-openssl-key alice
"$VAULT_BIN" create-openssl-key bob

# Only alice's private key stays in ./.vault/private_keys.
mkdir bob_private_keys
mv .vault/private_keys/bob.pem .vault/private_keys/bob.pub.pem bob_private_keys/
printf 'subscriptions = ["SIMPLE"]' > .vault/keys/alice/config.toml
printf 'subscriptions = ["SHARED", "GLOB_*"]' > .vault/keys/bob/config.toml

mkdir expected
printf 'hello world' > expected/SIMPLE
: > expected/EMPTY
printf 'x' > expected/ONE_BYTE
printf 'abcdefghijklmno' > expected/BLOCK_15
printf 'abcdefghijklmnop' > expected/BLOCK_16
printf 'abcdefghijklmnopq' > expected/BLOCK_17
perl -e 'print map { chr } 0..255' > expected/BINARY
printf 'Grüße, Welt!\n🔐 Schlüssel 🗝️\r\nlast line\n' > expected/UNICODE_MULTILINE
perl -e 'print map { chr($_ % 251) } 0..65535' > expected/LARGE
printf 'shared content' > expected/SHARED
printf 'glob a' > expected/GLOB_A

cp expected/* .vault/secrets/

# Encrypts all new secrets for alice and fulfills bob's subscriptions SHARED and GLOB_A.
"$VAULT_BIN"

# Encrypts BOB_ONLY for bob, alice cannot read it.
printf 'only bob can read this' > expected/BOB_ONLY
cp expected/BOB_ONLY .vault/secrets/
VAULT_PRIVATE_KEY_PATH="$WORK/vault/bob_private_keys" "$VAULT_BIN"

# Written into $WORK first, so a failure never leaves a partial golden directory behind.
mkdir "$WORK/out"
cp -R .vault bob_private_keys expected "$WORK/out/"
mv "$WORK/out" "$OUT"
echo "golden fixtures written to $OUT"
