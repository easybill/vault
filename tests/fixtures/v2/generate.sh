#!/bin/sh
# Generates the golden fixtures in ./golden.
#
# The fixtures are a repository with the V1 user alice and the V2 users carol and dave, written by
# vault 2.0.0 from a checkout of the commit that added them:
#
#   tests/fixtures/v2/generate.sh <path-to-that-checkout>
#
# The script builds the checkout with `cargo build`, uses its debug binary and checks its version.
# Never regenerate the fixtures with a newer vault, they pin what vault 2.0.0 wrote.
# The script refuses to run if ./golden already exists.
#
# Layout of ./golden:
#
#   .vault/repository_id                  created by `create-key carol`
#   .vault/keys/{alice,carol,dave}/       alice.pub.pem (V1), carol.pem.pub and dave.pem.pub (V2)
#   .vault/private_keys/alice.pem         alice's V1 key, loaded by default
#   carol_v2_keys/, dave_v2_keys/         the V2 key directories (VAULT_V2_KEY_PATH)
#   expected/<SECRET>                     the plaintexts
#
# carol adds SIMPLE, EMPTY, BINARY, LARGE, UNICODE_MULTILINE and SHARED and gives alice (V1) and
# dave (V2) access to SHARED. alice adds GLOB_A and gives dave access to it. dave adds DAVE_ONLY.
set -eu

REFERENCE_VERSION="Vault 2.0.0"

SRC=${1:?usage: generate.sh <path-to-a-vault-checkout>}
SRC="$(cd "$SRC" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="$SCRIPT_DIR/golden"

if [ -e "$OUT" ]; then
    echo "$OUT already exists, golden fixtures must not be regenerated" >&2
    exit 1
fi

(cd "$SRC" && cargo build)
VAULT_BIN="$SRC/target/debug/vault"

VERSION="$("$VAULT_BIN" --version)"
if [ "$VERSION" != "$REFERENCE_VERSION" ]; then
    echo "$VAULT_BIN is $VERSION, expected $REFERENCE_VERSION" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/home" "$WORK/no_v1_keys" "$WORK/vault/.vault/keys" "$WORK/vault/.vault/private_keys" "$WORK/vault/.vault/secrets"
cd "$WORK/vault"

# Isolate from the ~/.vault of the person running the script.
export HOME="$WORK/home"
export VAULT_FORCE_YES=1
unset VAULT_PRIVATE_KEY_PATH
unset VAULT_V2_KEY_PATH

CAROL_KEYS="$WORK/vault/carol_v2_keys"
DAVE_KEYS="$WORK/vault/dave_v2_keys"

"$VAULT_BIN" create-openssl-key alice
VAULT_V2_KEY_PATH="$CAROL_KEYS" "$VAULT_BIN" create-key carol
VAULT_V2_KEY_PATH="$DAVE_KEYS" "$VAULT_BIN" create-key dave

printf 'subscriptions = ["SHARED"]' > .vault/keys/alice/config.toml
printf 'subscriptions = ["SHARED", "GLOB_*"]' > .vault/keys/dave/config.toml

mkdir expected
printf 'hello world' > expected/SIMPLE
: > expected/EMPTY
perl -e 'print map { chr } 0..255' > expected/BINARY
perl -e 'print map { chr($_ % 251) } 0..65535' > expected/LARGE
printf 'Grüße, Welt!\n🔐 Schlüssel 🗝️\r\nlast line\n' > expected/UNICODE_MULTILINE
printf 'shared content' > expected/SHARED
printf 'glob a' > expected/GLOB_A
printf 'only dave can read this' > expected/DAVE_ONLY

# carol alone: encrypts her new secrets for herself and fulfills SHARED for alice and dave.
for secret in SIMPLE EMPTY BINARY LARGE UNICODE_MULTILINE SHARED; do
    cp "expected/$secret" .vault/secrets/
done
VAULT_PRIVATE_KEY_PATH="$WORK/no_v1_keys" VAULT_V2_KEY_PATH="$CAROL_KEYS" "$VAULT_BIN"

# alice alone: encrypts GLOB_A for herself and fulfills it for dave.
cp expected/GLOB_A .vault/secrets/
"$VAULT_BIN"

# dave alone: encrypts DAVE_ONLY for himself.
cp expected/DAVE_ONLY .vault/secrets/
VAULT_PRIVATE_KEY_PATH="$WORK/no_v1_keys" VAULT_V2_KEY_PATH="$DAVE_KEYS" "$VAULT_BIN"

# Written into $WORK first, so a failure never leaves a partial golden directory behind.
mkdir "$WORK/out"
cp -R .vault carol_v2_keys dave_v2_keys expected "$WORK/out/"
mv "$WORK/out" "$OUT"
echo "golden fixtures written to $OUT"
