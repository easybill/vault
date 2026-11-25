# vault

Smart and easy way to share secrets in repositories.

## Install with [cargo](https://doc.rust-lang.org/stable/cargo/getting-started/installation.html)

```sh
cargo install --git https://github.com/easybill/vault.git
```

## Download

You can download the latest binaries from the [releases page](https://github.com/easybill/vault/releases) or use these
permalinks for the latest version:

- [vault_linux_latest_x86_64](https://github.com/easybill/vault/releases/latest/download/vault_ubuntu-latest_x86_64)
- [vault_linux_latest_aarch64](https://github.com/easybill/vault/releases/latest/download/vault_ubuntu-latest_aarch64)
- [vault_mac_latest_aarch64](https://github.com/easybill/vault/releases/latest/download/vault_mac_aarch64)
- [vault_mac_x86_64](https://github.com/easybill/vault/releases/latest/download/vault_mac_x86_64)

## Quickstart

### Create a new user (each user has his own key)

Run this in the root of the repository (Vault offers to create the `.vault` directory if it is missing):

```sh
vault create-key [USERNAME]
```

This creates a V2 key and writes:

| Path                                        | Content                                                        |
|---------------------------------------------|----------------------------------------------------------------|
| `.vault/repository_id`                      | the [repository ID](#the-repository-id), only if it is missing |
| `.vault/keys/[USERNAME]/[USERNAME].pem.pub` | your public key                                                |
| `.vault/keys/[USERNAME]/config.toml`        | your subscriptions, empty                                      |
| `~/.vault/v2/[REPOSITORY_ID].pem`           | your private key, stays on your machine                        |
| `~/.vault/v2/[REPOSITORY_ID].pem.pub`       | your public key, needed next to the private key                |

Vault needs the directories `.vault/keys`, `.vault/private_keys` and `.vault/secrets`, but git does not track empty
directories. Commit `.vault/repository_id`, `.vault/keys/[USERNAME]/` and a `.gitkeep` in `.vault/private_keys`:

```sh
touch .vault/private_keys/.gitkeep
git add .vault/repository_id .vault/keys/[USERNAME] .vault/private_keys/.gitkeep
```

Do not put a `.gitkeep` into `.vault/secrets`: Vault would offer it as a new secret. If a directory is missing after a
clone, create it with `mkdir -p .vault/secrets .vault/private_keys`.

Private keys in `.vault/private_keys` (V1) must never be committed. These `.gitignore` lines keep them out:

```gitignore
.vault/private_keys/*.pem
.vault/private_keys/*.pem.pgp
```

V1 users are created with `vault create-openssl-key`, see [V1 keys](#v1-keys).

### Create a new Secret

```sh
# To create a new secret just put the file into the Secrets folder. The file name will later become the name of the secret.
echo "this is secret" > ./.vault/secrets/MY_NEW_SECRET

# now just call vault and it will find the unencrypted secret and ask if you want to encrypt it.
vault

# new secrets (1):
#   - ./.vault/secrets/MY_NEW_SECRET
# apply these 1 change(s)? (y)es to all / (n)o to all / (c)ase by case
# press y and your secret is encrypted.

# get the secret
vault get MY_NEW_SECRET # prints "this is secret"
```

### Sharing the Secret

Just add the secret in the file `./.vault/keys/[USER]/config.toml` as a subscription:

```toml
subscriptions = [
    "MY_NEW_SECRET", # Glob patterns are supported. e. g. DEV*
]
```

and now run vault:

```sh
vault
```

Vault now detects that there is an open subscription to a secret that you can fulfill. It lists it under
`open subscriptions you've the required right to fulfill` and asks the same question as for new secrets.

Tip: if you do not have access to a secret, but would like to have it, you can also create a subscription.
Someone who runs `vault` and has the appropriate access will be asked by vault whether they would like to share this
secret with you.

### Parse template with encrypted placeholders

vault can replace placeholders in templates (UFT8).

The placeholders have the structure: `{vault{ KEY }vault}`.

```sh
vault template ./example_template
// oder
vault template ./example_template 1> example_template_decoded
```

Vault throws an error if keys cannot be replaced.

** Attention: ** Vault may generate an error output if it stumbles e.g. over files which it cannot process.
Therefore, always pass only the stdout `1>` in a template.

### Fetching multiple secrets

Sometimes you need to fetch multiple secrets / templates. Vault speaks json.
You can fetch multiple secrets and templates in a single vault call.
The secret must be valid uf8 (for now), please open an issue if you need binary support.

```sh
vault get_multi '{"secrets": [{"secret": "foo"}], "templates": [{"template": "{vault{ foo }vault}TEST"}]}'
```

### Enforce vault versions using --expect_version=[VERSION_REQUIREMENT]

Vault is usually installed on the computers of all employees. if you have a script that calls vault underneath,
you may want to be able to force certain vault versions. maybe there was a bug in vault or a feature is being used
that is only available in this version. you can use the semver requirement syntax.

Example:

```sh
vault --expect_version='>=1.2.3, <1.8.0' get foo
```

If the version requirement does not match with your vault version, vault exits with an error. Install the latest
version from the [releases page](https://github.com/easybill/vault/releases) to resolve it.

### How it works?

Vault makes it possible to share encrypted information, for example in a git repository in a team.
Vault behaves like a key-value store, the values are encrypted, the keys are not.
It is possible to define rights in a fine granular way. Anyone who has access to a value can share this access.

Vault uses its own key pairs - please do not confuse them with OpenSSH keys. V2 keys are X-Wing keys, V1 keys are RSA
keys created with OpenSSL.
The Vault public key of each user (or for example of a user representing a web server) is stored in the `.vault`
directory.
Because the public key of each user is known, each user has the possibility to store secrets.
For each user who should have access to a key, it is encrypted once using his vault public key.

To encrypt a file/string put it in `./.vault/secrets/[KEY]` and run `vault`.
Vault notices this and suggests to encrypt the corresponding file. If you confirm this, the file will be replaced by a
folder with the same name.
`./.vault/secrets/[KEY]` becomes `./.vault/secrets/[KEY]/[USER].crypt`. For each user who has access to a key, such a
file is created.

With `vault get [KEY]` the content can be decrypted and output.

Now the key is encrypted, but you only have access to it yourself. To give another user access to the key, you create a
subscription. This sounds complicated, but it is quite simple. Simply add a subscription entry for the key in
`./.vault/keys/[USER]/config.toml` for the user.
Then run `vault`, then you will be informed that there is an open subscription, which you can fulfill yourself.
If you confirm this with "y" the key will be encrypted for the user using his public key and stored as usual under
`./.vault/secrets/[KEY]/[USER].crypt`.
The user now has the possibility to query the key and to fulfill subscriptions to this key himself if required.

It is important to understand that everyone has the possibility to modify subscriptions and thus can see who has access
to which data.
Anyone who has access to an encrypted entry can share it. This allows for example flows like the following:
"Person A" wants "Webserver" to have access to the key "production_mysql_pass", but has no access himself.
"Person A" now has the ability to add a subscription (`./.vault/keys/webserver/config.toml`) and push it using git.
"Person A" can now ask "Person B" who has access to the corresponding key to run `vault` and answer with a simple "y"
the question,
If "webserver" is allowed to get access to the corresponding key.
It should be noted that person A never had access to the key, but can monitor the process that the web server gets it.

### Cryptography

Every `.crypt` file starts with a 20 byte HEADER (big endian): the magic number 4242 (u16), the file version (u16), the
length of KEY (u64) and the length of CONTENT (u64). The file version is the version of the recipient's key.

Structure of a Vault (.crypt) file (version 1):

```            
 +------------------------+
 |    HEADER              |
 |                        |
 +------------------------+
 |    KEY                 |
 |    8096 bit RSA        |
 +------------------------+
 |                        |
 |    CONTENT             |
 |    AES-256-CBC         |
 |                        |
 |                        |
 +------------------------+

```

Vault encrypts the actual content (CONTENT) symmetrically via aes_256_cbc (+iv).
The key (KEY) to decrypt the content is encrypted asymmetrically via RSA (private/public key) and is chosen randomly.
Similar concept uses TLS -> TLS Key Exchange.

This theoretically allows to encrypt files of any size.
Currently, the size is limited, this can be relaxed later if necessary.

Structure of a Vault (.crypt) file (version 2):

```
 +------------------------+
 |    HEADER              |
 |                        |
 +------------------------+
 |    KEY                 |
 |    X-Wing ciphertext   |
 +------------------------+
 |                        |
 |    CONTENT             |
 |    nonce               |
 |    AES-256-GCM         |
 |    ciphertext + tag    |
 |                        |
 +------------------------+
```

KEY is the X-Wing (ML-KEM-768 + X25519) ciphertext (1120 bytes) that encapsulates a shared secret to the recipient's
public key. The content key is `SHA3-256("vault v2 aes-256-gcm" || shared secret)`.
CONTENT is a random 12 byte nonce followed by the AES-256-GCM ciphertext and its 16 byte tag. The 20 HEADER bytes are
authenticated as associated data, a changed header fails decryption like changed content.

V2 keys are PEM files: `XWING PRIVATE KEY` holds the 32 byte private key seed, `XWING PUBLIC KEY` the 1216 byte public
key.

## Keys

### Where the V2 keys are stored

The key directory `~/.vault/v2` holds one current key per repository, named after the
[repository ID](#the-repository-id), and the older keys from [rotations](#rotate-your-own-key):

```sh
~/.vault/v2/[REPOSITORY_ID].pem
~/.vault/v2/[REPOSITORY_ID].pem.pub
~/.vault/v2/[REPOSITORY_ID]_backup_[TIMESTAMP].pem
~/.vault/v2/[REPOSITORY_ID]_backup_[TIMESTAMP].pem.pub
```

Every private key needs its own `.pem.pub` next to it. Vault fails if it is missing or belongs to another key.
A private key can also be stored gpg encrypted, see [PGP / GPG + Smart Cards](#pgp--gpg--smart-cards).

The environment variable `VAULT_V2_KEY_PATH` sets another key directory. It is used instead of `~/.vault/v2`, which is
then not searched. An empty value counts as unset.

```sh
VAULT_V2_KEY_PATH=[PATH] vault get foo
```

`vault create-key` fails if the key directory already contains a key for this repository. Create the key of a second
user, e.g. a web server, in its own key directory and copy both files to `~/.vault/v2` on the server:

```sh
VAULT_V2_KEY_PATH=~/vault_webserver_keys vault create-key webserver
```

Locally, Vault run with the same `VAULT_V2_KEY_PATH` acts as the web server.

### How vault knows who you are

There is no user name setting. A V2 key belongs to the user whose registered public key
(`.vault/keys/[USER]/[USER].pem.pub`) in the current checkout is the same key. A V2 key that matches no registered
public key only decrypts. `vault` lists it under its file name. A V1 key belongs to the user of its file name
`[USER].pem`.

A V2 key is usable when it is registered in the checkout, whatever its file is called, so on a branch from before a
rotation the backup is used. A V1 key is usable unless its file name contains `_backup_` or it is superseded by a V2 key
of its user (see [Migrate a V1 key to V2](#migrate-a-v1-key-to-v2)). New secrets are encrypted with, and `vault rotate`
rotates, the first usable key. V2 keys come before V1 keys; within a version, the order of the `loaded keys` list
applies.

### The repository ID

`.vault/repository_id` holds a UUID that names the V2 key files of this repository in the key directory.
`vault create-key` and `vault rotate --migrate v2` create it if it is missing. Vault never changes it afterwards.
Commit it. Without it, Vault loads no V2 keys.

If two people create it at the same time, e.g. on two branches, `.vault/repository_id` conflicts in git. Keep one side
(`git checkout --ours .vault/repository_id` or `--theirs`). Whoever's ID was not kept has no loaded V2 key afterwards
(`vault get` fails with `could not find key`) and renames their local key files, including backups and `.pem.pgp`, to
the kept ID:

```sh
mv ~/.vault/v2/[OLD_ID].pem ~/.vault/v2/[KEPT_ID].pem
mv ~/.vault/v2/[OLD_ID].pem.pub ~/.vault/v2/[KEPT_ID].pem.pub
```

No secret has to be encrypted again.

### Rotate your own key

you can rotate your own private key.

```sh
vault rotate
```

The key is rotated into a new key of the same version. Vault gives the new key access to every secret your loaded keys
can read, removes the `.crypt` files of the old key and registers the new public key under the same user name. Commit
the changes in `.vault/`.

- V2: `[REPOSITORY_ID].pem` (`.pem.pub`, `.pem.pgp`) is renamed to `[REPOSITORY_ID]_backup_[TIMESTAMP].pem` (`.pem.pub`,
  `.pem.pgp`) and the new key takes its place. Backups are kept and still decrypt, so older branches and commits stay
  readable. The subscriptions in `config.toml` are kept.
- V1: the new key is written to `./.vault/private_keys/[USER].pem` and the old key there is renamed to
  `[USER]_backup_[TIMESTAMP].pem`, which only decrypts. If the old key was loaded from elsewhere
  (`VAULT_PRIVATE_KEY_PATH`, `~/.vault/private_keys` or a `.pem.pgp` file), replace its files with the new
  `./.vault/private_keys/[USER].pem` and `[USER].pub.pem`. The `config.toml` of the user starts without subscriptions.

### Migrate a V1 key to V2

```sh
vault rotate --migrate v2
```

This rotates the first usable V1 key into a new V2 key in the key directory and creates
`.vault/repository_id` if it is missing. Every secret your loaded keys can read is encrypted for the new key in file
format version 2, and the subscriptions in `config.toml` are kept. The V1 key is backed up as in a
[V1 rotation](#rotate-your-own-key). A V1 key that stays loaded is superseded by the V2 key of its user and only
decrypts in this repository. Commit the changes in `.vault/`.

The migration fails if the key directory already contains a key for this repository. With several V1 keys, migrate each
further key with its own `VAULT_V2_KEY_PATH`, because a key directory holds one current key per repository. There is no
way back to V1: `vault rotate` of a V2 key creates a V2 key and `--migrate` only accepts `v2`.

### Mixed V1 and V2 repositories

V1 and V2 users can share secrets in the same repository. Each `.crypt` file is written in the format of its
recipient's key: version 1 for a V1 key, version 2 for a V2 key.

As soon as one V2 key is in the repository, every user needs a vault version with V2 support (2.0.0 or newer). Older
versions cannot share secrets with V2 users and can fail to read secrets that contain a version 2 file. Scripts can
enforce this with [--expect_version](#enforce-vault-versions-using---expect_versionversion_requirement):

```sh
vault --expect_version='>=2.0.0' get foo
```

### V1 keys

V1 keys are RSA keys created with OpenSSL:

```sh
vault create-openssl-key [USERNAME]
```

This always writes the private key `./.vault/private_keys/[USERNAME].pem` with its public key `[USERNAME].pub.pem`, also
when `VAULT_PRIVATE_KEY_PATH` is set, and registers `.vault/keys/[USERNAME]/`. While the variable is set,
`./.vault/private_keys` is not searched, so move both files into its directory. Commit `.vault/keys/[USERNAME]/`, never
the private key.

### Overriding the Private Key Directory (V1)

By default, vault will look up V1 private keys in `./.vault/private_keys` and `~/.vault/private_keys`.
You can overwrite the directory `./.vault/private_keys` using the environment variable `VAULT_PRIVATE_KEY_PATH`.
`~/.vault/private_keys` is always searched.

```sh
VAULT_PRIVATE_KEY_PATH=[PATH] vault get foo
```

# PGP / GPG + Smart Cards

Vault supports pgp encrypted private keys, for V1 and V2 keys.
If vault comes across such a private key which has .pgp as file extension, vault tries to decrypt it using:

```sh
gpg --decrypt --pinentry-mode loopback [PRIVATE_KEY].pem.pgp
```

Authentication with a yubikey could then take place here, for example. The secrets themselves are not encrypted via gpg,
but the private key for decrypting the secrets can be protected in this way. Ideally with a smartcard / yubikey / ... .

The public key next to it (`.pem.pub` for V2, `.pub.pem` for V1) stays unencrypted. `vault create-key`,
`vault create-openssl-key` and `vault rotate` write the new private key unencrypted as `.pem`. Encrypt it yourself as
shown below.

Example (V2):

```sh
# without pgp:
~/.vault/v2/[REPOSITORY_ID].pem

# with pgp:
~/.vault/v2/[REPOSITORY_ID].pem.pgp

# list your keys:
gpg --list-keys

gpg --trust-model always --encrypt --recipient "[YOUR_KEY]" -o ~/.vault/v2/[REPOSITORY_ID].pem.pgp ~/.vault/v2/[REPOSITORY_ID].pem
rm ~/.vault/v2/[REPOSITORY_ID].pem
```

Example (V1):

```sh
# without pgp:
./.vault/private_keys/[username].pem

# with pgp:
./.vault/private_keys/[username].pem.pgp

# list your keys:
gpg --list-keys

gpg --trust-model always --encrypt --recipient "[YOUR_KEY]" -o ./.vault/private_keys/[USERNAME].pem.pgp ./.vault/private_keys/[USERNAME].pem
rm ./.vault/private_keys/[USERNAME].pem
```
