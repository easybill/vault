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

```sh
vault create-openssl-key [USERNAME]
```

### Create a new Secret

```sh
# To create a new secret just put the file into the Secrets folder. The file name will later become the name of the secret.
echo "this is secret" > ./.vault/secrets/MY_NEW_SECRET

# now just call vault and it will find the unencrypted secret and ask if you want to encrypt it.
vault

# do you want to add the new secret ./.vault/secrets/MY_NEW_SECRET (y/n)
# press y and your secret is encrypted.

# get the secret
vault get MY_NEW_SECRET # prints "this is secret"
```

### Sharing the Secret

Just add the secret in the file `./vault/keys/[USER]/config.toml` as a subscription:

```toml
subscriptions = [
    "MY_NEW_SECRET", # Glob patterns are supported. e. g. DEV*
]
```

and now run vault:

```sh
vault
```

Vault now detects that there is an open subscription to a secret that you can fulfill.

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

If the version requirement does not match with your vault version, you'll get an error prompt and help, how to update
vault.

### Rotate your own key

you can rotate your own private key.

```sh
vault rotate
```

### Overriding the Private Key Directory

By default, vault will look up `~/.vault/private_keys` and `~/.vault/private_keys`.
You can overwrite the directory using the environment variable `VAULT_PRIVATE_KEY_PATH`

```sh
VAULT_PRIVATE_KEY_PATH=[PATH] vault get foo
```

### How it works?

Vault makes it possible to share encrypted information, for example in a git repository in a team.
Vault behaves like a key-value store, the values are encrypted, the keys are not.
It is possible to define rights in a fine granular way. Anyone who has access to a value can share this access.

Vault is based on OpenSSL keys - please do not confuse them with OpenSSH keys. There are differences here :).
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
`./vault/keys/[USER]/config.toml` for the user.
Then run `./vault`, then you will be informed that there is an open subscription, which you can fulfill yourself.
If you confirm this with "y" the key will be encrypted for the user using his public key and stored as usual under
`./.vault/secrets/[KEY]/[USER].crypt`.
The user now has the possibility to query the key and to fulfill subscriptions to this key himself if required.

It is important to understand that everyone has the possibility to modify subscriptions and thus can see who has access
to which data.
Anyone who has access to an encrypted entry can share it. This allows for example flows like the following:
"Person A" wants "Webserver" to have access to the key "production_mysql_pass", but has no access himself.
"Person A" now has the ability to add a subscription (`./vault/keys/webserver/config.toml`) and push it using git.
"Person A" can now ask "Person B" who has access to the corresponding key to run `vault` and answer with a simple "y"
the question,
If "webserver" is allowed to get access to the corresponding key.
It should be noted that person A never had access to the key, but can monitor the process that the web server gets it.

### Cryptography

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
 |    RSA 256CBC          |
 |                        |
 |                        |
 +------------------------+

```

Vault encrypts the actual content (CONTENT) symmetrically via aes_256_cbc (+iv).
The key (KEY) to decrypt the content is encrypted asymmetrically via RSA (private/public key) and is chosen randomly.
Similar concept uses TLS -> TLS Key Exchange.

This theoretically allows to encrypt files of any size.
Currently, the size is limited, this can be relaxed later if necessary.

# PGP / GPG + Smart Cards

Vault supports pgp encrypted private keys.
If vault comes across such a private key which has .pgp as file extension, vault tries to decrypt it using:

```sh
gpg --decrypt ./.vault/private_keys/[username].pem.pgp`.
```

Authentication with a yubikey could then take place here, for example. The secrets themselves are not encrypted via gpg,
but the private key for decrypting the secrets can be protected in this way. Ideally with a smartcard / yubikey / ... .

Example:

```sh
# without pgp:
./.vault/private_keys/[username].pem

# with pgp:
./.vault/private_keys/[username].pem.pgp

# list your keys:
gpg --list-keys

gpg --trust-model always --encrypt --recipient "[YOUR_KEY]" -o ./.vault/private_keys/[USERNAME].pem.pgp ./.vault/private_keys/USERNAME.pem
```
