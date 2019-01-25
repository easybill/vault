# vault

### Installation

einfach die passende Binary unter releases runterladen.

### Beschreibung

Vault ermöglicht es verschlüsselte Informationen beispielsweise in einem git repository in einem Team zu teilen.
Vault verhält sich wie ein Key-Value store, die Werte werden verschlüsselt, die Keys nicht.
Dabei ist es möglich, Rechte fein granular zu definieren. Jeder der Zugriff auf einen Wert hat, kann diesen Zugriff weiter teilen.

Vault basiert auf OpenSSL Schlüsseln - diese bitte nicht mit OpenSSH Schlüsseln verwechseln. Hier gibt es unterschiede :).
Der Vault-Public-Key jedes Nutzers (oder beispielsweise eines Nutzer der einen Webserver repräsentiert) wird im .vault Verzeichnis abgelegt. 
Dadurch dass der Public-Key jedes Nutzers bekannt ist, hat jeder Nutzer die Möglichkeit Secrets abzulegen.
Für jeden Nutzer der Zugriff auf einen Key haben soll, wird dieser einmal mittels seines Vault-Public-Keys verschlüsselt.

Die einfachste Variante ist, den Inhalt eines Eintrags für sich selbst zu verschlüsseln.
Dazu reicht es im Ordner ./.vault/secrets/[KEY] eine Datei abzulegen und ./vault aufzurufen.
Vault merkt dies und schlägt vor, die entsprechende Datei zu verschlüsseln. Bestätigt man dies wird die Datei durch einen gleichnamigen Ordner ersetzt.
./.vault/secrets/[KEY] wird zu ./.vault/secrets/[KEY]/[USER].crypt. Für jeden Nutzer welcher Zugriff auf einen Schlüssel hat, wird eine solche Datei angelegt.

Mittels `vault get [KEY]` lässt sich der Inhalt entschlüsseln und ausgeben.

Nun ist der Key Verschlüsselt, jedoch hat man nur selbst Zugriff auf diesen.
Um einem anderen Nutzer Zugriff auf den Schlüssel zu geben, legt man eine Subscription an.
Dies hört sich kompliziert an, ist aber ganz einfach.
Dazu einfach in ./vault/keys/[USER]/config.toml bei dem User einen Subscription-Eintrag für den Key hinzufügen.
Im Anschluss dann schlicht ./vault aufrufen, dann wird man darauf hingeweisen, dass es eine offene Subscription gibt, welche man selbst erfüllen kann.
Bestätigt man dies mit "y" wird der Key für den Nutzer anhand seines Public-Keys verschlüsselt und  wie gewohnt unter ./.vault/secrets/[KEY]/[USER].crypt abgelegt.
Der Nutzer hat nun die Möglichkeit den Key abzufragen und bei Bedarf selbst Subscriptions zu diesem Key zu erfüllen.

Dabei ist wichtig zu verstehen, dass jeder die Möglichkeit hat Subscriptions zu modifizieren und damit einsehen kann, wer letzlich Zugriff auf welche Daten hat, bzw. haben möchte.
Jeder der Zugriff auf einen Verschlüsselten Eintrag hat, kann diesen weitergeben. Dies ermöglicht beispielsweise Flows wie folgt:
"Person A" möchte, dass "Webserver" Zugriff auf den key "production_mysql_pass" hat, hat aber selbst keinen Zugriff.
"Person A" hat nun die Möglichkeit eine Subscription (./vault/keys/webserver/config.toml) hinzuzufügen und mittels git zu pushen.
"Person A" kann nun "Person B" welche Zugriff auf den entsprechenden Schlüssel hat bitten, "./vault" auszuführen und mit einem einfachen "y" die Frage zu beantworten,
ob "Webserver" den Zugriff auf den entsprechenden Key bekommen darf.
Dabei ist zu beachten, dass Person A nie Zugriff auf den Schlüssel hatte, jedoch den Prozess überwachen kann, dass der Webserver diesen bekommt.
Dies würde sich auch automatisiert beweisen lassen, um beispielsweise in einem CI Prozess sicherzustellen, dass alle notwendigen Secrets vorhanden sind.

### Neuen User anlegen

```
vault create-openssl-key [USERNAME]
```

daraufhin werden keys für den User generiert und im richtigen Ordner abgelegt.

### Verschlüsselten Key ausgeben

```
vault get [KEY]
```

### Template mit verschlüsselten Platzhaltern parsen

vault kann Platzhalter in templates (UFT8) ersetzen.

Die Platzhalter haben den Aufbau: `{vault{ KEY }vault}`.

```
vault template ./example_template
// oder
vault template ./example_template 1> example_template_decoded
```

Vault wirft einen Fehler, falls Keys nicht ersetzt werden können.

** Achtung: ** Vault erzeugt ggf. ein error Output wenn es z. B. über Dateien stolpert welche es nicht verarbeiten kann.
Daher immer nur den stdout `1>` in ein template übergeben.

### Overriding the Private Key Directory

by default vault will lookup `~/.vault/private_keys` and `~/.vault/private_keys`.
you can overwrite the directory using the environment variable `VAULT_PRIVATE_KEY_PATH`

```
VAULT_PRIVATE_KEY_PATH=[PATH] vault get foo
```

### Cryptography

Aufbau einer Vault (.crypt) Datei (Version 1):

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

Vault verschlüsselt den eigentlichen Inhalt (CONTENT) symmetrisch via aes_256_cbc (+iv).
Der Schlüssel (KEY) um den Inhalt zu entschlüsseln, wird via asymmetrisch via RSA (Private / Public-Key) verschlüsselt und wird zufällig gewählt.
Ähnliches Konzept nutzt TLS -> TLS Key Exchange. 

Dies erlaubt theoretisch beliebig große Dateien zu verschlüsseln. 
Derzeit ist die Größe limitiert, dies kann ggf. später gelockert werden.



