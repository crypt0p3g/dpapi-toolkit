# Removable offline application plugins

Plugins are loaded only when selected (or when their narrow filename rule
matches) from the toolkit-local `plugins` directory. They are ordinary local
Python code and are therefore trusted at the same level as the toolkit itself;
remove a plugin directory to remove the feature. Plugin manifests cannot point
outside their own directory, and the toolkit never downloads plugins. Each
manifest may declare its own text, password, and file controls for the web
interface. The web interface always exposes **3. Plugins**; selecting a plugin
there reveals only that plugin's controls, names its required main artifact,
and states whether **2. Unlock key** is also needed. **1. Artifact** is not used
for plugin runs. Removing a plugin removes its choice and panel.

All application plugins are entirely offline. They do not contact a vendor
service or a Windows host.

## Certificate / PFX bundle

The Certificate / PFX plugin bundles a PEM/DER private key, or decrypts a
CAPI/CNG key first, then matches it to a certificate by public key. Both the key
input and the certificate input may be a single file or a folder, so a directory
of keys can be matched against a copied `SystemCertificates\My\Certificates`
folder in one run; each match is reported by the certificate SHA1 thumbprint:

```bash
python3 dpapi_toolkit.py private-key.pem --plugin certificate_pfx \
  --certificate certificate.cer --pfx-password 'new PFX password'

python3 dpapi_toolkit.py CNG_FILE --plugin certificate_pfx \
  --real-masterkey KEY --certificate CERT_FILE \
  --pfx-password 'new PFX password'

python3 dpapi_toolkit.py CRYPTO_KEYS_DIR --plugin certificate_pfx \
  --masterkey-dir PROTECT-SID --sid SID --password PASSWORD \
  --certificate MY_CERTIFICATES_DIR --pfx-password 'new PFX password'
```

## Entra ID CacheData

The CacheData plugin supports a password node when the exact password is known.
It validates the file checksum, applies the fixed PBKDF2/AES flow, and returns
the PRT JSON, raw DPAPI credential key, and derived SID-bound prekey. It can also
export a bounded Hashcat mode-33700 verifier for a separate authorized recovery
process. When a file contains several password nodes, each is attempted and
every node matching the supplied password is returned even if sibling nodes do
not decrypt. The toolkit itself accepts no wordlist, generates no candidates,
and does not launch Hashcat:

```bash
python3 dpapi_toolkit.py CacheData --plugin cachedata --password 'known password'
python3 dpapi_toolkit.py CacheData --plugin cachedata --cachedata-hashcat
```

PIN/NGC CacheData nodes remain separate because they require the collected NGC
and CNG key chain; TPM-backed keys cannot be reconstructed from copied files.

## Windows SYSTEM/SECURITY/SAM hives

The Windows-hives plugin derives the boot key from a collected `SYSTEM` hive.
Add a collected `SECURITY` hive to recover the 20-byte DPAPI_SYSTEM MachineKey
and UserKey, and optionally add `SAM` to export local account hashes. It does
not use Remote Registry, RPC, SMB, cached-domain-logon extraction, password
history, or general LSA-secret output. Pass the hives explicitly, or point the
main input at a folder that holds them (each hive is matched by name):

```bash
python3 dpapi_toolkit.py SYSTEM --plugin windows_hives \
  --security-hive SECURITY --sam-hive SAM

python3 dpapi_toolkit.py HIVES_DIR --plugin windows_hives
```

The raw `.dpapi_system` result can be supplied directly to a later command with
`--dpapi-system`. The `.sam` result uses the standard
`username:RID:LM:NT:::` representation and is written with owner-only
permissions like every other decrypted secret.

## DPAPI-NG (offline root key)

The DPAPI-NG plugin accepts an exported KDS root key as JSON and deliberately
uses only its preloaded in-process key cache. It supports the SID protection
descriptor implemented by the optional `dpapi-ng` package and refuses a cache
miss instead of allowing DNS/RPC discovery:

```bash
python3 dpapi_toolkit.py secret.dpapi-ng --plugin dpapi_ng \
  --dpapi-ng-root-key root-key.json
```

### Walkthrough

DPAPI-NG (the `NCryptProtectSecret`/`NCryptUnprotectSecret` API) protects data to
a protection descriptor, usually a SID or group, rather than to one account
password. Its keys derive from a domain-wide **KDS root key** stored on the
domain controllers. This plugin needs that root key supplied explicitly; it never
contacts a domain controller.

1. **Export the KDS root key (needs Domain Admin or SYSTEM).** The root keys live
   in the configuration partition at
   `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=...`.
   The `msKds-RootKeyData` attribute is confidential and only Domain Admins/SYSTEM
   can read it. Read the objects with a privileged LDAP query (for example
   `Get-ADObject -SearchBase 'CN=Master Root Keys,...' -Filter * -Properties *`),
   or recover them offline from a collected `NTDS.dit`.

2. **Write `root-key.json`.** The file is one object or a list of objects. Each
   object needs `RootKeyId` (the object `cn` GUID) and Base64 `RootKeyData` (the
   64-byte `msKds-RootKeyData`). The remaining fields are optional and fall back to
   the Windows defaults shown here when omitted:

   ```json
   [
     {
       "RootKeyId": "d9a2b0a1-1111-2222-3333-444455556666",
       "RootKeyData": "<base64 of msKds-RootKeyData>",
       "Version": 1,
       "KdfAlgorithm": "SP800_108_CTR_HMAC",
       "KdfParameters": "<base64 of msKds-KDFParam, optional>",
       "SecretAgreementAlgorithm": "DH",
       "SecretAgreementParameters": "<base64 of msKds-SecretAgreementParam, optional>",
       "PrivateKeyLength": 512,
       "PublicKeyLength": 2048
     }
   ]
   ```

   The attribute-to-field mapping is `cn` -> `RootKeyId`, `msKds-RootKeyData` ->
   `RootKeyData`, `msKds-Version` -> `Version`, `msKds-KDFAlgorithmID` ->
   `KdfAlgorithm`, `msKds-KDFParam` -> `KdfParameters`,
   `msKds-SecretAgreementAlgorithmID` -> `SecretAgreementAlgorithm`,
   `msKds-SecretAgreementParam` -> `SecretAgreementParameters`,
   `msKds-PrivateKeyLength` -> `PrivateKeyLength`, and `msKds-PublicKeyLength` ->
   `PublicKeyLength`. Only KDF `SP800_108_CTR_HMAC` and secret-agreement `DH`,
   `ECDH_P256`, `ECDH_P384`, or `ECDH_P521` are supported.

3. **Decrypt.** On the CLI, run the command above. In the web UI, open
   **3. Plugins**, choose **DPAPI-NG (offline root key)**, drop the DPAPI-NG
   artifact as the main input and `root-key.json` in its field, then **Run
   plugin**. `1. Artifact` and `2. Unlock key` are not used. If no supplied root
   key matches the blob, the plugin stops rather than falling back to the network.
