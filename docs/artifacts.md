# Artifact formats

Per-format CLI examples. All of these also work through the local web UI (see
[web-ui.md](web-ui.md)); the masterkey-unlocking options, output selection, and
batch behavior common to every format are documented in
[cli-reference.md](cli-reference.md).

## Classic DPAPI blob and PowerShell SecureString

A classic blob normally starts with:

```text
01000000d08c9ddf0115d1118c7a00c04fc297eb
```

```bash
python3 dpapi_toolkit.py blob.bin --type blob --real-masterkey KEY
python3 dpapi_toolkit.py blob.hex --type blob --real-masterkey KEY
python3 dpapi_toolkit.py securestring.txt --type powershell --real-masterkey KEY
```

Binary and hexadecimal input are both accepted, and in `auto`/`blob` mode a
Base64-wrapped blob is unwrapped automatically before the structure is parsed,
including the Chromium `DPAPI`-prefixed form used by browser key storage.

PowerShell support applies to `ConvertFrom-SecureString` output created without
an explicit `-Key` or `-SecureKey`.

`Export-Clixml` credential/SecureString documents are also supported. Every
DPAPI-backed `<SS>` value is decrypted and returned in one JSON document rather
than silently using only the first value:

```bash
python3 dpapi_toolkit.py credential.clixml --type clixml \
  --masterkey-dir Protect-SID --sid SID --password PASSWORD
```

## KeePass ProtectedUserKey.bin

KeePass Windows-user-account key material stored in `ProtectedUserKey.bin` is
a classic DPAPI blob. The filename is auto-detected and the clear key is saved
as `.key`:

```bash
python3 dpapi_toolkit.py ProtectedUserKey.bin --type keepass \
  --masterkey-dir Protect-SID --sid SID --password PASSWORD
```

## SCCM policy secrets

`--type sccm` scans a collected `OBJECTS.DATA`, SQL export, or an individual
`PolicySecret Version="1"` value for the wrapped SYSTEM-DPAPI blob. The full
file is bounded by the normal input/upload limits and the number and size of
candidate values are capped. Every PolicySecret is decrypted independently: a
missing masterkey produces an error object for that value while secrets whose
masterkeys are available remain in the JSON result.

```bash
python3 dpapi_toolkit.py OBJECTS.DATA --type sccm \
  --masterkey-dir SYSTEM-PROTECT --dpapi-system DPAPI_SYSTEM_HEX
```

## Credential Manager

Locations:

```text
%LOCALAPPDATA%\Microsoft\Credentials\*
%APPDATA%\Microsoft\Credentials\*
```

```bash
python3 dpapi_toolkit.py CREDENTIAL_FILE \
  --type credential \
  --masterkey MASTERKEY-GUID \
  --sid SID \
  --password PASSWORD
```

Output JSON includes target, username, credential, persistence, timestamp, and
attributes when the plaintext schema is recognized.

## Windows Vault

Locations:

```text
%LOCALAPPDATA%\Microsoft\Vault\<VAULT-GUID>\Policy.vpol
%LOCALAPPDATA%\Microsoft\Vault\<VAULT-GUID>\*.vcrd
%SYSTEMROOT%\System32\config\systemprofile\AppData\Local\Microsoft\Vault
```

Decrypt `Policy.vpol` and extract its AES keys:

```bash
python3 dpapi_toolkit.py Policy.vpol \
  --type vpol \
  --masterkey MASTERKEY-GUID \
  --sid SID \
  --password PASSWORD
```

Decrypt a record using its policy directly:

```bash
python3 dpapi_toolkit.py RECORD.vcrd \
  --type vcrd \
  --vault-policy Policy.vpol \
  --masterkey MASTERKEY-GUID \
  --sid SID \
  --password PASSWORD
```

Or provide an extracted Vault AES key/JSON:

```bash
python3 dpapi_toolkit.py RECORD.vcrd --type vcrd --vault-key AES_KEY_HEX
python3 dpapi_toolkit.py RECORD.vcrd --type vcrd --vault-key POLICY_OUTPUT.json
```

Batch mode decrypts `Policy.vpol` first and applies its keys to `.vcrd` files in
the same Vault directory.

## CAPI, CNG, and public certificates

Locations:

```text
CAPI: %APPDATA%\Microsoft\Crypto\RSA\<SID>\*
CNG:  %APPDATA%\Microsoft\Crypto\Keys\*
Cert: %APPDATA%\Microsoft\SystemCertificates\My\Certificates\<THUMBPRINT>
```

```bash
python3 dpapi_toolkit.py CAPI_FILE --type capi --real-masterkey KEY
python3 dpapi_toolkit.py CNG_FILE  --type cng  --real-masterkey KEY
python3 dpapi_toolkit.py CERT_FILE --type cert
```

Recognized private keys are converted to PKCS#8 PEM: CAPI/CNG RSA, CAPI DSS2,
CNG DSA (legacy 512–1024-bit blob), and CNG ECDH/ECDSA P-256, P-384, and P-521.
Unknown or newer Windows key structures remain available as raw decrypted
bytes. Public certificate files are converted to PEM-encoded `.crt` files.

To correlate a certificate with a decrypted key and build a PKCS#12/PFX, add
the certificate and an explicit PFX password. Public keys are compared before
the bundle is created, so a mismatched certificate is rejected:

```bash
python3 dpapi_toolkit.py CNG_FILE --type cng --real-masterkey KEY \
  --certificate CERT_FILE --pfx-password 'new PFX password'
```

Use `--pfx-password ''` only when an intentionally unencrypted PFX is required.
In the web UI this workflow is under **3. Plugins → Certificate / PFX bundle**.
Its main input accepts a ready PEM/DER private key, an encrypted CAPI/CNG key,
or a folder of keys; encrypted keys also use the masterkey material in
**2. Unlock key**. The certificate input accepts one certificate or a folder of
them (for example a copied `SystemCertificates\My\Certificates` directory). Each
recovered key is matched to a certificate by SHA-256 SPKI, and each match is
reported by its SHA-1 thumbprint (the store filename) and bundled into its own
PFX.

## Personal Wi-Fi profiles

Location:

```text
%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\<INTERFACE-GUID>\*.xml
```

Wi-Fi `keyMaterial` is normally SYSTEM DPAPI:

```bash
python3 dpapi_toolkit.py profile.xml \
  --type wifi \
  --masterkey SYSTEM-MASTERKEY-GUID \
  --dpapi-system DPAPI_SYSTEM_HEX
```

Or use an already-decrypted SYSTEM masterkey:

```bash
python3 dpapi_toolkit.py profile.xml --type wifi --real-masterkey SYSTEM_KEY
```

## Enterprise Wi-Fi / PEAP

Export `MSMUserData` from:

```text
HKCU\Software\Microsoft\Wlansvc\UserData\Profiles\<PROFILE-GUID>\MSMUserData
```

The outer layer is SYSTEM DPAPI and the nested password is user DPAPI:

```bash
python3 dpapi_toolkit.py MSMUserData.bin \
  --type wifi-peap \
  --system-masterkey SYSTEM-MASTERKEY-GUID \
  --dpapi-system DPAPI_SYSTEM_HEX \
  --masterkey USER-MASTERKEY-GUID \
  --sid USER_SID \
  --password USER_PASSWORD
```

`--system-masterkey` accepts an encrypted or already-decrypted SYSTEM masterkey
as a raw file or hex. Use `--real-masterkey` for the nested user layer when its
masterkey is already decrypted.

## Outlook IMAP

```bash
python3 dpapi_toolkit.py NTUSER.DAT \
  --type outlook \
  --masterkey MASTERKEY-GUID \
  --sid SID \
  --password PASSWORD
```

Direct hive parsing requires `python-registry`. Alternatively export the binary
`IMAP Password` registry value and supply it instead of `NTUSER.DAT`.

## Saved Remote Desktop `.rdp` files

Standard `.rdp` files may contain a DPAPI-protected line:

```text
password 51:b:<hexadecimal DPAPI blob>
```

```bash
python3 dpapi_toolkit.py connection.rdp \
  --type rdp \
  --masterkey MASTERKEY-GUID \
  --sid SID \
  --password PASSWORD
```

UTF-8, UTF-16LE, and BOM-marked files are supported. Output JSON includes the
address, username, domain, gateway, password field name, and decrypted value.

## Remote Desktop Connection Manager

RDCMan files normally use `.rdg` and store Base64 DPAPI credential profiles.

```bash
python3 dpapi_toolkit.py sessions.rdg \
  --type rdcman \
  --masterkey MASTERKEY-GUID \
  --sid SID \
  --password PASSWORD
```

## Windows Hello / NGC software keys

Collect these offline:

```text
%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc
%WINDIR%\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys
%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault
SYSTEM, SECURITY, and SOFTWARE hives
```

Inspect/decrypt a software-backed NGC CNG key:

```bash
python3 dpapi_toolkit.py NGC_CNG_KEY \
  --type ngc-cng \
  --masterkey SYSTEM-MASTERKEY-GUID \
  --dpapi-system DPAPI_SYSTEM_HEX \
  --pin PIN
```

Only the software CNG private-key/PIN stage is implemented. Microsoft Platform
Crypto Provider keys are TPM-bound and cannot normally be decrypted from copied
files. The full `15.dat` + secondary key + NgcPin Vault/registry password chain
is not implemented. Supply one known PIN with `--pin`; PIN Hashcat export and
brute-force functionality are intentionally disabled.

## Chromium Local State (browser os_crypt key)

Chromium browsers (Chrome, Edge, Brave) store the AES-256-GCM key that protects
`v10`/`v11` cookies and saved logins in the `Local State` file, under
`os_crypt.encrypted_key`. That value is Base64 of the ASCII prefix `DPAPI`
followed by a classic user-DPAPI blob:

```text
%LOCALAPPDATA%\Google\Chrome\User Data\Local State
%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State
```

Drop the whole `Local State` file, the raw `os_crypt.encrypted_key` string, or
the already-decoded `DPAPI`-prefixed value, and add the owning user's masterkey:

```bash
python3 dpapi_toolkit.py "Local State" --type localstate \
  --masterkey MASTERKEY-GUID --sid S-1-5-21-... --password PASSWORD

python3 dpapi_toolkit.py "Local State" --type localstate --real-masterkey KEY
```

`auto` also recognizes the file by name and by content. The result is JSON with
the recovered `os_crypt_key_hex` (normally the 32-byte AES-256-GCM key), which
then decrypts the browser's cookie and login databases. This recovers the DPAPI
key only; it does not read the SQLite databases, and app-bound encryption
(newer Chrome, not a plain DPAPI key) is out of scope.
