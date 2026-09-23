# Local web UI

The web UI is a thin front end over the same offline core as the CLI, so its
results match the command line exactly. Start it with:

```bash
python3 dpapi_web.py                 # http://127.0.0.1:8765/
python3 dpapi_web.py --port 9000 --no-open
```

It uses an inspect-first flow: drop an artifact and it shows the parsed
**Structure** (identity, cryptography, and binary fields) plus the required
master-key GUID, then drop or type the key material and decrypt. Decrypted
results appear under the **Decrypted data** tab with per-value copy buttons.
Drop an encrypted master-key file and it is auto-detected: enter the SID and
click **Masterkey → Hashcat** to export a `$DPAPImk$` hash, or add unlock
material and decrypt it. A dropped folder (or several files) switches to batch
mode and the results come back as a single zip download. Specialized decoders
live under **3. Plugins**, where both the plugin and its artifact are selected;
the main Artifact tab is kept for core masterkeys, DPAPI blobs, and Windows
artifact formats. Optional entropy and Vault controls are under **2. Unlock
key** in a collapsed section, so the normal workflow stays compact.

## Security posture of the local server

No web-framework dependency: it runs a standard-library HTTP server bound to
`127.0.0.1` (loopback only) at the site root. Mutating requests require a
per-run token embedded in the served page, cross-origin/host checks are
enforced, uploads are bounded, and downloads expire after ten minutes and are
single-use. The web API does not accept hosting-server input/output paths and
never writes persistent decrypted output: uploaded material is placed in a
private per-request temporary directory (memory-backed `/dev/shm` on Linux when
available), removed after the request on both success and failure, and results
are held only in bounded memory until their one-time browser download or expiry.
This is browser-request hardening, not an isolation boundary against a hostile
process running as the same operating-system user. Decrypted secrets pass
through this local process; use **Reset & wipe** or stop it when finished.

The server binds to `127.0.0.1` only; the only options are `--port` and
`--no-open`, and there is no way to bind a LAN or public interface. Each analyst
runs a separate copy and opens it from the same computer. Its request token
prevents cross-origin mutations; it is not user authentication and the server is
not a multi-user service.

Unlike the CLI, the local web interface deliberately has no `--out-dir`,
`--out-file`, server-side autosave, or typed server-path behavior. A folder run
is assembled below the request's temporary directory, zipped into memory, and
returned to the browser. Persistent copies exist only when the browser user
downloads or copies a result.

## Complete workflow

The web interface follows the same sequence for every core artifact:

1. In **1. Artifact**, drop the artifact, paste its hexadecimal form, or drop a
   folder for batch processing. Leave **Type** on `auto` when the format is
   recognized, or select the exact type from the tables below.
2. Click **Inspect** first. **Structure** shows the detected format, embedded
   DPAPI blobs, cryptographic fields, and required masterkey GUIDs. Inspection
   does not need a key and does not create decrypted output.
3. In **2. Unlock key**, add either an already-decrypted masterkey or the
   encrypted masterkey/Protect directory plus one applicable unlocking method.
4. Open **Optional entropy / Vault** only when the source application used
   extra entropy or the input is a Vault record.
5. Choose the output representation and click **Decrypt**. Read or copy values
   under **Decrypted data**, or use the one-time download button for a file.
6. Click **Reset & wipe** when finished. It clears the browser fields and
   expires pending in-memory downloads; stopping the local process clears the
   remaining download store.

Plugins use **3. Plugins** instead of **1. Artifact**. Select the plugin, drop
its named main input in that tab, fill the controls it reveals, and click
**Run plugin**. Use **2. Unlock key** only when the selected plugin says that a
classic-DPAPI masterkey is also required.

## Choose one masterkey path

These paths unlock the masterkey required by the artifact. Key material unlocks
an encrypted masterkey; it is not applied directly to the artifact.

| What you have | **2. Unlock key** flow |
|---|---|
| Decrypted masterkey | Drop the 64-byte masterkey or its 20-byte SHA1 mapping under **Decrypted masterkey**, or paste its hexadecimal/Base64 value. No SID or password is needed. |
| One encrypted user masterkey and password | Drop **Encrypted masterkey**, enter its owning SID and password, then decrypt the artifact. Select **Empty password** only when the password really is empty. |
| Protect directory and password | Drop the **Protect dir of masterkeys**, enter the owning SID and password, and decrypt. Every artifact blob is matched to its GUID-named masterkey. |
| Domain/Protected Users NT hash | Drop the encrypted masterkey or Protect directory, enter the owning `S-1-5-21-...` SID and the 16-byte NT hash. |
| Local SHA1 password hash | Drop the encrypted masterkey or Protect directory, enter the owning SID and the 20-byte `SHA1(password encoded as UTF-16LE)`. |
| Recovered Entra prekey | Drop the encrypted user masterkey or Protect directory, enter its `S-1-12-1-...` Entra SID, and paste the 20-byte recovered prekey. The field appears only for an Entra SID in a masterkey workflow. |
| Recovered Entra credential key | Drop the encrypted user masterkey or Protect directory, enter its `S-1-12-1-...` Entra SID, and paste the recovered credential key. The toolkit derives the SID-bound prekey. |
| DPAPI_SYSTEM | Drop the encrypted SYSTEM masterkey or SYSTEM Protect directory, then drop or paste DPAPI_SYSTEM. Do not put DPAPI_SYSTEM in the decrypted-masterkey field. |
| AD domain backup key | Drop the encrypted domain masterkey or Protect directory and add the AD backup key. If the PVK/PEM file is encrypted, also enter or load its file password. |

If an application used optional entropy, expand **Optional entropy / Vault** and
enter it as text, `hex:`, `base64:`, or `utf16:`, or drop the exact entropy
file. Explicit entropy replaces any built-in application entropy for that run.

## Core artifact flows

Every value offered by the web **Type** selector is covered here.

| Type | **1. Artifact** input | Additional flow | Result |
|---|---|---|---|
| `auto` | Any supported core artifact | Click **Inspect**, add the requested masterkey path when one is reported, then **Decrypt**. Use an explicit type if automatic recognition is ambiguous. | Detected format's normal result. |
| `masterkey` | GUID-named encrypted masterkey | Add one applicable unlock method from the table above. | Decrypted 64-byte masterkey. It can be downloaded and reused through **Decrypted masterkey**. |
| `credhist` | `CREDHIST` | Supply the current password, NT hash, or SHA1 hash. The SID is stored in the entries. The CLI additionally supports a current prekey or credential key. | JSON containing historical SIDs, SHA1 hashes, and NT hashes. Use the matching recovered hash to unlock an older masterkey. |
| `blob` | Raw or hex classic DPAPI blob | Add its required masterkey and optional entropy. | Raw, text, or selected output format. |
| `credential` | Credential Manager file | Add the owning user masterkey. | JSON with target, username, credential, persistence, timestamp, and attributes. |
| `capi` | Encrypted CAPI private-key file | Add the owning masterkey; normal CAPI entropy is selected automatically. | PKCS#8 PEM when the private-key structure is recognized, otherwise raw decrypted bytes. |
| `cng` | Encrypted CNG private-key file | Add the owning masterkey; normal CNG entropy is selected automatically. | PKCS#8 PEM when recognized, otherwise raw decrypted bytes. |
| `cert` | Serialized Windows, DER, or PEM public certificate | No masterkey is needed. | PEM-encoded `.crt`. Use the Certificate/PFX plugin when a matching private key should be bundled. |
| `vpol` | Vault `Policy.vpol` | Add the user or SYSTEM masterkey required by the policy blob. | JSON containing the Vault AES keys. |
| `vcrd` | Vault `.vcrd` record | Expand **Optional entropy / Vault** and either drop its `Policy.vpol` plus that policy's masterkey, paste a Vault AES key, or drop the JSON produced from `Policy.vpol`. | Decrypted Vault record JSON. |
| `powershell` | `ConvertFrom-SecureString` DPAPI hex | Paste or drop it, then add the owning user masterkey. This does not apply to values created with PowerShell `-Key` or `-SecureKey`. | UTF-8 plaintext. |
| `clixml` | PowerShell `Export-Clixml` document | Add the masterkey or Protect directory for every embedded SecureString. | One JSON document containing the username and every decrypted SecureString. |
| `keepass` | `ProtectedUserKey.bin` | Add its owning user masterkey. | Clear KeePass user-account key as `.key`. |
| `sccm` | `OBJECTS.DATA`, SQL export, or one `PolicySecret Version="1"` value | Add the matching SYSTEM masterkey and DPAPI_SYSTEM, or an already-decrypted SYSTEM masterkey. | JSON containing all recovered policy secrets. |
| `wifi` | Personal Wi-Fi profile XML | Add the required SYSTEM masterkey plus DPAPI_SYSTEM, or a decrypted SYSTEM masterkey. | JSON containing profile details and key material. An enterprise profile points to the separate `wifi-peap` flow. |
| `wifi-peap` | Exported `MSMUserData` binary | Add the outer SYSTEM masterkey in **SYSTEM masterkey (PEAP only)** plus DPAPI_SYSTEM. Also add the nested user masterkey/password path using the normal masterkey controls. | JSON containing PEAP identity and password. |
| `outlook` | `NTUSER.DAT` or exported binary `IMAP Password` value | `NTUSER.DAT` needs optional `python-registry`. Add the owning user masterkey. | JSON containing supported Outlook IMAP accounts and passwords. |
| `rdp` | Saved `.rdp` file containing `password 51:b:` | Add the owning user masterkey. | JSON containing connection metadata and decrypted password fields. |
| `rdcman` | RDCMan `.rdg` or `.settings` file | Add the masterkey or Protect directory for its credential profiles. | JSON containing every recovered credential profile. |
| `ngc-cng` | Software-backed Windows Hello CNG key | Add the encrypted SYSTEM masterkey and DPAPI_SYSTEM, then enter the one known PIN shown for this type. TPM-backed keys and PIN guessing are not supported. | Decrypted Windows Hello private key, or NGC metadata when the file is inspectable but not a supported software-PIN key. |
| `localstate` | Chromium `Local State` file, its `os_crypt.encrypted_key` value, or the `DPAPI`-prefixed key | Add the owning user masterkey. Base64 and the `DPAPI` prefix are handled automatically. | JSON with the recovered `os_crypt_key_hex` (the AES-256-GCM key for browser cookies/logins). |

## Chained recovery flows

Some jobs produce key material for a later job. Keep every stage local and use
the downloaded or copied result only in the next stage that names it.

### Offline hives to a SYSTEM-protected artifact

1. In **3. Plugins**, choose **Windows SYSTEM/SECURITY/SAM hives**.
2. Drop `SYSTEM` and `SECURITY` together into the one plugin input (or the folder
   that holds them); add `SAM` too only when local account hash export is also
   required, then **Run plugin**. Each hive is matched by name.
3. Download the `.dpapi_system` result, or click **Use as DPAPI_SYSTEM** on it to
   load it straight into **2. Unlock key**.
4. In **1. Artifact**, drop the SYSTEM-protected artifact. In **2. Unlock key**,
   add its encrypted SYSTEM masterkey or SYSTEM Protect directory and the
   downloaded DPAPI_SYSTEM value, then **Decrypt**.

### CacheData to an Entra user artifact

The usual Entra location is
`%WINDIR%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\AzureAD\<unique_hash>\Cache\CacheData`.
Microsoft-account entries use `MicrosoftAccount` instead of `AzureAD`.
Reading this system-profile location normally requires a process started with
**Run as administrator**: membership in the local Administrators group is not
enough when the process still has a filtered, medium-integrity UAC token. A
full/high-integrity administrator token is normally sufficient; SYSTEM is an
alternative if the actual host ACL or collection method requires it. Do not
change ownership or ACLs on evidence merely to make collection easier.

1. Collect that `CacheData` file with an authorized elevated or offline
   evidence-collection method. In **3. Plugins**, choose **Windows Entra ID
   CacheData**, drop the file, then choose one route:
   - enter the one known password and **Run plugin**; or
   - select **Export Hashcat mode 33700**, click **Run plugin**, download the
     `.hc33700` verifier, and test authorized candidates in a separate local
     Hashcat process with `hashcat -m 33700 FILE.hc33700 WORDLIST`.
2. If external recovery finds the password, clear the export checkbox, enter
   that password in the CacheData plugin, and run it again. The JSON result
   contains the Entra SID and derived `dpapi_prekey_hex`; the
   separate `.credkey` result contains the raw credential key.
3. In **1. Artifact**, drop the target artifact. In **2. Unlock key**, drop its
   encrypted Entra masterkey or Protect directory and enter the recovered
   `S-1-12-1-...` SID.
4. Paste either the derived prekey or the credential key, not both, and click
   **Decrypt**. These recovered keys unlock the masterkey, not the artifact and
   not a Windows Hello PIN.

### CREDHIST to an artifact protected before a password change

1. Decrypt `CREDHIST` with the current password/hash using the `credhist` flow.
2. Locate the entry whose GUID/SID corresponds to the older masterkey and copy
   its recovered SHA1 or NT hash.
3. Drop the older artifact in **1. Artifact** and its older encrypted masterkey
   in **2. Unlock key**. Enter the entry's SID and matching recovered hash, then
   **Decrypt**.

### Vault policy to Vault records

1. Decrypt `Policy.vpol` with type `vpol` and its DPAPI masterkey.
2. For one record, drop the `.vcrd`, select `vcrd`, and load the policy output
   JSON or paste one extracted AES key under **Optional entropy / Vault**.
3. Alternatively, drop the `.vcrd`, add the original `Policy.vpol` there, and
   leave its DPAPI masterkey material in **2. Unlock key** so both stages run
   together.
4. For a whole Vault folder, use the batch flow; the policy is processed before
   records in the same directory.

### CAPI/CNG private key and certificate to PFX

1. In **3. Plugins**, choose **Certificate / PFX bundle**.
2. Drop a ready PEM/DER private key, an encrypted CAPI/CNG key, or a folder of
   keys as the main plugin input, then add the matching certificate or a folder
   of certificates.
3. For encrypted CAPI/CNG keys, use **2. Unlock key** to add their DPAPI
   masterkey material.
4. Enter a new PFX password, or explicitly select an unencrypted PFX, then
   **Run plugin**. Each key is matched to a certificate by public key; the
   activity log reports every match by its SHA1 thumbprint (the store filename),
   and one PFX is created per match.

### Enterprise Wi-Fi / PEAP two-layer recovery

1. Export `MSMUserData`, drop it in **1. Artifact**, and select `wifi-peap`.
2. In **2. Unlock key**, add the outer SYSTEM masterkey using **SYSTEM masterkey
   (PEAP only)** and add DPAPI_SYSTEM when that masterkey is encrypted.
3. In the normal masterkey controls, add the nested user's encrypted masterkey
   plus SID/password material, a matching Protect directory, or an already
   decrypted user masterkey.
4. Click **Decrypt** to recover the PEAP identity and nested password.

## Hashcat and batch flows

To export a masterkey hash, drop the encrypted masterkey in **1. Artifact**,
select `masterkey` if needed, enter its owning SID in **2. Unlock key**, choose
the Hashcat context, and click **Masterkey → Hashcat**. This exports only a
`$DPAPImk$` record; it does not crack passwords or PINs. `domain-auto` exports
both domain derivation forms because the file does not reliably identify which
one applies.

For batch processing, drop a folder in **1. Artifact**, add one encrypted or
decrypted masterkey, or a Protect directory plus its unlock material, in
**2. Unlock key**, and click **Decrypt**. The toolkit recursively matches blobs
to GUID-named masterkeys and returns one in-memory ZIP containing the results and
`batch_report.json`. Batch mode recognizes certificates, CREDHIST, Wi-Fi XML,
RDP, RDCMan, Vault policies/records, Credentials, CAPI/CNG, and generic classic
DPAPI blobs. CLIXML, KeePass, SCCM, PEAP, Outlook, NGC, and plugins remain
single-artifact flows.

## Plugin flows

| Plugin | **3. Plugins** flow | Uses **2. Unlock key** | Result |
|---|---|---|---|
| Certificate / PFX bundle | Drop a PEM/DER private key, encrypted CAPI/CNG key, or a folder of keys; add one certificate or a certificate folder and a new PFX password, then **Run plugin**. | Only for encrypted CAPI/CNG input. | Each matching decrypted/normalized private key plus its PFX; the log shows certificate SHA1 and public-key SPKI SHA256 fingerprints. |
| Windows Entra ID CacheData | Drop `CacheData`. Enter one known password to decrypt, or select **Export Hashcat mode 33700** to create a verifier for a separate local Hashcat run. The toolkit itself performs no guessing. | No. | Decrypted PRT JSON, Entra SID, derived DPAPI prekey, and raw `.credkey`; or a `.hc33700` verifier. |
| DPAPI-NG (offline root key) | Drop the DPAPI-NG artifact and the exported KDS root-key JSON, then **Run plugin**. Only the supplied in-process key cache is used. | No. | Decrypted SID-descriptor payload when the matching root key is present. |
| Windows SYSTEM/SECURITY/SAM hives | Drop `SYSTEM` and `SECURITY` together (and `SAM` for local hashes), or the folder holding them, into the one plugin input. Each hive is matched by name. | No. | Raw/JSON DPAPI_SYSTEM material and optional SAM hash records. |
