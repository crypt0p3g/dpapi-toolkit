# CLI reference

The toolkit logic lives in the importable module `dpapi_toolkit.py`, which is
also the CLI. For per-format command examples (Vault, Wi-Fi, RDP, Chromium, and
the rest) see [artifacts.md](artifacts.md); for the removable plugins and the
DPAPI-NG walkthrough see [plugins.md](plugins.md).

## Help and inspection

Short command help:

```bash
python3 dpapi_toolkit.py -h
```

Detailed key, artifact, location, and limitation help:

```bash
python3 dpapi_toolkit.py -hh
```

Inspect a supported artifact without providing a key:

```bash
python3 dpapi_toolkit.py artifact.bin
```

The tool prints every embedded classic DPAPI blob and its required masterkey
GUID. No output file is created during inspection.

Use `-` as the input to read one artifact from standard input. Binary and
textual hexadecimal input are both accepted:

```bash
cat artifact.bin | python3 dpapi_toolkit.py - --type blob --real-masterkey KEY
printf '%s' '01000000...' | python3 dpapi_toolkit.py - --structure
```

Standard input is a single-artifact CLI flow; folder batch mode and web drag and
drop use local files instead.

Print the full parsed structure of a blob or an encrypted master-key file
without decrypting anything:

```bash
python3 dpapi_toolkit.py artifact.bin --structure
```

`--structure` lists each blob's identity and scope (version, provider/master-key
GUIDs, flags, description), cryptography (cipher and hash algorithms), and binary
fields (salt, HMAC, ciphertext, signature). For an encrypted master-key file it
also reports the PBKDF2 iteration count and the Hashcat mode it maps to. This is
the same breakdown the GUIs show in their Structure view.

## Automatic masterkey-directory lookup

`--masterkey-dir` works for both one artifact and recursive batch mode. The
tool reads the GUID embedded in each DPAPI blob, searches the directory
recursively, and decrypts only the matching GUID-named masterkey.

With a password:

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey-dir PROTECT-SID \
  --sid S-1-5-21-... \
  --password PASSWORD
```

With DPAPI_SYSTEM:

```bash
python3 dpapi_toolkit.py SYSTEM_BLOB \
  --masterkey-dir SYSTEM_PROTECT_DIRECTORY \
  --dpapi-system DPAPI_SYSTEM_HEX
```

With recovered user material:

```bash
python3 dpapi_toolkit.py BLOB --masterkey-dir PROTECT-SID --prekey PREKEY
python3 dpapi_toolkit.py BLOB --masterkey-dir PROTECT-SID --sid SID --nt-hash HASH
python3 dpapi_toolkit.py BLOB --masterkey-dir PROTECT-SID --sid SID --sha1-hash HASH
python3 dpapi_toolkit.py BLOB --masterkey-dir PROTECT-SID --sid SID --credkey KEY
```

With the AD domain backup key:

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey-dir PROTECT-SID \
  --domain-backup-key BACKUPKEY.pvk
```

The directory may also contain already-decrypted 20-byte mappings or 64-byte
masterkeys. For automatic matching, those raw files must be named exactly with
their masterkey GUID. `--real-masterkey KEY` remains the direct fallback when
you already know that one clear key applies, so it does not need directory
lookup.

Files containing multiple DPAPI blobs may reference different GUIDs. Each blob
is resolved and decrypted separately. If only some matching masterkeys are
available, those values are still returned and each unresolved value is listed
in the activity log and, for structured JSON formats, in an `errors` entry. The
run fails only when none of its independent values can be decrypted. CREDHIST is
the exception: it returns the recovered prefix, but cannot continue past a
missing link because every older entry depends on the preceding one. Optional
entropy works normally with directory lookup:

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey-dir PROTECT-SID \
  --sid SID --password PASSWORD \
  --entropy-file entropy.bin
```

## Output behavior

Outputs are never overwritten. A run timestamp is prepended to every output:

```text
20260831_142501_secret_dec.bin
```

If that name already exists, `_2`, `_3`, and so on are appended.
`--out-file NAME` selects the base output name but keeps the timestamp prefix.

Batch runs create a separate directory:

```text
20260831_142501_ARTIFACTS_dec/
```

With `--out-dir RESULTS`, the timestamped run directory is created below
`RESULTS`. For a single artifact, `--out-dir RESULTS` places the timestamped
output file directly in `RESULTS`. Every batch run also writes
`batch_report.json`.

Choose the output representation with `-o` / `--out`:

```bash
-o auto                 # automatic text/binary handling; default
-o hex                  # one continuous hexadecimal text line, saved as .hex
-o raw                  # exact decrypted bytes, saved as .bin
-o unhex                # ASCII/UTF-16 hex text -> binary .bin
-o utf16-utf8           # UTF-16LE -> UTF-8 .txt
--show                  # also display the result in the terminal
```

`--output-format` is a long alias for `-o/--out`. `--hex`, `--raw`, `--unhex`,
and `--utf16-utf8` remain available as convenience aliases. `--console` is an
alias for `--show`. Use `--out-file FILE` when a custom base filename is needed.
When `--out-dir` and `--out-file` are combined, the directory comes from
`--out-dir` and the base filename comes from `--out-file`.

Examples:

```bash
python3 dpapi_toolkit.py blob.bin --real-masterkey KEY -o hex --show
python3 dpapi_toolkit.py blob.bin --real-masterkey KEY -o raw --console
python3 dpapi_toolkit.py blob.bin --real-masterkey KEY -o unhex
python3 dpapi_toolkit.py blob.bin --real-masterkey KEY -o utf16-utf8 --show
```

Structured formats such as Credentials, Vault, Wi-Fi, RDP, Outlook, and RDCMan
are normally saved as JSON. RSA private keys are normally converted to PEM.

## Unlocking user masterkeys

Default location:

```text
%APPDATA%\Microsoft\Protect\<USER-SID>\<MASTERKEY-GUID>
```

### Current account password

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey MASTERKEY-GUID \
  --sid S-1-5-21-... \
  --password 'password'
```

Omit `--password` to receive a non-echoing prompt. For an empty password, pass
`--password ''` explicitly. Password mode automatically tries local, classic
domain, and newer domain derivation and accepts only a verified masterkey.

### NT hash

A 16-byte NT hash is a valid input for classic domain-style and Protected Users
masterkey derivation when the owning SID is also known. It is not interchangeable
with the 20-byte local SHA1 password hash; the toolkit tries only the derivations
appropriate to the supplied value and accepts a result only after masterkey HMAC
verification.

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey MASTERKEY-GUID \
  --sid S-1-5-21-... \
  --nt-hash NTHASH
```

### Local SHA1 password hash

This input is exactly the 20-byte digest
`SHA1(password.encode("utf-16le"))`. It is a classic local-DPAPI password
credential key, not an Entra `dpapi_prekey`. The toolkit combines it with the
owning SID to derive and verify the masterkey prekey.

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey MASTERKEY-GUID \
  --sid S-1-5-21-... \
  --sha1-hash SHA1
```

### Final prekey recovered from another offline source

This is already the final 20-byte SID-bound key used to unlock an encrypted user
masterkey. It is not a PIN and is not applied directly to a DPAPI blob.

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey MASTERKEY-GUID \
  --prekey PREKEY_HEX
```

### Unbound credential key

This is commonly recovered from CloudAP/CacheData. It still needs the owning
account SID so the toolkit can derive the masterkey prekey; it is not itself a
Windows Hello PIN input.

```bash
python3 dpapi_toolkit.py BLOB \
  --masterkey MASTERKEY-GUID \
  --sid S-1-5-21-... \
  --credkey CREDENTIAL_KEY_HEX
```

### Already-decrypted masterkey

```bash
python3 dpapi_toolkit.py BLOB --real-masterkey MASTERKEY_HEX
python3 dpapi_toolkit.py BLOB --real-masterkey MASTERKEY_BASE64
python3 dpapi_toolkit.py BLOB --real-masterkey masterkey.bin
```

`--real-masterkey` accepts the full 64-byte masterkey or its 20-byte SHA1
mapping. It bypasses password, SID, DPAPI_SYSTEM, and domain backup processing.

## SID interpretation: local, on-prem AD, and Entra ID

The tool validates and classifies a supplied SID before attempting decryption:

- `S-1-12-1-...` is treated as an Entra ID/cloud-account SID. The classic
  on-prem AD DPAPI domain backup key is rejected for this SID. Use recovered
  CloudAP `--prekey`/`--credkey`, an already-decrypted masterkey, or the software
  NGC path where applicable.
- `S-1-5-21-...` may be either a local account or an on-prem AD account. The SID
  alone cannot distinguish them; successful masterkey HMAC verification selects
  the usable password derivation.
- Built-in and service SIDs are identified separately when verbose output is
  enabled.

An Entra SID does not by itself prove that the account uses a PIN, nor whether
the Windows Hello key is software-backed or TPM-backed. That requires the NGC
protector/provider and CNG key metadata. `--pin` is accepted only with
`--type ngc-cng`. If the profile is Hello/TPM-only, the classic DPAPI masterkey
cannot be cracked from its SID and masterkey file: neither the PIN verifier nor
the TPM private key is stored in the `$DPAPImk$` record. Such a record can only
test password/credential-derived DPAPI candidates, when those exist. Software
NGC PIN testing is a separate `--type ngc-cng` workflow.

## SYSTEM and service-account DPAPI

Common masterkey locations:

```text
%WINDIR%\System32\Microsoft\Protect\S-1-5-18\User\<MASTERKEY-GUID>
%WINDIR%\System32\Microsoft\Protect\S-1-5-18\<MASTERKEY-GUID>
```

The DPAPI_SYSTEM LSA secret must be extracted offline from both the `SYSTEM` and
`SECURITY` hives. Accepted forms are:

- Full 44 bytes: version + 20-byte MachineKey + 20-byte UserKey.
- 40 bytes: MachineKey + UserKey.
- One 16/20-byte component.
- Text containing `MachineKey:` and `UserKey:` values.

Decrypt an artifact in one command:

```bash
python3 dpapi_toolkit.py SYSTEM_BLOB \
  --masterkey SYSTEM-MASTERKEY-GUID \
  --dpapi-system DPAPI_SYSTEM_HEX
```

Decrypt only the SYSTEM masterkey first:

```bash
python3 dpapi_toolkit.py SYSTEM-MASTERKEY-GUID \
  --type masterkey \
  --dpapi-system DPAPI_SYSTEM_HEX
```

The resulting timestamped `.bin` can then be supplied with `--real-masterkey`.

## AD domain backup key

Domain user masterkey files may contain a DomainKey section protected with the
domain DPAPI backup RSA key.

```bash
python3 dpapi_toolkit.py MASTERKEY-GUID \
  --type masterkey \
  --domain-backup-key BACKUPKEY.pvk
```

The alias `--pvk` is accepted. PEM, DER, Windows PVK, raw CAPI
PRIVATEKEYBLOB, hex, and Base64 inputs are supported. For encrypted PVK or PEM
files, use `--pvk-password TEXT` or `--pvk-password-file FILE`. Strong and
legacy weak-key Microsoft PVK encryption are both recognized; no password
guessing is performed.

Legacy version-1 masterkey DomainKey sections can instead be recovered with the
collected 256-byte `G$BCKUPKEY_<GUID>` ServerWrap key (the `.key` exported by
common AD backup-key tooling). The MS-BKRP HMAC and SID are validated locally;
no BKRP RPC request is made. A full `P_BACKUP_KEY` value containing the leading
version dword is accepted as well.

```bash
python3 dpapi_toolkit.py MASTERKEY-GUID --type masterkey \
  --pvk BACKUPKEY.pvk --pvk-password-file pvk-password.txt
```

## Optional entropy

If the application supplied optional entropy to `CryptProtectData`, the same
bytes are required during decryption.

Literal UTF-8 text:

```bash
python3 dpapi_toolkit.py BLOB --real-masterkey KEY --entropy 'application text'
```

Hex, Base64, or UTF-16LE text:

```bash
python3 dpapi_toolkit.py BLOB --real-masterkey KEY --entropy hex:01020304
python3 dpapi_toolkit.py BLOB --real-masterkey KEY --entropy base64:AQIDBA==
python3 dpapi_toolkit.py BLOB --real-masterkey KEY --entropy utf16:Secret
```

Exact bytes from a file:

```bash
python3 dpapi_toolkit.py BLOB --real-masterkey KEY --entropy-file entropy.bin
```

Explicit entropy overrides built-in entropy for that run. Without an explicit
value, known CAPI/CNG entropy is selected automatically.

## CREDHIST password history

Default location:

```text
%APPDATA%\Microsoft\Protect\<USER-SID>\CREDHIST
```

CREDHIST is a chain of older SHA1 and NT password hashes encrypted using the
newer credential. Start with the current password or current key material:

```bash
python3 dpapi_toolkit.py CREDHIST --type credhist --password CURRENT_PASSWORD
python3 dpapi_toolkit.py CREDHIST --type credhist --nt-hash CURRENT_NT_HASH
python3 dpapi_toolkit.py CREDHIST --type credhist --sha1-hash CURRENT_SHA1
python3 dpapi_toolkit.py CREDHIST --type credhist --prekey CURRENT_PREKEY
python3 dpapi_toolkit.py CREDHIST --type credhist --credkey CURRENT_CREDKEY
```

The SID is stored in each CREDHIST entry, so `--sid` is not required. Output is
JSON containing each history GUID, SID, SHA1 hash, and NT hash. Those recovered
hashes can then decrypt masterkeys protected before the password changed.

## Hashcat masterkey export

```bash
python3 dpapi_toolkit.py MASTERKEY-GUID --hashcat --sid S-1-5-21-...
```

`--hashcat` always treats the input as an encrypted master-key file, so
`--type` is not required. Add `--type masterkey` when you want to be explicit:

```bash
python3 dpapi_toolkit.py MASTERKEY-GUID --type masterkey --hashcat --sid S-1-5-21-...
```

The Hashcat mode comes from the masterkey's cipher/hash, and the derivation
context comes from the account type:

| Masterkey algorithms | Local account | Domain account (legacy) | Domain account (2016+) |
|---|---:|---:|---:|
| 3DES/SHA1 | 15300 | 15300 | 15310 |
| AES-256/SHA-512 | 15900 | 15900 | 15910 |

In short: a **local** account masterkey cracks as **15900** (or 15300), and a
**domain** account masterkey is usually **15910** (or 15310) on 2016-and-later
domain controllers, or 15900/15300 on older ones. The mode alone is not enough:
the `$DPAPImk$` record also embeds a context number (1 local, 2 domain, 3
domain-new), and Hashcat derives the key differently for each, so a local
masterkey only cracks with the local (context 1) record even though it is also
mode 15900.

The masterkey file does not reliably reveal which account type it belongs to, so
the default `--hashcat-context all` exports the local, domain, and domain-new
records; crack whichever matches. Use `local`, `domain`, `domain-new`, or
`domain-auto` (both domain forms) to narrow it.

To export every master key under a directory at once, add `--batch`. Each master
key becomes its own record (they may have different passwords and are cracked
independently), the owning SID is read from a `Protect\<SID>` parent directory
when present or from `--sid` otherwise, and the records are grouped into one file
per mode:

```bash
python3 dpapi_toolkit.py PROTECT-DIR --batch --hashcat --sid S-1-5-21-...
```

## Recursive batch mode

One encrypted masterkey for a directory:

```bash
python3 dpapi_toolkit.py ARTIFACTS \
  --batch \
  --masterkey MASTERKEY-GUID \
  --sid SID \
  --password PASSWORD
```

One already-decrypted masterkey:

```bash
python3 dpapi_toolkit.py ARTIFACTS --batch --real-masterkey KEY
```

A Protect folder of masterkeys matched to blobs by GUID:

```bash
python3 dpapi_toolkit.py ARTIFACTS \
  --batch \
  --masterkey-dir PROTECT-SID \
  --sid SID \
  --password PASSWORD
```

Domain masterkeys with an AD backup key:

```bash
python3 dpapi_toolkit.py ARTIFACTS \
  --batch \
  --masterkey-dir PROTECT-SID \
  --domain-backup-key BACKUPKEY.pvk
```

SYSTEM masterkeys:

```bash
python3 dpapi_toolkit.py ARTIFACTS \
  --batch \
  --masterkey-dir SYSTEM_PROTECT_DIR \
  --dpapi-system DPAPI_SYSTEM_HEX
```

Batch mode recursively recognizes certificates, CREDHIST, Wi-Fi XML, `.rdp`,
RDCMan, Vault policies/records, Credentials, CAPI/CNG, and generic embedded
classic DPAPI blobs. First-class CLIXML, KeePass, SCCM, and removable-plugin
dispatch currently use single-artifact mode. Masterkeys are cached by GUID. A
`--real-masterkey` has no GUID and is tried as a fallback. Within one recognized
multi-value file, successful values are kept when other GUIDs are unavailable;
the batch report marks that artifact as `partial` and records per-item errors.

## Default collection locations

| Artifact | Default location |
|---|---|
| User masterkeys | `%APPDATA%\Microsoft\Protect\<SID>\*` |
| SYSTEM masterkeys | `%WINDIR%\System32\Microsoft\Protect\S-1-5-18\*` |
| CREDHIST | `%APPDATA%\Microsoft\Protect\<SID>\CREDHIST` |
| Local Credentials | `%LOCALAPPDATA%\Microsoft\Credentials\*` |
| Roaming Credentials | `%APPDATA%\Microsoft\Credentials\*` |
| User Vault | `%LOCALAPPDATA%\Microsoft\Vault\*` |
| SYSTEM Vault | `%WINDIR%\System32\config\systemprofile\AppData\Local\Microsoft\Vault` |
| CAPI keys | `%APPDATA%\Microsoft\Crypto\RSA\<SID>\*` |
| CNG keys | `%APPDATA%\Microsoft\Crypto\Keys\*` |
| Public certificates | `%APPDATA%\Microsoft\SystemCertificates\My\Certificates\*` |
| Wi-Fi profiles | `%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\*\*.xml` |
| Outlook profiles | `NTUSER.DAT`, under `Software\Microsoft\Office\...\Outlook\Profiles` |
| NGC metadata | `%WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc` |

## Troubleshooting

`required master key <GUID>`

: Find that exact GUID-named file under the appropriate user or SYSTEM Protect
  directory, or supply its already-decrypted key with `--real-masterkey`.

`invalid padding` or `signature verification failed`

: The masterkey or optional entropy is wrong. DPAPI plaintext is accepted only
  after cryptographic verification.

`could not decrypt master key`

: Check the owning SID and unlocking material. A password changed by an
  administrator may require CREDHIST or the AD domain backup key.

`no classic DPAPI blob found`

: Force the correct `--type`, verify that the file was exported as binary, or
  confirm that the application actually uses classic DPAPI rather than DPAPI-NG
  or custom encryption.

`output path exists`

: Normal output selection avoids collisions automatically. This error would
  indicate a race with another process; rerun to receive a new timestamp/suffix.
