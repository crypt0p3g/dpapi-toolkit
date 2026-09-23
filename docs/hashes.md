# Getting crackable hashes (offline password recovery)

The toolkit never cracks passwords itself — it runs no wordlists, generates no
candidates, and launches no Hashcat. Instead it exports hashes and verifiers in
standard [Hashcat](https://hashcat.net/) formats so you can run an authorized
offline recovery in a separate process. Three sources produce crackable material,
and CREDHIST yields historical hashes as a byproduct.

| Source | Flag | Hashcat mode | Token | Recovers |
|---|---|---:|---|---|
| Windows master key | `--hashcat` | 15300 / 15310 / 15900 / 15910 | `$DPAPImk$` | user logon password |
| Entra ID / Microsoft-account CacheData | `--cachedata-hashcat` | 33700 | `$MSONLINEACCOUNT$` | cloud-account password |
| Local SAM | `--plugin windows_hives --sam-hive SAM` | 1000 | `username:RID:LM:NT:::` | local-account password (or pass-the-hash) |

Recovered passwords/hashes then unlock the master key that protects the actual
artifact — close the loop with the normal decrypt flow in
[cli-reference.md](cli-reference.md) and [artifacts.md](artifacts.md).

## 1. Master keys → `$DPAPImk$`

Export a `$DPAPImk$` record from one encrypted master key (the owning SID is
required):

```bash
python3 dpapi_toolkit.py MASTERKEY-GUID --hashcat --sid S-1-5-21-...
```

Every master key under a directory at once (each becomes its own record, grouped
one file per mode):

```bash
python3 dpapi_toolkit.py PROTECT-DIR --batch --hashcat --sid S-1-5-21-...
```

The mode comes from the master key's cipher/hash, and the record embeds a
context number (1 local, 2 domain, 3 domain-new) that Hashcat derives
differently — so the file does not reveal the account type and the default
`--hashcat-context all` exports every form; crack whichever matches:

```bash
hashcat -m 15900 FILE.hc15900 WORDLIST     # AES-256/SHA-512 master key
hashcat -m 15300 FILE.hc15300 WORDLIST     # legacy 3DES/SHA1 master key
```

Full mode/context table and the `local` / `domain` / `domain-new` / `domain-auto`
selectors are in [cli-reference.md → Hashcat masterkey export](cli-reference.md#hashcat-masterkey-export).
A cracked password feeds straight back in as `--password` to unlock the key.

## 2. Entra ID / Microsoft-account CacheData → `$MSONLINEACCOUNT$`

Export a mode-33700 verifier from a collected `CacheData` file. The toolkit
validates the file and emits the verifier only; it tests no candidates:

```bash
python3 dpapi_toolkit.py CacheData --plugin cachedata --cachedata-hashcat
```

Then recover the password in a separate local Hashcat process:

```bash
hashcat -m 33700 FILE.hc33700 WORDLIST
```

Feed the recovered password back into the same plugin to derive the DPAPI
prekey and credential key, which unlock the Entra user's master key:

```bash
python3 dpapi_toolkit.py CacheData --plugin cachedata --password 'recovered password'
```

See [plugins.md → Entra ID CacheData](plugins.md#entra-id-cachedata) and the
chained walkthrough in [web-ui.md](web-ui.md#chained-recovery-flows).

## 3. Local accounts → NT hashes from SAM

Extract local-account hashes offline from collected `SYSTEM` + `SECURITY` +
`SAM` hives:

```bash
python3 dpapi_toolkit.py SYSTEM --plugin windows_hives \
  --security-hive SECURITY --sam-hive SAM
```

The `.sam` result uses the standard `username:RID:LM:NT:::` format. Crack the NT
hash, or use it directly for pass-the-hash / as a master-key unlock via
`--nt-hash`:

```bash
hashcat -m 1000 nt_hashes.txt WORDLIST
```

Details in [plugins.md → Windows SYSTEM/SECURITY/SAM hives](plugins.md#windows-systemsecuritysam-hives).

## Byproduct: historical hashes from CREDHIST

Decrypting `CREDHIST` with the current password/key recovers every older SHA1
and NT hash in the chain. Those unlock master keys created before a password
change, and each NT hash is also crackable with `hashcat -m 1000`:

```bash
python3 dpapi_toolkit.py CREDHIST --type credhist --password CURRENT_PASSWORD
```

See [cli-reference.md → CREDHIST password history](cli-reference.md#credhist-password-history).

## In the web UI

Drop an encrypted master key (or the `Protect` folder) in **1. Artifact**, enter
the owning SID in **2. Unlock key**, choose the Hashcat context, and click
**Masterkey → Hashcat**; each mode comes back as its own download. The CacheData
verifier is exported from **3. Plugins → Windows Entra ID CacheData** with
**Export Hashcat mode 33700**. All exports are hashes/verifiers only — the
toolkit performs no guessing anywhere.
