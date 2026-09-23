"""Offline SYSTEM/SECURITY/SAM registry-hive processing.

Only local filenames are passed to Impacket's offline registry classes.  This
module never constructs RemoteOperations and never enables cached-logon,
password-history, or general LSA-secret output.
"""

from __future__ import annotations

import json
from pathlib import Path
import re


PLUGIN_ID = "windows_hives"
DPAPI_KEY = re.compile(r"(?im)^dpapi_(machine|user)key:0x([0-9a-f]{40})$")
SAM_LINE = re.compile(
    r"^[^:\r\n]+:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::$"
)


def parse_dpapi_system_callbacks(lines: list[str]) -> tuple[bytes, bytes]:
    found: dict[str, bytes] = {}
    for line in lines:
        for kind, value in DPAPI_KEY.findall(line):
            found[kind.casefold()] = bytes.fromhex(value)
    if set(found) != {"machine", "user"}:
        raise ValueError("SECURITY hive did not yield both DPAPI_SYSTEM keys")
    return found["machine"], found["user"]


def validate_sam_lines(lines: list[str]) -> list[str]:
    clean = []
    for value in lines:
        line = value.strip()
        if not SAM_LINE.fullmatch(line):
            raise ValueError("Impacket returned an unexpected SAM record")
        clean.append(line)
    if not clean:
        raise ValueError("SAM hive contained no local account hash records")
    return clean


def _hive_path(value: str | None, label: str) -> str | None:
    if not value:
        return None
    path = Path(value)
    try:
        with path.open("rb") as stream:
            magic = stream.read(4)
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {exc}") from None
    if magic != b"regf":
        raise ValueError(f"{label} is not a Windows registry hive")
    return str(path)


def _offline_classes():
    try:
        from impacket.examples.secretsdump import LocalOperations, LSASecrets, SAMHashes
    except ImportError:
        raise ValueError(
            "install the optional impacket package to use the windows_hives plugin"
        ) from None
    return LocalOperations, LSASecrets, SAMHashes


def _is_hive(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) == b"regf"
    except OSError:
        return False


def _locate_hive(files: list[Path], name: str) -> str | None:
    """Find a hive by name among files: exact basename, then stem (handles
    SYSTEM.hive / system.dat), then a real regf hive whose name contains it."""
    for item in files:
        if item.name.casefold() == name:
            return str(item)
    for item in files:
        if item.stem.casefold() == name:
            return str(item)
    for item in files:
        if name in item.name.casefold() and _is_hive(item):
            return str(item)
    return None


def run(_data, source_path, _was_hex, args, core, emit):
    if source_path is None:
        raise ValueError(
            "windows_hives requires the SYSTEM hive (drop SYSTEM, SECURITY and "
            "optional SAM together, or the folder holding them)"
        )
    source = Path(source_path)
    if source.is_dir():
        # One drop-all folder: locate each hive by name. Explicit flags win.
        files = [item for item in sorted(source.rglob("*")) if item.is_file()]
        system_src = _locate_hive(files, "system")
        if not system_src:
            seen = ", ".join(item.name for item in files[:12]) or "nothing"
            raise ValueError(
                f"no SYSTEM hive found among the dropped hives (saw: {seen}); "
                "include the SYSTEM hive and name it SYSTEM"
            )
        security_src = args.security_hive or _locate_hive(files, "security")
        sam_src = args.sam_hive or _locate_hive(files, "sam")
    else:
        system_src = str(source)
        security_src = args.security_hive
        sam_src = args.sam_hive

    system_path = _hive_path(system_src, "SYSTEM hive")
    security_path = _hive_path(security_src, "SECURITY hive")
    sam_path = _hive_path(sam_src, "SAM hive")
    if not security_path and not sam_path:
        raise ValueError(
            "drop a SECURITY hive (for DPAPI_SYSTEM) and/or a SAM hive together "
            "with SYSTEM"
        )

    LocalOperations, LSASecrets, SAMHashes = _offline_classes()
    try:
        boot_key = LocalOperations(system_path).getBootKey()
    except Exception as exc:
        raise ValueError(f"could not derive the SYSTEM boot key: {exc}") from None
    if not isinstance(boot_key, bytes) or len(boot_key) != 16:
        raise ValueError("SYSTEM hive produced an invalid boot key")
    emit("[+] derived the 16-byte boot key from the offline SYSTEM hive")

    payloads: list[tuple[bytes, str, str]] = []
    errors: list[str] = []
    if security_path:
        callbacks: list[str] = []
        lsa = None
        try:
            lsa = LSASecrets(
                security_path,
                boot_key,
                None,
                isRemote=False,
                history=False,
                perSecretCallback=lambda _kind, secret: callbacks.append(str(secret)),
            )
            # Impacket processes the hive locally. The callback deliberately
            # retains only the DPAPI_SYSTEM record parsed below.
            lsa.dumpSecrets()
            machine_key, user_key = parse_dpapi_system_callbacks(callbacks)
            raw = machine_key + user_key
            metadata = {
                "format": "DPAPI_SYSTEM",
                "machine_key_hex": machine_key.hex(),
                "user_key_hex": user_key.hex(),
                "combined_hex": raw.hex(),
            }
            payloads.extend((
                (raw, ".dpapi_system", "DPAPI_SYSTEM raw key material"),
                (json.dumps(metadata, indent=2).encode() + b"\n", ".json", "DPAPI_SYSTEM metadata"),
            ))
            emit("[+] recovered DPAPI_SYSTEM MachineKey and UserKey")
        except Exception as exc:
            message = f"could not decrypt DPAPI_SYSTEM from SECURITY: {exc}"
            errors.append(message)
            emit(f"[!] {message}")
        finally:
            if lsa is not None:
                try:
                    lsa.finish()
                except Exception as exc:
                    emit(f"[!] SECURITY hive cleanup warning: {exc}")

    if sam_path:
        sam_lines: list[str] = []
        sam = None
        try:
            sam = SAMHashes(
                sam_path,
                boot_key,
                isRemote=False,
                history=False,
                perSecretCallback=lambda secret: sam_lines.append(str(secret)),
            )
            sam.dump()
            clean = validate_sam_lines(sam_lines)
            payloads.append((("\n".join(clean) + "\n").encode(), ".sam", "local SAM hashes"))
            emit(f"[+] recovered {len(clean)} local SAM account hash record(s)")
        except Exception as exc:
            message = f"could not decrypt the offline SAM hive: {exc}"
            errors.append(message)
            emit(f"[!] {message}")
        finally:
            if sam is not None:
                try:
                    sam.finish()
                except Exception as exc:
                    emit(f"[!] SAM hive cleanup warning: {exc}")

    if not payloads:
        detail = errors[-1] if errors else "no requested hive output was recovered"
        raise ValueError(detail)
    if errors:
        emit(
            f"[!] partial hive result: recovered {len(payloads)} output(s); "
            f"{len(errors)} requested component(s) failed"
        )

    count = len(payloads)
    return [
        core.OutputItem(data, extension, label, source_path, index, count)
        for index, (data, extension, label) in enumerate(payloads)
    ]
