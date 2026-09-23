#!/usr/bin/env python3
"""Web front end for the offline DPAPI toolkit (standard library only).

Serves a single drag-and-drop page on loopback only. Dropped files are sent to
the server as base64 JSON (no framework, no multipart), written to a
short-lived temp directory, and fed to the same ``dpapi_toolkit`` core the CLI
uses.

    python3 dpapi_web.py            # http://127.0.0.1:8765/
    python3 dpapi_web.py --port 9000 --no-open

Security notes:
- The server binds to 127.0.0.1 only. It cannot be bound to a LAN or public
  interface; each analyst runs a separate copy on their own machine.
- Host and Origin values are checked against loopback, and a per-run request
  token rejects cross-origin mutations. This is browser-request hardening, not
  user authentication and not an isolation boundary against another process
  running as the same OS user.
- Decrypted secrets pass through this process. Stop it when finished.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import html
import io
import ipaddress
import json
import secrets
import shutil
import tempfile
import threading
import time
import webbrowser
import zipfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import dpapi_toolkit as dt
import dpapi_plugins


# A web request must never block on an interactive password prompt.
def _no_getpass(*_args, **_kwargs):
    raise ValueError(
        "a password is required: fill the Password field (or tick 'empty "
        "password'), or supply other key material"
    )


dt.getpass.getpass = _no_getpass

MAX_BODY = 96 * 1024 * 1024
MAX_UPLOAD_FILE = 64 * 1024 * 1024
MAX_UPLOAD_TOTAL = 64 * 1024 * 1024
MAX_UPLOAD_FILES = 4096
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
MAX_DOWNLOADS = 64
MAX_PREVIEW_BYTES = 256 * 1024
DOWNLOAD_TTL_SECONDS = 10 * 60
REQUEST_TIMEOUT_SECONDS = 20
LOCAL_HOSTS = frozenset(("127.0.0.1", "localhost", "::1"))
PAGE_PATH = "/"
MEMORY_TEMP_ROOT = Path("/dev/shm")

# Field names that carry a dropped single file (value -> temp path).
FILE_FIELDS = (
    "input", "masterkey", "real_masterkey", "dpapi_system", "domain_backup_key",
    "system_masterkey", "entropy_file", "vault_policy", "certificate",
    "pfx_password_file", "pvk_password_file", "dpapi_ng_root_key", "vault_key",
    "security_hive", "sam_hive",
)
# Free-text fields passed straight to the config (CLI dest names).
TEXT_FIELDS = (
    "sid", "machine_sid", "password", "nt_hash", "sha1_hash", "prekey", "credkey", "entropy",
    "pfx_password", "pvk_password", "key_password", "pin",
)
SELECT_FIELDS = ("type", "plugin", "output_format", "hashcat_context")
MATERIAL_TEXT_FIELDS = frozenset(("nt_hash", "sha1_hash", "prekey", "credkey"))
SERVER_STORAGE_FIELDS = frozenset(("autosave", "out_dir", "out_file"))

@dataclass
class UploadBudget:
    files: int = 0
    total: int = 0

    def decode(self, payload: dict, label: str) -> bytes:
        if not isinstance(payload, dict) or not isinstance(payload.get("b64"), str):
            raise ValueError(f"{label} is not a valid uploaded file")
        encoded = payload["b64"]
        if len(encoded) > ((MAX_UPLOAD_FILE + 2) // 3) * 4 + 4:
            raise ValueError(f"{label} exceeds the {MAX_UPLOAD_FILE // 1048576} MiB file limit")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(f"{label} contains invalid Base64") from None
        if len(data) > MAX_UPLOAD_FILE:
            raise ValueError(f"{label} exceeds the {MAX_UPLOAD_FILE // 1048576} MiB file limit")
        self.files += 1
        self.total += len(data)
        if self.files > MAX_UPLOAD_FILES:
            raise ValueError(f"upload contains more than {MAX_UPLOAD_FILES} files")
        if self.total > MAX_UPLOAD_TOTAL:
            raise ValueError(f"decoded uploads exceed {MAX_UPLOAD_TOTAL // 1048576} MiB")
        return data


@dataclass
class DownloadEntry:
    name: str
    data: bytes
    expires_at: float


# Short-lived, single-use decrypted outputs awaiting download.
_DOWNLOADS: dict[str, DownloadEntry] = {}
_DOWNLOADS_LOCK = threading.Lock()
_WORK_SLOTS = threading.BoundedSemaphore(2)


def _safe_upload_path(root: Path, relpath: str) -> Path:
    if not isinstance(relpath, str) or not relpath or "\x00" in relpath:
        raise ValueError("uploaded path is empty or invalid")
    rel = Path(relpath)
    if (
        rel.is_absolute()
        or rel.anchor
        or rel.drive
        or any(part in ("", ".", "..") for part in rel.parts)
    ):
        raise ValueError(f"unsafe uploaded path: {relpath!r}")
    resolved_root = root.resolve()
    target = (resolved_root / rel).resolve()
    try:
        target.relative_to(resolved_root)
    except ValueError:
        raise ValueError(f"uploaded path escapes its temporary directory: {relpath!r}") from None
    return target


def _safe_download_name(name: str) -> str:
    cleaned = "".join(
        character if character.isascii() and (character.isalnum() or character in "._-") else "_"
        for character in name
    ).strip("._")
    return cleaned[:180] or "dpapi-output.bin"


def _prune_downloads_locked(now: float | None = None) -> None:
    current = time.monotonic() if now is None else now
    for key in [key for key, entry in _DOWNLOADS.items() if entry.expires_at <= current]:
        del _DOWNLOADS[key]


def _expire_download(token: str) -> None:
    """Remove an unused decrypted download from process memory immediately."""
    with _DOWNLOADS_LOCK:
        _DOWNLOADS.pop(token, None)


def _download_reaper(stop: threading.Event) -> None:
    """Bound expired decrypted data in memory even while the server is idle."""
    interval = 1
    while not stop.wait(interval):
        with _DOWNLOADS_LOCK:
            _prune_downloads_locked()


def _register_download(name: str, data: bytes) -> str:
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"output exceeds the {MAX_DOWNLOAD_BYTES // 1048576} MiB download limit")
    token = secrets.token_urlsafe(24)
    with _DOWNLOADS_LOCK:
        _prune_downloads_locked()
        while _DOWNLOADS and (
            len(_DOWNLOADS) >= MAX_DOWNLOADS
            or sum(len(entry.data) for entry in _DOWNLOADS.values()) + len(data) > MAX_DOWNLOAD_BYTES
        ):
            oldest = min(_DOWNLOADS, key=lambda key: _DOWNLOADS[key].expires_at)
            del _DOWNLOADS[oldest]
        _DOWNLOADS[token] = DownloadEntry(
            _safe_download_name(name), data, time.monotonic() + DOWNLOAD_TTL_SECONDS
        )
    return token


def _take_download(token: str) -> DownloadEntry | None:
    with _DOWNLOADS_LOCK:
        _prune_downloads_locked()
        return _DOWNLOADS.pop(token, None)


def _clear_downloads() -> None:
    with _DOWNLOADS_LOCK:
        _DOWNLOADS.clear()


def _write_upload(tmp: Path, field: str, payload: dict, budget: UploadBudget) -> str:
    """Write one uploaded {name,b64} file into tmp and return its path."""
    supplied_name = payload.get("name", field)
    if not isinstance(supplied_name, str) or "\x00" in supplied_name:
        raise ValueError(f"invalid filename for {field}")
    name = Path(supplied_name).name or field
    data = budget.decode(payload, field)
    target = tmp / field / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(0o600)
    return str(target)


def _write_text_literal(tmp: Path, field: str, value: str) -> str:
    """Store browser text as literal data, never as a hosting-server path."""
    target = tmp / "literals" / f"{field}.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(value, encoding="utf-8")
    target.chmod(0o600)
    return str(target)


def _write_tree(tmp: Path, field: str, entries: list, budget: UploadBudget) -> str:
    """Rebuild an uploaded directory tree under tmp and return its root path."""
    root = tmp / field
    root.mkdir(parents=True, exist_ok=True)
    if not isinstance(entries, list):
        raise ValueError(f"{field} directory upload is invalid")
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{field} directory entry {index} is invalid")
        safe = _safe_upload_path(root, entry.get("relpath"))
        relative_key = safe.relative_to(root.resolve()).as_posix().casefold()
        if relative_key in seen:
            raise ValueError(f"duplicate uploaded path: {entry.get('relpath')!r}")
        seen.add(relative_key)
        data = budget.decode(entry, f"{field}/{entry.get('relpath', index)}")
        safe.parent.mkdir(parents=True, exist_ok=True)
        safe.write_bytes(data)
        safe.chmod(0o600)
    return str(root)


def _new_request_tempdir() -> Path:
    """Prefer volatile memory storage; fall back to a private removed directory."""
    if MEMORY_TEMP_ROOT.is_dir():
        try:
            return Path(tempfile.mkdtemp(prefix="dpapi_web_", dir=MEMORY_TEMP_ROOT))
        except OSError:
            pass
    return Path(tempfile.mkdtemp(prefix="dpapi_web_"))


def _build_config(request: dict, tmp: Path):
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    files = request.get("files", {})
    trees = request.get("trees", {})
    fields = request.get("fields", {})
    if not all(isinstance(item, dict) for item in (files, trees, fields)):
        raise ValueError("files, trees, and fields must be JSON objects")
    requested_storage = sorted(
        name for name in SERVER_STORAGE_FIELDS
        if fields.get(name) not in (None, "", False)
    )
    if requested_storage:
        raise ValueError(
            "the web interface never writes persistent server-side output: "
            + ", ".join(requested_storage)
        )
    budget = UploadBudget()
    input_text = fields.get("input", "")
    if input_text is not None and not isinstance(input_text, str):
        raise ValueError("input artifact text must be a string")

    # Plugin artifacts have their own tab/drop target but intentionally enter
    # the same core input pipeline after upload validation.
    input_field = (
        files.get("plugin_input")
        or files.get("input")
        or (input_text or "").strip()
    )
    if "plugin_input" in trees:  # a folder of keys dropped for a plugin
        input_value = _write_tree(tmp, "plugin_input", trees["plugin_input"], budget)
    elif isinstance(input_field, dict):
        input_value = _write_upload(tmp, "input", input_field, budget)
    elif "input" in trees:  # batch directory dropped as the artifact
        input_value = _write_tree(tmp, "input", trees["input"], budget)
    elif isinstance(input_field, str) and input_field:
        input_value = _write_text_literal(tmp, "input", input_field)
    elif input_field:
        raise ValueError("input artifact text must be a string")
    else:
        raise ValueError("drop or choose an input artifact first")

    pfx_password_sources = sum((
        bool(fields.get("pfx_password")),
        bool(fields.get("empty_pfx_password")),
        isinstance(files.get("pfx_password_file"), dict),
    ))
    if pfx_password_sources > 1:
        raise ValueError(
            "choose exactly one PFX password source: entered password, password file, "
            "or intentionally unencrypted"
        )

    overrides = {}
    for field in SELECT_FIELDS:
        if fields.get(field):
            overrides[field] = fields[field]
    # Only operation booleans go through; persistent web output is forbidden above.
    for field in ("hashcat", "cachedata_hashcat", "batch"):
        overrides[field] = bool(fields.get(field))

    for field in FILE_FIELDS:
        if field == "input":
            continue
        raw_value = fields.get(field, "")
        if raw_value is not None and not isinstance(raw_value, str):
            raise ValueError(f"{field} must be uploaded or supplied as text")
        if isinstance(files.get(field), dict):
            overrides[field] = _write_upload(tmp, field, files[field], budget)
        elif (raw_value or "").strip():
            overrides[field] = _write_text_literal(tmp, field, raw_value.strip())

    if "masterkey_dir" in trees:
        overrides["masterkey_dir"] = _write_tree(
            tmp, "masterkey_dir", trees["masterkey_dir"], budget
        )
    elif fields.get("masterkey_dir") not in (None, ""):
        raise ValueError("masterkey directories must be uploaded; server paths are disabled")

    # The certificate/PFX plugin accepts a dropped folder of certificates and
    # matches by public key, so a certificate tree overrides a single cert file.
    if "certificate" in trees:
        overrides["certificate"] = _write_tree(
            tmp, "certificate", trees["certificate"], budget
        )

    for field in TEXT_FIELDS:
        raw_value = fields.get(field)
        if raw_value is not None and not isinstance(raw_value, str):
            raise ValueError(f"{field} must be text")
        value = (
            (raw_value or "")
            if field in ("password", "entropy", "pfx_password", "pvk_password", "key_password", "pin")
            else (raw_value or "").strip()
        )
        if value:
            overrides[field] = (
                _write_text_literal(tmp, field, value)
                if field in MATERIAL_TEXT_FIELDS
                else value
            )

    # Password: blank -> None (keeps DPAPI_SYSTEM auto-try working); explicit
    # empty password only when ticked.
    if bool(fields.get("empty_password")):
        overrides["password"] = ""
    if bool(fields.get("empty_pfx_password")):
        overrides["pfx_password"] = ""
    overrides["show"] = False
    return dt.make_config(input_value, **overrides)


def _run(request: dict, inspect_only: bool) -> dict:
    tmp = _new_request_tempdir()
    log: list[str] = []
    emit = log.append
    results = []
    structure: list = []
    raw_hex = ""
    detected_type = None
    note = None
    ok = False
    try:
        cfg = _build_config(request, tmp)
        dt.validate_config(cfg, emit=emit)

        # Structure/raw preview for any single (non-batch) artifact, so the
        # Structure and Raw tabs fill whether the user inspects or decrypts.
        # A plugin folder input (e.g. a keys directory) has no single artifact
        # to preview, so skip it there.
        info = {"kind": "none"}
        if not cfg.batch and not Path(cfg.input).is_dir():
            data, _, _ = dt.read_data(cfg.input, "input")
            raw_hex = data[:65536].hex()
            info = dt.describe_input(data, cfg.type)
            structure = info["structure"]
            detected_type = info["detected_type"]
            note = info["note"]

        if cfg.batch and cfg.hashcat and not inspect_only:
            # Export a $DPAPImk$ record for every master key in the dropped folder,
            # one download per Hashcat mode. Each key is cracked independently.
            for item in dt.run_batch_hashcat(cfg, emit=emit):
                results.append(_store_output(item))
        elif cfg.batch and not inspect_only:
            # Batch output is always short-lived and returned to the browser as
            # one in-memory zip. The web API never accepts a hosting-server path.
            cfg.out_dir = str(tmp / "batch_out")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                dt.run_batch(cfg)
            log.extend(buffer.getvalue().splitlines())
            zip_result = _zip_batch_output(Path(cfg.out_dir), log)
            if zip_result:
                results.append(zip_result)
        elif inspect_only:
            if cfg.batch:
                emit("[i] batch mode: Decrypt processes all artifacts; Masterkey -> Hashcat exports every master key's hash")
            elif info["kind"] == "masterkey":
                # An encrypted master key is not a classic blob; don't run the
                # blob inspector (which would report "no classic DPAPI blob").
                emit("[+] input type: encrypted master key")
                for field in structure[0]["sections"][0]["fields"]:
                    if field["name"] == "Master-key GUID":
                        emit(f"[+] master key {field['value']}")
                if note:
                    emit(f"[i] {note}")
            elif info["kind"] == "cert":
                emit("[+] input type: public certificate")
                if note:
                    emit(f"[i] {note}")
            else:
                for attr in ("masterkey", "real_masterkey", "masterkey_dir"):
                    setattr(cfg, attr, None)
                dt.run_single(cfg, emit=emit)
        else:
            outputs = dt.run_single(cfg, emit=emit)
            if outputs:
                emit(
                    f"[+] operation completed successfully: "
                    f"{len(outputs)} output item(s) ready"
                )
            for item in outputs:
                results.append(_store_output(item))
        ok = True
    except (OSError, ValueError) as error:
        log.append(f"error: {error}")
        ok = False
    finally:
        try:
            shutil.rmtree(tmp)
        except OSError as error:
            log.append(f"error: could not remove temporary server data: {error}")
            ok = False
    return {"ok": ok, "log": log, "results": results,
            "required": [] if results else dt.required_guids(log), "structure": structure,
            "raw": raw_hex, "detected_type": detected_type, "note": note}


def _zip_batch_output(out_root: Path, log: list) -> dict | None:
    """Zip a batch run's output folder and register it as a single download."""
    buffer = io.BytesIO()
    files = sorted(p for p in out_root.rglob("*") if p.is_file()) if out_root.exists() else []
    if not files:
        return None
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(out_root))
    data = buffer.getvalue()
    token = _register_download("batch_results.zip", data)
    log.append(f"[+] packaged {len(files)} file(s) -> download batch_results.zip")
    return {
        "label": "batch results", "extension": ".zip", "size": len(data),
        "preview": f"{len(files)} file(s) - download the zip to extract",
        "is_text": False, "download": token, "name": "batch_results.zip",
    }


def _store_output(item) -> dict:
    preview_data = item.data[:MAX_PREVIEW_BYTES]
    truncated = len(item.data) > len(preview_data)
    try:
        preview = preview_data.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        preview = preview_data.hex()
        is_text = False
    name = f"{item.label.replace(' ', '_')}{item.extension}"
    token = _register_download(name, item.data)
    if truncated:
        preview += f"\n… preview truncated; download contains all {len(item.data)} bytes"
    return {
        "label": item.label, "extension": item.extension,
        "size": len(item.data), "preview": preview, "is_text": is_text,
        "download": token, "name": name,
    }


def build_page(token: str, nonce: str) -> bytes:
    plugin_options = '<option value="">none / auto-detect by filename</option>'
    plugin_panels = ""
    for manifest in dpapi_plugins.discover_plugins().values():
        plugin_options += (
            f'<option value="{html.escape(manifest.plugin_id, quote=True)}" '
            f'data-input-label="{html.escape(manifest.web_input_label, quote=True)}" '
            f'data-workflow-help="{html.escape(manifest.web_workflow_help, quote=True)}">'
            f'{html.escape(manifest.name)}</option>'
        )
        controls = []
        for field in manifest.web_fields:
            name = html.escape(field.name, quote=True)
            label = html.escape(field.label)
            help_text = html.escape(field.help, quote=True)
            title = f' title="{help_text}"' if help_text else ""
            optional = ' data-optional="true"' if field.optional else ""
            if field.kind == "file":
                controls.append(
                    f'<div class="drop" data-file="{name}"{optional}{title}>Drop '
                    f'<b>{label}</b><span class="clear" data-clear="{name}">clear</span></div>'
                )
            elif field.kind == "checkbox":
                controls.append(
                    f'<label class="row"{title}><span>{label}</span>'
                    f'<input type="checkbox" data-field="{name}"></label>'
                )
            else:
                placeholder = html.escape(field.placeholder, quote=True)
                autocomplete = ' autocomplete="off"' if field.kind == "password" else ""
                controls.append(
                    f'<label class="row"{title}><span>{label}</span>'
                    f'<input type="{field.kind}" data-field="{name}" '
                    f'placeholder="{placeholder}"{optional}{autocomplete}></label>'
                )
        help_html = (
            f'<small class="hint">{html.escape(manifest.web_help)}</small>'
            if manifest.web_help else ""
        )
        plugin_panels += (
            f'<fieldset data-plugin-panel="{html.escape(manifest.plugin_id, quote=True)}" hidden>'
            f'<legend>{html.escape(manifest.name)}</legend>'
            + "".join(controls) + help_html + '</fieldset>'
        )
    return (
        PAGE_TEMPLATE.replace("__TOKEN__", token)
        .replace("__NONCE__", nonce)
        .replace("__PLUGIN_OPTIONS__", plugin_options)
        .replace("__PLUGIN_PANELS__", plugin_panels)
    ).encode("utf-8")


def _canonical_host(value: str) -> str:
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or any(character.isspace() for character in host):
        raise ValueError("host must not be empty or contain whitespace")
    try:
        return ipaddress.ip_address(host).compressed.casefold()
    except ValueError:
        if any(character in host for character in "/\\:@"):
            raise ValueError("host must be a hostname or IP address without a port")
        try:
            return host.rstrip(".").encode("idna").decode("ascii").casefold()
        except UnicodeError:
            raise ValueError("host is not a valid hostname or IP address") from None


def _allowed_authority(value: str | None, port: int) -> bool:
    """The browser Host header must name loopback on the served port."""
    if not value:
        return False
    try:
        parsed = urlsplit(f"//{value}")
        parsed_port = parsed.port
        host = _canonical_host(parsed.hostname or "")
    except ValueError:
        return False
    return host in LOCAL_HOSTS and parsed_port in (None, port)


def _allowed_origin(value: str | None, port: int) -> bool:
    """A mutating request's Origin, when present, must be loopback HTTP."""
    if value is None:
        return True  # Permit non-browser clients that possess the request token.
    try:
        parsed = urlsplit(value)
        parsed_port = parsed.port or (80 if parsed.scheme == "http" else 443)
        host = _canonical_host(parsed.hostname or "")
    except ValueError:
        return False
    structurally_valid = (
        parsed.scheme == "http"
        and not parsed.username
        and not parsed.password
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
    )
    return structurally_valid and host in LOCAL_HOSTS and parsed_port == port


def make_handler(token: str, page_path: str, nonce: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "dpapi-web"

        def version_string(self):
            return self.server_version

        def setup(self):
            super().setup()
            self.connection.settimeout(REQUEST_TIMEOUT_SECONDS)

        def log_message(self, *_args):  # keep the console quiet
            pass

        def _send(self, code, body, content_type="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Permissions-Policy", "clipboard-write=(self)")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                f"script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; form-action 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _authed(self) -> bool:
            return secrets.compare_digest(
                self.headers.get("X-DPAPI-Token", ""), token)

        def _local_request(self, *, mutating: bool = False) -> bool:
            if not _allowed_authority(
                self.headers.get("Host"), self.server.server_port
            ):
                return False
            if mutating and not _allowed_origin(
                self.headers.get("Origin"), self.server.server_port
            ):
                return False
            fetch_site = self.headers.get("Sec-Fetch-Site")
            return not mutating or fetch_site in (None, "none", "same-origin")

        def do_GET(self):
            if not self._local_request():
                self._send(403, b'{"error":"forbidden host"}')
                return
            path = self.path.split("?", 1)[0]
            if path == page_path:
                self._send(200, build_page(token, nonce), "text/html; charset=utf-8")
                return
            if path.startswith("/download/"):
                entry = _take_download(path.rsplit("/", 1)[1])
                if not entry:
                    self._send(404, b'{"error":"not found"}')
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{entry.name}"')
                self.send_header("Content-Length", str(len(entry.data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(entry.data)
                return
            self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            if not self._local_request(mutating=True) or not self._authed():
                self._send(403, b'{"error":"forbidden"}')
                return
            path = self.path.split("?", 1)[0]
            if path not in ("/inspect", "/decrypt", "/reset"):
                self._send(404, b'{"error":"not found"}')
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(400, b'{"error":"invalid Content-Length"}')
                return
            if length < 0 or length > MAX_BODY:
                self._send(413, b'{"error":"payload too large"}')
                return
            if self.headers.get_content_type() != "application/json":
                self._send(415, b'{"error":"Content-Type must be application/json"}')
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self._send(400, b'{"error":"incomplete request body"}')
                return
            try:
                request = json.loads(body or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, b'{"error":"invalid JSON"}')
                return
            if not isinstance(request, dict):
                self._send(400, b'{"error":"JSON body must be an object"}')
                return
            if path == "/reset":
                _clear_downloads()
                self._send(200, b'{"ok":true}')
                return
            if not _WORK_SLOTS.acquire(blocking=False):
                self._send(429, b'{"error":"another operation is still running"}')
                return
            try:
                result = _run(request, inspect_only=(path == "/inspect"))
            except Exception:
                result = {"ok": False, "log": ["error: unexpected internal failure"]}
            finally:
                _WORK_SLOTS.release()
            self._send(200, json.dumps(result).encode("utf-8"))

    return Handler


def serve(port: int, open_browser: bool) -> None:
    token = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(18)
    handler = make_handler(token, PAGE_PATH, nonce)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    reaper_stop = threading.Event()
    reaper_thread = threading.Thread(
        target=_download_reaper, args=(reaper_stop,), daemon=True
    )
    reaper_thread.start()
    actual_port = httpd.server_address[1]
    url = f"http://127.0.0.1:{actual_port}{PAGE_PATH}"
    print(f"[+] DPAPI web UI on {url}")
    print("[i] loopback only; decrypted secrets pass through this local process")
    print("[i] press Ctrl+C to stop")
    if open_browser:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] stopping")
    finally:
        httpd.shutdown()
        httpd.server_close()
        reaper_stop.set()
        reaper_thread.join(timeout=1)
        _clear_downloads()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local (loopback-only) web UI for dpapi-toolkit"
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true", help="do not open a browser")
    args = parser.parse_args()
    serve(args.port, open_browser=not args.no_open)


PAGE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DPAPI Toolkit</title>
<style nonce="__NONCE__">
  /* Light is the base; dark values apply either by OS preference (unless the
     viewer forced light) or by an explicit data-theme="dark" choice. */
  :root { color-scheme:light; --accent:#356a7a; --accent-strong:#244b57;
      --surface:#ffffff; --surface-soft:#f1f1ef; --border:#c6c6c0; --muted:#5b5b55;
      --ok:#3f7d4f; --log-bg:#1b1b1a; --log-fg:#e0e0dc; --divider:#c6c6c0;
      --page-bg:#e8e8e4; --page-fg:#1b1b19; }
  body { font-family:system-ui,sans-serif; margin:0; background:var(--page-bg); color:var(--page-fg); }
  @media (prefers-color-scheme: dark){
    :root:not([data-theme="light"]) { color-scheme:dark; --accent:#63aebb; --accent-strong:#82c3cf;
        --surface:#242423; --surface-soft:#1c1c1b; --border:#454541; --muted:#999993;
        --ok:#5fae74; --log-bg:#121211; --log-fg:#e0e0dc; --divider:#3a3a37;
        --page-bg:#151514; --page-fg:#e5e5e1; }
  }
  :root[data-theme="dark"] { color-scheme:dark; --accent:#63aebb; --accent-strong:#82c3cf;
      --surface:#242423; --surface-soft:#1c1c1b; --border:#454541; --muted:#999993;
      --ok:#5fae74; --log-bg:#121211; --log-fg:#e0e0dc; --divider:#3a3a37;
      --page-bg:#151514; --page-fg:#e5e5e1; }
  :root[data-theme="light"] { color-scheme:light; }
  header { padding:9px 16px; background:var(--surface); color:inherit;
      border-bottom:1px solid var(--border); display:flex; align-items:center;
      justify-content:space-between; gap:12px; }
  header h1 { margin:0; font-size:13px; font-weight:700; letter-spacing:.08em;
      text-transform:uppercase; font-family:ui-monospace,monospace; }
  .theme-toggle { display:flex; align-items:center; gap:8px; white-space:nowrap; }
  .theme-label { font-size:10px; text-transform:uppercase; letter-spacing:.08em;
      color:var(--muted); font-family:ui-monospace,monospace; }
  .theme-seg { display:inline-flex; border:1px solid var(--border); border-radius:5px;
      overflow:hidden; background:var(--surface-soft); }
  .theme-seg button { background:transparent; color:var(--muted); border:0;
      border-right:1px solid var(--border); padding:4px 11px; font-size:11px;
      text-transform:uppercase; letter-spacing:.04em; font-family:ui-monospace,monospace;
      cursor:pointer; border-radius:0; transition:background .12s,color .12s; }
  .theme-seg button:last-child { border-right:0; }
  .theme-seg button:hover { background:color-mix(in srgb,var(--accent) 12%,transparent); color:inherit; }
  .theme-seg button.active { background:var(--accent); color:#fff; }
  .theme-seg button.active:hover { background:var(--accent-strong); color:#fff; }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  main { display:flex; gap:0; padding:14px; align-items:stretch; min-width:0; }
  #left { flex:0 0 432px; min-width:410px; max-width:none; }
  #gutter { flex:0 0 18px; align-self:stretch; cursor:col-resize; position:relative;
      touch-action:none; }
  #gutter::before { content:""; position:absolute; inset:0 7px; width:4px; min-height:100%;
      border-radius:4px; background:var(--divider); box-shadow:0 0 0 1px #0002; }
  #gutter:hover::before, #gutter:active::before { background:var(--accent); }
  #right { flex:1 1 auto; min-width:0; padding-left:10px; }
  @media (max-width: 900px){
    main{ flex-direction:column; }
    #left, #right{ flex:none !important; width:100%; min-width:0; max-width:none;
        padding-left:0; overflow:visible; }
    #gutter{ display:none; }
  }
  .cp { cursor:pointer; opacity:.55; margin-left:8px; font-size:11px; user-select:none;
      font-family:ui-monospace,monospace; text-decoration:underline; color:var(--muted); }
  .cp:hover { opacity:1; color:var(--accent); }
  fieldset { border:1px solid var(--border); border-radius:3px; margin:0 0 12px; padding:10px 12px;
      min-inline-size:0; width:100%; background:var(--surface); }
  legend { font-weight:600; padding:0 6px; }
  details.optional-section { border:1px solid var(--border); border-radius:3px; margin:0 0 12px;
      padding:0 12px; width:100%; background:var(--surface); }
  details.optional-section > summary { cursor:pointer; font-weight:600; padding:10px 0;
      color:var(--muted); user-select:none; }
  details.optional-section[open] > summary { color:inherit; border-bottom:1px solid var(--border); }
  details.optional-section > .optional-body { padding:7px 0 10px; }
  label.row { display:flex; align-items:center; gap:8px; margin:5px 0; font-size:13px; min-width:0; }
  label.row > span { flex:0 0 164px; min-width:0; white-space:nowrap; }
  input[type=text], input[type=password], textarea, select { flex:1; padding:5px 7px; border-radius:3px;
      border:1px solid var(--border); background:var(--surface-soft); color:inherit;
      min-width:0; width:100%; max-width:100%; }
  input:focus, textarea:focus, select:focus { outline:2px solid color-mix(in srgb,var(--accent) 45%,transparent);
      border-color:var(--accent); }
  label.row.stack { display:block; }
  label.row.stack > span { display:block; margin-bottom:6px; white-space:normal; }
  label.row.stack textarea { display:block; min-height:78px; resize:vertical;
      font-family:ui-monospace,monospace; white-space:pre-wrap; overflow-wrap:anywhere; }
  .drop { border:1px dashed var(--border); border-radius:3px; padding:15px; margin:6px 0;
      font-size:13px; transition:border-color .12s; cursor:pointer; min-width:0; overflow-wrap:anywhere;
      background:var(--surface-soft); }
  .drop.over { border-color:var(--accent); border-style:solid; }
  .drop b { color:var(--accent); }
  .drop .clear { float:right; cursor:pointer; opacity:.6; }
  /* filled: a control that currently holds data */
  .drop.has-data { border-style:solid; border-color:var(--ok);
      background:color-mix(in srgb,var(--ok) 9%,var(--surface-soft)); }
  input.has-data, select.has-data, textarea.has-data { border-color:var(--ok);
      background:color-mix(in srgb,var(--ok) 7%,var(--surface-soft)); }
  label.row.has-data > span::after { content:" ✓"; color:var(--ok); }
  /* needed: the next control(s) to fill for the loaded artifact */
  .drop.needed { border-style:solid; border-color:var(--accent);
      box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 28%,transparent); }
  input.needed, select.needed { border-color:var(--accent);
      box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 28%,transparent); }
  label.row.needed > span::after { content:" needed"; color:var(--accent);
      font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.04em; }
  button { padding:7px 13px; border-radius:3px; border:1px solid var(--accent-strong);
      background:var(--accent); color:#fff; font-size:13px; cursor:pointer; }
  button:hover { background:var(--accent-strong); }
  button:disabled { opacity:.45; cursor:not-allowed; }
  button.ready { box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 30%,transparent); }
  button.sec { background:transparent; color:var(--muted); border-color:var(--border); }
  button.sec:hover { background:var(--surface-soft); color:inherit; }
  #log-shell { margin-top:18px; padding-top:12px; border-top:1px solid var(--divider); }
  #log-shell h3 { margin:0 0 7px; font-size:11px; color:var(--muted); letter-spacing:.06em;
      text-transform:uppercase; font-family:ui-monospace,monospace; }
  #log { background:var(--log-bg); color:var(--log-fg); padding:10px; border:1px solid var(--border);
      border-radius:3px; height:270px;
      overflow:auto; white-space:pre-wrap; font-family:ui-monospace,monospace; font-size:12px; }
  .log-line { display:block; min-height:1.35em; }
  .log-command { color:#c9a7ff; }
  .log-info { color:#70b7ff; }
  .log-success { color:#72df9b; }
  .log-warning { color:#ffd166; }
  .log-required { color:#ff9d5c; font-weight:600; }
  .log-error { color:#ff7b86; font-weight:600; }
  .result { border:1px solid var(--border); background:var(--surface); border-radius:3px;
      padding:8px 10px; margin:8px 0; }
  .result h4 { margin:0 0 6px; font-size:13px; }
  .result pre { max-height:300px; overflow:auto; background:var(--log-bg); color:var(--log-fg); padding:8px;
      border-radius:3px; font-size:12px; white-space:pre-wrap; word-break:break-all; }
  .result-actions { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-top:6px; }
  .result-actions a { text-decoration:none; }
  button.sec.chained { border-color:var(--accent); color:var(--accent); font-weight:600; }
  button.sec.chained:hover { background:var(--accent); color:#fff; }
  .actions { display:flex; gap:10px; margin:6px 0 14px; flex-wrap:wrap; }
  small.hint { color:var(--muted); }
  .plugin-workflow { margin:9px 0 0; padding:8px 10px; border-left:2px solid var(--accent);
      background:var(--surface-soft); color:var(--muted); font-size:13px; }
  .tabs { display:flex; gap:4px; border-bottom:1px solid var(--border); margin-bottom:8px;
      flex-wrap:wrap; min-width:0; }
  .tab, .input-tab { background:transparent; color:inherit; border:0; border-bottom:2px solid transparent;
      padding:6px 12px; font-size:13px; cursor:pointer; opacity:.7; }
  .tab:hover, .input-tab:hover { background:var(--surface-soft); color:var(--accent); }
  .tab.active, .input-tab.active { opacity:1; border-bottom-color:var(--accent); color:var(--accent); }
  .input-tabs { margin-bottom:12px; flex-wrap:nowrap; white-space:nowrap; width:max-content;
      min-width:100%; }
  .pane { min-height:360px; padding:4px 7px; border-radius:3px;
      background:var(--surface); border:1px solid var(--border); }
  .pane .empty { opacity:.55; font-size:13px; }
  table.struct { width:100%; border-collapse:collapse; font-size:12.5px; }
  table.struct td { padding:2px 8px; vertical-align:top; border-bottom:1px solid #8882; }
  table.struct td.k { width:210px; opacity:.85; }
  table.struct td.v { font-family:ui-monospace,monospace; word-break:break-all; }
  table.struct tr.sect td { background:#8881; font-weight:600; font-family:inherit; }
  table.struct tr.blobhdr td { background:var(--accent); color:#fff; font-weight:600; }
  @media (max-width: 520px) {
    main { padding:9px; }
    .input-tabs { max-width:100%; overflow-x:auto; }
    .tab, .input-tab { padding-inline:8px; }
    label.row > span { flex-basis:145px; }
  }
</style>
</head>
<body>
<header>
  <h1>DPAPI Toolkit</h1>
  <div class="theme-toggle">
    <span class="theme-label">Theme</span>
    <div class="theme-seg" role="group" aria-label="Theme">
      <button type="button" data-theme-choice="auto">auto</button>
      <button type="button" data-theme-choice="light">light</button>
      <button type="button" data-theme-choice="dark">dark</button>
    </div>
  </div>
</header>
<main>
  <section id="left">
    <div class="tabs input-tabs" aria-label="Input workflow">
      <button class="input-tab active" data-input-tab="artifact">1. Artifact</button>
      <button class="input-tab" data-input-tab="unlock">2. Unlock key</button>
      <button id="plugin-tab" class="input-tab" data-input-tab="plugin">3. Plugins</button>
    </div>
    <div id="input-artifact" class="input-pane">
    <fieldset>
      <legend>Core DPAPI artifact</legend>
      <div class="drop" data-file="input">Drop <b>masterkey, blob, or artifact</b> here (or click)<span class="clear" data-clear="input">clear</span></div>
      <div class="drop" data-tree="input"><small class="hint">Drop a folder of artifacts (processed recursively)</small></div>
      <label class="row stack" title="Paste the artifact as hex (e.g. a PowerShell SecureString). Overrides a dropped file."><span>or paste hex</span><textarea data-field="input" rows="3" wrap="soft" placeholder="hex of the artifact (e.g. SecureString)"></textarea></label>
      <label class="row"><span>Type</span>
        <select data-field="type">
          <option>auto</option><option>masterkey</option><option>credhist</option>
          <option>blob</option><option>credential</option><option>capi</option>
          <option>cng</option><option>cert</option><option>vpol</option><option>vcrd</option>
          <option>powershell</option><option>clixml</option><option>keepass</option><option>sccm</option><option>wifi</option><option>wifi-peap</option>
          <option>outlook</option><option>rdp</option><option>rdcman</option><option>ngc-cng</option>
          <option>localstate</option>
        </select></label>
    </fieldset>
    </div>

    <div id="input-unlock" class="input-pane" hidden>
    <fieldset>
      <legend>Master key</legend>
      <div class="drop" data-file="masterkey">Drop <b>encrypted masterkey</b><span class="clear" data-clear="masterkey">clear</span></div>
      <div class="drop" data-tree="masterkey_dir"><small class="hint">Drop <b>Protect</b> dir of masterkeys (auto-match by GUID)</small></div>
      <div class="drop" data-file="real_masterkey">Drop <b>decrypted masterkey</b> file<span class="clear" data-clear="real_masterkey">clear</span></div>
      <label class="row" title="Paste the 64-byte masterkey (or its 20-byte SHA1) as hex or base64 - no file needed"><span>or masterkey hex</span><input type="text" data-field="real_masterkey" placeholder="hex / base64 of the decrypted masterkey"></label>
    </fieldset>

    <fieldset>
      <legend>Account / derivation</legend>
      <label class="row"><span>SID</span><input type="text" data-field="sid" placeholder="S-1-5-21-..."></label>
      <label class="row"><span>Password</span><input type="password" data-field="password"></label>
      <label class="row"><span>Empty password ('')</span><input type="checkbox" data-field="empty_password"></label>
      <label id="whfb-pin-options" class="row" title="One known Windows Hello software-key PIN; no guessing or Hashcat export" hidden><span>Known Hello PIN</span><input type="password" data-field="pin" autocomplete="off"></label>
      <label class="row" title="A 16-byte NT hash plus SID can unlock classic domain and Protected Users masterkeys"><span>NT hash (domain)</span><input type="text" data-field="nt_hash" placeholder="32 hex characters"></label>
      <label class="row" title="Local accounts only: SHA1(password.encode('utf-16le')), exactly 20 bytes / 40 hex characters. This is not a CloudAP/Entra prekey."><span>SHA1 password hash (local)</span><input type="text" data-field="sha1_hash" placeholder="40 hex characters"></label>
      <small id="recovered-key-help" class="hint" hidden>Recovered CloudAP/CacheData keys apply to an encrypted user masterkey, not directly to the artifact and not to a Windows Hello PIN.</small>
      <label id="prekey-options" class="row" title="Final 20-byte SID-bound DPAPI prekey recovered elsewhere (for example CloudAP or Mimikatz); unlocks the encrypted masterkey directly" hidden><span>Recovered prekey</span><input type="text" data-field="prekey" placeholder="40 hex characters"></label>
      <label id="credkey-options" class="row" title="Unbound credential key recovered from CloudAP/CacheData; requires the owning account SID" hidden><span>Recovered cred key</span><input type="text" data-field="credkey" placeholder="requires SID above"></label>
      <div class="drop" data-file="dpapi_system">Drop <b>DPAPI_SYSTEM</b><span class="clear" data-clear="dpapi_system">clear</span></div>
      <label id="dpapi-system-hex-row" class="row" title="Paste all 80 hex characters for MachineKey || UserKey, or one 40-character component key"><span>or DPAPI_SYSTEM hex</span><input type="text" data-field="dpapi_system" placeholder="80-char full value or 40-char key"></label>
      <div class="drop" data-file="domain_backup_key">Drop <b>AD DPAPI backup key</b><span class="clear" data-clear="domain_backup_key">clear</span></div>
      <label class="row" title="Paste the complete backup-key material as hexadecimal or Base64 instead of dropping a binary/PVK/PEM file"><span>or backup key text</span><input type="text" data-field="domain_backup_key" placeholder="hex or Base64"></label>
      <div id="pvk-password-options" hidden>
        <label class="row"><span>Backup-key file password</span><input type="password" data-field="pvk_password" autocomplete="off"></label>
        <div class="drop" data-file="pvk_password_file">Or load <b>backup-key password file</b><span class="clear" data-clear="pvk_password_file">clear</span></div>
        <small class="hint">Only needed when the supplied PVK/PEM itself is password-encrypted.</small>
      </div>
      <div class="drop" data-file="system_masterkey" title="ONLY for enterprise Wi-Fi (wifi-peap), which nests two DPAPI layers - this is the outer key. For scheduled tasks / services / other SYSTEM secrets, use 'encrypted masterkey' above + DPAPI_SYSTEM instead.">Drop <b>SYSTEM masterkey</b> (PEAP only)<span class="clear" data-clear="system_masterkey">clear</span></div>
    </fieldset>

    <details id="optional-entropy-vault" class="optional-section">
      <summary>Optional entropy / Vault</summary>
      <div class="optional-body">
        <label class="row" title="Optional entropy. Use hex: for exact bytes (replaces needing an entropy file)."><span>Entropy</span><input type="text" data-field="entropy" placeholder="text | hex: | base64: | utf16:"></label>
        <div class="drop" data-file="entropy_file">Or drop exact <b>entropy bytes</b><span class="clear" data-clear="entropy_file">clear</span></div>
        <div class="drop" data-file="vault_policy">Drop <b>Vault Policy.vpol</b> (derives the AES keys)<span class="clear" data-clear="vault_policy">clear</span></div>
        <label class="row"><span>Vault AES key</span><input type="text" data-field="vault_key" placeholder="hex key"></label>
        <div class="drop" data-file="vault_key">Or drop <b>Vault key JSON</b><span class="clear" data-clear="vault_key">clear</span></div>
      </div>
    </details>
    </div>

    <div id="input-plugin" class="input-pane" hidden>
      <fieldset>
        <legend>Offline plugin</legend>
        <label class="row"><span>Plugin</span>
          <select data-field="plugin">__PLUGIN_OPTIONS__</select></label>
        <div class="drop" data-file="plugin_input">Drop <b id="plugin-input-name">the plugin's main artifact</b> here (or click)<span class="clear" data-clear="plugin_input">clear</span></div>
        <div class="plugin-workflow"><strong>Workflow:</strong> <span id="plugin-workflow-help">Choose a plugin to see exactly which file and other tabs it needs.</span></div>
      </fieldset>
      __PLUGIN_PANELS__
      <div class="actions plugin-actions">
        <button id="run-plugin">Run plugin</button>
      </div>
    </div>
  </section>

  <div id="gutter" title="Drag to resize"></div>

  <section id="right">
    <fieldset>
      <legend>Output</legend>
      <label class="row"><span>Format</span>
        <select data-field="output_format"><option>auto</option><option>hex</option>
          <option>raw</option><option>unhex</option><option>utf16-utf8</option></select></label>
      <label id="hashcat-context-options" class="row" hidden><span>Hashcat context</span>
        <select data-field="hashcat_context"><option>all</option><option>local</option>
          <option>domain</option><option>domain-new</option><option>domain-auto</option></select></label>
      <small id="hashcat-hint" class="hint" hidden>Local account &rarr; 15900/15300 (local). Domain account &rarr; 15910/15310 (domain-new, 2016+ DCs) or 15900/15300 (domain, legacy). The default <b>all</b> exports every form so the key cracks whatever the account type.</small>
      <small class="hint">Results are kept only in short-lived server memory until their one-time browser download. No persistent server output is written.</small>
    </fieldset>

    <div class="actions">
      <button id="inspect" class="sec core-action">Inspect</button>
      <button id="decrypt" class="core-action">Decrypt</button>
      <button id="tohash" class="core-action" title="Export a $DPAPImk$ Hashcat hash from an encrypted masterkey file (needs SID)" hidden>Masterkey &rarr; Hashcat</button>
      <button id="reset" class="sec" title="Clear browser fields and expire all pending decrypted downloads">Reset &amp; wipe</button>
      <button id="clear-log" class="sec" title="Clear only the activity log; keep fields, files, and results">Clear log</button>
    </div>
    <div class="tabs">
      <button class="tab active" data-tab="structure">Structure</button>
      <button class="tab" data-tab="decrypted">Decrypted data</button>
    </div>
    <div id="pane-structure" class="pane"><p class="empty">Drop or inspect an artifact to see its parsed structure.</p></div>
    <div id="pane-decrypted" class="pane" hidden><p class="empty">Decrypted results appear here after Decrypt.</p></div>
    <section id="log-shell" aria-label="Activity log">
      <h3>Activity log</h3>
      <div id="log"></div>
    </section>
  </section>
</main>

<input type="file" id="filePicker" style="display:none">
<input type="file" id="dirPicker" style="display:none" webkitdirectory directory multiple>

<script nonce="__NONCE__">
const TOKEN = "__TOKEN__";
const files = {};   // field -> {name, b64}
const trees = {};   // field -> [{relpath, b64}]
const fields = {};  // field -> value
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
let running = false;
let lastRequired = [];  // master-key GUIDs the last inspect/decrypt reported
let lastDetected = "";  // artifact type the last run resolved to
let lastRunPlugin = ""; // plugin id the last run used (for chained-action buttons)

// The shared core emits CLI-style hints ("use --masterkey ..."); rewrite them
// into the equivalent web actions so the log never names flags the UI lacks.
const LOG_REWRITES = [
  [/use --masterkey, --real-masterkey, or --masterkey-dir/gi,
    'add master-key material in "2. Unlock key" (an encrypted masterkey + SID/password, a Protect folder, or a decrypted masterkey)'],
  [/enterprise profile: obtain MSMUserData and use --type wifi-peap/gi,
    'enterprise profile: load the exported MSMUserData and set Type to wifi-peap'],
  [/rerun with --system-masterkey FILE_OR_HEX/gi,
    'add the outer key in "SYSTEM masterkey (PEAP only)"'],
];
function rewriteLogLine(line){
  let out = line;
  for(const [pattern, replacement] of LOG_REWRITES) out = out.replace(pattern, replacement);
  return out;
}

function b64(file){
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result.split(",")[1] || "");
    r.onerror = rej;
    r.readAsDataURL(file);
  });
}
function log(lines){
  const box = document.getElementById("log");
  for(const value of lines){
    const line = rewriteLogLine(String(value));
    const row = document.createElement("span");
    row.className = "log-line";
    if(/required (?:master key|SYSTEM master key)|required GUID/i.test(line)) row.classList.add("log-required");
    else if(/^\s*(?:error\b|\[-\]|failed\b|failure\b)/i.test(line)) row.classList.add("log-error");
    else if(/^\s*(?:warning\b|warn\b|\[!\])/i.test(line)) row.classList.add("log-warning");
    else if(/^\s*\[\+\]/.test(line)) row.classList.add("log-success");
    else if(/^\s*\[i\]/i.test(line)) row.classList.add("log-info");
    else if(/^\s*>/.test(line)) row.classList.add("log-command");
    row.textContent = line;
    box.appendChild(row);
  }
  box.scrollTop = box.scrollHeight;
}

function updateConditionalUI(){
  const type = fields.type || "auto";
  const plugin = fields.plugin || "";
  const sid = String(fields.sid || "").trim();
  const isEntraSid = /^S-1-12-1-(?:\d+-){3}\d+$/i.test(sid);
  const hasMasterkey = type === "masterkey" || Boolean(files.masterkey) || Boolean(trees.masterkey_dir);
  const backupText = String(fields.domain_backup_key || "").trim();
  const pvk = document.getElementById("pvk-password-options");
  if(pvk) pvk.hidden = !(files.domain_backup_key || backupText);
  const whfb = document.getElementById("whfb-pin-options");
  if(whfb) whfb.hidden = type !== "ngc-cng";
  const recoveredHelp = document.getElementById("recovered-key-help");
  const prekey = document.getElementById("prekey-options");
  const credkey = document.getElementById("credkey-options");
  if(recoveredHelp) recoveredHelp.hidden = !(hasMasterkey && isEntraSid);
  if(prekey) prekey.hidden = !(hasMasterkey && isEntraSid);
  if(credkey) credkey.hidden = !(hasMasterkey && isEntraSid);
  document.querySelectorAll("[data-plugin-panel]").forEach(panel => {
    panel.hidden = panel.dataset.pluginPanel !== plugin;
  });
  const pluginControl = document.querySelector('select[data-field="plugin"]');
  const selectedPlugin = pluginControl && pluginControl.selectedOptions[0];
  const inputName = document.getElementById("plugin-input-name");
  const workflowHelp = document.getElementById("plugin-workflow-help");
  if(inputName){
    inputName.textContent = plugin && selectedPlugin
      ? selectedPlugin.dataset.inputLabel
      : "the plugin's main artifact";
  }
  if(workflowHelp){
    workflowHelp.textContent = plugin && selectedPlugin
      ? selectedPlugin.dataset.workflowHelp
      : "Choose a plugin to see exactly which file and other tabs it needs.";
  }
  refreshGuidance();
}

// Highlight controls that already hold data, and the next one(s) to fill for
// the loaded artifact: artifact -> master key -> SID -> password/secret.
function markNeeded(selector, alsoRow){
  document.querySelectorAll(selector).forEach(el => {
    el.classList.add("needed");
    if(alsoRow){ const row = el.closest("label.row"); if(row) row.classList.add("needed"); }
  });
}
function updateHashcatVisibility(){
  const type = fields.type || "auto";
  const activeInputTab = document.querySelector(".input-tab.active")?.dataset.inputTab;
  const visible = (type === "masterkey" || Boolean(fields.batch))
    && activeInputTab !== "plugin";
  const context = document.getElementById("hashcat-context-options");
  const hint = document.getElementById("hashcat-hint");
  const button = document.getElementById("tohash");
  if(context) context.hidden = !visible;
  if(hint) hint.hidden = !visible;
  if(button) button.hidden = !visible;
}
function refreshGuidance(){
  // Filled controls.
  document.querySelectorAll("[data-file]").forEach(el =>
    el.classList.toggle("has-data", Boolean(files[el.dataset.file])));
  document.querySelectorAll("[data-tree]").forEach(el =>
    el.classList.toggle("has-data", Boolean(trees[el.dataset.tree])));
  document.querySelectorAll("input[data-field],select[data-field],textarea[data-field]").forEach(el => {
    const key = el.dataset.field;
    const filled = el.type === "checkbox" ? el.checked
      : el.tagName === "SELECT" ? el.selectedIndex > 0
      : String(fields[key] || "").trim() !== "";
    el.classList.toggle("has-data", filled);
    const row = el.closest("label.row");
    if(row) row.classList.toggle("has-data", filled);
  });

  // Clear previous suggestions.
  document.querySelectorAll(".needed").forEach(el => el.classList.remove("needed"));

  const type = fields.type || "auto";
  const artifactLoaded = Boolean(files.input || files.plugin_input || trees.input
    || String(fields.input || "").trim());

  // Masterkey -> Hashcat is only meaningful with an encrypted masterkey loaded
  // and its owning SID entered. Gate the button on both (except while a run is
  // in flight, when every action button is disabled anyway).
  const tohash = document.getElementById("tohash");
  const hashcatContext = type === "masterkey" || Boolean(fields.batch);
  updateHashcatVisibility();
  if(tohash && !running){
    const ready = artifactLoaded && hashcatContext && String(fields.sid || "").trim() !== "";
    tohash.disabled = !ready;
    tohash.classList.toggle("ready", ready);
    tohash.title = ready
      ? (fields.batch
          ? "Export a $DPAPImk$ record for every master key in the folder"
          : "Export a $DPAPImk$ Hashcat hash from this encrypted masterkey")
      : "Load an encrypted masterkey (or a folder of them) and enter the owning SID to enable";
  }

  // A selected plugin has its own inputs: highlight its empty main input and the
  // non-optional controls in its panel, then stop (plugins skip the masterkey chain).
  if(fields.plugin){
    if(!files.plugin_input && !trees.plugin_input && !String(fields.input || "").trim()){
      markNeeded('[data-file="plugin_input"]');
    }
    const panel = document.querySelector(`[data-plugin-panel="${fields.plugin}"]`);
    if(panel){
      panel.querySelectorAll('input[data-field],[data-file]').forEach(el => {
        if(el.type === "checkbox" || el.dataset.optional === "true") return;
        const key = el.dataset.field || el.dataset.file;
        if(key === "pfx_password" &&
            (Boolean(fields.empty_pfx_password) || Boolean(files.pfx_password_file))) return;
        const filled = el.dataset.file
          ? (Boolean(files[key]) || Boolean(trees[key]))
          : String(fields[key] || "").trim() !== "";
        if(!filled){
          el.classList.add("needed");
          const row = el.closest("label.row");
          if(row) row.classList.add("needed");
        }
      });
      if(fields.plugin === "cachedata" &&
          !String(fields.password || "").length && !fields.cachedata_hashcat){
        markNeeded('input[data-field="password"]', true);
      }
    }
    return;
  }
  if(!artifactLoaded) return;
  // Batch: decrypt needs a master key, and Masterkey -> Hashcat needs the SID.
  // Highlight both so either path is clear.
  if(fields.batch){
    const hasDecryptedMK = Boolean(files.real_masterkey) || String(fields.real_masterkey || "").trim() !== "";
    const hasEncryptedMK = Boolean(files.masterkey) || Boolean(trees.masterkey_dir);
    if(!hasDecryptedMK && !hasEncryptedMK){
      markNeeded('[data-file="masterkey"]');
      markNeeded('[data-tree="masterkey_dir"]');
      markNeeded('[data-file="real_masterkey"]');
      markNeeded('input[data-field="real_masterkey"]', true);
    }
    if(String(fields.sid || "").trim() === "") markNeeded('input[data-field="sid"]', true);
    return;
  }
  // A master key is needed when a blob was found, or the chosen type uses one.
  const needsMasterkey = lastRequired.length > 0 || (type !== "auto" && type !== "cert");
  if(!needsMasterkey) return;

  const hasDecryptedMK = Boolean(files.real_masterkey) || String(fields.real_masterkey || "").trim() !== "";
  if(hasDecryptedMK) return;   // the artifact can be decrypted directly

  // SCCM uses SYSTEM-protected secrets. Ask for the pasteable DPAPI_SYSTEM hex
  // first and stop here so the larger masterkey drop zones do not visually
  // overpower the exact field the user needs to fill next.
  const SYSTEM_TYPES = new Set(["wifi", "wifi-peap", "sccm", "ngc-cng"]);
  const hasDPAPISystem = Boolean(files.dpapi_system) || String(fields.dpapi_system || "").trim() !== "";
  if(type === "sccm" && !hasDPAPISystem){
    markNeeded('#dpapi-system-hex-row input', true);
    return;
  }

  const hasEncryptedMK = Boolean(files.masterkey) || Boolean(trees.masterkey_dir) || type === "masterkey";
  if(!hasEncryptedMK){
    // Step 1: supply a master key (any one of these).
    markNeeded('[data-file="masterkey"]');
    markNeeded('[data-tree="masterkey_dir"]');
    markNeeded('[data-file="real_masterkey"]');
    markNeeded('input[data-field="real_masterkey"]', true);
    return;
  }
  // Step 2: unlock the encrypted master key. SYSTEM/local-system artifacts use
  // DPAPI_SYSTEM (no SID or password); user artifacts use SID + a secret.
  if(SYSTEM_TYPES.has(type)){
    if(!hasDPAPISystem){
      markNeeded('[data-file="dpapi_system"]');
      markNeeded('input[data-field="dpapi_system"]', true);
    }
    return;
  }
  const hasSID = String(fields.sid || "").trim() !== "";
  const hasSecret = ["password", "nt_hash", "sha1_hash", "prekey", "credkey"]
      .some(k => String(fields[k] || "").trim() !== "")
    || Boolean(fields.empty_password) || hasDPAPISystem
    || Boolean(files.domain_backup_key) || String(fields.domain_backup_key || "").trim() !== "";
  if(!hasSID) markNeeded('input[data-field="sid"]', true);
  if(!hasSecret) markNeeded('input[data-field="password"]', true);
}

// wire text/select/checkbox fields
document.querySelectorAll("[data-field]").forEach(el => {
  const key = el.dataset.field;
  const read = () => {
    const value = el.type === "checkbox" ? el.checked : el.value;
    fields[key] = value;
    // Plugin pages may repeat a common field such as SID or password. Keep
    // every visible representation synchronized to one request value.
    document.querySelectorAll(`[data-field="${key}"]`).forEach(peer => {
      if(peer === el) return;
      if(peer.type === "checkbox") peer.checked = Boolean(value);
      else peer.value = value;
    });
    updateConditionalUI();
  };
  el.addEventListener("input", read); el.addEventListener("change", read); read();
});
const pluginSelect = document.querySelector('select[data-field="plugin"]');
if(pluginSelect) pluginSelect.addEventListener("change", () => {
  if(pluginSelect.value){ setType("auto"); setInputTab("plugin"); }
});
// Typing the masterkey as hex/base64 drops any uploaded decrypted-masterkey file.
const realHex = document.querySelector('input[data-field="real_masterkey"]');
if(realHex) realHex.addEventListener("input", () => { delete files.real_masterkey; });

// Pasting the artifact as hex drops any dropped file/folder and returns to single mode.
let hexInspectTimer = null;
const inputHex = document.querySelector('textarea[data-field="input"]');
if(inputHex) inputHex.addEventListener("input", () => {
  delete files.input; delete files.plugin_input; delete trees.input;
  const tz = document.querySelector('[data-tree="input"]');
  if(tz) tz.innerHTML = treeOriginal.input;
  const fz = document.querySelector('[data-file="input"]');
  if(fz) fz.innerHTML = fileOriginal.input;
  setBatch(false); setType("auto"); wireClears();
  // Auto-inspect shortly after typing/pasting stops, so pasted hex gets the same
  // structure view, required-key report, and Unlock-key guidance as a dropped file.
  clearTimeout(hexInspectTimer);
  if((inputHex.value || "").trim().length >= 16 && !fields.plugin){
    hexInspectTimer = setTimeout(() => {
      if(!running && (fields.input || "").trim() && !fields.plugin) doRun("/inspect");
    }, 500);
  }
});

// single-file drop zones
let pickerTarget = null;
const filePicker = document.getElementById("filePicker");
filePicker.addEventListener("change", async e => {
  if(e.target.files[0] && pickerTarget){ await acceptFile(pickerTarget, e.target.files[0]); }
  filePicker.value = "";
});
const dirPicker = document.getElementById("dirPicker");
dirPicker.addEventListener("change", async e => {
  if(pickerTarget){ await acceptTree(pickerTarget, [...e.target.files]); }
  dirPicker.value = "";
});

async function acceptFile(field, file){
  if(file.size > MAX_FILE_BYTES){ log([`error: ${file.name} exceeds the 64 MiB file limit`]); return; }
  files[field] = { name: file.name, b64: await b64(file) };
  updateConditionalUI();
  const el = document.querySelector(`[data-file="${field}"]`);
  const pluginOption = document.querySelector('select[data-field="plugin"]')?.selectedOptions[0];
  const displayField = field === "plugin_input" && pluginOption?.dataset.inputLabel
    ? pluginOption.dataset.inputLabel : field;
  el.querySelector("b") && (el.innerHTML = `<b>${esc(displayField)}</b>: ${esc(file.name)} <span class="clear" data-clear="${esc(field)}">clear</span>`);
  wireClears();
  if(field === "input"){
    // A single artifact -> single mode: drop any batch folder + uncheck Batch,
    // clear any pasted hex, and reset Type so the new file is re-detected.
    delete trees.input;
    delete files.plugin_input;
    const pz = document.querySelector('[data-file="plugin_input"]');
    if(pz) pz.innerHTML = fileOriginal.plugin_input;
    const tz = document.querySelector('[data-tree="input"]');
    if(tz) tz.innerHTML = treeOriginal.input;
    clearInputHex();
    setBatch(false);
    setType("auto");
    const hiveName = file.name.toUpperCase();
    if(hiveName === "SYSTEM" || hiveName === "SECURITY" || hiveName === "SAM"){
      // A registry hive belongs to the hives plugin's one combined drop. Move it
      // there and prompt for the full set.
      const plugin = document.querySelector('[data-field="plugin"]');
      if(plugin){ plugin.value = "windows_hives"; fields.plugin = "windows_hives"; }
      files.plugin_input = files.input; delete files.input;
      const iz = document.querySelector('[data-file="input"]');
      if(iz) iz.innerHTML = fileOriginal.input;
      const pz = document.querySelector('[data-file="plugin_input"]');
      if(pz) pz.innerHTML = `<b>${esc(hiveName)}</b> loaded — drop SYSTEM, SECURITY `
        + `and optional SAM together here <span class="clear" data-clear="plugin_input">clear</span>`;
      wireClears();
      updateConditionalUI();
      setInputTab("plugin");
      log(["[i] hive detected. Drop SYSTEM, SECURITY and optionally SAM together in the plugin box, then Run plugin."]);
      return;
    }
    doRun("/inspect");
  } else if(field === "plugin_input"){
    delete files.input; delete trees.input;
    const core = document.querySelector('[data-file="input"]');
    if(core) core.innerHTML = fileOriginal.input;
    const tree = document.querySelector('[data-tree="input"]');
    if(tree) tree.innerHTML = treeOriginal.input;
    clearInputHex(); setBatch(false); setType("auto"); wireClears();
    log(["[i] plugin input ready; choose a plugin and click Run plugin"]);
  }
}
// Remember drop-zone labels so "clear" can restore plugin-friendly names.
const fileOriginal = {};
document.querySelectorAll("[data-file]").forEach(el => {
  fileOriginal[el.dataset.file] = el.innerHTML;
});
const treeOriginal = {};
document.querySelectorAll("[data-tree]").forEach(el => { treeOriginal[el.dataset.tree] = el.innerHTML; });

// Recursively read a dropped directory entry into {relpath, b64} records.
function readEntry(entry, path, out, state){
  return new Promise(resolve => {
    if(entry.isFile){
      entry.file(f => {
        if(state.files >= 4096){ state.error = "directory contains more than 4096 files"; resolve(); return; }
        if(f.size > MAX_FILE_BYTES){ state.error = `${f.name} exceeds the 64 MiB file limit`; resolve(); return; }
        if(state.total + f.size > MAX_TOTAL_BYTES){ state.error = "directory exceeds the 64 MiB decoded upload limit"; resolve(); return; }
        state.files += 1; state.total += f.size;
        const r = new FileReader();
        r.onload = () => { out.push({ relpath: path, b64: (r.result.split(",")[1] || "") }); resolve(); };
        r.onerror = () => resolve();
        r.readAsDataURL(f);
      }, () => resolve());
    } else if(entry.isDirectory){
      const reader = entry.createReader();
      const step = () => reader.readEntries(async ents => {
        if(!ents.length){ resolve(); return; }
        for(const e of ents){
          if(state.error) break;
          await readEntry(e, path + "/" + e.name, out, state);
        }
        step();
      }, () => resolve());
      step();
    } else { resolve(); }
  });
}

function setBatch(on){
  fields.batch = Boolean(on);
}
function setType(v){
  const s = document.querySelector('[data-field="type"]');
  if(s){ s.value = v; fields.type = v; }
  updateConditionalUI();
}
function clearInputHex(){
  const ih = document.querySelector('textarea[data-field="input"]');
  if(ih){ ih.value = ""; fields.input = ""; }
}
function setTree(field, entries){
  trees[field] = entries;
  // A folder of artifacts means multiple artifacts -> batch mode.
  if(field === "input"){
    delete files.input; delete files.plugin_input; clearInputHex(); setBatch(true);
    const pz = document.querySelector('[data-file="plugin_input"]');
    if(pz) pz.innerHTML = fileOriginal.plugin_input;
    // Batch needs a key too: decrypt uses the masterkey material, and Masterkey
    // -> Hashcat needs the SID. Move to Unlock key so the next step is visible.
    setInputTab("unlock");
    log(["[i] batch: add masterkey material and Decrypt, or enter the SID and click Masterkey -> Hashcat to export every master key's hash"]);
  }
  const el = document.querySelector(`[data-tree="${field}"]`);
  el.innerHTML = `<small class="hint"><b>${field}</b>: ${entries.length} files ` +
                 `<span class="clear" data-clear-tree="${field}">clear</span></small>`;
  const clr = el.querySelector('[data-clear-tree]');
  if(clr) clr.onclick = ev => { ev.stopPropagation(); delete trees[field];
    el.innerHTML = treeOriginal[field]; if(field === "input") setBatch(false);
    updateConditionalUI(); };
  updateConditionalUI();
}

async function acceptTree(field, fileList){
  const total = fileList.reduce((sum, file) => sum + file.size, 0);
  if(fileList.length > 4096){ log(["error: directory contains more than 4096 files"]); return; }
  if(fileList.some(file => file.size > MAX_FILE_BYTES)){ log(["error: a directory file exceeds the 64 MiB limit"]); return; }
  if(total > MAX_TOTAL_BYTES){ log(["error: directory exceeds the 64 MiB decoded upload limit"]); return; }
  const entries = [];
  for(const f of fileList){ entries.push({ relpath: f.webkitRelativePath || f.name, b64: await b64(f) }); }
  setTree(field, entries);
}
function resetPanes(){
  document.getElementById("pane-structure").innerHTML =
    '<p class="empty">Drop or inspect an artifact to see its parsed structure.</p>';
  document.getElementById("pane-decrypted").innerHTML =
    '<p class="empty">Decrypted results appear here after Decrypt.</p>';
}
function wireClears(){
  document.querySelectorAll("[data-clear]").forEach(c => {
    c.onclick = ev => { ev.stopPropagation();
      const f = c.dataset.clear; delete files[f]; delete trees[f];
      const el = document.querySelector(`[data-file="${f}"]`);
      el.innerHTML = fileOriginal[f] || `Drop <b>${f}</b><span class="clear" data-clear="${f}">clear</span>`;
      if(f === "input"){
        // Clearing the artifact resets Type, the pasted hex, and the panes.
        clearInputHex(); setType("auto"); resetPanes();
      }
      updateConditionalUI();
      wireClears(); };
  });
}
wireClears();

document.querySelectorAll("[data-file]").forEach(el => {
  const field = el.dataset.file;
  el.addEventListener("click", () => { pickerTarget = field; filePicker.click(); });
  el.addEventListener("dragover", e => { e.preventDefault(); el.classList.add("over"); });
  el.addEventListener("dragleave", () => el.classList.remove("over"));
  el.addEventListener("drop", async e => {
    e.preventDefault(); el.classList.remove("over");
    if(field === "input"){
      // Dropping a folder or several files here means multiple artifacts (batch).
      const roots = [];
      const items = e.dataTransfer.items;
      if(items && items.length && items[0].webkitGetAsEntry){
        for(const it of items){ const en = it.webkitGetAsEntry(); if(en) roots.push(en); }
      }
      const dirs = roots.filter(r => r && r.isDirectory);
      if(dirs.length){
        const entries = [], state = { files:0, total:0, error:null };
        for(const d of dirs){ await readEntry(d, d.name, entries, state); if(state.error) break; }
        if(state.error){ log(["error: " + state.error]); return; }
        if(entries.length){ setTree("input", entries); return; }
      }
      const flist = [...e.dataTransfer.files];
      if(flist.length > 1){
        await acceptTree("input", flist); return;
      }
      if(flist[0]){ await acceptFile("input", flist[0]); }
      return;
    }
    if(field === "certificate"){
      // The Certificate/PFX plugin can take a whole certs folder and match by key.
      const roots = [];
      const items = e.dataTransfer.items;
      if(items && items.length && items[0].webkitGetAsEntry){
        for(const it of items){ const en = it.webkitGetAsEntry(); if(en) roots.push(en); }
      }
      const dirs = roots.filter(r => r && r.isDirectory);
      if(dirs.length){
        const entries = [], state = { files:0, total:0, error:null };
        for(const d of dirs){ await readEntry(d, d.name, entries, state); if(state.error) break; }
        if(state.error){ log(["error: " + state.error]); return; }
        if(entries.length){ setCertTree(entries); return; }
      }
      const flist = [...e.dataTransfer.files];
      if(flist.length > 1){
        const entries = [];
        for(const f of flist){ entries.push({ relpath: f.webkitRelativePath || f.name, b64: await b64(f) }); }
        setCertTree(entries); return;
      }
      if(flist[0]){ delete trees.certificate; await acceptFile("certificate", flist[0]); }
      return;
    }
    if(field === "plugin_input"){
      // A plugin (certificate_pfx) can take a whole folder of keys, e.g. Crypto\Keys.
      const roots = [];
      const items = e.dataTransfer.items;
      if(items && items.length && items[0].webkitGetAsEntry){
        for(const it of items){ const en = it.webkitGetAsEntry(); if(en) roots.push(en); }
      }
      const dirs = roots.filter(r => r && r.isDirectory);
      if(dirs.length){
        const entries = [], state = { files:0, total:0, error:null };
        for(const d of dirs){ await readEntry(d, d.name, entries, state); if(state.error) break; }
        if(state.error){ log(["error: " + state.error]); return; }
        if(entries.length){ setPluginInputTree(entries); return; }
      }
      const flist = [...e.dataTransfer.files];
      if(flist.length > 1){
        const entries = [];
        for(const f of flist){ entries.push({ relpath: f.webkitRelativePath || f.name, b64: await b64(f) }); }
        setPluginInputTree(entries); return;
      }
      if(flist[0]){ delete trees.plugin_input; await acceptFile("plugin_input", flist[0]); }
      return;
    }
    if(e.dataTransfer.files[0]){ await acceptFile(field, e.dataTransfer.files[0]); }
  });
});
function setCertTree(entries){
  delete files.certificate;
  trees.certificate = entries;
  const el = document.querySelector('[data-file="certificate"]');
  if(el) el.innerHTML = `<b>certificate folder</b>: ${entries.length} file(s) `
    + `<span class="clear" data-clear="certificate">clear</span>`;
  wireClears();
  updateConditionalUI();
}
function setPluginInputTree(entries){
  delete files.plugin_input; delete files.input; delete trees.input;
  trees.plugin_input = entries;
  const el = document.querySelector('[data-file="plugin_input"]');
  const pluginControl = document.querySelector('select[data-field="plugin"]');
  const selectedPlugin = pluginControl && pluginControl.selectedOptions[0];
  const inputLabel = selectedPlugin && selectedPlugin.dataset.inputLabel
    ? selectedPlugin.dataset.inputLabel : "plugin input folder";
  if(el) el.innerHTML = `<b>${esc(inputLabel)}</b>: ${entries.length} file(s) `
    + `<span class="clear" data-clear="plugin_input">clear</span>`;
  clearInputHex(); setBatch(false); wireClears(); updateConditionalUI();
  log([`[i] ${inputLabel} ready (${entries.length} file(s)); complete any plugin-specific fields, then Run plugin`]);
}
document.querySelectorAll("[data-tree]").forEach(el => {
  const field = el.dataset.tree;
  el.addEventListener("click", ev => { if(ev.target.dataset.clearTree) return; pickerTarget = field; dirPicker.click(); });
  el.addEventListener("dragover", e => { e.preventDefault(); el.classList.add("over"); });
  el.addEventListener("dragleave", () => el.classList.remove("over"));
  el.addEventListener("drop", async e => {
    e.preventDefault(); el.classList.remove("over");
    // Grab directory entries synchronously (the item list is invalidated on await).
    const roots = [];
    const items = e.dataTransfer.items;
    if(items && items.length && items[0].webkitGetAsEntry){
      for(const it of items){ const en = it.webkitGetAsEntry(); if(en) roots.push(en); }
    }
    if(roots.length){
      const entries = [], state = { files:0, total:0, error:null };
      for(const root of roots){ await readEntry(root, root.name, entries, state); if(state.error) break; }
      if(state.error){ log(["error: " + state.error]); return; }
      if(entries.length){ setTree(field, entries); return; }
    }
    const flist = [...e.dataTransfer.files];  // fallback: files without directory info
    if(flist.length){ await acceptTree(field, flist); }
  });
});

const esc = s => (s == null ? "" : String(s)).replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function setTab(name){
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".pane").forEach(p => p.hidden = (p.id !== "pane-" + name));
}
document.querySelectorAll(".tab").forEach(t => t.onclick = () => setTab(t.dataset.tab));

function setInputTab(name){
  document.querySelectorAll(".input-tab").forEach(t =>
    t.classList.toggle("active", t.dataset.inputTab === name));
  document.querySelectorAll(".input-pane").forEach(p =>
    p.hidden = (p.id !== "input-" + name));
  document.querySelectorAll(".core-action").forEach(button =>
    button.hidden = (name === "plugin"));
  updateHashcatVisibility();
}
document.querySelectorAll(".input-tab").forEach(t =>
  t.onclick = () => setInputTab(t.dataset.inputTab));

function renderStructure(list){
  const pane = document.getElementById("pane-structure");
  if(!list || !list.length){
    pane.innerHTML = '<p class="empty">No classic DPAPI blob or master-key structure recognized.</p>';
    return;
  }
  let html = '<table class="struct">';
  for(const blob of list){
    const head = blob.label ? esc(blob.label) : "DPAPI blob";
    html += `<tr class="blobhdr"><td colspan="2">${head} &mdash; offset ${blob.offset} `
         +  `(0x${blob.offset.toString(16)}), ${blob.size} bytes</td></tr>`;
    for(const sec of blob.sections){
      html += `<tr class="sect"><td colspan="2">${esc(sec.title)}</td></tr>`;
      for(const f of sec.fields){
        let v = esc(f.value);
        if(f.hex){
          const short = f.hex.length > 64 ? f.hex.slice(0, 64) + "…" : f.hex;
          v += ` &mdash; <span title="${esc(f.hex)}">${short}</span>`;
        }
        const copyVal = f.hex ? f.hex : f.value;
        v += ` <span class="cp" data-copy="${esc(copyVal)}" title="Copy">copy</span>`;
        html += `<tr><td class="k">${esc(f.name)}</td><td class="v">${v}</td></tr>`;
      }
    }
  }
  pane.innerHTML = html + "</table>";
}

function renderDecrypted(results){
  const pane = document.getElementById("pane-decrypted");
  if(!results || !results.length){
    pane.innerHTML = '<p class="empty">No decrypted output.</p>';
    return;
  }
  pane.innerHTML = "";
  if(results.length > 1){
    const all = document.createElement("button");
    all.className = "sec"; all.textContent = "Download all"; all.style.marginBottom = "8px";
    all.onclick = () => {
      for(const r of results){
        const a = document.createElement("a");
        a.href = `/download/${r.download}`; a.download = r.name;
        document.body.appendChild(a); a.click(); a.remove();
      }
    };
    pane.appendChild(all);
  }
  for(const r of results){
    const div = document.createElement("div");
    div.className = "result";
    div.innerHTML = `<h4>${esc(r.label)} (${esc(r.extension)}, ${r.size} bytes)</h4>` +
      `<pre>${esc(r.preview)}</pre>`;
    const actions = document.createElement("div");
    actions.className = "result-actions";
    const copyBtn = document.createElement("button");
    copyBtn.className = "sec"; copyBtn.textContent = "Copy"; copyBtn.dataset.copy = r.preview;
    actions.appendChild(copyBtn);
    const dl = document.createElement("a");
    dl.href = `/download/${r.download}`; dl.download = r.name;
    dl.innerHTML = '<button class="sec">Download</button>';
    actions.appendChild(dl);
    const chained = chainedActionFor(r);
    if(chained) actions.appendChild(chained);
    div.appendChild(actions);
    pane.appendChild(div);
  }
}

// A result can feed the next stage. Offer a one-click hand-off when it does.
function chainedActionFor(r){
  if(lastRunPlugin === "windows_hives"
      && (/\.dpapi_system$/i.test(r.name || "") || /DPAPI_SYSTEM/i.test(r.label || ""))){
    const button = document.createElement("button");
    button.className = "sec chained";
    button.textContent = "Use as DPAPI_SYSTEM →";
    button.title = "Load this value into 2. Unlock key and return to the artifact flow";
    button.onclick = () => useAsDpapiSystem(r);
    return button;
  }
  if(!lastRunPlugin && (lastDetected === "capi" || lastDetected === "cng") && r.extension === ".pem"){
    const button = document.createElement("button");
    button.className = "sec chained";
    button.textContent = "Build PFX from this key →";
    button.title = "Open Certificate / PFX with this key loaded; then add the matching certificate";
    button.onclick = () => sendToPfx();
    return button;
  }
  return null;
}

// Chain: SAM/hives DPAPI_SYSTEM output -> Unlock key, back on the core flow.
function useAsDpapiSystem(r){
  const hex = String(r.preview || "").replace(/[^0-9a-fA-F]/g, "");
  if(!hex){ log(["[!] could not read the DPAPI_SYSTEM value; download it and paste it manually"]); return; }
  fields.dpapi_system = hex;
  document.querySelectorAll('input[data-field="dpapi_system"]').forEach(el => el.value = hex);
  const pluginSel = document.querySelector('select[data-field="plugin"]');
  if(pluginSel){ pluginSel.value = ""; fields.plugin = ""; }
  // Clear the hive input so the user drops the SYSTEM-protected artifact next.
  delete files.input; delete files.plugin_input; delete trees.input;
  const zi = document.querySelector('[data-file="input"]'); if(zi) zi.innerHTML = fileOriginal.input;
  const zp = document.querySelector('[data-file="plugin_input"]'); if(zp) zp.innerHTML = fileOriginal.plugin_input;
  const zt = document.querySelector('[data-tree="input"]'); if(zt) zt.innerHTML = treeOriginal.input;
  clearInputHex(); setBatch(false); wireClears();
  setType("auto"); setInputTab("artifact"); updateConditionalUI();
  log(["[i] DPAPI_SYSTEM loaded into 2. Unlock key. Now drop the SYSTEM-protected artifact in 1. Artifact and add its SYSTEM masterkey, then Decrypt."]);
}

// Chain: decrypted CAPI/CNG key -> Certificate / PFX plugin, key reused.
function sendToPfx(){
  const pluginSel = document.querySelector('select[data-field="plugin"]');
  if(pluginSel){ pluginSel.value = "certificate_pfx"; fields.plugin = "certificate_pfx"; }
  if(files.input){
    files.plugin_input = files.input;
    const zp = document.querySelector('[data-file="plugin_input"]');
    if(zp && zp.querySelector("b")){
      zp.innerHTML = `<b>private key or encrypted CAPI/CNG key</b>: ${esc(files.input.name || "encrypted key")}`
        + ` <span class="clear" data-clear="plugin_input">clear</span>`;
    }
    wireClears();
  }
  setType("auto"); setInputTab("plugin"); updateConditionalUI();
  log(["[i] Certificate / PFX ready. Add the matching certificate (PEM, DER, or serialized Windows) and a new PFX password, then Run plugin. The masterkey material in 2. Unlock key is reused to decrypt the key; the plugin logs the certificate thumbprint and SPKI fingerprints and builds a PFX only on an exact public-key match."]);
}

async function doRun(endpoint, extra){
  if(running){ log(["[i] another operation is already running"]); return; }
  running = true;
  document.querySelectorAll(".actions button, #run-plugin").forEach(button => button.disabled = true);
  const label = extra && extra.hashcat ? "masterkey -> hashcat" :
                (fields.plugin === "cachedata" && fields.cachedata_hashcat
                  ? "CacheData -> hashcat"
                  : (endpoint === "/inspect" ? "inspect" : "decrypt"));
  log([`> ${label} ...`]);
  const payloadFields = Object.assign({}, fields, extra || {});
  let resp;
  try {
    resp = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-DPAPI-Token": TOKEN },
      body: JSON.stringify({ fields: payloadFields, files, trees }),
    });
  } catch(err){
    log(["error: " + err]);
    running = false;
    document.querySelectorAll(".actions button, #run-plugin").forEach(button => button.disabled = false);
    updateConditionalUI();
    return;
  }
  let data;
  try { data = await resp.json(); }
  catch(_){ data = { log: [`error: server returned HTTP ${resp.status}`] }; }
  log(data.log || []);
  // Remember what the run reported so the Unlock-key fields can guide the user.
  // The core log already names each required master key, so we do not re-log it.
  lastRequired = Array.isArray(data.required) ? data.required : [];
  // Reflect a detected type (e.g. an encrypted masterkey) in the Type dropdown.
  if(data.detected_type){
    const sel = document.querySelector('[data-field="type"]');
    if(sel && sel.value !== data.detected_type){ sel.value = data.detected_type; fields.type = data.detected_type; }
  }
  // run_single resolves the real type only in its log ("[+] input type: cng"),
  // so parse it as a fallback for chained actions (e.g. CAPI/CNG -> PFX).
  const typeLine = (data.log || []).find(line => /^\[\+\] input type:/.test(line));
  const loggedType = typeLine ? typeLine.replace(/^\[\+\] input type:\s*/, "").trim() : "";
  lastDetected = data.detected_type || loggedType || fields.type || "";
  lastRunPlugin = payloadFields.plugin || "";
  updateConditionalUI();
  if("structure" in data) renderStructure(data.structure);
  if(endpoint === "/inspect"){
    setTab("structure");
    if((data.required && data.required.length) || data.detected_type === "masterkey"){
      setInputTab("unlock");
    }
  } else {
    renderDecrypted(data.results);
    setTab(data.results && data.results.length ? "decrypted" : "structure");
  }
  running = false;
  document.querySelectorAll(".actions button, #run-plugin").forEach(button => button.disabled = false);
  updateConditionalUI();
}

document.getElementById("inspect").onclick = () => doRun("/inspect");
document.getElementById("decrypt").onclick = () => doRun("/decrypt");
document.getElementById("tohash").onclick = () => doRun("/decrypt", { hashcat: true });
document.getElementById("run-plugin").onclick = () => doRun("/decrypt");
document.getElementById("reset").onclick = async () => {
  try {
    await fetch("/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-DPAPI-Token": TOKEN },
      body: "{}",
    });
  } catch(_) {}
  for(const store of [files, trees, fields]){ for(const key of Object.keys(store)) delete store[key]; }
  document.querySelectorAll("input, textarea").forEach(input => {
    if(input.type === "checkbox") input.checked = false; else input.value = "";
  });
  document.querySelectorAll("select").forEach(select => select.selectedIndex = 0);
  document.getElementById("log").textContent = "";
  resetPanes();
  location.reload();
};
// Clear only the activity log; leave fields, files, results, and downloads intact.
document.getElementById("clear-log").onclick = () => {
  document.getElementById("log").textContent = "";
};

// Theme: auto (follow the OS) / light / dark, remembered per browser.
(function(){
  const buttons = [...document.querySelectorAll("[data-theme-choice]")];
  let saved = "auto";
  try { saved = localStorage.getItem("dpapi-theme") || "auto"; } catch(_) {}
  const apply = value => {
    if(value === "auto") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = value;
    buttons.forEach(button => button.classList.toggle("active", button.dataset.themeChoice === value));
  };
  apply(saved);
  buttons.forEach(button => button.addEventListener("click", () => {
    apply(button.dataset.themeChoice);
    try { localStorage.setItem("dpapi-theme", button.dataset.themeChoice); } catch(_) {}
  }));
})();

// Enter submits: in a single-line field it runs the primary action (Decrypt, or
// Run plugin on the plugin tab); in the hex textarea use Ctrl/Cmd+Enter so plain
// Enter can still add a newline.
document.addEventListener("keydown", e => {
  if(e.key !== "Enter" || running) return;
  const el = e.target;
  const tag = el.tagName;
  const singleLine = tag === "INPUT" && el.type !== "checkbox";
  const textareaSubmit = tag === "TEXTAREA" && (e.ctrlKey || e.metaKey);
  if(!singleLine && !textareaSubmit) return;
  e.preventDefault();
  doRun("/decrypt");
});

// Copy-to-clipboard for any element carrying data-copy (struct values, results).
document.addEventListener("click", e => {
  const el = e.target.closest("[data-copy]");
  if(!el) return;
  const value = el.dataset.copy;
  const flash = () => { const old = el.textContent; el.textContent = "copied"; setTimeout(() => el.textContent = old, 900); };
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(value).then(flash).catch(() => {});
  } else {
    const ta = document.createElement("textarea"); ta.value = value; document.body.appendChild(ta);
    ta.select(); try { document.execCommand("copy"); flash(); } catch(_) {} ta.remove();
  }
});

// Draggable divider to resize the left column while preserving a usable pane
// on both sides. Its minimum is wide enough to keep all workflow tabs on one line.
(function(){
  const gutter = document.getElementById("gutter");
  const left = document.getElementById("left");
  const main = document.querySelector("main");
  let dragging = false;
  const inputTabs = document.querySelector(".input-tabs");
  const minimumLeftWidth = () => {
    const buttons = [...inputTabs.querySelectorAll(".input-tab")];
    const gap = parseFloat(getComputedStyle(inputTabs).columnGap) || 0;
    const tabWidth = buttons.reduce((total, button) => total + button.offsetWidth, 0);
    return Math.max(410, Math.ceil(tabWidth + gap * Math.max(0, buttons.length - 1)));
  };
  const widthBounds = () => {
    const rect = main.getBoundingClientRect();
    const minLeft = minimumLeftWidth();
    const minRight = 300;
    const maxLeft = Math.max(minLeft, rect.width - gutter.offsetWidth - minRight);
    return { rect, minLeft, maxLeft };
  };
  const clampWidth = width => {
    const { minLeft, maxLeft } = widthBounds();
    return Math.max(minLeft, Math.min(width, maxLeft));
  };
  const widthFromPointer = clientX => {
    const { rect } = widthBounds();
    return clampWidth(clientX - rect.left);
  };
  gutter.addEventListener("pointerdown", e => {
    if(getComputedStyle(gutter).display === "none") return;
    dragging = true;
    gutter.setPointerCapture(e.pointerId);
    e.preventDefault();
    document.body.style.userSelect = "none";
  });
  gutter.addEventListener("pointermove", e => {
    if(!dragging) return;
    if(e.pointerType === "mouse" && e.buttons === 0){ stop(); return; }
    left.style.flexBasis = widthFromPointer(e.clientX) + "px";
  });
  const stop = () => {
    if(!dragging) return;
    dragging = false;
    document.body.style.userSelect = "";
  };
  gutter.addEventListener("pointerup", stop);
  gutter.addEventListener("pointercancel", stop);
  gutter.addEventListener("lostpointercapture", stop);
  window.addEventListener("blur", stop);
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
