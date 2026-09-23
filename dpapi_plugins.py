"""Small, local-only plugin loader for application-specific DPAPI layers."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
import importlib.util
import json
from pathlib import Path
import re
from types import ModuleType


PLUGIN_ROOT = Path(__file__).with_name("plugins")
PLUGIN_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
MAX_MANIFEST_BYTES = 64 * 1024
WEB_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
WEB_FIELD_KINDS = frozenset(("text", "password", "file", "checkbox"))


@dataclass(frozen=True)
class PluginWebField:
    name: str
    kind: str
    label: str
    placeholder: str
    help: str
    optional: bool = False


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    name: str
    description: str
    directory: Path
    file_patterns: tuple[str, ...]
    web_help: str
    web_input_label: str
    web_workflow_help: str
    web_fields: tuple[PluginWebField, ...]


def discover_plugins() -> dict[str, PluginManifest]:
    root = PLUGIN_ROOT.resolve()
    manifests: dict[str, PluginManifest] = {}
    if not root.is_dir():
        return manifests
    for directory in sorted(path for path in root.iterdir() if path.is_dir()):
        manifest_path = directory / "plugin.json"
        module_path = directory / "plugin.py"
        if not manifest_path.is_file() or not module_path.is_file():
            continue
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError(f"plugin manifest is too large: {manifest_path}")
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid plugin manifest {manifest_path}: {exc}") from None
        if not isinstance(raw, dict):
            raise ValueError(f"plugin manifest must be an object: {manifest_path}")
        plugin_id = raw.get("id")
        name = raw.get("name")
        description = raw.get("description", "")
        patterns = raw.get("file_patterns", [])
        web = raw.get("web", {})
        if (
            not isinstance(plugin_id, str)
            or not PLUGIN_ID.fullmatch(plugin_id)
            or plugin_id != directory.name
        ):
            raise ValueError(f"plugin id must match its safe directory name: {directory}")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"plugin {plugin_id} has no display name")
        if not isinstance(description, str):
            raise ValueError(f"plugin {plugin_id} description must be text")
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) and pattern and "/" not in pattern and "\\" not in pattern
            for pattern in patterns
        ):
            raise ValueError(f"plugin {plugin_id} has invalid file patterns")
        if not isinstance(web, dict):
            raise ValueError(f"plugin {plugin_id} web configuration must be an object")
        web_help = web.get("help", description)
        web_input_label = web.get("input_label", "plugin artifact")
        web_workflow_help = web.get(
            "workflow_help",
            "Tab 1 is not used for plugins. Add the main input here.",
        )
        raw_web_fields = web.get("fields", [])
        if not isinstance(web_help, str):
            raise ValueError(f"plugin {plugin_id} web help must be text")
        if not isinstance(web_input_label, str) or not web_input_label.strip():
            raise ValueError(f"plugin {plugin_id} web input label must be text")
        if not isinstance(web_workflow_help, str) or not web_workflow_help.strip():
            raise ValueError(f"plugin {plugin_id} web workflow help must be text")
        if not isinstance(raw_web_fields, list) or len(raw_web_fields) > 16:
            raise ValueError(f"plugin {plugin_id} has invalid web fields")
        web_fields = []
        seen_web_fields = set()
        for field in raw_web_fields:
            if not isinstance(field, dict):
                raise ValueError(f"plugin {plugin_id} web field must be an object")
            field_name = field.get("name")
            kind = field.get("kind")
            label = field.get("label")
            placeholder = field.get("placeholder", "")
            field_help = field.get("help", "")
            optional = field.get("optional", False)
            if (
                not isinstance(field_name, str)
                or not WEB_FIELD.fullmatch(field_name)
                or field_name in seen_web_fields
                or kind not in WEB_FIELD_KINDS
                or not isinstance(label, str)
                or not label.strip()
                or not isinstance(placeholder, str)
                or not isinstance(field_help, str)
                or not isinstance(optional, bool)
            ):
                raise ValueError(f"plugin {plugin_id} has an invalid web field")
            seen_web_fields.add(field_name)
            web_fields.append(PluginWebField(
                field_name,
                kind,
                label.strip(),
                placeholder,
                field_help,
                optional,
            ))
        if plugin_id in manifests:
            raise ValueError(f"duplicate plugin id: {plugin_id}")
        manifests[plugin_id] = PluginManifest(
            plugin_id,
            name.strip(),
            description.strip(),
            directory.resolve(),
            tuple(patterns),
            web_help.strip(),
            web_input_label.strip(),
            web_workflow_help.strip(),
            tuple(web_fields),
        )
    return manifests


def detect_plugin(filename: str) -> str | None:
    matches = [
        manifest.plugin_id
        for manifest in discover_plugins().values()
        if any(fnmatch(filename.casefold(), pattern.casefold()) for pattern in manifest.file_patterns)
    ]
    return matches[0] if len(matches) == 1 else None


def load_plugin(plugin_id: str) -> tuple[PluginManifest, ModuleType]:
    manifest = discover_plugins().get(plugin_id)
    if manifest is None:
        raise ValueError(f"unknown or unavailable plugin {plugin_id!r}")
    root = PLUGIN_ROOT.resolve()
    module_path = (manifest.directory / "plugin.py").resolve()
    try:
        module_path.relative_to(root)
    except ValueError:
        raise ValueError(f"plugin {plugin_id} escapes the plugin directory") from None
    spec = importlib.util.spec_from_file_location(
        f"dpapi_toolkit_plugin_{plugin_id}", module_path
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load plugin {plugin_id}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if getattr(module, "PLUGIN_ID", None) != plugin_id or not callable(
        getattr(module, "run", None)
    ):
        raise ValueError(f"plugin {plugin_id} does not implement the required contract")
    return manifest, module


def run_plugin(plugin_id: str, data, source_path, was_hex, args, core, emit):
    manifest, module = load_plugin(plugin_id)
    emit(f"[+] plugin: {manifest.name} ({manifest.plugin_id})")
    return module.run(data, source_path, was_hex, args, core, emit)
