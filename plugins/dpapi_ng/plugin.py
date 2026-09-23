"""Strictly offline adapter for jborean93/dpapi-ng.

The public dpapi-ng convenience API can fall back to DNS/RPC on a cache miss.
This adapter intentionally uses the parsed blob and preloaded cache directly,
checks for a local key first, and never calls that network-capable API.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
import uuid


PLUGIN_ID = "dpapi_ng"
MAX_ROOT_KEY_JSON = 1024 * 1024
MAX_ROOT_KEYS = 64
MAX_PARAMETER_BYTES = 64 * 1024
SUPPORTED_KDF_ALGORITHMS = frozenset(("SP800_108_CTR_HMAC",))
SUPPORTED_SECRET_ALGORITHMS = frozenset(("DH", "ECDH_P256", "ECDH_P384", "ECDH_P521"))


def _field(record: dict, *names, default=None):
    folded = {str(key).casefold(): value for key, value in record.items()}
    for name in names:
        if name.casefold() in folded:
            return folded[name.casefold()]
    return default


def _b64(record: dict, name: str, *, optional: bool = False) -> bytes | None:
    value = _field(record, name)
    if value in (None, "") and optional:
        return None
    if not isinstance(value, str):
        raise ValueError(f"DPAPI-NG root-key field {name} must be Base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError(f"DPAPI-NG root-key field {name} is invalid Base64") from None
    if len(decoded) > MAX_PARAMETER_BYTES:
        raise ValueError(f"DPAPI-NG root-key field {name} exceeds 64 KiB")
    return decoded


def load_root_key_records(path_value: str) -> list[dict]:
    path = Path(path_value)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read --dpapi-ng-root-key: {exc}") from None
    if len(raw) > MAX_ROOT_KEY_JSON:
        raise ValueError("DPAPI-NG root-key JSON exceeds the 1 MiB limit")
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid DPAPI-NG root-key JSON: {exc}") from None
    records = parsed if isinstance(parsed, list) else [parsed]
    if not records or len(records) > MAX_ROOT_KEYS or not all(
        isinstance(record, dict) for record in records
    ):
        raise ValueError("DPAPI-NG root-key JSON must contain 1 to 64 objects")
    return records


def populate_cache(cache, records: list[dict]) -> None:
    for record in records:
        root_id = _field(record, "RootKeyId", "cn")
        if not isinstance(root_id, str):
            raise ValueError("DPAPI-NG root key is missing RootKeyId/cn")
        try:
            root_id = uuid.UUID(root_id)
        except ValueError:
            raise ValueError(f"invalid DPAPI-NG RootKeyId {root_id!r}") from None
        key = _b64(record, "RootKeyData")
        if not 32 <= len(key) <= 1024:
            raise ValueError("DPAPI-NG RootKeyData has an unsafe or invalid length")
        version = _field(record, "Version", default=1)
        private_length = _field(record, "PrivateKeyLength", default=512)
        public_length = _field(record, "PublicKeyLength", default=2048)
        if not all(type(value) is int for value in (version, private_length, public_length)):
            raise ValueError("DPAPI-NG key version/length fields must be integers")
        if version != 1:
            raise ValueError(f"unsupported DPAPI-NG root-key version {version}")
        if not 1 <= private_length <= 8192 or not 1 <= public_length <= 8192:
            raise ValueError("DPAPI-NG key lengths must be between 1 and 8192 bits")
        kdf_algorithm = _field(record, "KdfAlgorithm", default="SP800_108_CTR_HMAC")
        secret_algorithm = _field(record, "SecretAgreementAlgorithm", default="DH")
        if not isinstance(kdf_algorithm, str) or not isinstance(secret_algorithm, str):
            raise ValueError("DPAPI-NG algorithm fields must be text")
        if kdf_algorithm not in SUPPORTED_KDF_ALGORITHMS:
            raise ValueError(f"unsupported DPAPI-NG KDF algorithm {kdf_algorithm!r}")
        if secret_algorithm not in SUPPORTED_SECRET_ALGORITHMS:
            raise ValueError(
                f"unsupported DPAPI-NG secret-agreement algorithm {secret_algorithm!r}"
            )
        cache.load_key(
            key,
            root_id,
            version=version,
            kdf_algorithm=kdf_algorithm,
            kdf_parameters=_b64(record, "KdfParameters", optional=True),
            secret_algorithm=secret_algorithm,
            secret_parameters=_b64(record, "SecretAgreementParameters", optional=True),
            private_key_length=private_length,
            public_key_length=public_length,
        )


def run(data, source_path, was_hex, args, core, emit):
    if not args.dpapi_ng_root_key:
        raise ValueError("offline DPAPI-NG requires --dpapi-ng-root-key ROOT_KEY.json")
    try:
        from dpapi_ng import KeyCache
        from dpapi_ng._blob import DPAPINGBlob
        from dpapi_ng._client import _decrypt_blob
    except ImportError:
        raise ValueError(
            "install the optional dpapi-ng package to use the offline DPAPI-NG plugin"
        ) from None
    cache = KeyCache()
    populate_cache(cache, load_root_key_records(args.dpapi_ng_root_key))
    try:
        blob = DPAPINGBlob.unpack(data)
        target_sd = blob.protection_descriptor.get_target_sd()
        key = cache._get_key(
            target_sd,
            blob.key_identifier.root_key_identifier,
            blob.key_identifier.l0,
            blob.key_identifier.l1,
            blob.key_identifier.l2,
        )
    except (ValueError, NotImplementedError) as exc:
        raise ValueError(f"invalid or unsupported DPAPI-NG blob: {exc}") from None
    if key is None:
        raise ValueError(
            "no supplied offline KDS root key matches this DPAPI-NG blob; "
            "network fallback is disabled"
        )
    try:
        cleartext = _decrypt_blob(blob, key)
    except (ValueError, NotImplementedError) as exc:
        raise ValueError(f"DPAPI-NG decryption failed: {exc}") from None
    emit("[+] DPAPI-NG decrypted entirely from the supplied offline KDS root key")
    prepared, extension = core.prepare_output(
        cleartext, "blob", was_hex, args.output_format
    )
    return [core.OutputItem(prepared, extension, "DPAPI-NG", source_path)]
