#!/usr/bin/env python3
"""Offline DPAPI decryption for blobs, CAPI/CNG keys, and SecureStrings.

Examples:

    # Inspect an input and print its required master-key GUID.
    python3 dpapi_decrypt.py secret.bin

    # Decrypt with an encrypted master-key file (password is prompted).
    python3 dpapi_decrypt.py secret.bin --masterkey GUID_FILE --sid S-1-5-21-...

    # Supply an already-decrypted 64-byte master key (or 20-byte SHA1 mapping).
    python3 dpapi_decrypt.py secret.bin --real-masterkey HEX_OR_BASE64

    # Decode PowerShell ConvertFrom-SecureString output to UTF-8 text.
    python3 dpapi_decrypt.py securestring.txt --type powershell --masterkey ...

    # Extract a serialized Windows certificate to a PEM-encoded .crt file.
    python3 dpapi_decrypt.py THUMBPRINT_FILE --type cert

    # Decrypt and export a CNG RSA private key to PEM.
    python3 dpapi_decrypt.py CNG_KEY_FILE --type cng --masterkey GUID_FILE ...

    # Decrypt a Local/Roaming Windows Credential file to structured JSON.
    python3 dpapi_decrypt.py CREDENTIAL_FILE --masterkey GUID_FILE ...

    # Decrypt a Vault record using its Policy.vpol and DPAPI master key.
    python3 dpapi_decrypt.py RECORD.vcrd --vault-policy Policy.vpol \
        --masterkey GUID_FILE ...
"""

import argparse
import base64
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
import string
import struct
import sys
import uuid
import xml.etree.ElementTree as ET

import dpapi_plugins


CALG_3DES = 0x6603
CALG_AES_256 = 0x6610
CALG_SHA1 = 0x8004
CALG_HMAC = 0x8009
CALG_SHA_512 = 0x800E

DPAPI_PROVIDER = uuid.UUID("df9d8cd0-1501-11d1-8c7a-00c04fc297eb")
DPAPI_HEADER = b"\x01\x00\x00\x00" + DPAPI_PROVIDER.bytes_le
CNG_PRIVATE_KEY_ENTROPY = b"xT5rZW5qVVbrvpuA\x00"
NGC_PRIVATE_PROPERTIES_ENTROPY = b"6jnkd5J3ZdQDtrsu\x00"
CERT_CERT_PROP_ID = 32
MAX_KDF_ROUNDS = 1_000_000
MAX_XML_BYTES = 16 * 1024 * 1024
MAX_SCCM_POLICY_SECRETS = 10_000
MAX_SCCM_SECRET_TEXT = 2 * 1024 * 1024

CREDENTIAL_TYPES = {
    1: "generic",
    2: "domain_password",
    3: "domain_certificate",
    4: "domain_visible_password",
    5: "generic_certificate",
    6: "domain_extended",
}
CREDENTIAL_PERSISTENCE = {1: "session", 2: "local_machine", 3: "enterprise"}


@dataclass
class DPAPIBlob:
    masterkey_guid: uuid.UUID
    crypt_algo: int
    salt: bytes
    hash_algo: int
    hmac_value: bytes
    data: bytes
    signature: bytes
    signed_data: bytes


@dataclass
class LocatedBlob:
    offset: int
    size: int
    blob: DPAPIBlob
    entropy: bytes | None = None
    label: str | None = None


@dataclass
class EncryptedMasterKey:
    file_guid: uuid.UUID | None
    version: int
    salt: bytes
    rounds: int
    hash_algo: int
    crypt_algo: int
    data: bytes


@dataclass
class CredHistEntry:
    version: int
    hash_algo: int
    rounds: int
    sid: str
    crypt_algo: int
    sha_hash_length: int
    nt_hash_length: int
    salt: bytes
    encrypted: bytes
    version2: int
    guid: uuid.UUID


class ByteReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise ValueError(f"truncated DPAPI structure while reading {label}")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]

    def length_prefixed(self, label: str) -> bytes:
        return self.take(self.u32(f"{label} length"), label)


def validate_kdf_rounds(rounds: int, label: str = "KDF") -> None:
    if (
        not isinstance(rounds, int)
        or isinstance(rounds, bool)
        or not 1 <= rounds <= MAX_KDF_ROUNDS
    ):
        raise ValueError(
            f"{label} iteration count must be between 1 and {MAX_KDF_ROUNDS:,}, "
            f"found {rounds!r}"
        )


def safe_xml_fromstring(data: bytes, label: str) -> ET.Element:
    if len(data) > MAX_XML_BYTES:
        raise ValueError(f"{label} XML exceeds {MAX_XML_BYTES // 1048576} MiB")
    lowered = data[: min(len(data), 1024 * 1024)].lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ValueError(f"{label} XML declarations and entities are not allowed")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"invalid {label} XML: {exc}") from None


def existing_file(value: str) -> Path | None:
    try:
        path = Path(value)
        return path if path.is_file() else None
    except (OSError, ValueError):
        return None


def md4(data: bytes) -> bytes:
    """RFC 1320 MD4, used for the Windows NT password hash."""

    def rol(value, count):
        return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

    def f(x, y, z):
        return (x & y) | (~x & z)

    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def h(x, y, z):
        return x ^ y ^ z

    bit_length = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64)
    data += struct.pack("<Q", bit_length)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for offset in range(0, len(data), 64):
        words = struct.unpack("<16I", data[offset:offset + 64])
        original = a, b, c, d
        for index, shift in enumerate((3, 7, 11, 19) * 4):
            a = rol((a + f(b, c, d) + words[index]) & 0xFFFFFFFF, shift)
            a, b, c, d = d, a, b, c
        for index, shift in enumerate((3, 5, 9, 13) * 4):
            word = (index % 4) * 4 + index // 4
            a = rol(
                (a + g(b, c, d) + words[word] + 0x5A827999) & 0xFFFFFFFF,
                shift,
            )
            a, b, c, d = d, a, b, c
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for index, shift in enumerate((3, 9, 11, 15) * 4):
            a = rol(
                (a + h(b, c, d) + words[order[index]] + 0x6ED9EBA1)
                & 0xFFFFFFFF,
                shift,
            )
            a, b, c, d = d, a, b, c
        a = (a + original[0]) & 0xFFFFFFFF
        b = (b + original[1]) & 0xFFFFFFFF
        c = (c + original[2]) & 0xFFFFFFFF
        d = (d + original[3]) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def hash_details(algorithm: int, *, masterkey: bool = False):
    if algorithm == CALG_SHA1:
        return "sha1", 20, 64
    if algorithm == CALG_SHA_512:
        return "sha512", 16, 128
    if algorithm == CALG_HMAC:
        return ("sha1", 20, 64) if masterkey else ("sha512", 20, 64)
    raise ValueError(f"unsupported DPAPI hash algorithm 0x{algorithm:08x}")


def cipher_details(algorithm: int):
    if algorithm == CALG_AES_256:
        return 32, 16
    if algorithm == CALG_3DES:
        return 24, 8
    raise ValueError(f"unsupported DPAPI cipher algorithm 0x{algorithm:08x}")


def cbc_decrypt(data: bytes, key: bytes, iv: bytes, algorithm: int) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        if algorithm == CALG_AES_256:
            cipher_algorithm = algorithms.AES(key)
        elif algorithm == CALG_3DES:
            try:
                from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
            except ImportError:  # cryptography < 43
                TripleDES = algorithms.TripleDES
            cipher_algorithm = TripleDES(key)
        else:
            cipher_details(algorithm)
        decryptor = Cipher(cipher_algorithm, modes.CBC(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except ImportError:
        try:
            from Crypto.Cipher import AES, DES3
        except ImportError:
            sys.exit("install cryptography or pycryptodome")
        if algorithm == CALG_AES_256:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
        if algorithm == CALG_3DES:
            return DES3.new(key, DES3.MODE_CBC, iv).decrypt(data)
        cipher_details(algorithm)
        raise AssertionError("unreachable")


def unpad_pkcs7(data: bytes, block_size: int) -> bytes | None:
    if not data or len(data) % block_size:
        return None
    padding = data[-1]
    if not 1 <= padding <= block_size:
        return None
    if data[-padding:] != bytes([padding]) * padding:
        return None
    return data[:-padding]


def parse_dpapi_blob(data: bytes) -> tuple[DPAPIBlob, int]:
    """Parse one DPAPI blob and return it with its consumed size."""
    reader = ByteReader(data)
    if reader.u32("blob version") != 1:
        raise ValueError("not a version-1 DPAPI blob")
    if uuid.UUID(bytes_le=reader.take(16, "provider GUID")) != DPAPI_PROVIDER:
        raise ValueError("not a classic DPAPI blob")
    reader.u32("master-key version")
    masterkey_guid = uuid.UUID(bytes_le=reader.take(16, "master-key GUID"))
    reader.u32("flags")
    reader.length_prefixed("description")
    crypt_algo = reader.u32("cipher algorithm")
    reader.u32("cipher key length")
    salt = reader.length_prefixed("salt")
    reader.length_prefixed("HMAC key")
    hash_algo = reader.u32("hash algorithm")
    reader.u32("hash length")
    hmac_value = reader.length_prefixed("HMAC value")
    encrypted = reader.length_prefixed("ciphertext")
    signature_offset = reader.offset
    signature = reader.length_prefixed("signature")
    return (
        DPAPIBlob(
            masterkey_guid,
            crypt_algo,
            salt,
            hash_algo,
            hmac_value,
            encrypted,
            signature,
            data[20:signature_offset],
        ),
        reader.offset,
    )


def _windows_cert_der(data: bytes) -> bytes:
    """Extract the DER certificate (CERT_CERT_PROP_ID) from a serialized cert."""
    offset = 0
    certificate = None
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated serialized certificate property header")
        property_id, _reserved, length = struct.unpack_from("<III", data, offset)
        offset += 12
        if offset + length > len(data):
            raise ValueError("truncated serialized certificate property value")
        value = data[offset:offset + length]
        offset += length
        if property_id == CERT_CERT_PROP_ID:
            certificate = value

    if certificate is None:
        raise ValueError("serialized certificate has no CERT_CERT_PROP_ID property")
    return certificate


def windows_certificate_to_pem(data: bytes) -> bytes:
    """Normalize a PEM, DER, or serialized Windows certificate to PEM."""
    try:
        from cryptography.hazmat.primitives import serialization
        parsed = load_x509_certificate(data)
        return parsed.public_bytes(serialization.Encoding.PEM)
    except ImportError:
        raise ValueError("install cryptography to convert the certificate") from None
    except ValueError:
        raise ValueError("certificate is not PEM, DER, or a serialized Windows certificate") from None


def load_x509_certificate(data: bytes):
    try:
        from cryptography import x509
    except ImportError:
        raise ValueError("install cryptography to read certificates") from None
    loaders = (x509.load_pem_x509_certificate, x509.load_der_x509_certificate)
    for loader in loaders:
        try:
            return loader(data)
        except ValueError:
            pass
    try:
        return x509.load_der_x509_certificate(_windows_cert_der(data))
    except ValueError:
        raise ValueError("certificate is not PEM, DER, or a serialized Windows certificate") from None


def load_private_key(data: bytes, password: bytes | None = None):
    """Load a PEM or DER private key for certificate/PFX correlation."""
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ValueError("install cryptography to read private keys") from None
    errors = []
    for loader in (
        serialization.load_pem_private_key,
        serialization.load_der_private_key,
    ):
        try:
            return loader(data, password=password)
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
    detail = errors[-1] if errors else "unsupported key"
    raise ValueError(f"private key is not supported PEM or DER: {detail}")


def build_pkcs12_bundle(
    private_key_pem: bytes,
    certificate_data: bytes,
    password: bytes,
    friendly_name: bytes = b"dpapi-recovered-key",
    private_key_password: bytes | None = None,
) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError:
        raise ValueError("install cryptography to construct a PFX/PKCS#12 bundle") from None
    private_key = load_private_key(private_key_pem, private_key_password)
    certificate = load_x509_certificate(certificate_data)
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not hmac.compare_digest(key_public, certificate_public):
        raise ValueError("certificate public key does not match the decrypted private key")
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(
        friendly_name[:200], private_key, certificate, None, encryption
    )


def pfx_password(args) -> bytes:
    if args.pfx_password is not None:
        return args.pfx_password.encode("utf-8")
    if args.pfx_password_file:
        path = Path(args.pfx_password_file)
        try:
            value = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"cannot read --pfx-password-file: {exc}") from None
        if value.endswith(b"\r\n"):
            value = value[:-2]
        elif value.endswith(b"\n"):
            value = value[:-1]
        return value
    raise ValueError(
        "--certificate requires --pfx-password TEXT or --pfx-password-file FILE; "
        "use --pfx-password '' only when an unencrypted PFX is intentional"
    )


def pvk_password(args) -> bytes | None:
    """Return the exact password bytes for an encrypted PVK, if supplied."""
    if args.pvk_password is not None:
        return args.pvk_password.encode("utf-8")
    if args.pvk_password_file:
        path = Path(args.pvk_password_file)
        try:
            value = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"cannot read --pvk-password-file: {exc}") from None
        if value.endswith(b"\r\n"):
            value = value[:-2]
        elif value.endswith(b"\n"):
            value = value[:-1]
        return value
    return None


def describe_certificate(data: bytes) -> dict:
    """Structured summary of a PEM, DER, or serialized Windows certificate."""
    from cryptography.hazmat.primitives import hashes, serialization

    cert = load_x509_certificate(data)
    try:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        subject = issuer = "(unparsed)"
    thumbprint = cert.fingerprint(hashes.SHA1()).hex()
    key = cert.public_key()
    public_key_fingerprint = hashlib.sha256(key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()
    key_desc = type(key).__name__.replace("PublicKey", "")
    key_size = getattr(key, "key_size", None)
    if key_size:
        key_desc = f"{key_desc} {key_size}-bit"
    return {
        "offset": 0,
        "size": len(data),
        "label": "public certificate",
        "sections": [
            {"title": "Certificate", "fields": [
                {"name": "Subject", "value": subject},
                {"name": "Issuer", "value": issuer},
                {"name": "Serial", "value": format(cert.serial_number, "x")},
                {"name": "Not before", "value": str(cert.not_valid_before_utc)},
                {"name": "Not after", "value": str(cert.not_valid_after_utc)},
                {"name": "Signature algorithm",
                 "value": getattr(cert.signature_hash_algorithm, "name", "unknown")},
                {"name": "Public key", "value": key_desc},
                {"name": "SHA1 thumbprint", "value": thumbprint},
                {"name": "Public-key SHA256 (SPKI)", "value": public_key_fingerprint},
            ]},
        ],
    }


def find_credential_blob(data: bytes) -> list[LocatedBlob]:
    """Locate the DPAPI payload in a Local/Roaming Credential file."""
    if len(data) < 32:
        raise ValueError("Credential file is too short")
    version, size, _unknown = struct.unpack_from("<III", data)
    if version != 1 or size != len(data) - 12:
        raise ValueError("not a Windows Credential file")
    field = data[12:]
    if not field.startswith(DPAPI_HEADER):
        raise ValueError("Credential file does not contain a classic DPAPI blob")
    blob, consumed = parse_dpapi_blob(field)
    if consumed != size:
        raise ValueError(
            f"Credential payload length is {size}, but its DPAPI blob uses {consumed}"
        )
    return [LocatedBlob(12, consumed, blob, label="Credential payload")]


def find_vault_policy_blob(data: bytes) -> list[LocatedBlob]:
    """Locate the DPAPI payload containing a Vault policy's AES keys."""
    reader = ByteReader(data)
    if reader.u32("Vault policy version") != 1:
        raise ValueError("not a version-1 Vault policy")
    reader.take(16, "Vault policy GUID")
    reader.length_prefixed("Vault policy description")
    reader.take(12, "Vault policy metadata")
    reader.u32("Vault policy size")
    reader.take(16, "Vault policy GUID 2")
    reader.take(16, "Vault policy GUID 3")
    blob_size = reader.u32("Vault policy DPAPI blob size")
    offset = reader.offset
    field = reader.take(blob_size, "Vault policy DPAPI blob")
    trailing = data[reader.offset:]
    if any(trailing) or not field.startswith(DPAPI_HEADER):
        raise ValueError("not a serialized Vault policy")
    blob, consumed = parse_dpapi_blob(field)
    if consumed != blob_size:
        raise ValueError(
            f"Vault policy declares {blob_size} DPAPI bytes but the blob uses {consumed}"
        )
    return [LocatedBlob(offset, consumed, blob, label="Vault policy")]


def parse_vault_policy_keys(data: bytes) -> list[bytes]:
    """Extract AES keys from decrypted BCRYPT_KEY_DATA_BLOB policy wrappers."""
    keys = []
    position = 0
    while True:
        offset = data.find(b"KDBM", position)
        if offset < 0:
            break
        if offset + 12 <= len(data):
            _magic, version, key_length = struct.unpack_from("<III", data, offset)
            end = offset + 12 + key_length
            if version == 1 and key_length in (16, 24, 32) and end <= len(data):
                key = data[offset + 12:end]
                if key not in keys:
                    keys.append(key)
        position = offset + 1
    if not keys:
        raise ValueError("decrypted Vault policy contains no supported AES keys")
    return sorted(keys, key=len)


def parse_vault_record(data: bytes) -> dict:
    """Parse a Vault .vcrd record and its attribute map."""
    reader = ByteReader(data)
    schema_guid = uuid.UUID(bytes_le=reader.take(16, "Vault schema GUID"))
    reader.u32("Vault record unknown 0")
    last_written = struct.unpack("<Q", reader.take(8, "Vault timestamp"))[0]
    reader.u32("Vault record unknown 1")
    reader.u32("Vault record unknown 2")
    friendly_raw = reader.length_prefixed("Vault friendly name")
    try:
        friendly_name = friendly_raw.decode("utf-16le").rstrip("\x00")
    except UnicodeDecodeError:
        raise ValueError("Vault friendly name is not UTF-16LE") from None
    map_size = reader.u32("Vault attribute-map size")
    if not map_size or map_size % 12:
        raise ValueError("invalid Vault attribute-map size")
    map_data = reader.take(map_size, "Vault attribute map")
    entries = [
        struct.unpack_from("<III", map_data, offset)
        for offset in range(0, map_size, 12)
    ]
    offsets = [entry[1] for entry in entries]
    if (
        offsets != sorted(offsets)
        or offsets[0] < reader.offset
        or offsets[-1] >= len(data)
    ):
        raise ValueError("invalid Vault attribute offsets")
    attributes = []
    for index, (attribute_id, offset, unknown) in enumerate(entries):
        end = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        attributes.append(
            {"id": attribute_id, "unknown": unknown, "data": data[offset:end]}
        )
    return {
        "schema_guid": str(schema_guid),
        "last_written": filetime_to_iso(last_written),
        "friendly_name": friendly_name,
        "attributes": attributes,
    }


def find_cng_private_key_blob(data: bytes) -> list[LocatedBlob]:
    """Return the entropy-protected private-key field from a CNG container."""
    if len(data) < 44:
        raise ValueError("CNG key container is shorter than its 44-byte header")
    (
        _version,
        _unknown,
        name_length,
        _key_type,
        public_properties_length,
        private_properties_length,
        private_key_length,
        _unknown_array,
    ) = struct.unpack_from("<7I16s", data)
    declared_size = (
        44
        + name_length
        + public_properties_length
        + private_properties_length
        + private_key_length
    )
    if declared_size > len(data):
        raise ValueError(
            f"CNG key container declares {declared_size} bytes but has {len(data)}"
        )
    if not private_key_length:
        raise ValueError("CNG key container has no encrypted private key")

    offset = 44 + name_length + public_properties_length + private_properties_length
    field = data[offset:offset + private_key_length]
    if not field.startswith(DPAPI_HEADER):
        raise ValueError("CNG private key is not a classic DPAPI blob")
    blob, size = parse_dpapi_blob(field)
    if size != private_key_length:
        raise ValueError(
            f"CNG private-key length is {private_key_length}, "
            f"but its DPAPI blob uses {size}"
        )
    return [
        LocatedBlob(
            offset,
            size,
            blob,
            CNG_PRIVATE_KEY_ENTROPY,
            "CNG private key",
        )
    ]


def parse_ngc_cng_container(data: bytes) -> dict:
    """Parse the two protected fields in an NGC software CNG key container."""
    if len(data) < 44:
        raise ValueError("NGC CNG key container is shorter than its header")
    (
        version,
        _unknown,
        name_length,
        key_type,
        public_properties_length,
        private_properties_length,
        private_key_length,
        _unknown_array,
    ) = struct.unpack_from("<7I16s", data)
    total = (
        44
        + name_length
        + public_properties_length
        + private_properties_length
        + private_key_length
    )
    if version != 1 or total > len(data):
        raise ValueError("invalid NGC CNG key container lengths")
    try:
        name = data[44:44 + name_length].decode("utf-16le").rstrip("\x00")
    except UnicodeDecodeError:
        name = data[44:44 + name_length].hex()
    properties_offset = 44 + name_length + public_properties_length
    key_offset = properties_offset + private_properties_length
    properties_data = data[
        properties_offset:properties_offset + private_properties_length
    ]
    key_data = data[key_offset:key_offset + private_key_length]
    if not properties_data.startswith(DPAPI_HEADER):
        raise ValueError("NGC private properties are not a classic DPAPI blob")
    if not key_data.startswith(DPAPI_HEADER):
        raise ValueError("NGC private key is not a classic DPAPI blob")
    properties_blob, properties_size = parse_dpapi_blob(properties_data)
    key_blob, key_size = parse_dpapi_blob(key_data)
    if properties_size != private_properties_length or key_size != private_key_length:
        raise ValueError("NGC CNG protected-field length mismatch")
    return {
        "name": name,
        "key_type": key_type,
        "properties": LocatedBlob(
            properties_offset,
            properties_size,
            properties_blob,
            NGC_PRIVATE_PROPERTIES_ENTROPY,
            "NGC private key properties",
        ),
        "private_key": LocatedBlob(
            key_offset,
            key_size,
            key_blob,
            CNG_PRIVATE_KEY_ENTROPY,
            "NGC PIN-protected private key",
        ),
    }


def parse_ngc_private_properties(data: bytes) -> dict[str, bytes]:
    properties = {}
    offset = 0
    while offset < len(data):
        if offset + 20 > len(data):
            raise ValueError("truncated NGC private-key property header")
        total, _value_type, _unknown, name_length, value_length = struct.unpack_from(
            "<5I", data, offset
        )
        minimum = 20 + name_length + value_length
        if total < minimum or offset + total > len(data):
            raise ValueError("invalid NGC private-key property length")
        name_raw = data[offset + 20:offset + 20 + name_length]
        value = data[
            offset + 20 + name_length:offset + 20 + name_length + value_length
        ]
        name = name_raw.decode("utf-16le", errors="replace").rstrip("\x00")
        properties[name] = value
        offset += total
    return properties


def ngc_pin_secret(pin: str, salt: bytes, rounds: int) -> bytes:
    validate_kdf_rounds(rounds, "Windows Hello PIN KDF")
    pin_hex_utf16 = pin.encode().hex().upper().encode("utf-16le")
    derived = hashlib.pbkdf2_hmac("sha256", pin_hex_utf16, salt, rounds)
    derived_hex_utf16 = derived.hex().upper().encode("utf-16le")
    return hashlib.sha512(derived_hex_utf16).digest()


def find_capi_private_key_blobs(data: bytes) -> list[LocatedBlob]:
    """Return only the private-key DPAPI fields from a CAPI key container."""
    if len(data) < 40:
        raise ValueError("CAPI key container is shorter than its 40-byte header")

    (
        _version,
        _unknown,
        name_length,
        signing_public_length,
        signing_private_length,
        exchange_public_length,
        exchange_private_length,
        hash_length,
        signing_export_flag_length,
        exchange_export_flag_length,
    ) = struct.unpack_from("<10I", data)

    fields = (
        ("name", name_length, False),
        ("hash", hash_length, False),
        ("signing public key", signing_public_length, False),
        ("signing private key", signing_private_length, True),
        ("signing export flag", signing_export_flag_length, False),
        ("exchange public key", exchange_public_length, False),
        ("exchange private key", exchange_private_length, True),
        ("exchange export flag", exchange_export_flag_length, False),
    )
    declared_size = 40 + sum(length for _, length, _ in fields)
    if declared_size > len(data):
        raise ValueError(
            f"CAPI key container declares {declared_size} bytes but has {len(data)}"
        )

    found = []
    offset = 40
    for label, length, is_private_key in fields:
        if is_private_key and length:
            field = data[offset:offset + length]
            if not field.startswith(DPAPI_HEADER):
                raise ValueError(f"CAPI {label} is not a classic DPAPI blob")
            blob, size = parse_dpapi_blob(field)
            if size != length:
                raise ValueError(
                    f"CAPI {label} length is {length}, but its DPAPI blob uses {size}"
                )
            found.append(LocatedBlob(offset, size, blob, label=f"CAPI {label}"))
        offset += length

    if not found:
        raise ValueError("CAPI key container has no encrypted private key")
    return found


def find_dpapi_blobs(data: bytes, input_type: str) -> list[LocatedBlob]:
    if input_type in ("blob", "powershell", "keepass"):
        if not data.startswith(DPAPI_HEADER):
            raise ValueError(f"input is not a {input_type} DPAPI blob")
        blob, size = parse_dpapi_blob(data)
        return [LocatedBlob(0, size, blob)]

    if input_type == "credential":
        return find_credential_blob(data)

    if input_type == "vpol":
        return find_vault_policy_blob(data)

    if input_type == "cng":
        return find_cng_private_key_blob(data)

    if input_type == "capi":
        return find_capi_private_key_blobs(data)

    # Auto mode recognizes structured key containers before falling back to
    # locating an ordinary embedded DPAPI blob.
    try:
        return find_credential_blob(data)
    except ValueError:
        pass
    try:
        return find_vault_policy_blob(data)
    except ValueError:
        pass
    try:
        return find_cng_private_key_blob(data)
    except ValueError:
        pass
    try:
        return find_capi_private_key_blobs(data)
    except ValueError:
        pass

    found = []
    position = 0
    while True:
        offset = data.find(DPAPI_HEADER, position)
        if offset < 0:
            break
        try:
            blob, size = parse_dpapi_blob(data[offset:])
            found.append(LocatedBlob(offset, size, blob))
            position = offset + size
        except ValueError:
            position = offset + 1
    if not found:
        raise ValueError("no classic DPAPI blob found")
    return found


CIPHER_ALGO_NAMES = {
    0x6601: "DES (CBC)", 0x6602: "RC2 (CBC)", 0x6603: "3DES (CBC)",
    0x660E: "AES-128 (CBC)", 0x660F: "AES-192 (CBC)", 0x6610: "AES-256 (CBC)",
    0x6801: "RC4",
}
HASH_ALGO_NAMES = {
    0x8003: "MD5", 0x8004: "SHA-1", 0x8009: "HMAC",
    0x800C: "SHA-256", 0x800D: "SHA-384", 0x800E: "SHA-512",
}
DPAPI_FLAG_NAMES = {
    0x01: "UI_FORBIDDEN", 0x04: "LOCAL_MACHINE", 0x08: "CRED_SYNC",
    0x10: "AUDIT", 0x20: "NO_RECOVERY", 0x40: "VERIFY_PROTECTION",
    0x80: "CRED_REGENERATE", 0x20000000: "SYSTEM",
}


def _describe_flags(flags: int) -> str:
    names = [name for bit, name in sorted(DPAPI_FLAG_NAMES.items()) if flags & bit]
    return ", ".join(names) if names else "None"


def _binary_field(name: str, value: bytes) -> dict:
    if not value:
        return {"name": name, "value": "0 bytes (empty)", "hex": ""}
    return {"name": name, "value": f"{len(value)} bytes", "hex": value.hex()}


def describe_dpapi_blob(blob_bytes: bytes, offset: int = 0) -> dict:
    """Return a structured, display-ready breakdown of one classic DPAPI blob.

    Re-reads every header field (including the ones decryption discards, such as
    flags and the description) so a GUI can show the full parsed structure.
    """
    reader = ByteReader(blob_bytes)
    version = reader.u32("blob version")
    provider = uuid.UUID(bytes_le=reader.take(16, "provider GUID"))
    mk_version = reader.u32("master-key version")
    mk_guid = uuid.UUID(bytes_le=reader.take(16, "master-key GUID"))
    flags = reader.u32("flags")
    description_raw = reader.length_prefixed("description")
    crypt_algo = reader.u32("cipher algorithm")
    crypt_len = reader.u32("cipher key length")
    salt = reader.length_prefixed("salt")
    hmac_key = reader.length_prefixed("HMAC key")
    hash_algo = reader.u32("hash algorithm")
    hash_len = reader.u32("hash length")
    hmac_value = reader.length_prefixed("HMAC value")
    encrypted = reader.length_prefixed("ciphertext")
    signature_offset = reader.offset
    signature = reader.length_prefixed("signature")
    size = reader.offset
    signed = blob_bytes[20:signature_offset]
    try:
        description = description_raw.decode("utf-16le").rstrip("\x00")
    except UnicodeDecodeError:
        description = description_raw.hex()
    return {
        "offset": offset,
        "size": size,
        "label": None,
        "sections": [
            {"title": "Identity and scope", "fields": [
                {"name": "Blob size", "value": f"{size} bytes"},
                {"name": "Input offset", "value": f"{offset} (0x{offset:08X})"},
                {"name": "Version", "value": f"{version} (0x{version:08X})"},
                {"name": "Provider GUID", "value": str(provider)},
                {"name": "Master-key version",
                 "value": f"{mk_version} (0x{mk_version:08X})"},
                {"name": "Master-key GUID", "value": str(mk_guid)},
                {"name": "Flags", "value": f"0x{flags:08X}"},
                {"name": "Decoded flags", "value": _describe_flags(flags)},
                {"name": "Description", "value": description or "(none)"},
            ]},
            {"title": "Cryptography", "fields": [
                {"name": "Encryption algorithm",
                 "value": f"{CIPHER_ALGO_NAMES.get(crypt_algo, 'unknown')} "
                          f"(0x{crypt_algo:08X})"},
                {"name": "Encryption key length", "value": f"{crypt_len} bits"},
                {"name": "Hash algorithm",
                 "value": f"{HASH_ALGO_NAMES.get(hash_algo, 'unknown')} "
                          f"(0x{hash_algo:08X})"},
                {"name": "Hash length", "value": f"{hash_len} bits"},
            ]},
            {"title": "Binary fields", "fields": [
                _binary_field("Salt", salt),
                _binary_field("HMAC key material", hmac_key),
                _binary_field("HMAC verification value", hmac_value),
                _binary_field("Encrypted data", encrypted),
                _binary_field("Integrity signature", signature),
                {"name": "Signed structure region", "value": f"{len(signed)} bytes"},
            ]},
        ],
    }


def describe_artifact(data: bytes, input_type: str = "auto") -> list:
    """Locate every classic DPAPI blob in an artifact and describe each one."""
    try:
        blobs = find_dpapi_blobs(data, input_type)
    except ValueError:
        if input_type == "auto":
            return []
        try:
            blobs = find_dpapi_blobs(data, "auto")
        except ValueError:
            return []
    described = []
    for item in blobs:
        sub = data[item.offset:item.offset + item.size]
        try:
            info = describe_dpapi_blob(sub, item.offset)
        except ValueError:
            continue
        info["label"] = item.label
        described.append(info)
    return described


def hashcat_modes_for_masterkey(mk: "EncryptedMasterKey") -> str:
    """Human-readable Hashcat mode(s) an encrypted master key supports."""
    if mk.crypt_algo == CALG_3DES and mk.hash_algo in (CALG_SHA1, CALG_HMAC):
        return "15300 (local/domain) / 15310 (domain-new)"
    if mk.crypt_algo == CALG_AES_256 and mk.hash_algo == CALG_SHA_512:
        return "15900 (local/domain) / 15910 (domain-new)"
    return "not supported by Hashcat"


def describe_masterkey_file(data: bytes) -> dict:
    """Structured breakdown of an encrypted master-key file (not a classic blob)."""
    mk = parse_masterkey_file(data)
    cipher = CIPHER_ALGO_NAMES.get(mk.crypt_algo, "unknown")
    hash_name = HASH_ALGO_NAMES.get(mk.hash_algo, "unknown")
    return {
        "offset": 0,
        "size": len(data),
        "label": "encrypted master key",
        "sections": [
            {"title": "Identity and scope", "fields": [
                {"name": "File size", "value": f"{len(data)} bytes"},
                {"name": "Master-key GUID",
                 "value": str(mk.file_guid) if mk.file_guid else "(none in header)"},
                {"name": "Version", "value": f"{mk.version} (0x{mk.version:08X})"},
            ]},
            {"title": "Cryptography", "fields": [
                {"name": "Encryption algorithm",
                 "value": f"{cipher} (0x{mk.crypt_algo:08X})"},
                {"name": "Hash algorithm",
                 "value": f"{hash_name} (0x{mk.hash_algo:08X})"},
                {"name": "PBKDF2 iterations", "value": str(mk.rounds)},
                {"name": "Hashcat mode", "value": hashcat_modes_for_masterkey(mk)},
            ]},
            {"title": "Binary fields", "fields": [
                _binary_field("Salt", mk.salt),
                _binary_field("Encrypted key", mk.data),
            ]},
        ],
    }


def _decode_text_prefix(data: bytes, limit: int = 8192) -> str:
    """Decode the leading bytes as text, honoring a UTF-16/UTF-8 BOM.

    Export-Clixml writes UTF-16LE with a BOM, so an ASCII byte-substring search
    misses its markers; decode first, then search.
    """
    prefix = data[:limit]
    if prefix[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encoding = "utf-16"
    elif prefix[:3] == b"\xef\xbb\xbf":
        encoding = "utf-8-sig"
    else:
        encoding = "utf-8"
    try:
        return prefix.decode(encoding, errors="ignore")
    except LookupError:
        return prefix.decode("latin-1", errors="ignore")


def looks_like_clixml(data: bytes) -> bool:
    """True for a PowerShell Export-Clixml document in UTF-8 or UTF-16."""
    text = _decode_text_prefix(data)
    return "<Objs" in text and "schemas.microsoft.com/powershell/2004/04" in text


def looks_like_sccm(data: bytes) -> bool:
    """True when an SCCM PolicySecret Version=1 wrapper is present."""
    return re.search(
        rb'<PolicySecret\s+Version\s*=\s*["\']1["\']\s*>\s*<!\[CDATA\[',
        data,
        re.IGNORECASE,
    ) is not None


def unwrap_base64_dpapi(data: bytes) -> bytes | None:
    """If data is Base64 text wrapping a classic DPAPI blob (optionally with the
    Chromium ``DPAPI`` prefix), return the inner blob bytes; otherwise None."""
    if data.startswith(DPAPI_HEADER):
        return None  # already a raw blob
    compact = bytes(byte for byte in data if byte not in b" \t\r\n")
    if not compact:
        return None
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, TypeError):
        return None
    if decoded.startswith(b"DPAPI"):
        decoded = decoded[5:]
    return decoded if decoded.startswith(DPAPI_HEADER) else None


def looks_like_local_state(data: bytes) -> bool:
    """True for a Chromium 'Local State' file carrying os_crypt.encrypted_key."""
    text = _decode_text_prefix(data)
    return '"os_crypt"' in text and '"encrypted_key"' in text


def extract_local_state_blob(data: bytes) -> bytes:
    """Return the user-DPAPI blob from a Chromium 'Local State' file, its
    os_crypt.encrypted_key value, or a raw/base64 ``DPAPI``-prefixed key."""
    text = _decode_text_prefix(data, len(data)).strip()
    if text.startswith("{"):
        try:
            document = json.loads(text)
        except (ValueError, json.JSONDecodeError):
            document = None
        if isinstance(document, dict):
            os_crypt = document.get("os_crypt")
            key = os_crypt.get("encrypted_key") if isinstance(os_crypt, dict) else None
            if not isinstance(key, str):
                raise ValueError("Local State JSON has no os_crypt.encrypted_key")
            try:
                raw = base64.b64decode(key, validate=True)
            except (ValueError, TypeError):
                raise ValueError("os_crypt.encrypted_key is not valid Base64") from None
            if raw.startswith(b"DPAPI"):
                raw = raw[5:]
            if not raw.startswith(DPAPI_HEADER):
                raise ValueError(
                    "os_crypt.encrypted_key is not a DPAPI-protected key (only the "
                    "classic DPAPI 'DPAPI'-prefixed key is supported, not app-bound)"
                )
            return raw
    unwrapped = unwrap_base64_dpapi(data)
    if unwrapped is not None:
        return unwrapped
    raw = data[5:] if data.startswith(b"DPAPI") else data
    if raw.startswith(DPAPI_HEADER):
        return raw
    raise ValueError(
        "not a Chromium Local State file, an os_crypt.encrypted_key value, or a "
        "DPAPI blob"
    )


def describe_input(data: bytes, input_type: str = "auto") -> dict:
    """Identify and describe an artifact for a GUI's inspect view.

    Recognizes an encrypted master-key file (which is not a classic DPAPI blob)
    so the interface can offer the Hashcat/decrypt master-key workflow instead of
    failing with "no classic DPAPI blob found".
    """
    if input_type in ("auto", "masterkey") and not data.startswith(DPAPI_HEADER):
        try:
            structure = describe_masterkey_file(data)
        except ValueError:
            structure = None
        if structure is not None:
            return {
                "kind": "masterkey",
                "detected_type": "masterkey",
                "structure": [structure],
                "note": (
                    "encrypted master key detected - enter the SID and click "
                    "'Masterkey -> Hashcat' to export a $DPAPImk$ hash, or unlock it "
                    "and Decrypt: a user key needs SID + password (or NT/SHA1 hash, "
                    "prekey, credkey); a SYSTEM key needs DPAPI_SYSTEM; a domain key "
                    "can use the PVK backup key"
                ),
            }
    if input_type in ("auto", "cert"):
        try:
            cert_structure = describe_certificate(data)
        except Exception:  # noqa: BLE001 - not a certificate; keep probing
            cert_structure = None
        if cert_structure is not None:
            return {
                "kind": "cert",
                "detected_type": "cert",
                "structure": [cert_structure],
                "note": (
                    "public certificate (no secret) - click Decrypt to save it "
                    "as a PEM .crt file; no key material is needed"
                ),
            }

    if input_type in ("auto", "clixml") and looks_like_clixml(data):
        try:
            document = parse_powershell_clixml(data)
        except ValueError:
            document = None
        if document is not None:
            fields = []
            if document.get("username"):
                fields.append({"name": "Username", "value": document["username"]})
            for index, item in enumerate(document["secrets"], 1):
                guid = item["blob"].blob.masterkey_guid
                fields.append({
                    "name": f"SecureString {index}"
                    + (f" ({item['name']})" if item.get("name") else ""),
                    "value": f"required master key {guid}",
                })
            structure = [{
                "label": "PowerShell Export-Clixml", "offset": 0, "size": len(data),
                "sections": [{"title": "SecureStrings", "fields": fields}],
            }]
            return {
                "kind": "clixml", "detected_type": "clixml", "structure": structure,
                "note": (
                    f"PowerShell Export-Clixml with {len(document['secrets'])} "
                    "SecureString(s); add the owning user masterkey and Decrypt"
                ),
            }

    if input_type in ("auto", "sccm") and (
        input_type == "sccm" or looks_like_sccm(data)
    ):
        try:
            secrets = parse_sccm_policy_secrets(data)
        except ValueError:
            secrets = None
        if secrets:
            fields = [
                {
                    "name": f"PolicySecret {index}",
                    "value": f"required SYSTEM master key {item['blob'].blob.masterkey_guid}",
                }
                for index, item in enumerate(secrets, 1)
            ]
            return {
                "kind": "sccm",
                "detected_type": "sccm",
                "structure": [{
                    "label": "SCCM PolicySecret",
                    "offset": secrets[0]["source_offset"],
                    "size": len(data),
                    "sections": [{"title": "Encrypted policy secrets", "fields": fields}],
                }],
                "note": (
                    f"SCCM policy data with {len(secrets)} encrypted secret(s); "
                    "add DPAPI_SYSTEM and the matching SYSTEM masterkey"
                ),
            }

    if input_type in ("auto", "localstate") and (
        input_type == "localstate" or looks_like_local_state(data)
    ):
        try:
            blob_bytes = extract_local_state_blob(data)
        except ValueError:
            blob_bytes = None
        if blob_bytes is not None:
            return {
                "kind": "blob", "detected_type": "localstate",
                "structure": describe_artifact(blob_bytes, "blob"),
                "note": (
                    "Chromium Local State os_crypt key: add the owning user "
                    "masterkey and Decrypt to recover the AES-256-GCM key"
                ),
            }

    if input_type in ("auto", "blob"):
        unwrapped = unwrap_base64_dpapi(data)
        if unwrapped is not None:
            described = describe_artifact(unwrapped, "blob")
            if described:
                return {
                    "kind": "blob", "detected_type": None, "structure": described,
                    "note": "input was Base64-wrapped; decoded to a DPAPI blob",
                }

    described = describe_artifact(data, input_type)
    if described:
        return {"kind": "blob", "detected_type": None,
                "structure": described, "note": None}
    return {"kind": "none", "detected_type": None, "structure": [], "note": None}


def format_structure(described: list) -> list:
    """Render describe_* output as indented text lines for a console/log view."""
    lines = []
    for blob in described:
        head = blob["label"] if blob.get("label") else "DPAPI blob"
        lines.append(
            f"{head} @ offset {blob['offset']} (0x{blob['offset']:X}), "
            f"{blob['size']} bytes"
        )
        for section in blob["sections"]:
            lines.append(f"  [{section['title']}]")
            for field in section["fields"]:
                value = field["value"]
                hex_value = field.get("hex")
                if hex_value:
                    shown = hex_value[:64] + "…" if len(hex_value) > 64 else hex_value
                    value = f"{value} - {shown}"
                lines.append(f"    {field['name']:26} {value}")
    return lines


def set_odd_parity(data: bytes) -> bytes:
    output = bytearray()
    for value in data:
        high_seven = value & 0xFE
        output.append(high_seven | (high_seven.bit_count() % 2 == 0))
    return bytes(output)


def derive_dpapi_cipher_key(
    session_key: bytes, hash_algo: int, cipher_algo: int
) -> bytes:
    hash_name, _, block_size = hash_details(hash_algo)
    key_length, _ = cipher_details(cipher_algo)
    derived = (
        hmac.new(session_key, digestmod=hash_name).digest()
        if len(session_key) > block_size
        else session_key
    )
    if len(derived) < key_length:
        padded = (derived + b"\x00" * block_size)[:block_size]
        ipad = bytes(value ^ 0x36 for value in padded)
        opad = bytes(value ^ 0x5C for value in padded)
        derived = hashlib.new(hash_name, ipad).digest()
        derived += hashlib.new(hash_name, opad).digest()
        derived = set_odd_parity(derived)
    return derived[:key_length]


def decrypt_dpapi_blob(
    blob: DPAPIBlob, masterkey: bytes, entropy: bytes | None = None
) -> bytes:
    key_hash = masterkey if len(masterkey) == 20 else hashlib.sha1(masterkey).digest()
    hash_name, _, _ = hash_details(blob.hash_algo)
    session_hmac = hmac.new(key_hash, blob.salt, hash_name)
    if entropy is not None:
        session_hmac.update(entropy)
    session_key = session_hmac.digest()
    cipher_key = derive_dpapi_cipher_key(
        session_key, blob.hash_algo, blob.crypt_algo
    )
    _, block_size = cipher_details(blob.crypt_algo)
    padded = cbc_decrypt(
        blob.data, cipher_key, b"\x00" * block_size, blob.crypt_algo
    )
    cleartext = unpad_pkcs7(padded, block_size)
    if cleartext is None:
        raise ValueError("DPAPI ciphertext has invalid padding (wrong master key?)")

    calculated = hmac.new(key_hash, blob.hmac_value, hash_name)
    if entropy is not None:
        calculated.update(entropy)
    calculated.update(blob.signed_data)
    hash_block_size = hashlib.new(hash_name).block_size
    key_block = (key_hash + b"\x00" * hash_block_size)[:hash_block_size]
    inner = hashlib.new(hash_name, bytes(value ^ 0x36 for value in key_block))
    inner.update(blob.hmac_value)
    outer = hashlib.new(hash_name, bytes(value ^ 0x5C for value in key_block))
    outer.update(inner.digest())
    if entropy is not None:
        outer.update(entropy)
    outer.update(blob.signed_data)
    if not (
        hmac.compare_digest(calculated.digest(), blob.signature)
        or hmac.compare_digest(outer.digest(), blob.signature)
    ):
        raise ValueError("DPAPI signature verification failed (wrong master key?)")
    return cleartext


def dpapi_type1_session_key(
    blob: DPAPIBlob,
    masterkey: bytes,
    nonce: bytes,
    entropy: bytes,
    smartcard_secret: bytes,
    verify: bool = False,
) -> bytes:
    """Microsoft's legacy HMAC construction used by software NGC keys."""
    key_hash = masterkey if len(masterkey) == 20 else hashlib.sha1(masterkey).digest()
    hash_name, _, block_size = hash_details(blob.hash_algo)
    key_block = (key_hash + b"\x00" * block_size)[:block_size]
    inner = hashlib.new(hash_name, bytes(value ^ 0x36 for value in key_block))
    inner.update(nonce)
    inner.update(entropy)
    inner.update(smartcard_secret)
    if verify:
        inner.update(blob.signed_data)
    outer = hashlib.new(hash_name, bytes(value ^ 0x5C for value in key_block))
    outer.update(inner.digest())
    return outer.digest()


def decrypt_dpapi_blob_smartcard(
    blob: DPAPIBlob,
    masterkey: bytes,
    entropy: bytes,
    smartcard_secret: bytes,
) -> bytes:
    session_key = dpapi_type1_session_key(
        blob, masterkey, blob.salt, entropy, smartcard_secret
    )
    cipher_key = derive_dpapi_cipher_key(
        session_key, blob.hash_algo, blob.crypt_algo
    )
    _, block_size = cipher_details(blob.crypt_algo)
    padded = cbc_decrypt(
        blob.data, cipher_key, b"\x00" * block_size, blob.crypt_algo
    )
    cleartext = unpad_pkcs7(padded, block_size)
    if cleartext is None:
        raise ValueError("Windows Hello private key has invalid padding (wrong PIN?)")
    signature = dpapi_type1_session_key(
        blob,
        masterkey,
        blob.hmac_value,
        entropy,
        smartcard_secret,
        verify=True,
    )
    if not hmac.compare_digest(signature, blob.signature):
        raise ValueError("Windows Hello signature verification failed (wrong PIN?)")
    return cleartext


def parse_masterkey_file(data: bytes) -> EncryptedMasterKey:
    file_guid = None
    section = data
    if len(data) >= 128:
        header = struct.unpack_from("<III72sIIIQQQQ", data)
        masterkey_length = header[7]
        try:
            file_guid = uuid.UUID(header[3].decode("utf-16le").rstrip("\x00"))
        except (UnicodeDecodeError, ValueError):
            file_guid = None
        if file_guid and 32 <= masterkey_length <= len(data) - 128:
            section = data[128:128 + masterkey_length]

    if len(section) < 32:
        raise ValueError("master-key structure is shorter than 32 bytes")
    version, salt, rounds, hash_algo, crypt_algo = struct.unpack_from(
        "<I16sIII", section
    )
    if version not in (1, 2):
        raise ValueError(f"unsupported master-key version {version}")
    validate_kdf_rounds(rounds, "masterkey KDF")
    try:
        hash_details(hash_algo, masterkey=True)
        _, block_size = cipher_details(crypt_algo)
    except ValueError:
        raise ValueError(
            "not a valid encrypted master-key file (unexpected algorithm ids "
            f"hash=0x{hash_algo:08x} cipher=0x{crypt_algo:08x}); confirm this is "
            "the GUID-named Protect master-key file exported as raw binary, not "
            "text/hex/base64 or a different artifact"
        ) from None
    encrypted = section[32:]
    if not encrypted or len(encrypted) % block_size:
        raise ValueError("invalid encrypted master-key data length")
    return EncryptedMasterKey(
        file_guid, version, salt, rounds, hash_algo, crypt_algo, encrypted
    )


def binary_sid_to_string(data: bytes) -> str:
    if len(data) < 8:
        raise ValueError("binary SID is shorter than 8 bytes")
    revision, count = data[0], data[1]
    expected = 8 + count * 4
    if revision != 1 or expected != len(data):
        raise ValueError("invalid binary SID in CREDHIST entry")
    authority = int.from_bytes(data[2:8], "big")
    subauthorities = struct.unpack_from(f"<{count}I", data, 8) if count else ()
    return "S-{}-{}{}".format(
        revision,
        authority,
        "".join(f"-{value}" for value in subauthorities),
    )


def parse_credhist_entry(data: bytes) -> CredHistEntry:
    if len(data) < 64:
        raise ValueError("CREDHIST entry is shorter than 64 bytes")
    version, hash_algo, rounds, sid_length = struct.unpack_from("<4I", data)
    crypt_algo, sha_length, nt_length = struct.unpack_from("<3I", data, 16)
    salt = data[28:44]
    if version not in (1, 2) or not rounds or sid_length < 8:
        raise ValueError("invalid CREDHIST entry header")
    validate_kdf_rounds(rounds, "CREDHIST KDF")
    hash_details(hash_algo, masterkey=True)
    cipher_details(crypt_algo)
    encrypted_length = sha_length + nt_length
    encrypted_length += (-encrypted_length) % 16
    expected = 44 + sid_length + encrypted_length + 20
    if expected != len(data) or encrypted_length == 0:
        raise ValueError("invalid CREDHIST entry lengths")
    sid_end = 44 + sid_length
    version2 = struct.unpack_from("<I", data, sid_end + encrypted_length)[0]
    return CredHistEntry(
        version=version,
        hash_algo=hash_algo,
        rounds=rounds,
        sid=binary_sid_to_string(data[44:sid_end]),
        crypt_algo=crypt_algo,
        sha_hash_length=sha_length,
        nt_hash_length=nt_length,
        salt=salt,
        encrypted=data[sid_end:sid_end + encrypted_length],
        version2=version2,
        guid=uuid.UUID(bytes_le=data[sid_end + encrypted_length + 4:]),
    )


def parse_credhist_file(data: bytes) -> tuple[int, uuid.UUID, list[CredHistEntry]]:
    if len(data) < 24:
        raise ValueError("CREDHIST file is too short")
    version = struct.unpack_from("<I", data)[0]
    current_guid = uuid.UUID(bytes_le=data[4:20])
    entries = []
    end = len(data)
    while end > 20:
        if end < 24:
            raise ValueError("truncated CREDHIST entry length")
        entry_length = struct.unpack_from("<I", data, end - 4)[0]
        if entry_length == 0:
            end -= 4
            break
        if entry_length < 68 or entry_length > end - 20:
            raise ValueError("invalid CREDHIST reverse entry length")
        start = end - entry_length
        entries.append(parse_credhist_entry(data[start:end - 4]))
        end = start
    if end < 20 or any(data[20:end]):
        raise ValueError("unexpected data before the first CREDHIST entry")
    return version, current_guid, entries


def decrypt_credhist_entry(
    entry: CredHistEntry, candidate_keys
) -> tuple[bytes, bytes, str] | None:
    hash_name, _, _ = hash_details(entry.hash_algo, masterkey=True)
    key_length, iv_length = cipher_details(entry.crypt_algo)
    for label, key in candidate_keys:
        derived = dpapi_masterkey_kdf(
            hash_name,
            key,
            entry.salt,
            entry.rounds,
            key_length + iv_length,
        )
        cleartext = cbc_decrypt(
            entry.encrypted,
            derived[:key_length],
            derived[key_length:],
            entry.crypt_algo,
        )
        hash_end = entry.sha_hash_length
        nt_end = hash_end + entry.nt_hash_length
        if nt_end > len(cleartext) or any(cleartext[nt_end:]):
            continue
        sha_hash = cleartext[:hash_end]
        nt_hash = cleartext[hash_end:nt_end]
        if len(sha_hash) != 20 or len(nt_hash) != 16:
            continue
        return sha_hash, nt_hash, label
    return None


def credhist_initial_keys(args, sid: str):
    if args.prekey:
        key, _, _ = read_data(args.prekey, "DPAPI prekey")
        if len(key) != 20:
            raise ValueError("--prekey must contain exactly 20 bytes")
        return [("supplied SID-bound prekey", key)]
    if args.nt_hash:
        key, _, _ = read_data(args.nt_hash, "NT hash")
        if len(key) != 16:
            raise ValueError("--nt-hash must contain exactly 16 bytes")
        return list(userkey_keys(sid, key))
    if args.sha1_hash:
        key, _, _ = read_data(args.sha1_hash, "local SHA1 password hash")
        if len(key) != 20:
            raise ValueError(
                "--sha1-hash must contain exactly 20 bytes: "
                "SHA1(password encoded as UTF-16LE)"
            )
        return list(userkey_keys(sid, key))
    if args.credkey:
        key, _, _ = read_data(args.credkey, "DPAPI credential key")
        if not 16 <= len(key) <= 128:
            raise ValueError("--credkey must contain between 16 and 128 bytes")
        return list(userkey_keys(sid, key if len(key) == 20 else hashlib.sha1(key).digest()))
    if args.dpapi_system:
        candidates = []
        for label, key in parse_dpapi_system(args.dpapi_system):
            candidates.extend(
                (f"{label}, {derived_label}", derived)
                for derived_label, derived in userkey_keys(sid, key)
            )
        return candidates
    password = args.password
    if password is None:
        password = getpass.getpass("Current account password: ")
    return list(password_keys(sid, password))


def decrypt_credhist(data: bytes, args) -> dict:
    version, current_guid, entries = parse_credhist_file(data)
    if not entries:
        return {"version": version, "current_guid": str(current_guid), "entries": []}
    candidates = credhist_initial_keys(args, entries[0].sid)
    recovered = []
    errors = []
    for index, entry in enumerate(entries):
        decrypted = decrypt_credhist_entry(entry, candidates)
        if decrypted is None:
            error = (
                f"could not decrypt CREDHIST entry {index + 1}; check the current "
                "password/key. Later entries depend on this entry and were not attempted"
            )
            if not recovered:
                raise ValueError(error)
            errors.append({
                "index": index + 1,
                "guid": str(entry.guid),
                "sid": entry.sid,
                "error": error,
                "remaining_entries_not_attempted": len(entries) - index - 1,
            })
            break
        sha_hash, nt_hash, label = decrypted
        recovered.append(
            {
                "index": index + 1,
                "guid": str(entry.guid),
                "sid": entry.sid,
                "sha1_hash": sha_hash.hex(),
                "nt_hash": nt_hash.hex(),
                "unlocked_with": label,
            }
        )
        candidates = list(userkey_keys(entry.sid, sha_hash))
    result = {
        "version": version,
        "current_guid": str(current_guid),
        "entries": recovered,
    }
    if errors:
        result["errors"] = errors
    return result


def decode_domain_backup_key(value: str) -> bytes:
    """Read a domain backup key supplied as raw, PEM, hex, or Base64."""
    path = existing_file(value)
    raw = path.read_bytes() if path else value.encode("ascii")
    if raw.lstrip().startswith(b"-----BEGIN"):
        return raw
    try:
        text_value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return raw
    compact = "".join(text_value.removeprefix("0x").split())
    if compact and len(compact) % 2 == 0 and all(
        character in string.hexdigits for character in compact
    ):
        return bytes.fromhex(compact)
    try:
        decoded = base64.b64decode("".join(text_value.split()), validate=True)
    except (ValueError, TypeError):
        return raw
    return decoded or raw


def capi_privatekeyblob_to_key(data: bytes):
    """Convert a CAPI PRIVATEKEYBLOB from a PVK file into an RSA key object."""
    if len(data) < 20:
        raise ValueError("domain backup PRIVATEKEYBLOB is too short")
    blob_type, version, reserved, algorithm = struct.unpack_from("<BBHI", data)
    magic, bit_length, public_exponent = struct.unpack_from("<III", data, 8)
    if (
        blob_type != 7
        or version != 2
        or reserved != 0
        or magic != 0x32415352
        or bit_length < 512
        or bit_length % 16
    ):
        raise ValueError("not a supported RSA2 CAPI PRIVATEKEYBLOB")
    modulus_length = bit_length // 8
    prime_length = bit_length // 16
    sizes = (
        modulus_length,
        prime_length,
        prime_length,
        prime_length,
        prime_length,
        prime_length,
        modulus_length,
    )
    if 20 + sum(sizes) > len(data):
        raise ValueError("truncated domain backup PRIVATEKEYBLOB")
    values = []
    offset = 20
    for size in sizes:
        values.append(int.from_bytes(data[offset:offset + size], "little"))
        offset += size
    modulus, prime1, prime2, exponent1, exponent2, coefficient, private_exponent = values
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa

        return rsa.RSAPrivateNumbers(
            prime1,
            prime2,
            private_exponent,
            exponent1,
            exponent2,
            coefficient,
            rsa.RSAPublicNumbers(public_exponent, modulus),
        ).private_key()
    except ImportError:
        raise ValueError("install cryptography to use a domain backup key") from None
    except ValueError as exc:
        raise ValueError(f"invalid domain backup RSA key: {exc}") from None


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Small local RC4 implementation used only for the legacy PVK format."""
    if not key:
        raise ValueError("PVK RC4 key is empty")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(len(data))
    i = j = 0
    for offset, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def decrypt_pvk_privatekeyblob(
    encrypted_blob: bytes, salt: bytes, password: bytes
) -> bytes:
    """Decrypt a Microsoft PVK PRIVATEKEYBLOB, including weak-key legacy PVKs."""
    if len(encrypted_blob) < 20:
        raise ValueError("encrypted PVK private-key blob is too short")
    digest = hashlib.sha1(salt + password).digest()
    for key in (digest[:16], digest[:5] + b"\0" * 11):
        candidate = encrypted_blob[:8] + rc4_crypt(key, encrypted_blob[8:])
        if candidate[8:12] in (b"RSA2", b"DSS2"):
            return candidate
    raise ValueError("could not decrypt PVK; the password is incorrect or unsupported")


def load_domain_backup_key(value: str, password: bytes | None = None):
    raw = decode_domain_backup_key(value)
    # Legacy ServerWrap key exported by tools such as Impacket: either the raw
    # 256-byte key or the complete P_BACKUP_KEY (version 1 + key).
    if len(raw) == 256:
        return raw
    if len(raw) == 260 and struct.unpack_from("<I", raw)[0] == 1:
        return raw[4:]
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ValueError("install cryptography to use a domain backup key") from None

    loaders = (serialization.load_pem_private_key, serialization.load_der_private_key)
    for loader in loaders:
        for loader_password in ((password, None) if password is not None else (None,)):
            try:
                key = loader(raw, password=loader_password)
                if hasattr(key, "decrypt"):
                    return key
            except (ValueError, TypeError):
                pass

    key_blob = raw
    if len(raw) >= 24 and struct.unpack_from("<I", raw)[0] == 0xB0B5F11E:
        _magic, version, _key_spec, encrypted, salt_length, key_length = struct.unpack_from(
            "<6I", raw
        )
        if version != 0:
            raise ValueError(f"unsupported PVK version {version}")
        if encrypted not in (0, 1):
            raise ValueError(f"unsupported PVK encryption flag {encrypted}")
        if bool(encrypted) != bool(salt_length):
            raise ValueError("inconsistent PVK encryption and salt fields")
        if salt_length > 1024 or key_length > 16 * 1024 * 1024:
            raise ValueError("PVK salt or private-key length exceeds the safety limit")
        end = 24 + salt_length + key_length
        if key_length == 0 or end > len(raw):
            raise ValueError("invalid PVK private-key length")
        salt = raw[24:24 + salt_length]
        key_blob = raw[24 + salt_length:end]
        if encrypted:
            if password is None:
                raise ValueError(
                    "password-encrypted PVK requires --pvk-password or "
                    "--pvk-password-file"
                )
            key_blob = decrypt_pvk_privatekeyblob(key_blob, salt, password)
    return capi_privatekeyblob_to_key(key_blob)


def decrypt_serverwrap_domain_key(
    section: bytes, server_key: bytes, expected_sid: str | None = None
) -> bytes:
    """Unwrap a version-1 MS-BKRP ServerWrap masterkey entirely offline."""
    if len(server_key) != 256:
        raise ValueError("legacy AD ServerWrap backup key must contain exactly 256 bytes")
    if len(section) < 96:
        raise ValueError("legacy domain backup section is too short")
    version, payload_length, ciphertext_length = struct.unpack_from("<III", section)
    if version != 1:
        raise ValueError("not a version-1 legacy domain backup section")
    if payload_length == 0 or payload_length > 1024 * 1024:
        raise ValueError("invalid legacy domain backup payload length")
    if ciphertext_length < 52 + payload_length or 96 + ciphertext_length != len(section):
        raise ValueError("invalid legacy domain backup ciphertext length")
    r2 = section[28:96]
    encrypted_payload = section[96:]
    sym_key = hmac.new(server_key, r2, hashlib.sha1).digest()
    payload = rc4_crypt(sym_key, encrypted_payload)
    r3 = payload[:32]
    supplied_mac = payload[32:52]
    sid_length = ciphertext_length - 52 - payload_length
    if sid_length < 8 or sid_length > 68:
        raise ValueError("invalid SID length in legacy domain backup payload")
    sid = payload[52:52 + sid_length]
    secret = payload[52 + sid_length:]
    if sid[0] != 1 or sid[1] > 15 or sid_length != 8 + 4 * sid[1]:
        raise ValueError("invalid SID in legacy domain backup payload")
    calculated_mac = hmac.new(
        hmac.new(server_key, r3, hashlib.sha1).digest(),
        sid + secret,
        hashlib.sha1,
    ).digest()
    if not hmac.compare_digest(supplied_mac, calculated_mac):
        raise ValueError("legacy domain backup payload MAC verification failed")
    if expected_sid is not None and binary_sid_to_string(sid) != expected_sid:
        raise ValueError("legacy domain backup payload SID does not match --sid")
    if len(secret) not in (20, 64):
        raise ValueError(
            f"legacy domain backup payload returned an unexpected {len(secret)}-byte masterkey"
        )
    return secret


def decrypt_masterkey_with_domain_backup(
    masterkey_file: bytes, backup_key, verbose: bool = False,
    expected_sid: str | None = None,
) -> bytes:
    if len(masterkey_file) < 128:
        raise ValueError("domain master-key file is shorter than its header")
    header = struct.unpack_from("<III72sIIIQQQQ", masterkey_file)
    master_length, backup_length, credhist_length, domain_length = header[7:11]
    domain_offset = 128 + master_length + backup_length + credhist_length
    if domain_length < 28 or domain_offset + domain_length > len(masterkey_file):
        raise ValueError("master-key file has no valid domain backup section")
    section = masterkey_file[domain_offset:domain_offset + domain_length]
    version, secret_length, access_length = struct.unpack_from("<III", section)
    if version not in (1, 2):
        raise ValueError(f"unsupported domain backup section version {version}")
    if version == 1:
        if not isinstance(backup_key, bytes):
            raise ValueError(
                "legacy domain backup section requires the collected 256-byte "
                "G$BCKUPKEY_* ServerWrap key"
            )
        cleartext = decrypt_serverwrap_domain_key(section, backup_key, expected_sid)
        if verbose:
            print("[+] decrypted master key with legacy AD ServerWrap backup key")
        return cleartext
    if 28 + secret_length + access_length > len(section):
        raise ValueError("invalid domain backup section lengths")
    if isinstance(backup_key, bytes):
        raise ValueError(
            "version-2 domain backup section requires the AD RSA private key/PVK"
        )
    secret = section[28:28 + secret_length]
    try:
        from cryptography.hazmat.primitives.asymmetric import padding

        cleartext = backup_key.decrypt(secret[::-1], padding.PKCS1v15())
    except ValueError:
        raise ValueError(
            "domain backup key could not decrypt this masterkey (wrong backup key?)"
        ) from None
    if len(cleartext) < 8:
        raise ValueError("decrypted domain masterkey structure is truncated")
    master_length, supplemental_length = struct.unpack_from("<II", cleartext)
    if (
        master_length not in (20, 64)
        or 8 + master_length + supplemental_length > len(cleartext)
    ):
        raise ValueError("invalid decrypted domain masterkey structure")
    if verbose:
        print("[+] decrypted master key with the domain backup key")
    return cleartext[8:8 + master_length]


def password_keys(sid: str, password: str):
    sid = sid.strip()
    sid_bytes = (sid + "\x00").encode("utf-16le")
    sid_without_nul = sid.encode("utf-16le")
    password_bytes = password.encode("utf-16le")
    nt_hash = md4(password_bytes)
    yield "SHA1(password)", hmac.new(
        hashlib.sha1(password_bytes).digest(), sid_bytes, "sha1"
    ).digest()
    yield "NT(password)", hmac.new(nt_hash, sid_bytes, "sha1").digest()
    protected = hashlib.pbkdf2_hmac(
        "sha256", nt_hash, sid_without_nul, 10000
    )
    protected = hashlib.pbkdf2_hmac(
        "sha256", protected, sid_without_nul, 1
    )[:16]
    yield "NT(password), Protected Users", hmac.new(
        protected, sid_bytes, "sha1"
    ).digest()


def userkey_keys(sid: str, user_key: bytes):
    """Derive user master-key prekeys from a DPAPI_SYSTEM/UserKey-style key."""
    sid = sid.strip()
    sid_bytes = (sid + "\x00").encode("utf-16le")
    sid_without_nul = sid.encode("utf-16le")
    yield "user key + SID", hmac.new(user_key, sid_bytes, "sha1").digest()
    if len(user_key) == 16:
        protected = hashlib.pbkdf2_hmac(
            "sha256", user_key, sid_without_nul, 10000
        )
        protected = hashlib.pbkdf2_hmac(
            "sha256", protected, sid_without_nul, 1
        )[:16]
        yield "user key + SID, Protected Users", hmac.new(
            protected, sid_bytes, "sha1"
        ).digest()


def classify_sid(sid: str) -> str:
    value = sid.strip()
    parts = value.split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        raise ValueError("SID must use canonical S-1-... form")
    try:
        numbers = [int(part, 10) for part in parts[1:]]
    except ValueError:
        raise ValueError("SID contains a non-decimal component") from None
    if numbers[0] != 1 or any(number < 0 or number > 0xFFFFFFFF for number in numbers[2:]):
        raise ValueError("unsupported or invalid SID")
    if value.upper().startswith("S-1-12-1-"):
        return "entra"
    if value.upper().startswith("S-1-5-21-"):
        return "account"
    if value.upper() in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
        return "service"
    if value.upper().startswith("S-1-5-80-"):
        return "service"
    return "other"


def validate_sid_context(args, emit=print) -> None:
    if args.pin is not None and args.type != "ngc-cng":
        raise ValueError("--pin is only valid with --type ngc-cng")
    if not args.sid:
        return
    sid_type = classify_sid(args.sid)
    args.sid_type = sid_type
    if sid_type == "entra":
        emit("[i] SID type: Entra ID/cloud account (S-1-12-1)")
        emit(
            "[i] the SID alone cannot show whether Windows Hello is software- "
            "or TPM-backed; inspect the NGC provider/key metadata"
        )
        emit(
            "[i] if this is a Hello/TPM-only profile, the classic DPAPI "
            "masterkey cannot be cracked from the SID/masterkey file: it does "
            "not contain a verifier for the PIN or TPM private key"
        )
        if args.domain_backup_key:
            raise ValueError(
                "an Entra-only SID cannot use the on-prem AD DPAPI domain backup key; "
                "use a recovered CloudAP prekey/credkey, clear masterkey, or the "
                "software NGC workflow where applicable"
            )
        if args.hashcat and args.type != "ngc-cng":
            emit(
                "[i] this DPAPI masterkey hash cannot crack the Windows Hello "
                "PIN or TPM key; it only tests password/credential-derived DPAPI "
                "candidates. Software PIN testing uses --type ngc-cng"
            )
    elif sid_type == "account" and args.verbose:
        emit(
            "[i] SID type: S-1-5-21 account; the SID alone cannot distinguish "
            "a local account from an on-prem AD account"
        )
    elif sid_type == "service" and args.verbose:
        emit("[i] SID type: Windows built-in/service account")


def parse_dpapi_system(value: str) -> list[tuple[str, bytes]]:
    """Read a DPAPI_SYSTEM LSA secret or its displayed text representation."""
    path = existing_file(value)
    raw = path.read_bytes() if path else value.encode("ascii")
    text_value = None
    try:
        text_value = raw.decode("ascii")
    except UnicodeDecodeError:
        pass

    if text_value is not None:
        import re

        named = []
        for label, pattern in (
            ("DPAPI_SYSTEM MachineKey", r"(?i)machinekey\s*:?\s*(?:0x)?([0-9a-f]{40})"),
            ("DPAPI_SYSTEM UserKey", r"(?i)userkey\s*:?\s*(?:0x)?([0-9a-f]{40})"),
        ):
            match = re.search(pattern, text_value)
            if match:
                named.append((label, bytes.fromhex(match.group(1))))
        if named:
            return named
        compact = text_value.strip()
        if compact[:4].lower() == "hex:":
            compact = compact[4:]
        if compact[:2].lower() == "0x":
            compact = compact[2:]
        # Accept the usual copied hex renderings without weakening the strict
        # length checks below.  Named secretsdump output is handled above.
        compact = re.sub(r"[\s:_-]", "", compact)
        if compact and len(compact) % 2 == 0 and all(
            character in string.hexdigits for character in compact
        ):
            raw = bytes.fromhex(compact)

    if len(raw) == 44:
        version = struct.unpack_from("<I", raw)[0]
        if version not in (1, 2):
            raise ValueError(f"unsupported DPAPI_SYSTEM version {version}")
        raw = raw[4:]
    if len(raw) == 40:
        return [
            ("DPAPI_SYSTEM MachineKey", raw[:20]),
            ("DPAPI_SYSTEM UserKey", raw[20:]),
        ]
    if len(raw) in (16, 20):
        return [("DPAPI_SYSTEM/user key", raw)]
    raise ValueError(
        "DPAPI_SYSTEM must be the full 44-byte secret, 40-byte "
        "MachineKey||UserKey, a 16/20-byte key, or secretsdump-style text"
    )


def dpapi_masterkey_kdf(
    hash_name: str, key: bytes, salt: bytes, rounds: int, length: int
) -> bytes:
    validate_kdf_rounds(rounds, "masterkey KDF")
    if length < 0 or length > 4096:
        raise ValueError(f"invalid masterkey KDF output length {length}")
    material = bytearray()
    block_number = 1
    while len(material) < length:
        derived = hmac.new(
            key, salt + struct.pack(">I", block_number), hash_name
        ).digest()
        block_number += 1
        for _ in range(rounds - 1):
            actual = hmac.new(key, derived, hash_name).digest()
            derived = bytes(left ^ right for left, right in zip(derived, actual))
        material.extend(derived)
    return bytes(material[:length])


def decrypt_masterkey_with_keys(
    masterkey: EncryptedMasterKey,
    candidate_keys,
    verbose: bool,
) -> bytes:
    hash_name, hmac_length, _ = hash_details(
        masterkey.hash_algo, masterkey=True
    )
    key_length, iv_length = cipher_details(masterkey.crypt_algo)
    for label, password_key in candidate_keys:
        derived = dpapi_masterkey_kdf(
            hash_name,
            password_key,
            masterkey.salt,
            masterkey.rounds,
            key_length + iv_length,
        )
        cleartext = cbc_decrypt(
            masterkey.data,
            derived[:key_length],
            derived[key_length:],
            masterkey.crypt_algo,
        )
        if len(cleartext) < 16 + hmac_length + 64:
            continue
        decrypted_key = cleartext[-64:]
        hmac_key = hmac.new(password_key, cleartext[:16], hash_name).digest()
        expected = hmac.new(hmac_key, decrypted_key, hash_name).digest()
        if hmac.compare_digest(
            cleartext[16:16 + hmac_length], expected[:hmac_length]
        ):
            if verbose:
                print(f"[+] decrypted master key with {label}")
            return decrypted_key
    raise ValueError("could not decrypt master key with the supplied prekeys")


def decrypt_masterkey(
    masterkey: EncryptedMasterKey, sid: str, password: str, verbose: bool
) -> bytes:
    try:
        return decrypt_masterkey_with_keys(
            masterkey, password_keys(sid, password), verbose
        )
    except ValueError:
        raise ValueError(
            "could not decrypt master key: check the SID and password"
        ) from None


def hashcat_masterkey_record(
    masterkey: EncryptedMasterKey, sid: str, context: str
) -> tuple[int, str]:
    """Return Hashcat mode and a $DPAPImk$ record for one master-key section."""
    if (
        masterkey.crypt_algo == CALG_3DES
        and masterkey.hash_algo in (CALG_SHA1, CALG_HMAC)
    ):
        format_version = 1
        mode = 15310 if context == "domain-new" else 15300
    elif (
        masterkey.crypt_algo == CALG_AES_256
        and masterkey.hash_algo == CALG_SHA_512
    ):
        format_version = 2
        mode = 15910 if context == "domain-new" else 15900
    else:
        raise ValueError(
            "Hashcat supports DPAPI masterkeys using 3DES/SHA1 or AES-256/SHA-512"
        )
    context_number = {"local": 1, "domain": 2, "domain-new": 3}[context]
    cipher_name = "des3" if masterkey.crypt_algo == CALG_3DES else "aes256"
    hash_name = (
        "sha1"
        if masterkey.hash_algo in (CALG_SHA1, CALG_HMAC)
        else "sha512"
    )
    ciphertext = masterkey.data.hex()
    record = (
        f"$DPAPImk${format_version}*{context_number}*{sid}*{cipher_name}*"
        f"{hash_name}*{masterkey.rounds}*{masterkey.salt.hex()}*"
        f"{len(ciphertext)}*{ciphertext}"
    )
    return mode, record


def read_data(value: str, label: str) -> tuple[bytes, Path | None, bool]:
    source_path = None
    if value == "-":
        raw = sys.stdin.buffer.read()
    else:
        path = existing_file(value)
        if path:
            source_path = path
            raw = path.read_bytes()
        else:
            compact = "".join(value.removeprefix("0x").split())
            try:
                return bytes.fromhex(compact), None, True
            except ValueError as exc:
                raise ValueError(
                    f"{label} is neither a readable file nor valid hex"
                ) from exc

    was_hex = False
    text = None
    for encoding in ("ascii", "utf-8-sig", "utf-16"):
        try:
            text = raw.decode(encoding)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if text is not None:
        compact = "".join(text.strip().removeprefix("0x").split())
        if (
            compact
            and len(compact) % 2 == 0
            and all(character in string.hexdigits for character in compact)
        ):
            raw = bytes.fromhex(compact)
            was_hex = True
    if not raw:
        raise ValueError(f"{label} is empty")
    return raw, source_path, was_hex


def read_real_masterkey(value: str) -> tuple[bytes, Path | None]:
    """Read an already-decrypted DPAPI masterkey from raw, hex, or Base64."""
    source_path = existing_file(value)
    raw = source_path.read_bytes() if source_path else value.encode("ascii")
    try:
        text_value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        key = raw
    else:
        compact = "".join(text_value.removeprefix("0x").split())
        if compact and len(compact) % 2 == 0 and all(
            character in string.hexdigits for character in compact
        ):
            key = bytes.fromhex(compact)
        else:
            try:
                key = base64.b64decode("".join(text_value.split()), validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    "real masterkey is neither raw binary, valid hex, nor Base64"
                ) from exc
    if len(key) not in (20, 64):
        raise ValueError(
            f"real masterkey must be exactly 20 or 64 bytes (got {len(key)})"
        )
    return key, source_path


def read_entropy(args) -> bytes | None:
    cached = getattr(args, "_resolved_entropy", None)
    if cached is not None:
        return cached
    if args.entropy_file:
        path = Path(args.entropy_file)
        if not path.is_file():
            raise ValueError("--entropy-file must be a readable file")
        value = path.read_bytes()
    elif args.entropy is not None:
        supplied = args.entropy
        if supplied.startswith("hex:"):
            try:
                value = bytes.fromhex("".join(supplied[4:].split()))
            except ValueError:
                raise ValueError("--entropy hex: value is not valid hex") from None
        elif supplied.startswith("base64:"):
            try:
                value = base64.b64decode(
                    "".join(supplied[7:].split()), validate=True
                )
            except (ValueError, TypeError):
                raise ValueError("--entropy base64: value is not valid Base64") from None
        elif supplied.startswith("utf16:"):
            value = supplied[6:].encode("utf-16le")
        else:
            value = supplied.encode("utf-8")
    else:
        return None
    if not value:
        raise ValueError("optional entropy must not be empty")
    args._resolved_entropy = value
    return value


def effective_entropy(args, built_in: bytes | None = None) -> bytes | None:
    supplied = read_entropy(args)
    return supplied if supplied is not None else built_in


def read_vault_keys(value: str) -> list[bytes]:
    path = existing_file(value)
    if path:
        raw = path.read_bytes()
        try:
            document = json.loads(raw)
            values = document.get("aes_keys", [])
            keys = [bytes.fromhex(item) for item in values]
            if keys and all(len(key) in (16, 24, 32) for key in keys):
                return keys
        except (UnicodeDecodeError, ValueError, TypeError, AttributeError):
            pass
    raw, _, _ = read_data(value, "Vault AES key")
    if len(raw) not in (16, 24, 32):
        raise ValueError("Vault AES key must contain 16, 24, or 32 bytes")
    return [raw]


def xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def xml_first_text(element, name: str) -> str | None:
    for child in element.iter():
        if xml_local_name(child.tag) == name and child.text is not None:
            return child.text.strip()
    return None


def xml_direct_text(element, name: str) -> str | None:
    for child in element:
        if xml_local_name(child.tag) == name and child.text is not None:
            return child.text.strip()
    return None


def decode_secret_text(data: bytes, preferred: str | None = None) -> str:
    encodings = [preferred] if preferred else []
    looks_utf16 = len(data) >= 2 and data[1::2].count(0) >= max(1, len(data[1::2]) // 2)
    encodings.extend(("utf-16le", "utf-8") if looks_utf16 else ("utf-8", "utf-16le"))
    for encoding in dict.fromkeys(encodings):
        try:
            value = data.decode(encoding).rstrip("\x00")
        except UnicodeDecodeError:
            continue
        if value and all(character.isprintable() or character.isspace() for character in value):
            return value
    return data.hex()


def parse_wifi_profile(data: bytes) -> dict:
    root = safe_xml_fromstring(data, "Wi-Fi profile")
    name = xml_first_text(root, "name")
    key_material = xml_first_text(root, "keyMaterial")
    protected_text = xml_first_text(root, "protected")
    protected = (
        None if protected_text is None else protected_text.casefold() in ("true", "1", "yes")
    )
    enterprise = any(xml_local_name(item.tag) == "EAPConfig" for item in root.iter())
    result = {
        "ssid": name,
        "enterprise": enterprise,
        "protected": protected,
        "blob": None,
    }
    if key_material:
        if protected is False:
            result["password"] = key_material
            return result
        compact = "".join(key_material.split())
        try:
            field = bytes.fromhex(compact)
        except ValueError:
            result["password"] = key_material
            return result
        if protected is None and not field.startswith(DPAPI_HEADER):
            result["password"] = key_material
            return result
        blob, consumed = parse_dpapi_blob(field)
        if consumed != len(field):
            raise ValueError("Wi-Fi keyMaterial has trailing bytes")
        result["blob"] = LocatedBlob(0, consumed, blob, label="Wi-Fi keyMaterial")
    return result


def parse_rdcman(data: bytes) -> list[dict]:
    root = safe_xml_fromstring(data, "RDCMan")
    parents = {child: parent for parent in root.iter() for child in parent}
    profiles = []
    for element in root.iter():
        element_type = xml_local_name(element.tag)
        if element_type not in ("credentialsProfile", "logonCredentials"):
            continue
        password = xml_direct_text(element, "password")
        if not password:
            continue
        try:
            field = base64.b64decode(password, validate=True)
            blob, consumed = parse_dpapi_blob(field)
        except (ValueError, TypeError):
            continue
        if consumed != len(field):
            continue
        scope = None
        cursor = parents.get(element)
        while cursor is not None:
            ancestor_type = xml_local_name(cursor.tag)
            if ancestor_type in ("server", "group"):
                ancestor_name = xml_first_text(cursor, "name")
                scope = f"{ancestor_type}:{ancestor_name}" if ancestor_name else ancestor_type
                break
            cursor = parents.get(cursor)
        profiles.append(
            {
                "kind": element_type,
                "scope": scope,
                "profile": xml_direct_text(element, "profileName"),
                "username": xml_direct_text(element, "userName"),
                "domain": xml_direct_text(element, "domain"),
                "blob": LocatedBlob(0, consumed, blob, label="RDCMan password"),
            }
        )
    if not profiles:
        raise ValueError("RDCMan file contains no Base64 DPAPI credential profiles")
    return profiles


def parse_powershell_clixml(data: bytes) -> dict:
    stripped = data.lstrip()
    if stripped.startswith(b"#< CLIXML"):
        newline = stripped.find(b"\n")
        if newline < 0:
            raise ValueError("PowerShell CLIXML has no XML document")
        stripped = stripped[newline + 1:]
    root = safe_xml_fromstring(stripped, "PowerShell CLIXML")
    if xml_local_name(root.tag) != "Objs":
        raise ValueError("PowerShell CLIXML root is not <Objs>")
    username = None
    secrets = []
    for element in root.iter():
        local_name = xml_local_name(element.tag)
        property_name = element.attrib.get("N") or element.attrib.get("Name")
        if (
            local_name == "S"
            and property_name
            and property_name.casefold() in ("username", "user", "login")
            and element.text is not None
            and username is None
        ):
            username = element.text
        if local_name != "SS" or element.text is None:
            continue
        compact = "".join(element.text.split())
        try:
            field = bytes.fromhex(compact)
            blob, consumed = parse_dpapi_blob(field)
        except ValueError:
            continue
        if consumed != len(field):
            continue
        secrets.append(
            {
                "name": property_name or f"SecureString {len(secrets) + 1}",
                "blob": LocatedBlob(0, consumed, blob, label="PowerShell SecureString"),
            }
        )
    if not secrets:
        raise ValueError("PowerShell CLIXML contains no DPAPI-protected <SS> values")
    return {"username": username, "secrets": secrets}


def parse_sccm_policy_secrets(data: bytes) -> list[dict]:
    pattern = re.compile(
        rb'<PolicySecret\s+Version\s*=\s*["\']1["\']\s*>\s*'
        rb'<!\[CDATA\[([0-9A-Fa-f\s]{1,'
        + str(MAX_SCCM_SECRET_TEXT).encode("ascii")
        + rb'})\]\]>\s*</PolicySecret\s*>',
        re.IGNORECASE,
    )
    candidates = []
    for match in pattern.finditer(data):
        if len(candidates) >= MAX_SCCM_POLICY_SECRETS:
            raise ValueError(
                f"SCCM input contains more than {MAX_SCCM_POLICY_SECRETS} PolicySecret values"
            )
        candidates.append((match.start(), match.group(1)))
    if not candidates:
        candidates = [(0, data)]
    secrets = []
    for source_offset, payload in candidates:
        try:
            if payload is data:
                decoded = payload
            else:
                decoded = bytes.fromhex(payload.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            continue
        blob_offset = decoded.find(DPAPI_HEADER)
        if blob_offset < 0:
            continue
        try:
            blob, consumed = parse_dpapi_blob(decoded[blob_offset:])
        except ValueError:
            continue
        secrets.append(
            {
                "source_offset": source_offset,
                "wrapper_prefix": decoded[:blob_offset],
                "blob": LocatedBlob(
                    blob_offset,
                    consumed,
                    blob,
                    label="SCCM PolicySecret",
                ),
            }
        )
    if not secrets:
        raise ValueError("input contains no valid SCCM PolicySecret DPAPI values")
    return secrets


def decode_rdp_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    elif len(data) >= 4 and data[1::2].count(0) >= len(data[1::2]) // 2:
        encoding = "utf-16le"
    else:
        encoding = "utf-8-sig"
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid .rdp text encoding: {exc}") from None


def parse_rdp_file(data: bytes) -> list[dict]:
    fields = {}
    passwords = []
    for line in decode_rdp_text(data).splitlines():
        parts = line.strip().split(":", 2)
        if len(parts) != 3:
            continue
        name, value_type, value = parts
        normalized = name.strip().lower()
        fields[normalized] = value.strip()
        if value_type.lower() != "b" or not normalized.endswith("password 51"):
            continue
        try:
            encrypted = bytes.fromhex("".join(value.split()))
            blob, consumed = parse_dpapi_blob(encrypted)
        except ValueError:
            continue
        if consumed != len(encrypted):
            continue
        passwords.append(
            {
                "field": name.strip(),
                "blob": LocatedBlob(0, consumed, blob, label=f"RDP {name.strip()}"),
            }
        )
    if not passwords:
        raise ValueError(".rdp file contains no valid password 51:b DPAPI value")
    context = {
        "address": fields.get("full address"),
        "username": fields.get("username"),
        "domain": fields.get("domain"),
        "gateway": fields.get("gatewayhostname"),
    }
    for item in passwords:
        item.update(context)
    return passwords


def peap_identity(data: bytes) -> tuple[str | None, str | None]:
    marker = b"\x04\x00\x00\x00\x02\x00\x00\x00"
    offset = data.find(marker)
    if offset < 0:
        return None, None
    values = data[offset + len(marker):].split(b"\x00", 2)
    username = values[0].decode("utf-8", errors="replace") if values else None
    domain = values[1].decode("utf-8", errors="replace") if len(values) > 1 else None
    return username or None, domain or None


def parse_outlook_hive(path: Path) -> list[dict]:
    try:
        from Registry import Registry
    except ImportError:
        raise ValueError(
            "reading NTUSER.DAT requires python-registry; alternatively export the "
            "binary 'IMAP Password' value and pass that file/hex to --type outlook"
        ) from None
    hive = Registry.Registry(str(path))
    office = hive.open("Software\\Microsoft\\Office")
    versions = []
    for key in office.subkeys():
        try:
            versions.append((tuple(int(part) for part in key.name().split(".")), key.name()))
        except ValueError:
            pass
    if not versions:
        raise ValueError("NTUSER.DAT has no numeric Microsoft Office version keys")
    version = max(versions)[1]
    profiles = hive.open(
        f"Software\\Microsoft\\Office\\{version}\\Outlook\\Profiles"
    )
    accounts = []
    for profile in profiles.subkeys():
        try:
            provider = profile.subkey("9375CFF0413111d3B88A00104B2A6676")
        except Registry.RegistryKeyNotFoundException:
            continue
        for account in provider.subkeys():
            values = {value.name().lower(): value.value() for value in account.values()}
            encrypted = values.get("imap password")
            if not isinstance(encrypted, bytes) or not encrypted:
                continue
            if encrypted[0] == 2:
                encrypted = encrypted[1:]
            try:
                blob, consumed = parse_dpapi_blob(encrypted)
            except ValueError:
                continue
            accounts.append(
                {
                    "profile": profile.name(),
                    "account": values.get("account name"),
                    "display_name": values.get("display name"),
                    "email": values.get("email"),
                    "blob": LocatedBlob(0, consumed, blob, label="Outlook IMAP password"),
                }
            )
    if not accounts:
        raise ValueError("no DPAPI-protected Outlook IMAP Password values found")
    return accounts


def resolve_masterkey_value(
    value: str,
    args,
    target_guids: set[uuid.UUID],
    *,
    system: bool = False,
) -> bytes:
    data, _, _ = read_data(value, "master key")
    try:
        encrypted = parse_masterkey_file(data)
    except ValueError:
        if len(data) not in (20, 64):
            raise ValueError(
                "master key must be an encrypted master-key file/hex or a "
                "20/64-byte decrypted key"
            ) from None
        return data

    if encrypted.file_guid and encrypted.file_guid not in target_guids:
        required = ", ".join(str(value) for value in sorted(target_guids, key=str))
        raise ValueError(
            f"master-key GUID {encrypted.file_guid} does not match required {required}"
        )

    if args.prekey:
        prekey, _, _ = read_data(args.prekey, "DPAPI prekey")
        if len(prekey) != 20:
            raise ValueError("--prekey must contain exactly 20 bytes")
        return decrypt_masterkey_with_keys(
            encrypted, [("supplied SID-bound prekey", prekey)], args.verbose
        )

    if args.credkey:
        if not args.sid:
            raise ValueError("--sid is required with --credkey")
        credkey, _, _ = read_data(args.credkey, "DPAPI credential key")
        if not 16 <= len(credkey) <= 128:
            raise ValueError("--credkey must contain between 16 and 128 bytes")
        credkey_sha1 = credkey if len(credkey) == 20 else hashlib.sha1(credkey).digest()
        return decrypt_masterkey_with_keys(
            encrypted,
            userkey_keys(args.sid, credkey_sha1),
            args.verbose,
        )

    if args.nt_hash:
        if not args.sid:
            raise ValueError("--sid is required with --nt-hash")
        nt_hash, _, _ = read_data(args.nt_hash, "NT hash")
        if len(nt_hash) != 16:
            raise ValueError("--nt-hash must contain exactly 16 bytes")
        return decrypt_masterkey_with_keys(
            encrypted, userkey_keys(args.sid, nt_hash), args.verbose
        )

    if args.sha1_hash:
        if not args.sid:
            raise ValueError("--sid is required with --sha1-hash")
        sha1_hash, _, _ = read_data(args.sha1_hash, "local SHA1 password hash")
        if len(sha1_hash) != 20:
            raise ValueError(
                "--sha1-hash must contain exactly 20 bytes: "
                "SHA1(password encoded as UTF-16LE)"
            )
        return decrypt_masterkey_with_keys(
            encrypted, userkey_keys(args.sid, sha1_hash), args.verbose
        )

    if args.domain_backup_key:
        private_key = getattr(args, "_domain_private_key", None)
        if private_key is None:
            private_key = load_domain_backup_key(
                args.domain_backup_key, pvk_password(args)
            )
            args._domain_private_key = private_key
        return decrypt_masterkey_with_domain_backup(
            data, private_key, args.verbose, args.sid
        )

    if system:
        if not args.dpapi_system:
            raise ValueError(
                "an encrypted SYSTEM master-key file requires --dpapi-system"
            )
        system_keys = parse_dpapi_system(args.dpapi_system)
        candidates = list(system_keys)
        if args.sid:
            for label, key in system_keys:
                for derived_label, derived in userkey_keys(args.sid, key):
                    candidates.append((f"{label}, {derived_label}", derived))
        return decrypt_masterkey_with_keys(encrypted, candidates, args.verbose)

    if args.dpapi_system and args.password is None:
        system_keys = parse_dpapi_system(args.dpapi_system)
        candidates = list(system_keys)
        if args.sid:
            for label, key in system_keys:
                for derived_label, derived in userkey_keys(args.sid, key):
                    candidates.append((f"{label}, {derived_label}", derived))
        try:
            return decrypt_masterkey_with_keys(encrypted, candidates, args.verbose)
        except ValueError:
            if not args.sid:
                raise ValueError(
                    "DPAPI_SYSTEM did not decrypt this master key; add --sid if it "
                    "is a service-account master key"
                ) from None

    if not args.sid:
        raise ValueError(
            "--sid is required for a password-protected encrypted master-key file"
        )
    password = args.password
    if password is None:
        password = getpass.getpass("Master-key password: ")
    return decrypt_masterkey(encrypted, args.sid, password, args.verbose)


def has_masterkey(args) -> bool:
    return bool(args.masterkey or args.real_masterkey or args.masterkey_dir)


def resolve_masterkey(
    args, target_guids: set[uuid.UUID], *, system: bool = False
) -> bytes:
    if args.masterkey_dir:
        keys = {
            resolve_masterkey_for_guid(args, guid, system=system)
            for guid in target_guids
        }
        if len(keys) != 1:
            raise ValueError(
                "the artifact uses multiple masterkeys; resolve each blob by GUID"
            )
        return keys.pop()
    if args.real_masterkey:
        key, _ = read_real_masterkey(args.real_masterkey)
        return key
    return resolve_masterkey_value(
        args.masterkey, args, target_guids, system=system
    )


def resolve_masterkey_for_guid(
    args, guid: uuid.UUID, *, system: bool = False
) -> bytes:
    if args.real_masterkey:
        key, _ = read_real_masterkey(args.real_masterkey)
        return key
    if not args.masterkey_dir:
        return resolve_masterkey(args, {guid}, system=system)

    state = getattr(args, "_directory_masterkey_state", None)
    if state is None:
        state = {"cache": {}, "fallback": None, "results": [], "scanned": set()}
        args._directory_masterkey_state = state
    if guid not in state["cache"] and guid not in state["scanned"]:
        cache, fallback, results = build_masterkey_cache(args, {guid}, system=system)
        state["cache"].update(cache)
        if state["fallback"] is None:
            state["fallback"] = fallback
        state["results"].extend(results)
        state["scanned"].add(guid)
    try:
        return cached_masterkey(state["cache"], state["fallback"], guid)
    except ValueError:
        errors = [item for item in state["results"] if item["status"] == "error"]
        detail = errors[-1]["error"] if errors else "matching GUID file was not found"
        raise ValueError(
            f"could not resolve masterkey {guid} from --masterkey-dir: {detail}"
        ) from None


def decrypt_located_items_partial(
    args,
    items: list[LocatedBlob],
    emit=lambda *_: None,
    *,
    system: bool = False,
    item_label: str = "item",
) -> tuple[list[tuple[int, bytes]], list[dict]]:
    """Decrypt independent DPAPI items without discarding successful siblings.

    A missing/wrong masterkey or one malformed ciphertext is recorded against
    that item. The caller still receives every successfully decrypted value. If
    none succeed, retain the traditional hard-failure behavior so an operation
    is never reported as successful with no recovered data.
    """
    recovered: list[tuple[int, bytes]] = []
    errors: list[dict] = []
    for index, located in enumerate(items, 1):
        guid = located.blob.masterkey_guid
        try:
            masterkey = resolve_masterkey_for_guid(args, guid, system=system)
            cleartext = decrypt_dpapi_blob(
                located.blob,
                masterkey,
                effective_entropy(args, located.entropy),
            )
        except (OSError, ValueError) as exc:
            failure = {
                "index": index,
                "masterkey_guid": str(guid),
                "error": str(exc),
            }
            errors.append(failure)
            emit(f"[!] {item_label} {index} ({guid}) was not decrypted: {exc}")
            continue
        recovered.append((index - 1, cleartext))
    if not recovered:
        detail = errors[-1]["error"] if errors else "no decryptable values found"
        raise ValueError(
            f"could not decrypt any of {len(items)} {item_label}(s): {detail}"
        )
    if errors:
        emit(
            f"[!] partial result: decrypted {len(recovered)} of {len(items)} "
            f"{item_label}(s); {len(errors)} failed"
        )
    return recovered, errors


def capi_rsa_to_pem(data: bytes) -> bytes | None:
    """Convert a decrypted CAPI RSA2 private-key blob to PKCS#1 PEM."""
    if len(data) < 20 or data[:4] != b"RSA2":
        return None
    component_stride, bit_length = struct.unpack_from("<II", data, 4)
    modulus_length = bit_length // 8
    if (
        bit_length % 16
        or modulus_length < 64
        or component_stride < modulus_length
        or component_stride % 2
    ):
        return None
    component_length = modulus_length // 2
    component_half_stride = component_stride // 2
    expected = 20 + component_stride * 2 + component_half_stride * 5
    if len(data) < expected:
        return None
    public_exponent = int.from_bytes(data[16:20], "little")
    offset = 20

    def integer(size, stride):
        nonlocal offset
        value = int.from_bytes(data[offset:offset + size], "little")
        offset += stride
        return value

    modulus = integer(modulus_length, component_stride)
    prime1 = integer(component_length, component_half_stride)
    prime2 = integer(component_length, component_half_stride)
    exponent1 = integer(component_length, component_half_stride)
    exponent2 = integer(component_length, component_half_stride)
    coefficient = integer(component_length, component_half_stride)
    private_exponent = integer(modulus_length, component_stride)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.RSAPrivateNumbers(
            prime1,
            prime2,
            private_exponent,
            exponent1,
            exponent2,
            coefficient,
            rsa.RSAPublicNumbers(public_exponent, modulus),
        ).private_key()
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    except (ImportError, ValueError):
        return None


def cng_rsa_to_pem(data: bytes) -> bytes | None:
    """Convert a BCRYPT_RSAPRIVATE_BLOB/RSAFULLPRIVATE_BLOB to PKCS#1 PEM."""
    if len(data) < 24 or data[:4] not in (b"RSA2", b"RSA3"):
        return None
    (
        _magic,
        bit_length,
        exponent_length,
        modulus_length,
        prime1_length,
        prime2_length,
    ) = struct.unpack_from("<6I", data)
    required = (
        24
        + exponent_length
        + modulus_length
        + prime1_length
        + prime2_length
    )
    if (
        bit_length != modulus_length * 8
        or not exponent_length
        or prime1_length == 0
        or prime2_length == 0
        or required > len(data)
    ):
        return None

    offset = 24

    def integer(size):
        nonlocal offset
        value = int.from_bytes(data[offset:offset + size], "big")
        offset += size
        return value

    public_exponent = integer(exponent_length)
    modulus = integer(modulus_length)
    prime1 = integer(prime1_length)
    prime2 = integer(prime2_length)
    if modulus != prime1 * prime2:
        return None
    try:
        private_exponent = pow(
            public_exponent, -1, math.lcm(prime1 - 1, prime2 - 1)
        )
        exponent1 = private_exponent % (prime1 - 1)
        exponent2 = private_exponent % (prime2 - 1)
        coefficient = pow(prime2, -1, prime1)

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.RSAPrivateNumbers(
            prime1,
            prime2,
            private_exponent,
            exponent1,
            exponent2,
            coefficient,
            rsa.RSAPublicNumbers(public_exponent, modulus),
        ).private_key()
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    except (ImportError, ValueError):
        return None


def cng_ecc_to_pem(data: bytes) -> bytes | None:
    """Convert a BCRYPT_ECCPRIVATE_BLOB to PKCS#8 PEM."""
    if len(data) < 8:
        return None
    magic, key_length = struct.unpack_from("<II", data)
    curves = {
        0x324B4345: (32, "secp256r1"),  # ECK2: ECDH P-256 private
        0x344B4345: (48, "secp384r1"),  # ECK4: ECDH P-384 private
        0x364B4345: (66, "secp521r1"),  # ECK6: ECDH P-521 private
        0x32534345: (32, "secp256r1"),  # ECS2: ECDSA P-256 private
        0x34534345: (48, "secp384r1"),  # ECS4: ECDSA P-384 private
        0x36534345: (66, "secp521r1"),  # ECS6: ECDSA P-521 private
    }
    details = curves.get(magic)
    if details is None or key_length != details[0] or len(data) < 8 + key_length * 3:
        return None
    offset = 8
    x = int.from_bytes(data[offset:offset + key_length], "big")
    offset += key_length
    y = int.from_bytes(data[offset:offset + key_length], "big")
    offset += key_length
    private_value = int.from_bytes(data[offset:offset + key_length], "big")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        curve = getattr(ec, details[1].upper(), None)
        if curve is None:
            curve = {
                "secp256r1": ec.SECP256R1,
                "secp384r1": ec.SECP384R1,
                "secp521r1": ec.SECP521R1,
            }[details[1]]
        key = ec.derive_private_key(private_value, curve())
        public = key.public_key().public_numbers()
        if public.x != x or public.y != y:
            return None
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    except (ImportError, ValueError):
        return None


def cng_dsa_to_pem(data: bytes) -> bytes | None:
    """Convert the 512-1024 bit BCRYPT_DSA_PRIVATE_BLOB form to PEM."""
    if len(data) < 52:
        return None
    magic, key_length = struct.unpack_from("<II", data)
    if magic != 0x56505344 or not 64 <= key_length <= 128:
        return None
    required = 52 + key_length * 3 + 20
    if len(data) < required:
        return None
    q = int.from_bytes(data[32:52], "big")
    offset = 52
    p = int.from_bytes(data[offset:offset + key_length], "big")
    offset += key_length
    g = int.from_bytes(data[offset:offset + key_length], "big")
    offset += key_length
    y = int.from_bytes(data[offset:offset + key_length], "big")
    offset += key_length
    x = int.from_bytes(data[offset:offset + 20], "big")
    if not all((p, q, g, y, x)) or pow(g, x, p) != y:
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import dsa

        public = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g))
        key = dsa.DSAPrivateNumbers(x, public).private_key()
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    except (ImportError, ValueError):
        return None


def capi_dss_to_pem(data: bytes) -> bytes | None:
    """Convert the decrypted DSS2 private-key body from a CAPI container."""
    if len(data) < 8 or data[:4] != b"DSS2":
        return None
    bit_length = struct.unpack_from("<I", data, 4)[0]
    key_length = bit_length // 8
    required = 8 + key_length + 20 + key_length + 20
    if bit_length % 64 or not 64 <= key_length <= 128 or len(data) < required:
        return None
    offset = 8
    p = int.from_bytes(data[offset:offset + key_length], "little")
    offset += key_length
    q = int.from_bytes(data[offset:offset + 20], "little")
    offset += 20
    g = int.from_bytes(data[offset:offset + key_length], "little")
    offset += key_length
    x = int.from_bytes(data[offset:offset + 20], "little")
    if not all((p, q, g, x)):
        return None
    y = pow(g, x, p)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import dsa

        public = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g))
        key = dsa.DSAPrivateNumbers(x, public).private_key()
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    except (ImportError, ValueError):
        return None


def private_key_to_pem(data: bytes, container_type: str) -> bytes | None:
    converters = (
        (capi_rsa_to_pem, capi_dss_to_pem)
        if container_type == "capi"
        else (cng_rsa_to_pem, cng_ecc_to_pem, cng_dsa_to_pem)
    )
    for converter in converters:
        pem = converter(data)
        if pem is not None:
            return pem
    return None


def filetime_to_iso(value: int) -> str | None:
    if not value:
        return None
    try:
        unix_seconds = (value - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(unix_seconds, timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return f"filetime:{value}"


def decoded_value(data: bytes) -> str:
    if not data:
        return ""
    if len(data) % 2 == 0:
        try:
            text = data.decode("utf-16le").rstrip("\x00")
            if text and all(character.isprintable() or character.isspace() for character in text):
                return text
        except UnicodeDecodeError:
            pass
    data = data.rstrip(b"\x00")
    if not data:
        return ""
    try:
        text = data.decode("utf-8").rstrip("\x00")
        if text and all(character.isprintable() or character.isspace() for character in text):
            return text
    except UnicodeDecodeError:
        pass
    return f"hex:{data.hex()}"


def parse_credential_plaintext(data: bytes) -> dict:
    reader = ByteReader(data)
    flags = reader.u32("credential flags")
    declared_size = reader.u32("credential size")
    reader.u32("credential unknown 0")
    credential_type = reader.u32("credential type")
    flags2 = reader.u32("credential flags 2")
    last_written = struct.unpack("<Q", reader.take(8, "credential timestamp"))[0]
    reader.u32("credential unknown 2")
    persistence = reader.u32("credential persistence")
    attribute_count = reader.u32("credential attribute count")
    reader.take(8, "credential unknown 3")

    target = reader.length_prefixed("credential target")
    target_alias = reader.length_prefixed("credential target alias")
    description = reader.length_prefixed("credential description")
    unknown = reader.length_prefixed("credential unknown value")
    username = reader.length_prefixed("credential username")
    credential = reader.length_prefixed("credential secret")

    attributes = []
    for index in range(attribute_count):
        attribute_flags = reader.u32(f"credential attribute {index + 1} flags")
        keyword = reader.length_prefixed(
            f"credential attribute {index + 1} keyword"
        )
        value = reader.length_prefixed(f"credential attribute {index + 1} value")
        attributes.append(
            {
                "flags": attribute_flags,
                "keyword": decoded_value(keyword),
                "value": decoded_value(value),
            }
        )
    if reader.offset != len(data):
        raise ValueError(
            f"Credential plaintext has {len(data) - reader.offset} trailing bytes"
        )
    if declared_size not in (0, len(data)):
        raise ValueError(
            f"Credential plaintext declares {declared_size} bytes but has {len(data)}"
        )
    return {
        "type": CREDENTIAL_TYPES.get(credential_type, credential_type),
        "persistence": CREDENTIAL_PERSISTENCE.get(persistence, persistence),
        "last_written": filetime_to_iso(last_written),
        "flags": flags,
        "flags2": flags2,
        "target": decoded_value(target),
        "target_alias": decoded_value(target_alias),
        "description": decoded_value(description),
        "username": decoded_value(username),
        "credential": decoded_value(credential),
        "unknown": decoded_value(unknown),
        "attributes": attributes,
    }


def vault_attribute_ciphertext(attribute: dict) -> tuple[bytes, bytes] | None:
    raw = attribute["data"]
    if len(raw) <= 20:
        return None
    attribute_id = struct.unpack_from("<I", raw)[0]
    offset = 16
    if raw[offset:offset + 6] == b"\x00" * 6:
        offset += 6
    if attribute_id >= 100:
        offset += 4
    if offset + 5 > len(raw):
        return None
    size = struct.unpack_from("<I", raw, offset)[0]
    offset += 4
    iv_present = raw[offset] != 0
    offset += 1
    if iv_present:
        if offset + 4 > len(raw):
            return None
        iv_size = struct.unpack_from("<I", raw, offset)[0]
        offset += 4
        if iv_size != 16 or offset + iv_size > len(raw) or size < iv_size + 5:
            return None
        iv = raw[offset:offset + iv_size]
        offset += iv_size
        data_size = size - iv_size - 5
    else:
        iv = b"\x00" * 16
        if size < 1:
            return None
        data_size = size - 1
    ciphertext = raw[offset:offset + data_size]
    if len(ciphertext) != data_size or not ciphertext or len(ciphertext) % 16:
        return None
    return iv, ciphertext


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            raise ValueError("install cryptography or pycryptodome") from None
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def parse_vault_schema(data: bytes, friendly_name: str) -> dict:
    reader = ByteReader(data)
    version = reader.u32("Vault schema version")
    count = reader.u32("Vault schema field count")
    reader.u32("Vault schema unknown")
    if version > 16 or not 1 <= count <= 32:
        raise ValueError("invalid decrypted Vault schema header")
    values = []
    ids = []
    for index in range(count):
        field_id = reader.u32(f"Vault schema field {index + 1} ID")
        size = reader.u32(f"Vault schema field {index + 1} size")
        if field_id > 0x10000:
            raise ValueError("invalid decrypted Vault schema field ID")
        ids.append(field_id)
        values.append(reader.take(size, f"Vault schema field {index + 1}"))
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate decrypted Vault schema field IDs")

    name = friendly_name.rstrip("\x00")
    if name == "Internet Explorer" and len(values) >= 3:
        return {
            "identity": decoded_value(values[0]),
            "resource": decoded_value(values[1]),
            "authenticator": decoded_value(values[2]),
        }
    if name == "WinBio Key" and len(values) >= 3:
        return {
            "sid": f"hex:{values[0].hex()}",
            "friendly_name": decoded_value(values[1]),
            "biometric_key": decoded_value(values[2]),
        }
    return {
        f"field_{field_id}": decoded_value(value)
        for field_id, value in zip(ids, values)
    }


def decrypt_vault_record(record: dict, keys: list[bytes]) -> dict:
    attributes = sorted(
        record["attributes"], key=lambda item: item["id"] < 100
    )
    for key in sorted(keys, key=len, reverse=True):
        if len(key) not in (16, 24, 32):
            continue
        for attribute in attributes:
            encrypted = vault_attribute_ciphertext(attribute)
            if encrypted is None:
                continue
            iv, ciphertext = encrypted
            cleartext = aes_cbc_decrypt(ciphertext, key, iv)
            try:
                values = parse_vault_schema(cleartext, record["friendly_name"])
            except ValueError:
                continue
            return {
                "schema_guid": record["schema_guid"],
                "friendly_name": record["friendly_name"],
                "last_written": record["last_written"],
                "attribute_id": attribute["id"],
                **values,
            }
    raise ValueError("could not decrypt a valid Vault record with the supplied AES keys")


def printable_text(data: bytes) -> bool:
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(value) and all(character.isprintable() or character.isspace() for character in value)


def explicit_output_format(data: bytes, output_format: str):
    if output_format == "auto":
        return None
    if output_format == "raw":
        return data, ".bin"
    if output_format == "hex":
        return data.hex().encode("ascii") + b"\n", ".hex"
    if output_format == "utf16-utf8":
        try:
            text = data.decode("utf-16le").rstrip("\x00")
        except UnicodeDecodeError:
            raise ValueError("decrypted output is not valid UTF-16LE") from None
        return text.encode("utf-8"), ".txt"
    if output_format == "unhex":
        try:
            if len(data) >= 2 and data[1::2].count(0) >= max(1, len(data[1::2]) // 2):
                text = data.decode("utf-16le").rstrip("\x00")
            else:
                text = data.decode("ascii")
            compact = "".join(text.strip().removeprefix("0x").split())
            decoded = bytes.fromhex(compact)
        except (UnicodeDecodeError, ValueError):
            raise ValueError("decrypted output is not valid textual hex") from None
        if not decoded:
            raise ValueError("decrypted textual hex is empty")
        return decoded, ".bin"
    raise ValueError(f"unsupported output format {output_format}")


def prepare_output(
    data: bytes, input_type: str, was_hex: bool, output_format: str = "auto"
):
    explicit = explicit_output_format(data, output_format)
    if explicit is not None:
        return explicit
    if input_type == "capi":
        pem = private_key_to_pem(data, "capi")
        return (pem, ".pem") if pem else (data, ".bin")

    if input_type == "cng":
        pem = private_key_to_pem(data, "cng")
        return (pem, ".pem") if pem else (data, ".bin")

    if input_type == "credential":
        parsed = parse_credential_plaintext(data)
        return (json.dumps(parsed, indent=2, ensure_ascii=False).encode() + b"\n", ".json")

    if input_type == "vpol":
        keys = parse_vault_policy_keys(data)
        parsed = {
            "aes_keys": [key.hex() for key in keys],
            "aes128_key": next((key.hex() for key in keys if len(key) == 16), None),
            "aes256_key": next((key.hex() for key in keys if len(key) == 32), None),
        }
        return (json.dumps(parsed, indent=2).encode() + b"\n", ".json")

    if input_type == "powershell":
        try:
            text = data.decode("utf-16le").rstrip("\x00")
        except UnicodeDecodeError:
            raise ValueError("PowerShell plaintext is not valid UTF-16LE") from None
        if not text or not all(
            character.isprintable() or character.isspace() for character in text
        ):
            raise ValueError("PowerShell plaintext is not printable UTF-16LE")
        return text.encode("utf-8"), ".txt"

    if input_type == "keepass":
        return data, ".key"

    if was_hex:
        try:
            text = data.decode("utf-16le").rstrip("\x00")
            if text and all(
                character.isprintable() or character.isspace() for character in text
            ):
                return text.encode("utf-8"), ".txt"
        except UnicodeDecodeError:
            pass
    if printable_text(data):
        return data, ".txt"
    return data, ".bin"


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    counter = 2
    while True:
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def unique_directory(path: Path) -> Path:
    if not path.exists():
        return path
    counter = 2
    while True:
        candidate = path.with_name(f"{path.name}_{counter}")
        if not candidate.exists():
            return candidate
        counter += 1


def output_path(
    base: Path | None,
    requested: str | None,
    index: int,
    count: int,
    extension: str,
    run_id: str,
    output_dir: str | None = None,
) -> Path:
    if requested:
        path = Path(requested)
        if output_dir:
            path = Path(output_dir) / path.name
        suffix = f"_{index + 1}" if count > 1 else ""
        filename = f"{run_id}_{path.stem}{suffix}{path.suffix or extension}"
        return unique_path(path.with_name(filename))
    stem = base.stem if base else "dpapi"
    suffix = f"_{index + 1}" if count > 1 else ""
    parent = Path(output_dir) if output_dir else (base.parent if base else Path.cwd())
    return unique_path(parent / f"{run_id}_{stem}_dec{suffix}{extension}")


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
    os.chmod(path, 0o600)


def display_output(data: bytes, extension: str, label: str) -> None:
    print(f"[+] output {label}:")
    if extension in (".txt", ".json", ".pem", ".crt") or printable_text(data):
        try:
            print(data.decode("utf-8").rstrip("\n"))
            return
        except UnicodeDecodeError:
            pass
    print(data.hex())


def emit_output(path: Path, data: bytes, extension: str, args, label: str) -> None:
    write_private(path, data)
    if args.show:
        display_output(data, extension, label)


def batch_destination(
    output_root: Path,
    relative_source: Path,
    extension: str,
    index: int = 0,
    count: int = 1,
) -> Path:
    suffix = f"_{index + 1}" if count > 1 else ""
    destination = (
        output_root
        / relative_source.parent
        / f"{relative_source.stem}_dec{suffix}{extension}"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    return unique_path(destination)


def build_masterkey_cache(
    args,
    target_guids: set[uuid.UUID] | None = None,
    *,
    system: bool = False,
) -> tuple[dict[uuid.UUID, bytes], bytes | None, list[dict]]:
    cache = {}
    fallback = None
    results = []
    candidates: list[tuple[str, bool]] = []
    if args.real_masterkey:
        key, source_path = read_real_masterkey(args.real_masterkey)
        fallback = key
        results.append(
            {
                "source": str(source_path) if source_path else "<literal --real-masterkey>",
                "status": "fallback",
                "key_size": len(key),
            }
        )
    if args.masterkey:
        candidates.append((args.masterkey, True))
    if args.masterkey_dir:
        directory = Path(args.masterkey_dir)
        if not directory.is_dir():
            raise ValueError("--masterkey-dir must be a readable directory")
        candidates.extend(
            (str(path), False)
            for path in sorted(directory.rglob("*"))
            if path.is_file()
        )

    for value, explicit in candidates:
        source_path = existing_file(value)
        display_source = str(source_path) if source_path else "<literal --masterkey>"
        entry = {"source": display_source, "status": "skipped"}
        try:
            raw, source, _ = read_data(value, "master key")
            try:
                encrypted = parse_masterkey_file(raw)
            except ValueError:
                if len(raw) not in (20, 64):
                    if explicit:
                        raise ValueError("explicit --masterkey is not a supported masterkey")
                    results.append(entry)
                    continue
                guid = None
                if source_path:
                    try:
                        guid = uuid.UUID(source_path.name)
                    except ValueError:
                        pass
                if guid:
                    if target_guids is not None and guid not in target_guids:
                        results.append(entry)
                        continue
                    cache[guid] = raw
                    entry.update(status="decrypted", guid=str(guid), key_size=len(raw))
                elif explicit:
                    fallback = raw
                    entry.update(status="fallback", key_size=len(raw))
                results.append(entry)
                continue

            if encrypted.file_guid is None:
                if explicit:
                    raise ValueError("encrypted masterkey has no file GUID")
                results.append(entry)
                continue
            if (
                target_guids is not None
                and encrypted.file_guid not in target_guids
                and not explicit
            ):
                results.append(entry)
                continue
            entry["guid"] = str(encrypted.file_guid)
            if (
                args.password is None
                and args.sid
                and not any(
                    (
                        args.prekey,
                        args.credkey,
                        args.nt_hash,
                        args.sha1_hash,
                        args.domain_backup_key,
                        args.dpapi_system,
                    )
                )
            ):
                args.password = getpass.getpass("Master-key password: ")
            cleartext = resolve_masterkey_value(
                str(source) if source else value,
                args,
                {encrypted.file_guid},
                system=system,
            )
            cache[encrypted.file_guid] = cleartext
            entry.update(
                status="decrypted",
                guid=str(encrypted.file_guid),
                key_size=len(cleartext),
            )
        except (OSError, ValueError) as exc:
            entry.update(status="error", error=str(exc))
        results.append(entry)
    return cache, fallback, results


def cached_masterkey(
    cache: dict[uuid.UUID, bytes], fallback: bytes | None, guid: uuid.UUID
) -> bytes:
    key = cache.get(guid, fallback)
    if key is None:
        raise ValueError(f"no decrypted masterkey available for {guid}")
    return key


def batch_detected_type(blobs: list[LocatedBlob]) -> str:
    labels = {item.label or "" for item in blobs}
    if any(label.startswith("CNG ") for label in labels):
        return "cng"
    if any(label.startswith("CAPI ") for label in labels):
        return "capi"
    if "Credential payload" in labels:
        return "credential"
    if "Vault policy" in labels:
        return "vpol"
    return "blob"


def contexts_for_hashcat(hashcat_context: str) -> tuple[str, ...]:
    """Expand the requested Hashcat context into concrete derivation contexts."""
    if hashcat_context == "all":
        return ("local", "domain", "domain-new")
    if hashcat_context == "domain-auto":
        return ("domain", "domain-new")
    return (hashcat_context,)


def run_batch_hashcat(args, emit=lambda *_: None) -> list:
    """Export a $DPAPImk$ record for every master key under a directory.

    Each master key becomes its own record and is cracked independently, so a set
    of master keys with different passwords is fine. The owning SID comes from a
    ``Protect\\<SID>`` parent directory when the layout has one, otherwise from
    ``--sid``, which lets one run cover several users. Records are grouped into one
    file per Hashcat mode.
    """
    input_root = Path(args.input)
    if not input_root.is_dir():
        raise ValueError("--batch requires the input argument to be a directory")
    files = sorted(path for path in input_root.rglob("*") if path.is_file())
    contexts = contexts_for_hashcat(args.hashcat_context)
    by_mode: dict[int, list[str]] = {}
    found = 0
    missing_sid = 0
    for path in files:
        try:
            raw, _, _ = read_data(str(path), "masterkey")
            masterkey = parse_masterkey_file(raw)
        except (OSError, ValueError):
            continue
        found += 1
        sid = args.sid
        for parent in path.parents:
            try:
                classify_sid(parent.name)
                sid = parent.name
                break
            except ValueError:
                continue
        if not sid:
            emit(f"[!] {path.name}: no SID (folder is not S-1-... and --sid not set); skipped")
            missing_sid += 1
            continue
        for context in contexts:
            try:
                mode, record = hashcat_masterkey_record(masterkey, sid, context)
            except ValueError:
                continue
            records = by_mode.setdefault(mode, [])
            if record not in records:
                records.append(record)
    if not by_mode:
        if found and missing_sid:
            raise ValueError(
                "found master keys but no SID: pass --sid, or use a "
                "Protect\\<SID> directory layout"
            )
        raise ValueError("no DPAPI master-key files found under the directory")
    emit(f"[+] exported {found} master key(s) as Hashcat records")
    ordered = sorted(by_mode.items())
    outputs = []
    for index, (mode, records) in enumerate(ordered):
        data = ("\n".join(records) + "\n").encode()
        outputs.append(OutputItem(
            data, f".hc{mode}", f"Hashcat {mode}", input_root, index, len(ordered),
            pre_wrote=(f"[+] mode {mode}: {len(records)} record(s)",),
            wrote_template="[+] wrote Hashcat records -> {dest}",
        ))
    return outputs


def run_batch(args) -> None:
    input_root = Path(args.input)
    if not input_root.is_dir():
        raise ValueError("--batch requires the input argument to be a directory")
    output_parent = Path(args.out_dir) if args.out_dir else input_root.parent
    output_root = unique_directory(
        output_parent / f"{args.run_id}_{input_root.name}_dec"
    )
    output_root.mkdir(parents=True, exist_ok=True)

    if (
        args.masterkey_dir
        and args.sid
        and args.password is None
        and not any(
            (
                args.prekey,
                args.credkey,
                args.nt_hash,
                args.sha1_hash,
                args.domain_backup_key,
                args.dpapi_system,
            )
        )
    ):
        args.password = getpass.getpass("Master-key password: ")

    cache, fallback, masterkey_results = build_masterkey_cache(args)
    if not cache and fallback is None:
        errors = [item for item in masterkey_results if item["status"] == "error"]
        detail = errors[0]["error"] if errors else "no supported masterkey files found"
        raise ValueError(f"batch has no usable decrypted masterkeys: {detail}")

    output_resolved = output_root.resolve()
    files = [
        path
        for path in sorted(input_root.rglob("*"))
        if path.is_file() and output_resolved not in path.resolve().parents
    ]
    report = {
        "input_root": str(input_root.resolve()),
        "output_root": str(output_root.resolve()),
        "masterkeys": masterkey_results,
        "artifacts": [],
    }
    processed = set()
    vault_keys_by_directory = {}

    # First decrypt every Policy.vpol so Vault records in the same directory
    # can use its AES keys during the second pass.
    for source in files:
        relative = source.relative_to(input_root)
        try:
            raw, _, _ = read_data(str(source), "batch artifact")
            items = find_vault_policy_blob(raw)
        except (OSError, ValueError):
            continue
        entry = {"source": str(relative), "type": "vpol"}
        try:
            item = items[0]
            key = cached_masterkey(cache, fallback, item.blob.masterkey_guid)
            cleartext = decrypt_dpapi_blob(
                item.blob, key, effective_entropy(args, item.entropy)
            )
            vault_keys = parse_vault_policy_keys(cleartext)
            vault_keys_by_directory[source.parent] = vault_keys
            prepared, extension = prepare_output(
                cleartext, "vpol", False, args.output_format
            )
            destination = batch_destination(output_root, relative, extension)
            emit_output(destination, prepared, extension, args, str(relative))
            entry.update(
                status="decrypted",
                masterkey_guid=str(item.blob.masterkey_guid),
                outputs=[str(destination.relative_to(output_root))],
            )
        except (OSError, ValueError) as exc:
            entry.update(status="error", error=str(exc))
        report["artifacts"].append(entry)
        processed.add(source)

    for source in files:
        if source in processed:
            continue
        relative = source.relative_to(input_root)
        entry = {"source": str(relative)}
        try:
            data, _, was_hex = read_data(str(source), "batch artifact")

            if source.name.upper() == "CREDHIST":
                result = decrypt_credhist(data, args)
                prepared = json.dumps(result, indent=2).encode() + b"\n"
                destination = batch_destination(output_root, relative, ".json")
                emit_output(destination, prepared, ".json", args, str(relative))
                entry.update(
                    type="credhist",
                    status="partial" if result.get("errors") else "decrypted",
                    outputs=[str(destination.relative_to(output_root))],
                )
                if result.get("errors"):
                    entry["errors"] = result["errors"]
                report["artifacts"].append(entry)
                continue

            try:
                certificate = windows_certificate_to_pem(data)
            except ValueError:
                certificate = None
            if certificate is not None:
                destination = batch_destination(output_root, relative, ".crt")
                emit_output(destination, certificate, ".crt", args, str(relative))
                entry.update(
                    type="certificate",
                    status="converted",
                    outputs=[str(destination.relative_to(output_root))],
                )
                report["artifacts"].append(entry)
                continue

            if b"WLANProfile" in data[:4096]:
                profile = parse_wifi_profile(data)
                item = profile.pop("blob")
                if item is None:
                    raise ValueError("Wi-Fi profile has no encrypted keyMaterial")
                key = cached_masterkey(cache, fallback, item.blob.masterkey_guid)
                profile["password"] = decode_secret_text(
                    decrypt_dpapi_blob(
                        item.blob, key, effective_entropy(args, item.entropy)
                    ),
                    "utf-8",
                )
                prepared = json.dumps(profile, indent=2, ensure_ascii=False).encode() + b"\n"
                destination = batch_destination(output_root, relative, ".json")
                emit_output(destination, prepared, ".json", args, str(relative))
                entry.update(
                    type="wifi",
                    status="decrypted",
                    masterkey_guids=[str(item.blob.masterkey_guid)],
                    outputs=[str(destination.relative_to(output_root))],
                )
                report["artifacts"].append(entry)
                continue

            if source.suffix.lower() == ".rdp":
                passwords = parse_rdp_file(data)
                guids = []
                recovered_passwords = []
                item_errors = []
                for index, password in enumerate(passwords, 1):
                    item = password["blob"]
                    guid = item.blob.masterkey_guid
                    try:
                        key = cached_masterkey(cache, fallback, guid)
                        cleartext = decrypt_dpapi_blob(
                            item.blob, key, effective_entropy(args, item.entropy)
                        )
                    except (OSError, ValueError) as exc:
                        item_errors.append({
                            "index": index,
                            "masterkey_guid": str(guid),
                            "error": str(exc),
                        })
                        continue
                    recovered = {key: value for key, value in password.items() if key != "blob"}
                    recovered["password"] = decode_secret_text(cleartext, "utf-16le")
                    recovered_passwords.append(recovered)
                    guids.append(str(guid))
                if not recovered_passwords:
                    detail = item_errors[-1]["error"] if item_errors else "no password fields"
                    raise ValueError(f"could not decrypt any RDP password field: {detail}")
                recovered_passwords.extend({**item, "status": "error"} for item in item_errors)
                prepared = json.dumps(recovered_passwords, indent=2, ensure_ascii=False).encode() + b"\n"
                destination = batch_destination(output_root, relative, ".json")
                emit_output(destination, prepared, ".json", args, str(relative))
                entry.update(
                    type="rdp",
                    status="partial" if item_errors else "decrypted",
                    masterkey_guids=sorted(set(guids)),
                    outputs=[str(destination.relative_to(output_root))],
                )
                if item_errors:
                    entry["errors"] = item_errors
                report["artifacts"].append(entry)
                continue

            if source.suffix.lower() in (".rdg", ".settings") or b"<RDCMan" in data[:4096]:
                profiles = parse_rdcman(data)
                guids = []
                recovered_profiles = []
                item_errors = []
                for index, profile in enumerate(profiles, 1):
                    item = profile["blob"]
                    guid = item.blob.masterkey_guid
                    try:
                        key = cached_masterkey(cache, fallback, guid)
                        cleartext = decrypt_dpapi_blob(
                            item.blob, key, effective_entropy(args, item.entropy)
                        )
                    except (OSError, ValueError) as exc:
                        item_errors.append({
                            "index": index,
                            "masterkey_guid": str(guid),
                            "error": str(exc),
                        })
                        continue
                    recovered = {key: value for key, value in profile.items() if key != "blob"}
                    recovered["password"] = decode_secret_text(cleartext, "utf-16le")
                    recovered_profiles.append(recovered)
                    guids.append(str(guid))
                if not recovered_profiles:
                    detail = item_errors[-1]["error"] if item_errors else "no credentials"
                    raise ValueError(f"could not decrypt any RDCMan credential: {detail}")
                recovered_profiles.extend({**item, "status": "error"} for item in item_errors)
                prepared = json.dumps(recovered_profiles, indent=2, ensure_ascii=False).encode() + b"\n"
                destination = batch_destination(output_root, relative, ".json")
                emit_output(destination, prepared, ".json", args, str(relative))
                entry.update(
                    type="rdcman",
                    status="partial" if item_errors else "decrypted",
                    masterkey_guids=sorted(set(guids)),
                    outputs=[str(destination.relative_to(output_root))],
                )
                if item_errors:
                    entry["errors"] = item_errors
                report["artifacts"].append(entry)
                continue

            try:
                record = parse_vault_record(data)
            except ValueError:
                record = None
            if record is not None:
                keys = vault_keys_by_directory.get(source.parent)
                if not keys:
                    raise ValueError("no decrypted Policy.vpol found in this Vault directory")
                parsed = decrypt_vault_record(record, keys)
                prepared = json.dumps(parsed, indent=2, ensure_ascii=False).encode() + b"\n"
                destination = batch_destination(output_root, relative, ".json")
                emit_output(destination, prepared, ".json", args, str(relative))
                entry.update(
                    type="vcrd",
                    status="decrypted",
                    outputs=[str(destination.relative_to(output_root))],
                )
                report["artifacts"].append(entry)
                continue

            blobs = find_dpapi_blobs(data, "auto")
            detected_type = batch_detected_type(blobs)
            outputs = []
            guids = []
            item_errors = []
            for index, item in enumerate(blobs):
                guid = item.blob.masterkey_guid
                try:
                    key = cached_masterkey(cache, fallback, guid)
                    cleartext = decrypt_dpapi_blob(
                        item.blob, key, effective_entropy(args, item.entropy)
                    )
                except (OSError, ValueError) as exc:
                    item_errors.append({
                        "index": index + 1,
                        "masterkey_guid": str(guid),
                        "error": str(exc),
                    })
                    continue
                prepared, extension = prepare_output(
                    cleartext, detected_type, was_hex, args.output_format
                )
                destination = batch_destination(
                    output_root, relative, extension, index, len(blobs)
                )
                emit_output(destination, prepared, extension, args, str(relative))
                outputs.append(str(destination.relative_to(output_root)))
                guids.append(str(guid))
            if not outputs:
                detail = item_errors[-1]["error"] if item_errors else "no decryptable blobs"
                raise ValueError(f"could not decrypt any DPAPI blob: {detail}")
            entry.update(
                type=detected_type,
                status="partial" if item_errors else "decrypted",
                masterkey_guids=sorted(set(guids)),
                outputs=outputs,
            )
            if item_errors:
                entry["errors"] = item_errors
        except (OSError, ValueError) as exc:
            message = str(exc)
            status = "skipped" if message == "no classic DPAPI blob found" else "error"
            entry.update(status=status, error=message)
        report["artifacts"].append(entry)

    report_path = output_root / "batch_report.json"
    prepared = json.dumps(report, indent=2, ensure_ascii=False).encode() + b"\n"
    emit_output(report_path, prepared, ".json", args, "batch report")
    decrypted = sum(
        item.get("status") in ("decrypted", "partial", "converted")
        for item in report["artifacts"]
    )
    partial = sum(item.get("status") == "partial" for item in report["artifacts"])
    errors = sum(item.get("status") == "error" for item in report["artifacts"])
    skipped = sum(item.get("status") == "skipped" for item in report["artifacts"])
    print(f"[+] masterkey cache: {len(cache)} GUID key(s)" + (" + fallback" if fallback else ""))
    print(
        f"[+] batch results: {decrypted} decrypted/converted ({partial} partial), "
        f"{errors} errors, {skipped} skipped"
    )
    print(f"[+] output directory: {output_root}")
    print(f"[+] report: {report_path}")


EXTENDED_HELP = r"""
DPAPI quick guide
=================

First identify what key material you have
-----------------------------------------
  Encrypted masterkey GUID file
    A file named like 01234567-89ab-cdef-0123-456789abcdef under a Protect
    directory. Use --masterkey plus one unlocking method: --password/--sid,
    --prekey, --nt-hash/--sid, --credkey/--sid, --dpapi-system, or --pvk.

  Decrypted masterkey
    A 64-byte key, or its 20-byte SHA1 mapping. Use --real-masterkey. It accepts
    a raw file, hex, or Base64 and does not need a SID or password.

  DPAPI_SYSTEM secret
    This is not a masterkey. It is either 40 bytes (MachineKey || UserKey) or
    44 bytes (version || MachineKey || UserKey). Use --dpapi-system together
    with the encrypted SYSTEM masterkey file. A single 16/20-byte component or
    secretsdump-style MachineKey/UserKey text is also accepted.

  User prekey or password material
    --prekey HEX      final 20-byte SID-bound key; no further derivation
    --nt-hash HEX     16-byte NT hash; requires --sid
    --sha1-hash HEX   SHA1(password encoded as UTF-16LE), 20 bytes; requires --sid
    --credkey HEX     unbound credential key; requires --sid
    --password TEXT   account password; requires --sid

  AD domain backup private key
    Use --pvk with PEM, DER, PVK, CAPI PRIVATEKEYBLOB, hex, or Base64. Add
    --pvk-password or --pvk-password-file for encrypted PVK/PEM. This is the
    domain BCKUPKEY private key, not DPAPI_SYSTEM. Legacy version-1 DomainKey
    sections also accept an exported raw 256-byte G$BCKUPKEY_* ServerWrap key.

Common commands
---------------
  Inspect an artifact and print the required masterkey GUID:
    python3 dpapi_decrypt.py BLOB

  Decrypt with the user's password:
    python3 dpapi_decrypt.py BLOB --masterkey MASTERKEY-GUID \
      --sid S-1-5-21-... --password PASSWORD

  Decrypt with an already-decrypted masterkey:
    python3 dpapi_decrypt.py BLOB --real-masterkey KEY_HEX_OR_BASE64

  Find the required GUID recursively in a masterkey directory:
    python3 dpapi_decrypt.py BLOB --masterkey-dir PROTECT-SID \
      --sid S-1-5-21-... --password PASSWORD

  The directory lookup works with --prekey, --credkey, --nt-hash, --sha1-hash,
  --dpapi-system, or --pvk instead of a password. A raw 20/64-byte key is also
  accepted when its filename is exactly the required GUID. Files containing
  several blobs resolve every GUID independently. --entropy/--entropy-file is
  applied after the matching masterkey decrypts the artifact.

  Decrypt a SYSTEM blob using the 40/44-byte DPAPI_SYSTEM secret:
    python3 dpapi_decrypt.py BLOB --masterkey SYSTEM-MASTERKEY-GUID \
      --dpapi-system DPAPI_SYSTEM_HEX

  Decrypt one domain masterkey with the AD backup key:
    python3 dpapi_decrypt.py MASTERKEY-GUID --type masterkey --pvk BACKUPKEY.pvk

  Decrypt a directory with one clear masterkey:
    python3 dpapi_decrypt.py ARTIFACTS --batch --real-masterkey KEY

  Decrypt a directory and automatically match a folder of masterkeys by GUID:
    python3 dpapi_decrypt.py ARTIFACTS --batch --masterkey-dir PROTECT-SID \
      --sid S-1-5-21-... --password PASSWORD

  Batch output goes to TIMESTAMP_ARTIFACTS_dec. With --out-dir, that timestamped
  run directory is created below the requested directory. It keeps the input
  layout and writes batch_report.json. Existing files are never overwritten.

  Decrypt a blob that used optional entropy:
    python3 dpapi_decrypt.py BLOB --real-masterkey KEY --entropy 'application text'
    python3 dpapi_decrypt.py BLOB --real-masterkey KEY --entropy hex:01020304
    python3 dpapi_decrypt.py BLOB --real-masterkey KEY --entropy-file entropy.bin

  Recover password-history hashes from CREDHIST:
    python3 dpapi_decrypt.py CREDHIST --type credhist --password CURRENT_PASSWORD

  Decrypt a saved password in an .rdp file:
    python3 dpapi_decrypt.py connection.rdp --type rdp --masterkey MASTERKEY \
      --sid S-1-5-21-... --password PASSWORD

Output control
--------------
  Every output name starts with YYYYMMDD_HHMMSS_. If a path still collides, a
  numeric suffix is added. --out-file chooses the base filename but keeps the
  timestamp.
  --out-dir DIRECTORY places single-file results in that directory. In batch
  mode it is the parent of the timestamped run directory.

  -o hex         save one continuous hexadecimal line as .hex
  -o raw         save exact decrypted bytes as .bin
  -o unhex       decode decrypted ASCII/UTF-16 hexadecimal text to .bin
  -o utf16-utf8  decode decrypted UTF-16LE and save UTF-8 text
  --show         also print the result to the terminal (--console is an alias)
  --output-format is the long alias for -o/--out. The older --hex, --raw,
  --unhex, and --utf16-utf8 flag forms remain accepted.

SID interpretation
------------------
  S-1-12-1-... identifies an Entra ID/cloud account SID. The on-prem AD domain
  backup key does not apply. Use recovered CloudAP material, a clear masterkey,
  or the software NGC workflow where applicable.

  S-1-5-21-... can represent either a local account or an on-prem AD account;
  that distinction cannot be learned from the SID alone. Likewise, an Entra
  SID alone cannot prove whether Windows Hello is software-backed or TPM-backed.
  Inspect the NGC provider/key metadata. If the profile is Hello/TPM-only, the
  classic DPAPI masterkey cannot be cracked from its SID/masterkey file because
  it contains no PIN verifier or TPM private key. Its Hashcat record only tests
  password/credential-derived DPAPI candidates, if present. --pin is accepted
  only with --type ngc-cng for the separate software-NGC workflow.

Supported --type values
-----------------------
  auto       detect common files (default)
  masterkey  decrypt a GUID masterkey file
  credhist   recover older SHA1/NT hashes from CREDHIST
  blob       classic CryptProtectData blob
  credential Credential Manager file
  vpol/vcrd  Windows Vault policy or record
  capi/cng   private-key container
  cert       public certificate file
  powershell ConvertFrom-SecureString hex
  clixml     PowerShell Export-Clixml SecureString/credential document
  keepass    KeePass ProtectedUserKey.bin
  sccm       SCCM OBJECTS.DATA, SQL export, or PolicySecret value
  wifi       personal Wi-Fi profile XML
  wifi-peap  enterprise Wi-Fi MSMUserData
  outlook    Outlook IMAP registry value or NTUSER.DAT
  rdp        saved password 51:b value in a standard *.rdp file
  rdcman     Remote Desktop Connection Manager *.rdg
  ngc-cng    Windows Hello software CNG key

  Multi-value artifacts are recovered per item. Missing or incorrect
  masterkeys do not discard successful siblings; partial failures are logged
  and included in structured JSON. The command fails only when no independent
  item can be decrypted. CREDHIST returns the recovered prefix and stops at a
  broken link because later entries depend on it.

Where Windows normally stores the files
---------------------------------------
  User masterkeys
    %APPDATA%\Microsoft\Protect\<USER-SID>\<MASTERKEY-GUID>
    %APPDATA%\Microsoft\Protect\<USER-SID>\CREDHIST
    CREDHIST is unlocked with the current password/hash/prekey and returns the
    older SHA1 and NT hashes needed for masterkeys protected before a change.

  SYSTEM masterkeys
    %WINDIR%\System32\Microsoft\Protect\S-1-5-18\User\<MASTERKEY-GUID>
    %WINDIR%\System32\Microsoft\Protect\S-1-5-18\<MASTERKEY-GUID>
    DPAPI_SYSTEM must be extracted using both SYSTEM and SECURITY hives.

  Credential Manager and Vault
    %LOCALAPPDATA%\Microsoft\Credentials\*
    %APPDATA%\Microsoft\Credentials\*
    %LOCALAPPDATA%\Microsoft\Vault\<VAULT-GUID>\Policy.vpol and *.vcrd
    Use --type credential, --type vpol, or --type vcrd.

  CAPI, CNG, and public certificates
    CAPI: %APPDATA%\Microsoft\Crypto\RSA\<SID>\*
    CNG:  %APPDATA%\Microsoft\Crypto\Keys\*
    Cert: %APPDATA%\Microsoft\SystemCertificates\My\Certificates\<THUMBPRINT>
    Use --type capi, --type cng, or --type cert.

  Wi-Fi
    Profiles: %ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\<GUID>\*.xml
    Personal profiles use --type wifi and a SYSTEM masterkey.
    Enterprise MSMUserData is stored in NTUSER.DAT below:
      Software\Microsoft\Wlansvc\UserData\Profiles\<GUID>\MSMUserData
    Use --type wifi-peap, --system-masterkey for the outer SYSTEM blob, and
    --masterkey or --real-masterkey for the nested user blob.

  Outlook IMAP, saved RDP, and RDCMan
    Outlook: NTUSER.DAT, under the Office\<version>\Outlook\Profiles tree.
    RDP: user-created *.rdp files containing password 51:b:<DPAPI hex>.
    RDCMan: *.rdg files, commonly under the user's Documents directory.
    Use --type outlook, --type rdp, or --type rdcman.

  Classic blob and PowerShell SecureString
    A classic DPAPI blob normally starts with:
      01000000d08c9ddf0115d1118c7a00c04fc297eb
    Use --type blob or --type powershell. SecureString support is for output
    created without PowerShell's explicit -Key or -SecureKey options.

Windows Hello / NGC
-------------------
  Collect:
    %WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc
    %WINDIR%\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys
    %WINDIR%\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault
    SOFTWARE, SYSTEM, and SECURITY registry hives

  --type ngc-cng supports the software CNG private-key/PIN stage. Supply its
  SYSTEM masterkey, then supply one known --pin. PIN Hashcat export and brute
  force are intentionally not implemented. Keys from the
  Microsoft Platform Crypto Provider are TPM-bound and cannot normally be
  decrypted from copied files alone. This command does not implement the full
  NGC 15.dat + secondary key + NgcPin Vault/registry password-recovery chain.

Password and Hashcat contexts
-----------------------------
  Password decryption automatically tries local, domain, and domain-new and
  accepts only a candidate whose masterkey HMAC verifies.

  Hashcat masterkey modes come from the algorithms; the context comes from the
  account type. A local account masterkey is 15900/15300; a domain account is
  15910/15310 on 2016+ DCs, or 15900/15300 on older ones:
    3DES/SHA1       local/domain 15300, domain-new 15310
    AES256/SHA512   local/domain 15900, domain-new 15910

  Export records:
    python3 dpapi_decrypt.py MASTERKEY-GUID --hashcat --sid S-1-5-21-...
    python3 dpapi_decrypt.py PROTECT-DIR --batch --hashcat --sid S-1-5-21-...
  The file does not reveal the account type, so the default --hashcat-context all
  exports the local, domain and domain-new records; use local/domain/domain-new
  or domain-auto to narrow. --batch exports every masterkey under a directory,
  one file per mode, taking each SID from a Protect\\<SID> folder or --sid.

  A validated CloudAP CacheData password node can be exported for external
  Hashcat mode 33700 processing:
    python3 dpapi_toolkit.py CacheData --plugin cachedata --hashcat
  The toolkit does not accept wordlists, generate candidates, or launch
  Hashcat. Rerun the CacheData plugin with the recovered --password to derive
  its DPAPI credential key and SID-bound prekey.

Important current limitations
-----------------------------
  - DPAPI-NG / NCryptProtectSecret blobs are not classic DPAPI. The optional
    dpapi_ng plugin supports offline SID-descriptor decryption from an exported
    KDS root key; it never falls back to DNS or RPC.
  - Only the primary encrypted section of a masterkey file is tried. Its local
    BackupKey section is not yet used as a fallback.
  - The removable windows_hives plugin extracts DPAPI_SYSTEM from collected
    SYSTEM + SECURITY hives and can optionally export local SAM hashes. It uses
    only local files through the optional Impacket dependency.
  - The CacheData plugin can recover a CloudAP/Entra credential key after a
    known or externally recovered password is supplied. Other CloudAP/LSASS
    sources still require an explicit --prekey or --credkey.
  - Encrypted PVK/PEM backup keys require an explicit password; no guessing is
    performed.
  - CAPI/CNG RSA, CAPI DSS2, CNG DSA (legacy), and CNG ECC P-256/P-384/P-521
    private keys can be converted to PEM. Unrecognized structures remain raw.
  - Entra CacheData password nodes support one known password or export of a
    Hashcat mode-33700 verifier for an external local recovery tool. The
    NGC/PIN node chain, TPM-backed keys, and CNG DSA V2 are not yet implemented.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline Windows DPAPI decryption. Run with only INPUT to inspect "
            "the artifact and print its required masterkey GUID."
        )
    )
    parser.add_argument(
        "input",
        help="artifact/masterkey file, literal hex, directory with --batch, or '-'",
    )
    parser.add_argument(
        "--type",
        metavar="TYPE",
        choices=(
            "auto",
            "masterkey",
            "credhist",
            "blob",
            "credential",
            "capi",
            "cng",
            "cert",
            "vpol",
            "vcrd",
            "powershell",
            "clixml",
            "keepass",
            "sccm",
            "wifi",
            "wifi-peap",
            "outlook",
            "rdp",
            "rdcman",
            "ngc-cng",
            "localstate",
        ),
        default="auto",
        help="input format; use -hh for the supported types (default: auto)",
    )
    manifests = dpapi_plugins.discover_plugins()
    parser.add_argument(
        "--plugin",
        choices=tuple(manifests),
        help="optional removable offline application-format plugin",
    )
    parser.add_argument(
        "--masterkey",
        metavar="FILE_OR_HEX",
        help="encrypted GUID masterkey file; unlock it with password/hash/SYSTEM/PVK",
    )
    parser.add_argument(
        "--real-masterkey",
        "--decrypted-masterkey",
        metavar="FILE_OR_HEX_OR_BASE64",
        help="already-decrypted 64-byte masterkey or 20-byte SHA1 mapping",
    )
    parser.add_argument(
        "--masterkey-dir",
        metavar="DIRECTORY",
        help="recursively find required GUID masterkeys for one file or --batch",
    )
    parser.add_argument(
        "--domain-backup-key",
        "--pvk",
        metavar="FILE_OR_HEX_OR_BASE64",
        help="AD DPAPI domain backup private key in PEM/PVK/raw/hex/Base64 form",
    )
    parser.add_argument(
        "--dpapi-ng-root-key",
        metavar="JSON_FILE",
        help=(
            "exported KDS root-key JSON for the offline dpapi_ng plugin; "
            "no DNS/RPC fallback is permitted"
        ),
    )
    parser.add_argument(
        "--security-hive",
        metavar="SECURITY_FILE",
        help="offline SECURITY hive for the removable windows_hives plugin",
    )
    parser.add_argument(
        "--sam-hive",
        metavar="SAM_FILE",
        help="optional offline SAM hive for local-account hashes with windows_hives",
    )
    pvk_group = parser.add_mutually_exclusive_group()
    pvk_group.add_argument(
        "--pvk-password",
        help="password for an encrypted PVK/PEM domain backup private key",
    )
    pvk_group.add_argument(
        "--pvk-password-file",
        metavar="FILE",
        help="read the encrypted PVK/PEM password from a local file",
    )
    parser.add_argument(
        "--system-masterkey",
        metavar="FILE_OR_HEX",
        help="outer SYSTEM masterkey used only by --type wifi-peap",
    )
    parser.add_argument(
        "--dpapi-system",
        metavar="FILE_OR_HEX_OR_TEXT",
        help=(
            "40/44-byte DPAPI_SYSTEM secret (80/88 hex characters), one "
            "16/20-byte component (32/40 hex characters), or secretsdump text"
        ),
    )
    parser.add_argument(
        "--prekey",
        metavar="FILE_OR_HEX",
        help="20-byte SID-bound DPAPI prekey (for example CloudAP/Mimikatz dpapi)",
    )
    parser.add_argument(
        "--credkey",
        metavar="FILE_OR_HEX",
        help="unbound DPAPI credential key; requires --sid",
    )
    parser.add_argument(
        "--nt-hash",
        metavar="FILE_OR_HEX",
        help="16-byte NT hash used to derive domain/domain-new prekeys",
    )
    parser.add_argument(
        "--sha1-hash",
        metavar="FILE_OR_HEX",
        help=(
            "local DPAPI password hash, computed as 20-byte "
            "SHA1(password encoded as UTF-16LE); used with --sid"
        ),
    )
    parser.add_argument("--sid", help="SID of the account that owns --masterkey")
    parser.add_argument(
        "--machine-sid",
        help="machine/account-domain SID for application plugins that require it",
    )
    parser.add_argument(
        "--password",
        help="account password for --masterkey (omit the option to prompt safely)",
    )
    entropy_group = parser.add_mutually_exclusive_group()
    entropy_group.add_argument(
        "--entropy",
        metavar="TEXT_OR_PREFIXED_VALUE",
        help="optional entropy as UTF-8 text, hex:VALUE, base64:VALUE, or utf16:TEXT",
    )
    entropy_group.add_argument(
        "--entropy-file",
        metavar="FILE",
        help="file containing exact optional-entropy bytes",
    )
    parser.add_argument(
        "--vault-policy",
        metavar="POLICY_VPOL",
        help="Policy.vpol used to obtain AES keys for a .vcrd input",
    )
    parser.add_argument(
        "--vault-key",
        metavar="HEX_OR_JSON",
        help="Vault AES key hex or a JSON file produced from Policy.vpol",
    )
    parser.add_argument(
        "--certificate",
        metavar="FILE",
        help="certificate to correlate with a decrypted CAPI/CNG key and bundle as PFX",
    )
    pfx_group = parser.add_mutually_exclusive_group()
    pfx_group.add_argument(
        "--pfx-password",
        help="password for --certificate PFX output (an explicit empty string disables encryption)",
    )
    pfx_group.add_argument(
        "--pfx-password-file",
        metavar="FILE",
        help="read the PFX password from a local file instead of the command line",
    )
    parser.add_argument(
        "--key-password",
        help="password for a PEM/DER private key used by the certificate_pfx plugin",
    )
    parser.add_argument(
        "--out-file",
        metavar="FILE",
        help="custom output base filename (timestamp prefix is still added)",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "-o",
        "--out",
        "--output-format",
        dest="output_format",
        choices=("auto", "hex", "raw", "unhex", "utf16-utf8"),
        default="auto",
        help="saved payload transformation (default: auto)",
    )
    output_group.add_argument(
        "--hex",
        dest="output_format",
        action="store_const",
        const="hex",
        help="save decrypted bytes as one hexadecimal text line",
    )
    output_group.add_argument(
        "--raw",
        dest="output_format",
        action="store_const",
        const="raw",
        help="save decrypted bytes without conversion",
    )
    output_group.add_argument(
        "--unhex",
        dest="output_format",
        action="store_const",
        const="unhex",
        help="decode decrypted ASCII/UTF-16 hex text to binary",
    )
    output_group.add_argument(
        "--utf16-utf8",
        dest="output_format",
        action="store_const",
        const="utf16-utf8",
        help="decode decrypted UTF-16LE and save UTF-8 text",
    )
    parser.add_argument(
        "--show",
        "--console",
        action="store_true",
        help="also display saved text or a hex representation of binary output",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="recursively process artifacts below the INPUT directory",
    )
    parser.add_argument(
        "--out-dir",
        metavar="DIRECTORY",
        help="single-output directory or parent for a timestamped batch run",
    )
    parser.add_argument(
        "--hashcat",
        action="store_true",
        help=(
            "export Hashcat record(s) from an encrypted masterkey file "
            "(add --batch for a directory) or from --plugin cachedata"
        ),
    )
    parser.add_argument(
        "--cachedata-hashcat",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--hashcat-context",
        choices=("all", "local", "domain", "domain-new", "domain-auto"),
        default="all",
        help="DPAPI derivation context (default: all exports the local, domain, "
        "and domain-new forms so the key cracks whatever the account type)",
    )
    parser.add_argument(
        "--pin",
        help="Windows Hello PIN for --type ngc-cng software-key decryption",
    )
    parser.add_argument(
        "--structure",
        action="store_true",
        help="print the parsed blob/master-key structure and exit (no decryption)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.epilog = (
        "Use -hh or --help-files for examples, key types, Windows locations, "
        "and current limitations."
    )
    return parser


@dataclass
class OutputItem:
    """One decrypted result to be written by a frontend.

    The core computes the already-prepared bytes, extension, and display label;
    the frontend (CLI or GUI) decides where and whether to write it. ``pre_wrote``
    holds status lines printed after the file is written but before the final
    "wrote" line; ``wrote_template`` is that final line, formatted with ``n`` (byte
    count) and ``dest`` (destination path).
    """

    data: bytes
    extension: str
    label: str
    source_path: "Path | None"
    index: int = 0
    count: int = 1
    pre_wrote: tuple = ()
    wrote_template: str = "[+] wrote {n} bytes -> {dest}"


def validate_config(args, emit=print) -> None:
    """Validate mutually exclusive options and the SID context once per run."""
    if args.masterkey and args.real_masterkey:
        raise ValueError("use either --masterkey or --real-masterkey, not both")
    if args.entropy is not None and args.entropy_file:
        raise ValueError("use either --entropy or --entropy-file, not both")
    if args.plugin and args.type != "auto":
        raise ValueError("use --plugin with --type auto")
    if args.plugin and args.batch:
        raise ValueError("application plugins currently process one artifact at a time")
    if args.cachedata_hashcat and args.plugin != "cachedata":
        raise ValueError("--cachedata-hashcat is only valid with --plugin cachedata")
    if args.type == "ngc-cng" and args.hashcat:
        raise ValueError("Windows Hello PIN Hashcat export is intentionally disabled")
    if (args.pfx_password is not None or args.pfx_password_file) and not args.certificate:
        raise ValueError("PFX password options require --certificate")
    if args.key_password is not None and args.plugin != "certificate_pfx":
        raise ValueError("--key-password is only valid with --plugin certificate_pfx")
    if (args.pvk_password is not None or args.pvk_password_file) and not args.domain_backup_key:
        raise ValueError("PVK password options require --domain-backup-key/--pvk")
    validate_sid_context(args, emit)


def run_single(args, emit=lambda *_: None) -> list:
    """Decrypt a single artifact and return its OutputItems without writing files.

    Status lines are sent to ``emit`` as they are produced, so both the CLI and a
    GUI see progress (and any partial output before an exception). All per-type
    dispatch that ``main()`` used to perform inline now lives here. Callers must
    have already run :func:`validate_config` and set ``args.run_id``.
    """
    if args.plugin and Path(args.input).is_dir():
        # A plugin may take a whole folder (e.g. certificate_pfx matching a
        # directory of keys); hand it the directory and let it enumerate.
        data, source_path, was_hex = b"", Path(args.input), False
    else:
        data, source_path, was_hex = read_data(args.input, "input")
        if args.plugin is None and args.type == "auto" and source_path:
            args.plugin = dpapi_plugins.detect_plugin(source_path.name)
    if args.plugin:
        return dpapi_plugins.run_plugin(
            args.plugin, data, source_path, was_hex, args, sys.modules[__name__], emit
        )
    if args.type == "auto" and source_path:
        if source_path.name.upper() == "CREDHIST":
            args.type = "credhist"
        elif source_path.name.casefold() == "protecteduserkey.bin":
            args.type = "keepass"
        elif source_path.suffix.lower() == ".rdp":
            args.type = "rdp"
        elif source_path.suffix.lower() in (".rdg", ".settings"):
            args.type = "rdcman"
        elif source_path.name.lower().endswith((".clixml", ".cli.xml")):
            args.type = "clixml"
        elif source_path.name.upper() == "OBJECTS.DATA" or looks_like_sccm(data):
            args.type = "sccm"
        elif source_path.name == "Local State" or looks_like_local_state(data):
            args.type = "localstate"
        elif looks_like_clixml(data):
            args.type = "clixml"

    if args.type == "localstate":
        blob_bytes = extract_local_state_blob(data)
        located = find_dpapi_blobs(blob_bytes, "blob")
        emit("[+] input type: Chromium Local State (os_crypt key)")
        for item in located:
            emit(f"[+] required master key {item.blob.masterkey_guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        item = located[0]
        masterkey = resolve_masterkey_for_guid(args, item.blob.masterkey_guid)
        cleartext = decrypt_dpapi_blob(
            item.blob, masterkey, effective_entropy(args, item.entropy)
        )
        result = {
            "os_crypt_key_hex": cleartext.hex(),
            "length_bytes": len(cleartext),
            "algorithm": "AES-256-GCM" if len(cleartext) == 32 else "unknown",
            "usage": "decrypts Chromium 'v10'/'v11' cookies and logins with AES-256-GCM",
        }
        prepared = json.dumps(result, indent=2).encode() + b"\n"
        return [OutputItem(
            prepared, ".json", "Chromium os_crypt key", source_path,
            pre_wrote=(f"[+] recovered {len(cleartext)}-byte os_crypt key",),
        )]

    if args.type == "credhist":
        result = decrypt_credhist(data, args)
        if result.get("errors"):
            error = result["errors"][0]
            emit(f"[!] partial CREDHIST result: {error['error']}")
        prepared = json.dumps(result, indent=2).encode() + b"\n"
        return [OutputItem(
            prepared, ".json", "CREDHIST", source_path,
            pre_wrote=(f"[+] recovered {len(result['entries'])} CREDHIST entrie(s)",),
        )]

    if args.type == "clixml":
        document = parse_powershell_clixml(data)
        emit(
            f"[+] input type: PowerShell Export-Clixml "
            f"({len(document['secrets'])} SecureString value(s))"
        )
        for item in document["secrets"]:
            emit(f"[+] required master key {item['blob'].blob.masterkey_guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        located_items = [item["blob"] for item in document["secrets"]]
        decrypted, errors = decrypt_located_items_partial(
            args, located_items, emit, item_label="CLIXML SecureString"
        )
        recovered = []
        for item_index, cleartext in decrypted:
            item = document["secrets"][item_index]
            recovered.append(
                {
                    "name": item["name"],
                    "value": decode_secret_text(cleartext, "utf-16le"),
                }
            )
        result = {"username": document["username"], "secrets": recovered}
        if errors:
            result["errors"] = [
                {**error, "name": document["secrets"][error["index"] - 1]["name"]}
                for error in errors
            ]
        prepared = json.dumps(result, indent=2, ensure_ascii=False).encode() + b"\n"
        return [OutputItem(prepared, ".json", "PowerShell CLIXML", source_path)]

    if args.type == "sccm":
        secrets = parse_sccm_policy_secrets(data)
        emit(f"[+] input type: SCCM PolicySecret ({len(secrets)} value(s))")
        for item in secrets:
            emit(f"[+] required SYSTEM master key {item['blob'].blob.masterkey_guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        located_items = [item["blob"] for item in secrets]
        decrypted, errors = decrypt_located_items_partial(
            args, located_items, emit, system=True, item_label="SCCM secret"
        )
        recovered = []
        decrypted_by_index = dict(decrypted)
        errors_by_index = {error["index"] - 1: error for error in errors}
        for item_index, item in enumerate(secrets):
            if item_index in decrypted_by_index:
                recovered.append({
                    "index": item_index + 1,
                    "source_offset": item["source_offset"],
                    "wrapper_prefix_hex": item["wrapper_prefix"].hex(),
                    "value": decode_secret_text(
                        decrypted_by_index[item_index], "utf-16le"
                    ),
                })
                continue
            error = errors_by_index[item_index]
            recovered.append({
                **error,
                "source_offset": item["source_offset"],
                "wrapper_prefix_hex": item["wrapper_prefix"].hex(),
                "status": "error",
            })
        prepared = json.dumps(recovered, indent=2, ensure_ascii=False).encode() + b"\n"
        return [OutputItem(prepared, ".json", "SCCM PolicySecret", source_path)]

    if args.hashcat and args.type != "ngc-cng":
        if not args.sid:
            raise ValueError("--sid is required for Hashcat master-key export")
        encrypted = parse_masterkey_file(data)
        contexts = contexts_for_hashcat(args.hashcat_context)
        records = [
            (context, *hashcat_masterkey_record(encrypted, args.sid, context))
            for context in contexts
        ]
        stem = str(encrypted.file_guid) if encrypted.file_guid else (
            source_path.stem if source_path else "masterkey"
        )
        parent = source_path.parent if source_path else Path.cwd()
        hash_base = parent / stem
        outputs = []
        for index, (context, mode, record) in enumerate(records):
            outputs.append(OutputItem(
                record.encode() + b"\n", f".hc{mode}", "Hashcat record",
                hash_base, index, len(records),
                pre_wrote=(f"[+] Hashcat context: {context}; mode: {mode}",),
                wrote_template="[+] wrote Hashcat record -> {dest}",
            ))
        return outputs

    if args.type == "masterkey":
        encrypted = parse_masterkey_file(data)
        target = {encrypted.file_guid} if encrypted.file_guid else set()
        cleartext = resolve_masterkey_value(args.input, args, target)
        explicit = explicit_output_format(cleartext, args.output_format)
        prepared, extension = explicit if explicit is not None else (cleartext, ".bin")
        return [OutputItem(
            prepared, extension, "masterkey", source_path,
            pre_wrote=(
                f"[+] decrypted master key {encrypted.file_guid or '<unknown GUID>'}",
            ),
        )]

    if args.type == "ngc-cng":
        container = parse_ngc_cng_container(data)
        properties_item = container["properties"]
        key_item = container["private_key"]
        required = {
            properties_item.blob.masterkey_guid,
            key_item.blob.masterkey_guid,
        }
        emit("[+] input type: Windows Hello NGC software CNG key")
        emit(f"[+] key name: {container['name']}")
        for guid in sorted(required, key=str):
            emit(f"[+] required SYSTEM master key {guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        properties_masterkey = resolve_masterkey_for_guid(
            args, properties_item.blob.masterkey_guid, system=True
        )
        properties_clear = decrypt_dpapi_blob(
            properties_item.blob,
            properties_masterkey,
            effective_entropy(args, properties_item.entropy),
        )
        properties = parse_ngc_private_properties(properties_clear)
        salt = properties.get("NgcSoftwareKeyPbkdf2Salt")
        rounds_data = properties.get("NgcSoftwareKeyPbkdf2Round")
        result = {
            "key_name": container["name"],
            "key_type": container["key_type"],
            "masterkey_guid": str(key_item.blob.masterkey_guid),
            "properties": sorted(properties),
        }
        if salt is not None:
            result["pin_salt"] = salt.hex()
        if rounds_data is not None:
            if len(rounds_data) not in (4, 8):
                raise ValueError("invalid NgcSoftwareKeyPbkdf2Round length")
            rounds = int.from_bytes(rounds_data, "little")
            result["pin_rounds"] = rounds
        else:
            rounds = None

        if args.pin is not None:
            if salt is None or rounds is None:
                raise ValueError("this CNG key has no software Windows Hello PIN properties")
            try:
                private_masterkey = resolve_masterkey_for_guid(
                    args, key_item.blob.masterkey_guid, system=True
                )
                secret = ngc_pin_secret(args.pin, salt, rounds)
                cleartext = decrypt_dpapi_blob_smartcard(
                    key_item.blob,
                    private_masterkey,
                    effective_entropy(args, key_item.entropy),
                    secret,
                )
            except (OSError, ValueError) as exc:
                result["private_key_error"] = {
                    "masterkey_guid": str(key_item.blob.masterkey_guid),
                    "error": str(exc),
                }
                emit(
                    "[!] partial Windows Hello result: properties were recovered, "
                    f"but the private key was not decrypted: {exc}"
                )
                prepared = json.dumps(result, indent=2).encode() + b"\n"
                return [OutputItem(
                    prepared, ".json", "NGC partial metadata", source_path,
                    wrote_template="[!] wrote partial NGC metadata -> {dest}",
                )]
            explicit = explicit_output_format(cleartext, args.output_format)
            if explicit is not None:
                prepared, extension = explicit
            else:
                pem = private_key_to_pem(cleartext, "cng")
                prepared, extension = (pem, ".pem") if pem else (cleartext, ".bin")
            return [OutputItem(
                prepared, extension, "Windows Hello key", source_path,
                wrote_template="[+] Windows Hello PIN verified; wrote {n} bytes -> {dest}",
            )]

        prepared = json.dumps(result, indent=2).encode() + b"\n"
        return [OutputItem(
            prepared, ".json", "NGC metadata", source_path,
            wrote_template="[+] wrote NGC key metadata -> {dest}",
        )]

    if args.type == "wifi":
        profile = parse_wifi_profile(data)
        emit("[+] input type: Wi-Fi profile")
        emit(f"[+] SSID: {profile['ssid'] or '<unknown>'}")
        item = profile.pop("blob")
        if item is None:
            if "password" in profile:
                emit("[i] keyMaterial is already plaintext")
            elif profile["enterprise"]:
                emit("[i] enterprise profile: obtain MSMUserData and use --type wifi-peap")
            else:
                emit("[i] profile has no keyMaterial")
        else:
            emit(f"[+] required master key {item.blob.masterkey_guid}")
            if not has_masterkey(args):
                emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
                return []
            masterkey = resolve_masterkey_for_guid(
                args, item.blob.masterkey_guid, system=True
            )
            cleartext = decrypt_dpapi_blob(
                item.blob, masterkey, effective_entropy(args, item.entropy)
            )
            profile["password"] = decode_secret_text(cleartext, "utf-8")
        prepared = json.dumps(profile, indent=2, ensure_ascii=False).encode() + b"\n"
        return [OutputItem(prepared, ".json", "Wi-Fi profile", source_path)]

    if args.type == "wifi-peap":
        outer_blob, _ = parse_dpapi_blob(data)
        emit("[+] input type: Wi-Fi PEAP MSMUserData")
        emit(f"[+] outer SYSTEM blob requires master key {outer_blob.masterkey_guid}")
        if not args.system_masterkey and not args.masterkey_dir:
            emit(
                "[i] rerun with --system-masterkey FILE_OR_HEX or "
                "--masterkey-dir DIRECTORY"
            )
            return []
        if args.system_masterkey:
            system_key = resolve_masterkey_value(
                args.system_masterkey,
                args,
                {outer_blob.masterkey_guid},
                system=True,
            )
        else:
            system_key = resolve_masterkey_for_guid(
                args, outer_blob.masterkey_guid, system=True
            )
        outer_clear = decrypt_dpapi_blob(
            outer_blob, system_key, effective_entropy(args)
        )
        username, domain = peap_identity(outer_clear)
        nested = []
        position = 0
        while True:
            offset = outer_clear.find(DPAPI_HEADER, position)
            if offset < 0:
                break
            try:
                blob, size = parse_dpapi_blob(outer_clear[offset:])
                nested.append(LocatedBlob(offset, size, blob, label="PEAP password"))
                position = offset + size
            except ValueError:
                position = offset + 1
        if not nested:
            raise ValueError("decrypted PEAP data contains no nested user DPAPI blob")
        for item in nested:
            emit(f"[+] nested user blob requires master key {item.blob.masterkey_guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        decrypted, errors = decrypt_located_items_partial(
            args, nested, emit, item_label="PEAP nested password"
        )
        passwords = [decode_secret_text(value, "utf-8") for _, value in decrypted]
        result = {
            "username": username,
            "domain": domain,
            "password": passwords[0] if len(passwords) == 1 else passwords,
        }
        if errors:
            result["errors"] = errors
        prepared = json.dumps(result, indent=2, ensure_ascii=False).encode() + b"\n"
        return [OutputItem(prepared, ".json", "Wi-Fi PEAP", source_path)]

    if args.type == "rdcman":
        profiles = parse_rdcman(data)
        emit(f"[+] input type: RDCMan ({len(profiles)} credential profiles)")
        for item in profiles:
            emit(f"[+] required master key {item['blob'].blob.masterkey_guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        decrypted, errors = decrypt_located_items_partial(
            args, [item["blob"] for item in profiles], emit,
            item_label="RDCMan credential",
        )
        results = []
        decrypted_by_index = dict(decrypted)
        errors_by_index = {error["index"] - 1: error for error in errors}
        for item_index, profile in enumerate(profiles):
            item = {
                key: value
                for key, value in profile.items()
                if key != "blob"
            }
            if item_index in decrypted_by_index:
                item["password"] = decode_secret_text(
                    decrypted_by_index[item_index], "utf-16le"
                )
                results.append(item)
                continue
            error = errors_by_index[item_index]
            item.update(error)
            item["status"] = "error"
            results.append(item)
        prepared = json.dumps(results, indent=2, ensure_ascii=False).encode() + b"\n"
        return [OutputItem(prepared, ".json", "RDCMan", source_path)]

    if args.type == "rdp":
        passwords = parse_rdp_file(data)
        emit(f"[+] input type: saved .rdp file ({len(passwords)} password field(s))")
        for item in passwords:
            emit(f"[+] required master key {item['blob'].blob.masterkey_guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        decrypted, errors = decrypt_located_items_partial(
            args, [item["blob"] for item in passwords], emit,
            item_label="RDP password field",
        )
        results = []
        decrypted_by_index = dict(decrypted)
        errors_by_index = {error["index"] - 1: error for error in errors}
        for item_index, password in enumerate(passwords):
            item = {
                key: value
                for key, value in password.items()
                if key != "blob"
            }
            if item_index in decrypted_by_index:
                item["password"] = decode_secret_text(
                    decrypted_by_index[item_index], "utf-16le"
                )
                results.append(item)
                continue
            error = errors_by_index[item_index]
            item.update(error)
            item["status"] = "error"
            results.append(item)
        prepared = json.dumps(results, indent=2, ensure_ascii=False).encode() + b"\n"
        return [OutputItem(prepared, ".json", "RDP", source_path)]

    if args.type == "outlook":
        if data.startswith(b"regf"):
            if source_path is None:
                raise ValueError("an NTUSER.DAT hive must be supplied as a file")
            accounts = parse_outlook_hive(source_path)
        else:
            field = data[1:] if data[:1] == b"\x02" else data
            blob, consumed = parse_dpapi_blob(field)
            if consumed != len(field):
                raise ValueError("Outlook IMAP Password value has trailing bytes")
            accounts = [{"blob": LocatedBlob(0, consumed, blob, label="Outlook IMAP password")}]
        emit(f"[+] input type: Outlook IMAP ({len(accounts)} account(s))")
        for item in accounts:
            emit(f"[+] required master key {item['blob'].blob.masterkey_guid}")
        if not has_masterkey(args):
            emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
            return []
        decrypted, errors = decrypt_located_items_partial(
            args, [item["blob"] for item in accounts], emit,
            item_label="Outlook password",
        )
        results = []
        decrypted_by_index = dict(decrypted)
        errors_by_index = {error["index"] - 1: error for error in errors}
        for item_index, account in enumerate(accounts):
            item = {
                key: value
                for key, value in account.items()
                if key != "blob"
            }
            if item_index in decrypted_by_index:
                item["password"] = decode_secret_text(
                    decrypted_by_index[item_index], "utf-16le"
                )
                results.append(item)
                continue
            error = errors_by_index[item_index]
            item.update(error)
            item["status"] = "error"
            results.append(item)
        prepared = json.dumps(results, indent=2, ensure_ascii=False, default=str).encode() + b"\n"
        return [OutputItem(prepared, ".json", "Outlook", source_path)]

    certificate_pem = None
    if args.type in ("auto", "cert"):
        try:
            certificate_pem = windows_certificate_to_pem(data)
        except ValueError:
            if args.type == "cert":
                raise
    if certificate_pem is not None:
        return [OutputItem(
            certificate_pem, ".crt", "certificate", source_path,
            pre_wrote=("[+] input type: certificate",),
        )]

    vault_record = None
    if args.type in ("auto", "vcrd"):
        try:
            vault_record = parse_vault_record(data)
        except ValueError:
            if args.type == "vcrd":
                raise
    if vault_record is not None:
        emit("[+] input type: Vault credential record")
        emit(f"[+] friendly name: {vault_record['friendly_name']}")
        if args.vault_key:
            vault_keys = read_vault_keys(args.vault_key)
        elif args.vault_policy:
            policy_data, _, _ = read_data(args.vault_policy, "Vault policy")
            policy_blobs = find_vault_policy_blob(policy_data)
            policy_item = policy_blobs[0]
            emit(
                "[+] Vault policy requires master key "
                f"{policy_item.blob.masterkey_guid}"
            )
            if not has_masterkey(args):
                emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
                return []
            masterkey = resolve_masterkey_for_guid(
                args, policy_item.blob.masterkey_guid
            )
            policy_cleartext = decrypt_dpapi_blob(
                policy_item.blob,
                masterkey,
                effective_entropy(args, policy_item.entropy),
            )
            vault_keys = parse_vault_policy_keys(policy_cleartext)
        else:
            raise ValueError(
                "Vault record requires --vault-policy Policy.vpol or --vault-key HEX"
            )
        parsed_record = decrypt_vault_record(vault_record, vault_keys)
        prepared = json.dumps(
            parsed_record, indent=2, ensure_ascii=False
        ).encode() + b"\n"
        return [OutputItem(prepared, ".json", "Vault record", source_path)]

    # Auto/blob artifacts are often stored Base64-encoded (optionally with a
    # Chromium 'DPAPI' prefix); unwrap that before searching for the structure.
    if args.type in ("auto", "blob"):
        unwrapped = unwrap_base64_dpapi(data)
        if unwrapped is not None:
            emit("[i] input was Base64-wrapped; decoded to a DPAPI blob")
            data = unwrapped
    blobs = find_dpapi_blobs(data, args.type)
    detected_type = args.type
    if detected_type == "auto":
        labels = {item.label or "" for item in blobs}
        if any(label.startswith("CNG ") for label in labels):
            detected_type = "cng"
        elif any(label.startswith("CAPI ") for label in labels):
            detected_type = "capi"
        elif "Credential payload" in labels:
            detected_type = "credential"
        elif "Vault policy" in labels:
            detected_type = "vpol"
        else:
            detected_type = "blob"

    emit(f"[+] input type: {detected_type}")
    for index, item in enumerate(blobs, 1):
        location = f" at offset 0x{item.offset:x}" if item.offset else ""
        label = f" ({item.label})" if item.label else ""
        emit(
            f"[+] blob {index}{label}{location}: required master key "
            f"{item.blob.masterkey_guid}"
        )
    if not has_masterkey(args):
        emit("[i] use --masterkey, --real-masterkey, or --masterkey-dir")
        return []

    decrypted, _errors = decrypt_located_items_partial(
        args, blobs, emit, item_label="DPAPI blob"
    )
    prepared_outputs = []
    for item_index, cleartext in decrypted:
        output_type = "powershell" if args.type == "powershell" else detected_type
        prepared, extension = prepare_output(
            cleartext, output_type, was_hex, args.output_format
        )
        prepared_outputs.append((item_index, prepared, extension))
    outputs = [
        OutputItem(
            prepared, extension, f"blob {item_index + 1}", source_path,
            output_index, len(prepared_outputs),
        )
        for output_index, (item_index, prepared, extension)
        in enumerate(prepared_outputs)
    ]
    if args.certificate:
        certificate_data, certificate_path, _ = read_data(
            args.certificate, "certificate"
        )
        password = pfx_password(args)
        bundles = []
        errors = []
        for item in outputs:
            if item.extension != ".pem":
                continue
            try:
                bundle = build_pkcs12_bundle(
                    item.data,
                    certificate_data,
                    password,
                    (certificate_path.stem if certificate_path else "certificate").encode(
                        "utf-8", errors="replace"
                    ),
                )
            except ValueError as exc:
                errors.append(str(exc))
                continue
            bundles.append(
                OutputItem(bundle, ".pfx", "certificate + private key", source_path)
            )
        if not bundles:
            detail = errors[-1] if errors else "decrypted artifact produced no supported PEM key"
            raise ValueError(f"could not correlate certificate and private key: {detail}")
        emit(f"[+] correlated {len(bundles)} certificate/private-key pair(s)")
        outputs.extend(bundles)
    return outputs


def write_outputs(outputs, args, emit=lambda *_: None) -> None:
    """Write each OutputItem to disk with the CLI's timestamped naming rules."""
    for item in outputs:
        destination = output_path(
            item.source_path, args.out_file, item.index, item.count,
            item.extension, args.run_id, args.out_dir,
        )
        emit_output(destination, item.data, item.extension, args, item.label)
        for message in item.pre_wrote:
            emit(message)
        emit(item.wrote_template.format(n=len(item.data), dest=destination))


def make_config(input_value: str, **overrides):
    """Build an argparse-style config for :func:`run_single` from a GUI/caller.

    Starts from the CLI parser defaults so every attribute the core reads exists,
    applies ``overrides`` (using the same dest names as the CLI, e.g.
    ``real_masterkey``, ``output_format``), and assigns a ``run_id`` if absent.
    """
    args = build_parser().parse_args([input_value])
    for key, value in overrides.items():
        if not hasattr(args, key):
            raise AttributeError(f"unknown config option: {key}")
        setattr(args, key, value)
    if not getattr(args, "run_id", None):
        args.run_id = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    return args


def required_guids(emitted_lines) -> list:
    """Extract required master-key GUIDs from run_single's emitted status lines."""
    pattern = re.compile(
        r"required (?:SYSTEM )?master key ([0-9a-fA-F-]{36})"
    )
    seen = []
    for line in emitted_lines:
        match = pattern.search(line)
        if match and match.group(1) not in seen:
            seen.append(match.group(1))
    return seen


def main() -> None:
    if "-hh" in sys.argv[1:] or "--help-files" in sys.argv[1:]:
        print(build_parser().format_help())
        print(EXTENDED_HELP.strip())
        return
    args = build_parser().parse_args()
    args.run_id = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    validate_config(args)
    if args.structure:
        data, _, _ = read_data(args.input, "input")
        info = describe_input(data, args.type)
        if not info["structure"]:
            print("no classic DPAPI blob or master-key structure found")
            return
        if info["kind"] == "masterkey":
            print("[+] input type: encrypted master key")
        for line in format_structure(info["structure"]):
            print(line)
        if info["note"]:
            print(f"[i] {info['note']}")
        return
    if args.batch and args.hashcat:
        outputs = run_batch_hashcat(args, emit=print)
        write_outputs(outputs, args, emit=print)
        return
    if args.batch:
        run_batch(args)
        return
    outputs = run_single(args, emit=print)
    write_outputs(outputs, args, emit=print)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"error: {error}")
