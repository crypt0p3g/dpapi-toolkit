"""Certificate/private-key correlation and offline PKCS#12 creation.

Both the key input and the certificate input may be a single file or a folder:

- Key input: one decrypted PEM/DER private key, one encrypted CAPI/CNG key, or a
  folder of them (for example a copied ``Crypto\\Keys`` directory). Encrypted
  CAPI/CNG keys are decrypted through the normal core engine using the master-key
  material in 2. Unlock key.
- Certificate input: one certificate or a folder of them (for example a copied
  ``SystemCertificates\\My\\Certificates`` directory, whose files are named by the
  certificate SHA1 thumbprint).

Every recovered key is matched to a certificate by SHA256(SPKI) of the public
key. Each match is reported by the certificate SHA1 thumbprint (the store
filename) and bundled into its own PFX.
"""

from __future__ import annotations

from copy import copy
from pathlib import Path
import hashlib


PLUGIN_ID = "certificate_pfx"


def _spki_sha256(key, serialization) -> str:
    public = key.public_key() if hasattr(key, "public_key") else key
    encoded = public.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest().upper()


def _files_under(path: Path) -> list:
    if path.is_dir():
        found = sorted(item for item in path.rglob("*") if item.is_file())
        if not found:
            raise ValueError(f"no files found under {path.name}")
        return found
    return [path]


def _load_certificates(cert_arg, core, serialization):
    """Return {spki_sha256: (name, der_bytes, certificate)} from a file or folder."""
    path = Path(cert_arg)
    if path.is_dir():
        sources = [(item.name, item.read_bytes()) for item in _files_under(path)]
    else:
        data, cert_path, _ = core.read_data(cert_arg, "certificate")
        sources = [((cert_path.name if cert_path else "certificate"), data)]
    by_spki, errors = {}, []
    for name, data in sources:
        try:
            certificate = core.load_x509_certificate(data)
        except ValueError as exc:
            errors.append(f"{name}: {exc}")
            continue
        by_spki.setdefault(
            _spki_sha256(certificate.public_key(), serialization),
            (name, data, certificate),
        )
    if not by_spki:
        detail = f" ({'; '.join(errors)})" if errors else ""
        raise ValueError(f"no readable certificate found{detail}")
    return by_spki


def _recover_key_pem(raw, path, args, core):
    """Return a PKCS#8 PEM for one key: a ready PEM/DER key, or a CAPI/CNG decrypt."""
    from cryptography.hazmat.primitives import serialization

    key_password = (
        args.key_password.encode("utf-8")
        if args.key_password is not None
        else None
    )
    try:
        key = core.load_private_key(raw, key_password)
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    except ValueError:
        pass
    if path is None:
        return None
    inner = copy(args)
    inner.plugin = ""
    inner.type = "auto"
    inner.input = str(path)
    inner.certificate = None
    inner.pfx_password = None
    inner.pfx_password_file = None
    inner.key_password = None
    inner.output_format = "auto"
    try:
        outputs = core.run_single(inner, emit=lambda *_: None)
    except ValueError:
        return None
    for item in outputs:
        if item.extension == ".pem":
            return item.data
    return None


def _recover_keys(data, source_path, args, core, emit):
    """Return [(name, pem_bytes)] from one key input or a folder of key inputs."""
    if source_path is not None and Path(source_path).is_dir():
        paths = _files_under(Path(source_path))
    elif source_path is not None:
        paths = [Path(source_path)]
    else:
        pem = _recover_key_pem(data, None, args, core)
        return [("input", pem)] if pem else []
    keys = []
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            emit(f"[!] {path.name}: cannot read ({exc})")
            continue
        pem = _recover_key_pem(raw, path, args, core)
        if pem:
            keys.append((path.name, pem))
        else:
            emit(f"[!] {path.name}: not a private key and not a decryptable CAPI/CNG key")
    return keys


def run(data, source_path, _was_hex, args, core, emit):
    if not args.certificate:
        raise ValueError("certificate/PFX bundling requires a matching certificate")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError:
        raise ValueError("install cryptography to construct a PFX/PKCS#12 bundle") from None

    certs_by_spki = _load_certificates(args.certificate, core, serialization)
    emit(f"[+] {len(certs_by_spki)} candidate certificate(s)")

    keys = _recover_keys(data, source_path, args, core, emit)
    if not keys:
        raise ValueError("no private key recovered from the key input")
    emit(f"[+] {len(keys)} recovered private key(s)")

    pfx_secret = core.pfx_password(args)
    outputs, errors = [], []
    for index, (key_name, pem) in enumerate(keys):
        try:
            key = core.load_private_key(pem)
        except ValueError as exc:
            errors.append(f"{key_name}: {exc}")
            continue
        match = certs_by_spki.get(_spki_sha256(key, serialization))
        if match is None:
            emit(f"[!] {key_name}: no certificate public key matches this key")
            errors.append(f"{key_name}: no matching certificate")
            continue
        cert_name, cert_data, certificate = match
        thumbprint = certificate.fingerprint(hashes.SHA1()).hex().upper()
        emit(f"[+] {key_name} -> {thumbprint} ({certificate.subject.rfc4514_string()})")
        emit(f"[+] certificate SHA1 thumbprint: {thumbprint}")
        emit(f"[+] certificate public-key SHA256 (SPKI): {_spki_sha256(certificate.public_key(), serialization)}")
        emit(f"[+] private-key public-key SHA256 (SPKI): {_spki_sha256(key, serialization)}")
        try:
            bundle = core.build_pkcs12_bundle(
                pem, cert_data, pfx_secret, thumbprint.encode("ascii")
            )
        except ValueError as exc:
            errors.append(f"{key_name}: {exc}")
            continue
        outputs.extend((
            core.OutputItem(
                pem, ".pem", f"private key {thumbprint}", source_path,
                index * 2, len(keys) * 2,
            ),
            core.OutputItem(
                bundle, ".pfx", f"PFX {thumbprint}", source_path,
                index * 2 + 1, len(keys) * 2,
            ),
        ))

    if not outputs:
        detail = errors[-1] if errors else "no key matched any certificate"
        raise ValueError(f"could not correlate any key and certificate: {detail}")
    emit(
        f"[+] matched and created {len(outputs) // 2} PFX bundle(s)"
        + (f"; {len(errors)} key(s) unmatched" if errors else "")
    )
    return outputs
