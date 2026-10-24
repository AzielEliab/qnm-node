"""TLS 1.3 certificates. Peer authentication is the pinned certificate.

No custom cipher. The certificate is not the Ed25519 identity.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import stat
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qnsd.lan.contract import LanRefuse


def _chmod_private(path: Path) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def cert_sha256(pem: bytes | str) -> str:
    raw = pem.encode("utf-8") if isinstance(pem, str) else pem
    cert = x509.load_pem_x509_certificate(raw)
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def cert_common_name(pem: bytes | str) -> str:
    raw = pem.encode("utf-8") if isinstance(pem, str) else pem
    cert = x509.load_pem_x509_certificate(raw)
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        raise LanRefuse("QNS-LAN-IDENTITY", "certificate has no name", outcome="refused", security=True)
    return str(attrs[0].value)


def ensure_cert(directory: Path, handle: str) -> dict[str, str]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, stat.S_IRWXU)
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    if cert_path.is_file() and key_path.is_file():
        pem = cert_path.read_text(encoding="utf-8")
        if cert_common_name(pem) != handle:
            raise LanRefuse("QNS-LAN-IDENTITY", "stored certificate name mismatch", outcome="refused", security=True)
        return {"cert_pem": pem, "cert_sha256": cert_sha256(pem), "cert_path": str(cert_path), "key_path": str(key_path)}
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, handle)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"qns:{handle}")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_path.write_bytes(key_pem)
    _chmod_private(key_path)
    cert_path.write_bytes(cert_pem)
    _chmod_private(cert_path)
    pem_text = cert_pem.decode("ascii")
    return {
        "cert_pem": pem_text,
        "cert_sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "cert_path": str(cert_path),
        "key_path": str(key_path),
    }


def server_context(cert_path: str, key_path: str, peer_pems: list[str]):
    import ssl

    if not peer_pems:
        raise LanRefuse("QNS-LAN-ABSENT", "no pinned peer certificate", outcome="absent", security=False)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(cadata="".join(peer_pems))
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    return ctx


def client_context(cert_path: str, key_path: str, peer_pem: str):
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    ctx.load_verify_locations(cadata=peer_pem)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False
    return ctx
