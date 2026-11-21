import datetime
import ipaddress
import json
import os
import socket
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cryptostore.atomic_files import write_file_atomically

CERTIFICATE_VALIDITY_DAYS = 365


@dataclass(frozen=True)
class TlsMaterial:
    certificate_path: str
    private_key_path: str
    fingerprint: str  # SHA-256 del certificado, como lo muestra el navegador


def local_addresses() -> list[str]:
    addresses = {"127.0.0.1", "::1"}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            # No envía nada: solo pregunta al sistema qué IP usaría para salir a la red
            probe.connect(("192.0.2.1", 9))
            addresses.add(probe.getsockname()[0])
        except OSError:
            pass
    return sorted(addresses)


def ensure_self_signed_certificate(directory: str, host_names: list[str]) -> TlsMaterial:
    names = sorted(set(host_names) | {"localhost"} | set(local_addresses()))
    certificate_path = os.path.join(directory, "cert.pem")
    private_key_path = os.path.join(directory, "key.pem")
    names_path = os.path.join(directory, "names.json")

    # Se reutiliza el mismo certificado mientras cubra los mismos nombres: su huella no cambia entre reinicios
    if os.path.exists(certificate_path) and os.path.exists(names_path):
        with open(names_path) as names_file:
            if json.load(names_file) == names:
                return TlsMaterial(certificate_path, private_key_path, _fingerprint_of(certificate_path))

    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cryptostore (local)")])
    now = datetime.datetime.now(datetime.timezone.utc)
    # Nombres alternativos: las IPs y nombres por los que se entrará a la interfaz
    alternative_names = [_alternative_name(name) for name in names]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CERTIFICATE_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    write_file_atomically(private_key_path, private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write_file_atomically(certificate_path, certificate.public_bytes(serialization.Encoding.PEM), permissions=0o644)
    write_file_atomically(names_path, json.dumps(names).encode(), permissions=0o644)
    return TlsMaterial(certificate_path, private_key_path, _fingerprint_of(certificate_path))


def _alternative_name(name: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        return x509.DNSName(name)


def _fingerprint_of(certificate_path: str) -> str:
    with open(certificate_path, "rb") as certificate_file:
        certificate = x509.load_pem_x509_certificate(certificate_file.read())
    return ":".join(f"{byte:02X}" for byte in certificate.fingerprint(hashes.SHA256()))
