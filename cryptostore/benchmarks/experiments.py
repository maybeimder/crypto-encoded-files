import os
import statistics
import tempfile
import time
from dataclasses import dataclass
from typing import Callable

from fastapi.testclient import TestClient

from cryptostore.client.access_manager import AccessManager
from cryptostore.client.file_downloader import FileDownloader
from cryptostore.client.file_uploader import FileUploader
from cryptostore.client.private_identity import PrivateIdentity
from cryptostore.client.session import ClientSession
from cryptostore.protocol.access_grant import AccessGrant
from cryptostore.protocol.file_blocks import DEFAULT_BLOCK_SIZE, FileKeyMaterial, SourceFileEncryptor
from cryptostore.protocol.file_metadata import FileMetadata
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.serialization import canonical_json
from cryptostore.protocol.verified_download import VerifiedFileAssembler
from cryptostore.server.api import create_app

MEBIBYTE = 1 << 20


@dataclass(frozen=True)
class Timing:
    mean_seconds: float
    standard_deviation_seconds: float


def measure(operation: Callable[[], None], repetitions: int) -> Timing:
    durations = []
    for _ in range(repetitions):
        started_at = time.perf_counter()
        operation()
        durations.append(time.perf_counter() - started_at)
    deviation = statistics.stdev(durations) if len(durations) > 1 else 0.0
    return Timing(statistics.mean(durations), deviation)


def megabytes_per_second(size_in_bytes: int, timing: Timing) -> float | None:
    # Con archivos diminutos el tiempo es casi todo costo fijo; la velocidad no dice nada
    if size_in_bytes < MEBIBYTE or timing.mean_seconds == 0:
        return None
    return size_in_bytes / MEBIBYTE / timing.mean_seconds


def write_random_file(directory: str, size_in_bytes: int, name: str = "origen.bin") -> str:
    path = os.path.join(directory, name)
    with open(path, "wb") as random_file:
        # Por partes de 1 MiB para no generar 100 MB de golpe en memoria
        remaining = size_in_bytes
        while remaining > 0:
            chunk_size = min(remaining, MEBIBYTE)
            random_file.write(os.urandom(chunk_size))
            remaining -= chunk_size
    return path


def encrypt_in_memory(source_path: str, owner: PrivateIdentity, block_size: int):
    key_material = FileKeyMaterial.generate()
    encryptor = SourceFileEncryptor(source_path, key_material, block_size)
    blocks = list(encryptor.encrypted_blocks())
    metadata = FileMetadata("origen.bin", "application/octet-stream", encryptor.file_size)
    manifest = SignedManifest.build(
        key_material=key_material, owner_id=owner.user_id, owner_signing_private_key=owner.signing_private_key,
        block_size=block_size, block_hashes=[block.digest for block in blocks],
        encrypted_metadata=metadata.encrypt(key_material),
    )
    return key_material, manifest, [block.payload for block in blocks]


def crypto_throughput(file_sizes: list[int], repetitions: int) -> list[dict]:
    owner = PrivateIdentity.generate("medicion")
    rows = []
    with tempfile.TemporaryDirectory() as work_directory:
        for file_size in file_sizes:
            source_path = write_random_file(work_directory, file_size)
            # Cifrado: leer, cifrar cada bloque, calcular huellas y firmar el manifiesto
            encryption = measure(lambda: encrypt_in_memory(source_path, owner, DEFAULT_BLOCK_SIZE), repetitions)
            key_material, manifest, payloads = encrypt_in_memory(source_path, owner, DEFAULT_BLOCK_SIZE)
            destination = os.path.join(work_directory, "destino.bin")

            def verify_and_decrypt():
                # Descifrado completo como en una descarga: firma, huellas, AEAD y renombrado atómico
                body = manifest.verify(owner.public)
                VerifiedFileAssembler(body, key_material, file_size).assemble(
                    lambda index: payloads[index], destination)
            decryption = measure(verify_and_decrypt, repetitions)
            rows.append({
                "file_size_bytes": file_size,
                "blocks": manifest.body.total_blocks,
                "encrypt_seconds": encryption.mean_seconds,
                "encrypt_stdev_seconds": encryption.standard_deviation_seconds,
                "encrypt_mib_per_second": megabytes_per_second(file_size, encryption),
                "decrypt_seconds": decryption.mean_seconds,
                "decrypt_stdev_seconds": decryption.standard_deviation_seconds,
                "decrypt_mib_per_second": megabytes_per_second(file_size, decryption),
            })
            os.remove(source_path)
    return rows


def block_size_overhead(file_size: int, block_sizes: list[int], repetitions: int) -> list[dict]:
    owner = PrivateIdentity.generate("medicion")
    rows = []
    with tempfile.TemporaryDirectory() as work_directory:
        source_path = write_random_file(work_directory, file_size)
        for block_size in block_sizes:
            encryption = measure(lambda: encrypt_in_memory(source_path, owner, block_size), repetitions)
            _, manifest, payloads = encrypt_in_memory(source_path, owner, block_size)
            stored_ciphertext_bytes = sum(len(payload) for payload in payloads)
            # Lo que se guarda de más: la etiqueta de cada bloque y el manifiesto (con una huella por bloque).
            # El nonce y los datos asociados no se guardan: se recalculan
            tag_bytes = stored_ciphertext_bytes - file_size
            manifest_bytes = len(canonical_json(manifest.to_json_dict()))
            total_overhead_bytes = tag_bytes + manifest_bytes
            rows.append({
                "block_size_bytes": block_size,
                "blocks": len(payloads),
                "tag_bytes": tag_bytes,
                "manifest_bytes": manifest_bytes,
                "overhead_bytes": total_overhead_bytes,
                "overhead_bytes_per_block": total_overhead_bytes / len(payloads),
                "overhead_percent": 100 * total_overhead_bytes / file_size,
                "encrypt_seconds": encryption.mean_seconds,
            })
    return rows


def grant_growth(recipient_counts: list[int], file_sizes: list[int], repetitions: int) -> list[dict]:
    owner = PrivateIdentity.generate("dueno")
    largest_count = max(recipient_counts)
    recipients = [PrivateIdentity.generate(f"destinatario-{number}").public for number in range(largest_count)]
    rows = []
    with tempfile.TemporaryDirectory() as work_directory:
        for file_size in file_sizes:
            source_path = write_random_file(work_directory, file_size)
            key_material, manifest, _ = encrypt_in_memory(source_path, owner, DEFAULT_BLOCK_SIZE)
            for recipient_count in recipient_counts:
                chosen = recipients[:recipient_count]

                def issue_all_grants():
                    # Compartir con N personas = N sellados HPKE de la misma clave de 32 bytes
                    return [AccessGrant.issue(data_encryption_key=key_material.data_encryption_key,
                                              manifest=manifest, recipient=recipient) for recipient in chosen]
                timing = measure(issue_all_grants, repetitions)
                grants = issue_all_grants()
                raw_bytes = sum(len(grant.sealed_data_key.encapsulated_key) + len(grant.sealed_data_key.ciphertext)
                                for grant in grants)
                stored_bytes = sum(len(canonical_json(grant.to_json_dict())) for grant in grants)
                rows.append({
                    "file_size_bytes": file_size,
                    "recipients": recipient_count,
                    "grant_raw_bytes": raw_bytes,
                    "grant_stored_bytes": stored_bytes,
                    "issue_seconds": timing.mean_seconds,
                })
            os.remove(source_path)
    return rows


def end_to_end(file_sizes: list[int], repetitions: int) -> list[dict]:
    rows = []
    with tempfile.TemporaryDirectory() as work_directory:
        # Servidor real en el mismo proceso (sin red): mide cifrado + HTTP + disco del servidor
        app = create_app(os.path.join(work_directory, "servidor"))
        owner = ClientSession.create(os.path.join(work_directory, "dueno"), "dueno", "medicion",
                                     "http://testserver", http_client=TestClient(app))
        recipient = ClientSession.create(os.path.join(work_directory, "destinatario"), "destinatario", "medicion",
                                         "http://testserver", http_client=TestClient(app))
        for truster, trusted in ((owner, recipient), (recipient, owner)):
            truster.trust_store.pin(trusted.identity.display_name,
                                    truster.server_api.get_user(trusted.identity.user_id), trusted.identity.user_id)

        for file_size in file_sizes:
            source_path = write_random_file(work_directory, file_size)
            uploaded_file_ids = []
            upload_timing = measure(
                lambda: uploaded_file_ids.append(FileUploader(owner).upload(source_path).file_id), repetitions)
            file_id = uploaded_file_ids[-1]
            AccessManager(owner).share(file_id, "destinatario")
            destination = os.path.join(work_directory, "bajado.bin")
            download_timing = measure(
                lambda: FileDownloader(recipient).download(file_id, destination, overwrite=True), repetitions)
            rows.append({
                "file_size_bytes": file_size,
                "upload_seconds": upload_timing.mean_seconds,
                "upload_mib_per_second": megabytes_per_second(file_size, upload_timing),
                "download_seconds": download_timing.mean_seconds,
                "download_mib_per_second": megabytes_per_second(file_size, download_timing),
            })
            os.remove(source_path)
    return rows
