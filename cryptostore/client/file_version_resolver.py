from dataclasses import dataclass

from cryptostore.client.session import ClientSession
from cryptostore.errors import VerificationError
from cryptostore.protocol.file_blocks import FileKeyMaterial
from cryptostore.protocol.file_metadata import FileMetadata
from cryptostore.protocol.manifest import ManifestBody, SignedManifest


@dataclass(frozen=True)
class ResolvedFileVersion:
    manifest: SignedManifest
    key_material: FileKeyMaterial
    metadata: FileMetadata

    @property
    def body(self) -> ManifestBody:
        return self.manifest.body


# Obtiene la última versión de un archivo y la deja lista para usar, verificando todo por el camino
class FileVersionResolver:
    def __init__(self, session: ClientSession):
        self._session = session

    def resolve(self, file_id: str) -> ResolvedFileVersion:
        server_api = self._session.server_api
        manifest = server_api.get_manifest(file_id)
        # El dueño se busca en la libreta local; si no está verificado, se rechaza aquí
        owner = self._session.trusted_identity(manifest.body.owner_id)
        # Firma del dueño y versión no anterior a la última vista por este cliente
        body = manifest.verify(owner, minimum_content_version=self._session.workspace.seen_version(file_id))
        if body.file_id.hex() != file_id:
            raise VerificationError("el servidor entregó el manifiesto de otro archivo")

        # La envolvente propia solo abre con mi clave privada y atada a este manifiesto exacto
        grant = server_api.get_my_grant(file_id)
        data_encryption_key = grant.open(
            manifest=manifest,
            recipient_id=self._session.identity.user_id,
            recipient_encryption_private_key=self._session.identity.encryption_private_key,
        )
        key_material = body.key_material_with(data_encryption_key)
        metadata = FileMetadata.decrypt(key_material, body.encrypted_metadata)

        self._session.workspace.record_seen_version(file_id, body.content_version)
        return ResolvedFileVersion(manifest, key_material, metadata)
