import re
from dataclasses import dataclass

from cryptostore.client.file_version_resolver import FileVersionResolver, ResolvedFileVersion
from cryptostore.client.session import ClientSession
from cryptostore.errors import IdentityError
from cryptostore.protocol.access_grant import AccessGrant
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.public_identity import normalize_fingerprint

_USER_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class RecipientEntry:
    user_id: str
    label: str


def revocation_scope_message(recipient_label: str) -> str:
    return (
        f"Acceso retirado a {recipient_label}.\n"
        f"  - El servidor ya no le entrega su envolvente: no puede obtener la clave del archivo desde aquí.\n"
        f"  - Lo que {recipient_label} ya descargó (el archivo o su clave) sigue en su equipo. "
        f"Retirar el acceso no puede borrar esa copia.\n"
        f"  - Los cambios futuros súbalos como versión nueva (upload --replace): "
        f"usan una clave de datos nueva que {recipient_label} no recibirá."
    )


class AccessManager:
    def __init__(self, session: ClientSession):
        self._session = session

    def share(self, file_id: str, alias: str) -> int:
        # Solo contactos con huella verificada: sellar para una clave falsa entregaría el archivo a un impostor
        recipient = self._session.trust_store.require_alias(alias)
        resolved = FileVersionResolver(self._session).resolve(file_id)
        self._require_owner(resolved)
        # Compartir = sellar la clave de datos para el destinatario; el contenido no se vuelve a cifrar
        grant = AccessGrant.issue(data_encryption_key=resolved.key_material.data_encryption_key,
                                  manifest=resolved.manifest, recipient=recipient)
        return self._session.server_api.put_grant(grant)

    def revoke(self, file_id: str, alias_or_user_id: str) -> tuple[int, str]:
        recipient_id = self._recipient_id(alias_or_user_id)
        if recipient_id == self._session.identity.user_id:
            raise IdentityError("el dueño no puede retirarse el acceso a sí mismo")
        # Revocar = pedir al servidor que borre la envolvente; no hay nada que cifrar de nuevo
        acl_epoch = self._session.server_api.delete_grant(file_id, recipient_id)
        return acl_epoch, self._session.describe_user(recipient_id)

    def recipients(self, file_id: str) -> tuple[int, list[RecipientEntry]]:
        acl_epoch, recipient_ids = self._session.server_api.list_grants(file_id)
        entries = [RecipientEntry(user_id, self._session.describe_user(user_id)) for user_id in recipient_ids]
        return acl_epoch, entries

    def grant_to_self(self, manifest: SignedManifest, data_encryption_key: bytes) -> None:
        # El dueño también guarda su envolvente en el servidor, para volver a abrir y compartir el archivo después
        grant = AccessGrant.issue(data_encryption_key=data_encryption_key, manifest=manifest,
                                  recipient=self._session.identity.public)
        self._session.server_api.put_grant(grant)

    def renew_after_new_version(self, manifest: SignedManifest, data_encryption_key: bytes) -> tuple[list[str], list[str]]:
        file_id = manifest.body.file_id.hex()
        _, current_recipient_ids = self._session.server_api.list_grants(file_id)
        renewed, skipped = [], []
        for recipient_id in current_recipient_ids:
            if recipient_id == self._session.identity.user_id:
                continue
            # La versión nueva tiene otra clave de datos: hay que sellarla otra vez para cada destinatario vigente
            recipient = self._session.trust_store.find_by_user_id(recipient_id)
            if recipient is None:
                skipped.append(self._session.describe_user(recipient_id))
                continue
            self._session.server_api.put_grant(AccessGrant.issue(
                data_encryption_key=data_encryption_key, manifest=manifest, recipient=recipient))
            renewed.append(self._session.describe_user(recipient_id))
        return renewed, skipped

    def _require_owner(self, resolved: ResolvedFileVersion) -> None:
        if resolved.body.owner_id != self._session.identity.user_id:
            raise IdentityError("solo el dueño puede compartir este archivo")

    def _recipient_id(self, alias_or_user_id: str) -> str:
        identity = self._session.trust_store.find_by_alias(alias_or_user_id)
        if identity is not None:
            return identity.user_id
        # También se acepta la huella completa, por si el contacto ya no está en la libreta
        normalized = normalize_fingerprint(alias_or_user_id)
        if _USER_ID_PATTERN.fullmatch(normalized):
            return normalized
        raise IdentityError(f"'{alias_or_user_id}' no es un alias de la libreta ni una huella completa")
