import argparse
import getpass
import os
import sys

from cryptostore.client.access_manager import AccessManager, revocation_scope_message
from cryptostore.client.file_downloader import FileDownloader
from cryptostore.client.file_uploader import FileUploader
from cryptostore.client.file_catalog import PROBLEM_UNVERIFIED_OWNER, list_visible_files
from cryptostore.client.progress import TerminalProgressBar
from cryptostore.client.server_api import ServerError
from cryptostore.client.session import ClientSession
from cryptostore.errors import CryptoStoreError, VerificationError
from cryptostore.protocol.file_blocks import DEFAULT_BLOCK_SIZE
from cryptostore.protocol.public_identity import format_fingerprint_for_humans, normalize_fingerprint
from cryptostore.web.__main__ import add_web_arguments, serve

PASSPHRASE_ENVIRONMENT_VARIABLE = "CRYPTOSTORE_PASSPHRASE"
HOME_ENVIRONMENT_VARIABLE = "CRYPTOSTORE_HOME"
SERVER_URL_ENVIRONMENT_VARIABLE = "CRYPTOSTORE_SERVER_URL"
DEFAULT_HOME = os.path.join("~", ".cryptostore")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptostore",
        description="Cliente de almacenamiento cifrado: todo se cifra y verifica en este equipo.",
    )
    parser.add_argument("--home", default=os.environ.get(HOME_ENVIRONMENT_VARIABLE, DEFAULT_HOME),
                        help=f"carpeta local del usuario (por defecto {DEFAULT_HOME}, o ${HOME_ENVIRONMENT_VARIABLE})")
    commands = parser.add_subparsers(dest="command", required=True, metavar="comando")

    init_command = commands.add_parser("init", help="crear identidad y registrarla en el servidor")
    init_command.add_argument("--name", required=True, help="nombre visible")
    # Sin --server se usa CRYPTOSTORE_SERVER_URL: así cada equipo apunta a su servidor desde el .env
    server_from_environment = os.environ.get(SERVER_URL_ENVIRONMENT_VARIABLE)
    init_command.add_argument("--server", default=server_from_environment, required=server_from_environment is None,
                              help=f"URL del servidor, p. ej. http://192.168.1.20:8000 (o ${SERVER_URL_ENVIRONMENT_VARIABLE})")

    commands.add_parser("whoami", help="mostrar la propia huella para dictarla a otros")
    commands.add_parser("users", help="usuarios registrados en el servidor y si ya los verificaste")
    commands.add_parser("contacts", help="contactos verificados en la libreta local")

    trust_command = commands.add_parser("trust", help="fijar un contacto tras comparar su huella")
    trust_command.add_argument("alias")
    trust_command.add_argument("--fingerprint", required=True, help="huella dictada por el contacto")

    untrust_command = commands.add_parser("untrust", help="quitar un contacto de la libreta")
    untrust_command.add_argument("alias")

    upload_command = commands.add_parser("upload", help="cifrar y subir un archivo (reanuda si se cortó)")
    upload_command.add_argument("path")
    upload_command.add_argument("--replace", metavar="FILE_ID", help="publicar como versión nueva de ese archivo")
    upload_command.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE, help=argparse.SUPPRESS)

    commands.add_parser("list", help="archivos propios y compartidos conmigo")

    download_command = commands.add_parser("download", help="descargar, verificar y descifrar un archivo")
    download_command.add_argument("file_id")
    download_command.add_argument("destination", nargs="?", help="ruta o carpeta de destino (por defecto la actual)")
    download_command.add_argument("--overwrite", action="store_true")

    share_command = commands.add_parser("share", help="dar acceso a un contacto verificado")
    share_command.add_argument("file_id")
    share_command.add_argument("alias")

    revoke_command = commands.add_parser("revoke", help="retirar el acceso a un destinatario")
    revoke_command.add_argument("file_id")
    revoke_command.add_argument("recipient", help="alias de la libreta o huella completa")

    recipients_command = commands.add_parser("recipients", help="quién tiene acceso a un archivo")
    recipients_command.add_argument("file_id")

    web_command = commands.add_parser("web", help="interfaz web con login (varios usuarios, local o en la red)")
    add_web_arguments(web_command)
    return parser


def main(argument_list: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argument_list)
    try:
        if arguments.command == "init":
            return command_init(arguments)
        # La web tiene su propio login; no se abre sesión aquí
        if arguments.command == "web":
            serve(arguments)
            return 0
        session = ClientSession.open(arguments.home, read_passphrase(confirm=False))
        return COMMAND_HANDLERS[arguments.command](session, arguments)
    except VerificationError as error:
        # Rechazo criptográfico: nada se entregó al usuario
        print(f"RECHAZADO: {error}", file=sys.stderr)
        return 2
    except (CryptoStoreError, ServerError, FileExistsError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def read_passphrase(confirm: bool) -> str:
    # Para guiones y pruebas se puede dar por variable de entorno; si no, se pide sin mostrarla
    from_environment = os.environ.get(PASSPHRASE_ENVIRONMENT_VARIABLE)
    if from_environment:
        return from_environment
    passphrase = getpass.getpass("Contraseña de la identidad: ")
    if confirm and getpass.getpass("Repítala: ") != passphrase:
        raise CryptoStoreError("las contraseñas no coinciden")
    return passphrase


def command_init(arguments) -> int:
    session = ClientSession.create(arguments.home, arguments.name, read_passphrase(confirm=True), arguments.server)
    print(f"Identidad '{arguments.name}' creada en {session.workspace.home_directory}")
    print("Dicte esta huella a sus contactos por un canal confiable:")
    print(f"  {format_fingerprint_for_humans(session.identity.user_id)}")
    return 0


def command_whoami(session: ClientSession, _arguments) -> int:
    print(f"{session.identity.display_name}")
    print(f"  huella: {format_fingerprint_for_humans(session.identity.user_id)}")
    return 0


def command_users(session: ClientSession, _arguments) -> int:
    for user in session.server_api.list_users():
        # Sin huellas: la que vale es la que dicta cada persona, no la que muestra el servidor
        if user["user_id"] == session.identity.user_id:
            status = "tú"
        else:
            alias = session.trust_store.alias_of(user["user_id"])
            status = f"verificado como '{alias}'" if alias else "sin verificar"
        print(f"{user['display_name']:<16} {status}")
    return 0


def command_contacts(session: ClientSession, _arguments) -> int:
    for alias, identity in sorted(session.trust_store.aliases().items()):
        print(f"{alias:<16} {format_fingerprint_for_humans(identity.user_id)}")
    return 0


def command_trust(session: ClientSession, arguments) -> int:
    # Se pide al servidor la identidad con esa huella y se comprueba localmente que realmente la tenga
    identity = session.server_api.get_user(normalize_fingerprint(arguments.fingerprint))
    session.trust_store.pin(arguments.alias, identity, arguments.fingerprint)
    print(f"'{arguments.alias}' verificado y fijado ({identity.display_name}).")
    return 0


def command_untrust(session: ClientSession, arguments) -> int:
    session.trust_store.remove(arguments.alias)
    print(f"'{arguments.alias}' eliminado de la libreta.")
    return 0


def command_upload(session: ClientSession, arguments) -> int:
    uploader = FileUploader(session, on_progress=TerminalProgressBar("Subiendo  "))
    result = uploader.upload(arguments.path, replace_file_id=arguments.replace, block_size=arguments.block_size)
    if result.blocks_already_on_server:
        print(f"Reanudada: {result.blocks_already_on_server} de {result.total_blocks} bloques ya estaban en el servidor.")
    print(f"Publicado {result.file_id} (versión {result.content_version}, {result.total_blocks} bloques).")
    if result.renewed_recipients:
        print(f"Acceso renovado a la nueva versión para: {', '.join(result.renewed_recipients)}")
    if result.skipped_recipients:
        print(f"Sin renovar (no están en su libreta): {', '.join(result.skipped_recipients)}")
    return 0


def command_list(session: ClientSession, _arguments) -> int:
    for listing in list_visible_files(session):
        if listing.problem:
            description = f"({listing.problem})"
        else:
            description = f"{listing.name}  ({listing.plaintext_size} bytes)"
        print(f"{listing.file_id}  v{listing.latest_version:<3} dueño: {listing.owner_label:<12} {description}")
        if listing.problem_kind == PROBLEM_UNVERIFIED_OWNER:
            print(f"    pide a {listing.owner_claimed_name} que te dicte su huella y ejecuta: "
                  f"cryptostore trust {listing.owner_claimed_name} --fingerprint \"…\"")
    return 0


def command_download(session: ClientSession, arguments) -> int:
    downloader = FileDownloader(session, on_progress=TerminalProgressBar("Bajando   "))
    result = downloader.download(arguments.file_id, arguments.destination, overwrite=arguments.overwrite)
    print(f"Verificado y guardado en {result.destination_path} "
          f"({result.metadata.plaintext_size} bytes, versión {result.content_version}).")
    return 0


def command_share(session: ClientSession, arguments) -> int:
    acl_epoch = AccessManager(session).share(arguments.file_id, arguments.alias)
    print(f"Acceso dado a {arguments.alias} sin volver a cifrar el contenido (época de permisos {acl_epoch}).")
    return 0


def command_revoke(session: ClientSession, arguments) -> int:
    acl_epoch, recipient_label = AccessManager(session).revoke(arguments.file_id, arguments.recipient)
    print(revocation_scope_message(recipient_label))
    print(f"(época de permisos {acl_epoch})")
    return 0


def command_recipients(session: ClientSession, arguments) -> int:
    acl_epoch, entries = AccessManager(session).recipients(arguments.file_id)
    print(f"Época de permisos {acl_epoch}:")
    for entry in entries:
        print(f"  {entry.label:<16} {format_fingerprint_for_humans(entry.user_id)}")
    return 0


COMMAND_HANDLERS = {
    "whoami": command_whoami,
    "users": command_users,
    "contacts": command_contacts,
    "trust": command_trust,
    "untrust": command_untrust,
    "upload": command_upload,
    "list": command_list,
    "download": command_download,
    "share": command_share,
    "revoke": command_revoke,
    "recipients": command_recipients,
}
