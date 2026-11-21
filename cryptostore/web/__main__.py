import argparse
import os
import sys
import webbrowser

import uvicorn

from cryptostore.web.app import DEFAULT_ALLOWED_HOSTS, create_web_app
from cryptostore.web.network_access import is_loopback_host, parse_networks
from cryptostore.web.tls import ensure_self_signed_certificate, local_addresses

DEFAULT_USERS_DIRECTORY = os.path.join("~", ".cryptostore-users")
_TRUE_VALUES = {"1", "true", "yes", "si", "sí"}


def _environment(name: str, default: str) -> str:
    return os.environ.get(f"CRYPTOSTORE_WEB_{name}", default)


def add_web_arguments(parser: argparse.ArgumentParser) -> None:
    # Cada opción también se puede dar por variable de entorno CRYPTOSTORE_WEB_* (útil en Docker)
    parser.add_argument("--users-dir", default=os.environ.get("CRYPTOSTORE_USERS_DIR", DEFAULT_USERS_DIRECTORY),
                        help=f"carpeta con una subcarpeta por usuario (por defecto {DEFAULT_USERS_DIRECTORY})")
    parser.add_argument("--host", default=_environment("HOST", "127.0.0.1"),
                        help="IP donde escuchar: 127.0.0.1 solo este equipo, 0.0.0.0 todas, o una IP concreta")
    parser.add_argument("--port", type=int, default=int(_environment("PORT", "8765")))
    parser.add_argument("--allow-from", default=_environment("ALLOW_FROM", "local"),
                        help="equipos que pueden conectarse: local, privadas, todas o rangos (192.168.1.0/24,10.0.0.7)")
    parser.add_argument("--allow-host", action="append", default=[],
                        help="nombre de host extra por el que se entrará (p. ej. mi-portatil.local); repetible")
    parser.add_argument("--tls", action="store_true", default=_environment("TLS", "").lower() in _TRUE_VALUES,
                        help="servir por HTTPS (certificado autofirmado si no se dan --tls-cert/--tls-key)")
    parser.add_argument("--tls-cert", default=_environment("TLS_CERT", "") or None)
    parser.add_argument("--tls-key", default=_environment("TLS_KEY", "") or None)
    parser.add_argument("--idle-minutes", type=float, default=float(_environment("IDLE_MINUTES", "30")),
                        help="minutos sin actividad antes de cerrar la sesión (por defecto 30)")
    parser.add_argument("--open", action="store_true", help="abrir el navegador automáticamente")


def serve(arguments: argparse.Namespace) -> None:
    users_directory = os.path.abspath(os.path.expanduser(arguments.users_dir))
    extra_hosts = set(arguments.allow_host) | {
        name.strip() for name in _environment("ALLOWED_HOSTS", "").split(",") if name.strip()}
    allowed_networks = parse_networks(arguments.allow_from)
    listens_beyond_this_machine = not is_loopback_host(arguments.host)

    tls_options, scheme = {}, "http"
    if arguments.tls:
        if arguments.tls_cert and arguments.tls_key:
            tls_options = {"ssl_certfile": arguments.tls_cert, "ssl_keyfile": arguments.tls_key}
            fingerprint = None
        else:
            material = ensure_self_signed_certificate(os.path.join(users_directory, ".tls"), sorted(extra_hosts))
            tls_options = {"ssl_certfile": material.certificate_path, "ssl_keyfile": material.private_key_path}
            fingerprint = material.fingerprint
        scheme = "https"

    app = create_web_app(users_directory, allowed_hosts=DEFAULT_ALLOWED_HOSTS | extra_hosts,
                         allowed_networks=allowed_networks, secure_cookies=arguments.tls,
                         idle_seconds=arguments.idle_minutes * 60)

    print(f"Usuarios en {users_directory}  (la terminal usa --home {users_directory}/<usuario>)")
    # Escuchando en todas las interfaces se muestran las IPs por las que otros equipos pueden entrar
    if arguments.host in ("0.0.0.0", "::"):
        addresses = [address for address in local_addresses() if address not in ("::1",)]
    else:
        addresses = [arguments.host]
    # Dentro de Docker las IPs propias son las del contenedor, no las que ven los demás equipos
    if os.path.exists("/.dockerenv"):
        print(f"En Docker: abra {scheme}://<IP de este equipo>:<puerto publicado>/ (p. ej. {scheme}://192.168.1.20:8765/)")
    else:
        for address in addresses:
            print(f"Abra: {scheme}://{address}:{arguments.port}/")
    print(f"Equipos permitidos: {arguments.allow_from}")
    if arguments.tls and fingerprint:
        print("Certificado autofirmado. Antes de aceptar el aviso del navegador, compare su huella SHA-256:")
        print(f"  {fingerprint}")
    if listens_beyond_this_machine and not arguments.tls:
        # Por la red viajarían contraseñas y archivos en claro: el cifrado de extremo a extremo empieza en este proceso
        print("AVISO: expuesta a la red sin HTTPS. Contraseñas y archivos viajarían sin cifrar hasta aquí. Use --tls.")
    print("Ctrl+C para cerrar. Las claves y el cifrado viven en este proceso: quien use esta interfaz confía en este equipo.")

    if arguments.open:
        webbrowser.open(f"{scheme}://{addresses[0]}:{arguments.port}/")
    uvicorn.run(app, host=arguments.host, port=arguments.port, log_level="warning", **tls_options)


def main(argument_list: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cryptostore-web", description="Interfaz web con login por usuario.")
    add_web_arguments(parser)
    serve(parser.parse_args(argument_list))
    return 0


if __name__ == "__main__":
    sys.exit(main())
