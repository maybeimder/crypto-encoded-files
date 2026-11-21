import argparse
import os

import uvicorn

from cryptostore.server.api import create_app


def parse_arguments(argument_list: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cryptostore-server",
        description="Servidor de objetos cifrados: guarda bloques, manifiestos y envolventes sin poder abrirlos.",
    )
    # Cada opción también se puede dar por variable de entorno (útil en Docker)
    parser.add_argument("--data-dir", default=os.environ.get("CRYPTOSTORE_DATA_DIR", "./server-data"),
                        help="carpeta donde se guardan los objetos (por defecto ./server-data)")
    parser.add_argument("--host", default=os.environ.get("CRYPTOSTORE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CRYPTOSTORE_PORT", "8000")))
    return parser.parse_args(argument_list)


def main(argument_list: list[str] | None = None) -> None:
    arguments = parse_arguments(argument_list)
    print(f"Datos del servidor en {os.path.abspath(arguments.data_dir)}")
    uvicorn.run(create_app(arguments.data_dir), host=arguments.host, port=arguments.port)


if __name__ == "__main__":
    main()
