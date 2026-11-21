import os
import re
import socket
import threading
import time

import pytest
import uvicorn

from cryptostore.client import cli
from cryptostore.client.workspace import ClientWorkspace
from cryptostore.server.__main__ import parse_arguments
from cryptostore.server.api import create_app

BLOCK_SIZE = "1024"


@pytest.fixture(scope="module")
def server_url(tmp_path_factory):
    # Servidor real con uvicorn en un puerto libre, como lo usaría la CLI
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(str(tmp_path_factory.mktemp("servidor"))),
                                           host="127.0.0.1", port=port, log_level="warning"))
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    server_thread.join()


@pytest.fixture
def run_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(cli.PASSPHRASE_ENVIRONMENT_VARIABLE, "contraseña de prueba")

    def _run(user: str, *arguments: str) -> tuple[int, str]:
        exit_code = cli.main(["--home", str(tmp_path / user), *arguments])
        captured = capsys.readouterr()
        return exit_code, captured.out + captured.err
    return _run


def fingerprint_of(tmp_path, user: str) -> str:
    return ClientWorkspace(str(tmp_path / user)).load_session().user_id


def test_full_flow_through_the_command_line(run_cli, server_url, tmp_path):
    for user in ("alice", "bob", "carol"):
        exit_code, output = run_cli(user, "init", "--name", user, "--server", server_url)
        assert exit_code == 0 and "huella" in output.lower()

    # Cada pareja compara huellas "por un canal confiable" y las fija en su libreta
    for truster, trusted in (("alice", "bob"), ("alice", "carol"), ("bob", "alice"), ("carol", "alice")):
        exit_code, _ = run_cli(truster, "trust", trusted, "--fingerprint", fingerprint_of(tmp_path, trusted))
        assert exit_code == 0

    # `users` no muestra huellas: la válida es la que dicta cada persona
    exit_code, output = run_cli("bob", "users")
    assert exit_code == 0 and "verificado como 'alice'" in output and fingerprint_of(tmp_path, "alice")[:8] not in output

    source = tmp_path / "contrato.txt"
    source.write_bytes(os.urandom(4 * 1024 + 10))
    exit_code, output = run_cli("alice", "upload", str(source), "--block-size", BLOCK_SIZE)
    assert exit_code == 0
    file_id = re.search(r"Publicado ([0-9a-f]{32})", output).group(1)

    assert run_cli("alice", "share", file_id, "bob")[0] == 0
    exit_code, output = run_cli("bob", "list")
    assert "contrato.txt" in output and "alice" in output

    bob_copy = tmp_path / "copia-bob.txt"
    assert run_cli("bob", "download", file_id, str(bob_copy))[0] == 0
    assert bob_copy.read_bytes() == source.read_bytes()

    assert run_cli("carol", "download", file_id, str(tmp_path / "carol.txt"))[0] == 1
    # Dave recibe el archivo pero aún no verificó a alice: la lista le dice qué hacer
    run_cli("dave", "init", "--name", "dave", "--server", server_url)
    run_cli("alice", "trust", "dave", "--fingerprint", fingerprint_of(tmp_path, "dave"))
    run_cli("alice", "share", file_id, "dave")
    exit_code, output = run_cli("dave", "list")
    assert "a quien aún no verificaste" in output and "cryptostore trust alice" in output
    assert run_cli("alice", "share", file_id, "carol")[0] == 0
    carol_copy = tmp_path / "copia-carol.txt"
    assert run_cli("carol", "download", file_id, str(carol_copy))[0] == 0

    exit_code, output = run_cli("alice", "revoke", file_id, "carol")
    assert exit_code == 0 and "sigue en su equipo" in output
    assert run_cli("carol", "download", file_id, str(tmp_path / "carol-2.txt"))[0] == 1
    assert carol_copy.read_bytes() == source.read_bytes()
    assert run_cli("bob", "download", file_id, str(tmp_path / "bob-2.txt"))[0] == 0

    exit_code, output = run_cli("alice", "recipients", file_id)
    assert "bob" in output and "carol" not in output


def test_trust_rejects_wrong_fingerprint(run_cli, server_url, tmp_path):
    for user in ("erin", "frank"):
        run_cli(user, "init", "--name", user, "--server", server_url)
    correct_fingerprint = fingerprint_of(tmp_path, "frank")
    # Se cambia el último dígito por otro distinto para que la huella nunca coincida por azar
    replacement_digit = "1" if correct_fingerprint[-1] == "0" else "0"
    wrong_fingerprint = correct_fingerprint[:-1] + replacement_digit
    exit_code, _ = run_cli("erin", "trust", "frank", "--fingerprint", wrong_fingerprint)
    assert exit_code == 1


def test_wrong_passphrase_is_reported(run_cli, server_url, monkeypatch):
    run_cli("gina", "init", "--name", "gina", "--server", server_url)
    monkeypatch.setenv(cli.PASSPHRASE_ENVIRONMENT_VARIABLE, "otra")
    exit_code, output = run_cli("gina", "whoami")
    assert exit_code == 1 and "contraseña" in output


def test_server_entrypoint_arguments():
    arguments = parse_arguments(["--data-dir", "/tmp/datos", "--port", "9100"])
    assert (arguments.data_dir, arguments.port, arguments.host) == ("/tmp/datos", 9100, "127.0.0.1")
