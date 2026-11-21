import os

import pytest
from fastapi.testclient import TestClient

from cryptostore.client.access_manager import AccessManager
from cryptostore.client.file_downloader import FileDownloader
from cryptostore.client.file_uploader import FileUploader
from cryptostore.client.server_api import ServerError
from cryptostore.client.session import ClientSession
from cryptostore.client.upload_checkpoint import UploadCheckpointStore
from cryptostore.errors import FormatError, IdentityError, VerificationError
from cryptostore.server.api import create_app

BLOCK_SIZE = 1024
PASSPHRASE = "contraseña de prueba"


@pytest.fixture
def server_directory(tmp_path):
    return tmp_path / "servidor"


@pytest.fixture
def make_session(tmp_path, server_directory):
    app = create_app(str(server_directory))

    def _make(name: str) -> ClientSession:
        return ClientSession.create(str(tmp_path / name), name, PASSPHRASE, "http://testserver",
                                    http_client=TestClient(app))
    return _make


@pytest.fixture
def alice(make_session):
    return make_session("alice")


@pytest.fixture
def bob(make_session, alice):
    session = make_session("bob")
    trust_each_other(alice, session)
    return session


@pytest.fixture
def carol(make_session, alice):
    session = make_session("carol")
    trust_each_other(alice, session)
    return session


@pytest.fixture
def source_file(tmp_path):
    path = tmp_path / "informe.pdf"
    path.write_bytes(os.urandom(5 * BLOCK_SIZE + 123))
    return path


def trust_each_other(first: ClientSession, second: ClientSession) -> None:
    for truster, trusted in ((first, second), (second, first)):
        identity = truster.server_api.get_user(trusted.identity.user_id)
        truster.trust_store.pin(trusted.identity.display_name, identity, trusted.identity.user_id)


def upload(session, path, **options):
    return FileUploader(session).upload(str(path), block_size=BLOCK_SIZE, **options)


def download(session, file_id, destination):
    return FileDownloader(session).download(file_id, str(destination))


def checkpoints_of(session):
    return UploadCheckpointStore(session.workspace.checkpoints_directory, session.identity.encryption_private_key)


def interrupt_after(session, monkeypatch, successful_blocks: int):
    real_put_block = session.server_api.put_block
    sent_blocks = []

    def flaky_put_block(*arguments):
        if len(sent_blocks) == successful_blocks:
            raise ServerError(0, "conexión cortada (simulada)")
        sent_blocks.append(arguments)
        real_put_block(*arguments)
    monkeypatch.setattr(session.server_api, "put_block", flaky_put_block)
    return lambda: monkeypatch.setattr(session.server_api, "put_block", real_put_block)


def test_owner_and_two_recipients_download_with_progress(alice, bob, carol, source_file, tmp_path):
    progress_updates = []
    result = FileUploader(alice, on_progress=lambda done, total: progress_updates.append((done, total))) \
        .upload(str(source_file), block_size=BLOCK_SIZE)
    assert progress_updates[-1] == (6, 6) and result.total_blocks == 6

    access_manager = AccessManager(alice)
    access_manager.share(result.file_id, "bob")
    access_manager.share(result.file_id, "carol")

    for session in (alice, bob, carol):
        destination = tmp_path / f"de-{session.identity.display_name}.pdf"
        downloaded = download(session, result.file_id, destination)
        assert destination.read_bytes() == source_file.read_bytes()
        assert downloaded.metadata.name == "informe.pdf"


def test_download_into_directory_uses_original_name(alice, source_file, tmp_path):
    result = upload(alice, source_file)
    target_directory = tmp_path / "descargas"
    target_directory.mkdir()
    downloaded = download(alice, result.file_id, target_directory)
    assert downloaded.destination_path == str(target_directory / "informe.pdf")


def test_recipient_must_have_verified_the_owner(alice, make_session, source_file, tmp_path):
    stranger = make_session("dave")
    alice.trust_store.pin("dave", alice.server_api.get_user(stranger.identity.user_id), stranger.identity.user_id)
    result = upload(alice, source_file)
    AccessManager(alice).share(result.file_id, "dave")
    with pytest.raises(IdentityError):
        download(stranger, result.file_id, tmp_path / "x")
    assert not (tmp_path / "x").exists()


def test_cannot_share_with_unverified_contact(alice, source_file):
    result = upload(alice, source_file)
    with pytest.raises(IdentityError):
        AccessManager(alice).share(result.file_id, "mallory")


def test_revoke_cuts_server_access_but_not_previous_copy(alice, bob, carol, source_file, tmp_path):
    result = upload(alice, source_file)
    for alias in ("bob", "carol"):
        AccessManager(alice).share(result.file_id, alias)
    previous_copy = tmp_path / "copia-de-carol.pdf"
    download(carol, result.file_id, previous_copy)

    _, label = AccessManager(alice).revoke(result.file_id, "carol")
    assert label == "carol"

    with pytest.raises(ServerError):
        download(carol, result.file_id, tmp_path / "otra.pdf")
    download(bob, result.file_id, tmp_path / "de-bob.pdf")
    assert previous_copy.read_bytes() == source_file.read_bytes()
    _, recipients = AccessManager(alice).recipients(result.file_id)
    assert sorted(entry.label for entry in recipients) == ["bob", "tú"]


def test_interrupted_upload_resumes_without_resending(alice, source_file, monkeypatch, tmp_path):
    restore = interrupt_after(alice, monkeypatch, successful_blocks=3)
    with pytest.raises(ServerError):
        upload(alice, source_file)
    assert len(checkpoints_of(alice).find_for_source(str(source_file))) == 1

    restore()
    result = upload(alice, source_file)
    assert result.blocks_already_on_server == 3
    assert checkpoints_of(alice).find_for_source(str(source_file)) == []
    download(alice, result.file_id, tmp_path / "reanudado.pdf")
    assert (tmp_path / "reanudado.pdf").read_bytes() == source_file.read_bytes()


def test_changed_file_after_interruption_gets_a_new_key(alice, source_file, monkeypatch):
    restore = interrupt_after(alice, monkeypatch, successful_blocks=2)
    with pytest.raises(ServerError):
        upload(alice, source_file)
    interrupted_file_id = checkpoints_of(alice).find_for_source(str(source_file))[0].key_material.file_id.hex()

    restore()
    source_file.write_bytes(os.urandom(5 * BLOCK_SIZE + 123))
    result = upload(alice, source_file)
    assert result.file_id != interrupted_file_id and result.blocks_already_on_server == 0


def test_file_modified_during_upload_aborts_before_sending_changed_block(alice, tmp_path, monkeypatch,
                                                                          server_directory):
    # Archivo mayor que el búfer de lectura (8 KB), para que el cambio llegue a leerse
    source_file = tmp_path / "grande.bin"
    source_file.write_bytes(os.urandom(20 * BLOCK_SIZE))
    changed_block_index = 15
    real_put_block = alice.server_api.put_block

    def put_then_modify_source(file_id, version, index, payload):
        real_put_block(file_id, version, index, payload)
        if index == 0:
            with open(source_file, "r+b") as source:
                source.seek(changed_block_index * BLOCK_SIZE)
                source.write(b"cambio a mitad de la carga")
    monkeypatch.setattr(alice.server_api, "put_block", put_then_modify_source)

    with pytest.raises(FormatError):
        upload(alice, source_file)
    uploaded_indexes = {int(path.name) for path in (server_directory / "files").glob("*/v1/blocks/*")}
    assert uploaded_indexes == set(range(changed_block_index))
    assert checkpoints_of(alice).find_for_source(str(source_file)) == []


def test_new_version_renews_current_recipients_only(alice, bob, carol, source_file, tmp_path):
    first = upload(alice, source_file)
    for alias in ("bob", "carol"):
        AccessManager(alice).share(first.file_id, alias)
    AccessManager(alice).revoke(first.file_id, "carol")

    source_file.write_bytes(b"segunda version del informe")
    second = upload(alice, source_file, replace_file_id=first.file_id)
    assert (second.file_id, second.content_version) == (first.file_id, 2)
    assert second.renewed_recipients == ["bob"]

    downloaded = download(bob, first.file_id, tmp_path / "v2.pdf")
    assert downloaded.content_version == 2
    assert (tmp_path / "v2.pdf").read_bytes() == b"segunda version del informe"
    with pytest.raises(ServerError):
        download(carol, first.file_id, tmp_path / "carol-v2.pdf")


def test_only_owner_can_publish_new_version(alice, bob, source_file):
    result = upload(alice, source_file)
    AccessManager(alice).share(result.file_id, "bob")
    with pytest.raises(IdentityError):
        upload(bob, source_file, replace_file_id=result.file_id)


def test_server_serving_an_older_version_is_detected(alice, bob, source_file, monkeypatch, tmp_path):
    first = upload(alice, source_file)
    AccessManager(alice).share(first.file_id, "bob")
    old_manifest = bob.server_api.get_manifest(first.file_id)
    source_file.write_bytes(b"version nueva")
    upload(alice, source_file, replace_file_id=first.file_id)
    download(bob, first.file_id, tmp_path / "nueva.pdf")

    monkeypatch.setattr(bob.server_api, "get_manifest", lambda file_id, version=None: old_manifest)
    with pytest.raises(VerificationError):
        download(bob, first.file_id, tmp_path / "vieja.pdf")
    assert not (tmp_path / "vieja.pdf").exists()


def test_block_tampered_on_server_disk_is_rejected(alice, source_file, server_directory, tmp_path):
    result = upload(alice, source_file)
    stored_block = server_directory / "files" / result.file_id / "v1" / "blocks" / "3"
    stored_block.write_bytes(b"\x00" + stored_block.read_bytes()[1:])
    with pytest.raises(VerificationError):
        download(alice, result.file_id, tmp_path / "manipulado.pdf")
    assert not (tmp_path / "manipulado.pdf").exists()


def test_lost_commit_response_is_recognized(alice, source_file, monkeypatch, tmp_path):
    real_commit = alice.server_api.commit_manifest

    def commit_then_retry(manifest):
        real_commit(manifest)
        real_commit(manifest)  # como un reintento tras perder la respuesta: el servidor responde 409
    monkeypatch.setattr(alice.server_api, "commit_manifest", commit_then_retry)

    result = upload(alice, source_file)
    download(alice, result.file_id, tmp_path / "ok.pdf")
    assert (tmp_path / "ok.pdf").read_bytes() == source_file.read_bytes()


def test_empty_file_roundtrip(alice, tmp_path):
    empty = tmp_path / "vacio.txt"
    empty.write_bytes(b"")
    result = upload(alice, empty)
    download(alice, result.file_id, tmp_path / "vacio-descargado.txt")
    assert (tmp_path / "vacio-descargado.txt").read_bytes() == b""


def test_existing_destination_is_not_overwritten(alice, source_file, tmp_path):
    result = upload(alice, source_file)
    existing = tmp_path / "ya-existe.pdf"
    existing.write_bytes(b"no tocar")
    with pytest.raises(FileExistsError):
        download(alice, result.file_id, existing)
    assert existing.read_bytes() == b"no tocar"
