import os

import pytest
from fastapi.testclient import TestClient

from cryptostore.protocol.access_grant import AccessGrant
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.server.api import create_app
from tests.support import decrypt_for_test, encrypt_for_test

SECRET_FILE_NAME = "nomina-confidencial.xlsx"
SECRET_CONTENT = b"SALARIO-DE-ALICE-1234567 " * 300


# El servidor se negó a entregar el manifiesto o la envolvente
class AccessDenied(Exception):
    pass


# Un usuario hablando con la API con su propio token
class ApiSession:
    def __init__(self, http_client: TestClient, identity):
        self.http_client = http_client
        self.identity = identity
        response = http_client.post("/users", json=identity.public.to_json_dict())
        assert response.status_code == 201, response.text
        assert response.json()["user_id"] == identity.user_id
        self.headers = {"Authorization": f"Bearer {response.json()['token']}"}

    def request(self, method: str, url: str, **kwargs):
        return self.http_client.request(method, url, headers=self.headers, **kwargs)


@pytest.fixture
def server_directory(tmp_path):
    return tmp_path / "server-data"


@pytest.fixture
def http_client(server_directory):
    return TestClient(create_app(str(server_directory)))


@pytest.fixture
def sessions(http_client, alice, bob, carol, mallory):
    return {person.display_name: ApiSession(http_client, person) for person in (alice, bob, carol, mallory)}


@pytest.fixture
def secret_upload(tmp_path, alice):
    source = tmp_path / SECRET_FILE_NAME
    source.write_bytes(SECRET_CONTENT)
    return encrypt_for_test(str(source), alice)


def upload_through_api(session: ApiSession, upload) -> str:
    file_id = upload.manifest.body.file_id.hex()
    version = upload.manifest.body.content_version
    for index, payload in enumerate(upload.blocks):
        response = session.request("PUT", f"/files/{file_id}/versions/{version}/blocks/{index}", content=payload)
        assert response.status_code == 204, response.text
    response = session.request("PUT", f"/files/{file_id}/versions/{version}/manifest",
                               json=upload.manifest.to_json_dict())
    assert response.status_code == 204, response.text
    return file_id


def share_through_api(owner: ApiSession, upload, recipient) -> int:
    grant = AccessGrant.issue(data_encryption_key=upload.key_material.data_encryption_key,
                              manifest=upload.manifest, recipient=recipient.public)
    file_id = upload.manifest.body.file_id.hex()
    response = owner.request("PUT", f"/files/{file_id}/grants/{recipient.user_id}", json=grant.to_json_dict())
    assert response.status_code == 200, response.text
    return response.json()["acl_epoch"]


def download_through_api(session: ApiSession, file_id: str, owner, destination) -> None:
    # Como lo haría el cliente: manifiesto, envolvente propia y bloques, todo verificado
    manifest_response = session.request("GET", f"/files/{file_id}/manifest")
    grant_response = session.request("GET", f"/files/{file_id}/grants/mine")
    if manifest_response.status_code != 200 or grant_response.status_code != 200:
        raise AccessDenied((manifest_response.status_code, grant_response.status_code))
    manifest = SignedManifest.from_json_dict(manifest_response.json())
    data_encryption_key = AccessGrant.from_json_dict(grant_response.json()).open(
        manifest=manifest, recipient_id=session.identity.user_id,
        recipient_encryption_private_key=session.identity.encryption_private_key)
    version = manifest.body.content_version
    blocks = [session.request("GET", f"/files/{file_id}/versions/{version}/blocks/{index}").content
              for index in range(manifest.body.total_blocks)]
    decrypt_for_test(manifest, blocks, data_encryption_key, owner, destination)


def test_owner_and_two_recipients_download_then_revoke_one(sessions, secret_upload, alice, bob, carol, tmp_path):
    file_id = upload_through_api(sessions["alice"], secret_upload)
    for person in (alice, bob, carol):
        share_through_api(sessions["alice"], secret_upload, person)

    for name in ("alice", "bob", "carol"):
        destination = tmp_path / f"descarga-{name}.bin"
        download_through_api(sessions[name], file_id, alice, destination)
        assert destination.read_bytes() == SECRET_CONTENT

    response = sessions["alice"].request("DELETE", f"/files/{file_id}/grants/{carol.user_id}")
    assert response.status_code == 200

    with pytest.raises(AccessDenied):
        download_through_api(sessions["carol"], file_id, alice, tmp_path / "carol-despues.bin")
    download_through_api(sessions["bob"], file_id, alice, tmp_path / "bob-despues.bin")
    assert (tmp_path / "bob-despues.bin").read_bytes() == SECRET_CONTENT
    assert (tmp_path / "descarga-carol.bin").read_bytes() == SECRET_CONTENT  # la copia previa sigue ahí


def test_adding_a_recipient_does_not_touch_stored_blocks(sessions, secret_upload, bob, server_directory):
    file_id = upload_through_api(sessions["alice"], secret_upload)
    blocks_directory = server_directory / "files" / file_id / "v1" / "blocks"
    snapshot_before = {path.name: (path.stat().st_mtime_ns, path.read_bytes()) for path in blocks_directory.iterdir()}

    share_through_api(sessions["alice"], secret_upload, bob)

    snapshot_after = {path.name: (path.stat().st_mtime_ns, path.read_bytes()) for path in blocks_directory.iterdir()}
    assert snapshot_before == snapshot_after


def test_acl_epoch_grows_with_each_share_and_revoke(sessions, secret_upload, bob, carol):
    file_id = upload_through_api(sessions["alice"], secret_upload)
    assert share_through_api(sessions["alice"], secret_upload, bob) == 1
    assert share_through_api(sessions["alice"], secret_upload, carol) == 2
    assert sessions["alice"].request("DELETE", f"/files/{file_id}/grants/{bob.user_id}").json() == {"acl_epoch": 3}
    listed = sessions["alice"].request("GET", f"/files/{file_id}/grants").json()
    assert listed == {"acl_epoch": 3, "recipient_ids": [carol.user_id]}


def test_server_never_stores_plaintext_or_file_name(sessions, secret_upload, alice, bob, server_directory):
    upload_through_api(sessions["alice"], secret_upload)
    share_through_api(sessions["alice"], secret_upload, bob)
    every_stored_byte = b"".join(path.read_bytes() for path in server_directory.rglob("*") if path.is_file())
    assert b"SALARIO-DE-ALICE" not in every_stored_byte
    assert SECRET_FILE_NAME.encode() not in every_stored_byte
    assert alice.encryption_private_key not in every_stored_byte
    assert secret_upload.key_material.data_encryption_key not in every_stored_byte


def test_unauthorized_user_gets_nothing(sessions, secret_upload):
    file_id = upload_through_api(sessions["alice"], secret_upload)
    mallory = sessions["mallory"]
    assert mallory.request("GET", f"/files/{file_id}/manifest").status_code == 403
    assert mallory.request("GET", f"/files/{file_id}/versions/1/blocks/0").status_code == 403
    assert mallory.request("GET", f"/files/{file_id}/grants/mine").status_code == 404
    assert mallory.request("GET", "/files").json() == []


def test_only_owner_can_upload_share_or_revoke(sessions, secret_upload, bob):
    file_id = upload_through_api(sessions["alice"], secret_upload)
    mallory = sessions["mallory"]
    assert mallory.request("PUT", f"/files/{file_id}/versions/2/blocks/0", content=b"x" * 32).status_code == 403
    assert mallory.request("PUT", f"/files/{file_id}/grants/{bob.user_id}", json={}).status_code in (400, 403)
    assert mallory.request("DELETE", f"/files/{file_id}/grants/{bob.user_id}").status_code == 403


def test_block_retry_is_idempotent_but_a_different_block_conflicts(sessions):
    alice_session = sessions["alice"]
    url = f"/files/{os.urandom(16).hex()}/versions/1/blocks/0"
    assert alice_session.request("PUT", url, content=b"a" * 40).status_code == 204
    assert alice_session.request("PUT", url, content=b"a" * 40).status_code == 204
    assert alice_session.request("PUT", url, content=b"b" * 40).status_code == 409


def test_published_version_is_immutable(sessions, secret_upload):
    file_id = upload_through_api(sessions["alice"], secret_upload)
    response = sessions["alice"].request("PUT", f"/files/{file_id}/versions/1/blocks/0", content=b"x" * 32)
    assert response.status_code == 409


def test_manifest_with_missing_block_is_refused(sessions, secret_upload):
    alice_session = sessions["alice"]
    file_id = secret_upload.manifest.body.file_id.hex()
    alice_session.request("PUT", f"/files/{file_id}/versions/1/blocks/0", content=secret_upload.blocks[0])
    response = alice_session.request("PUT", f"/files/{file_id}/versions/1/manifest",
                                     json=secret_upload.manifest.to_json_dict())
    assert response.status_code == 400


def test_manifest_signed_by_another_user_is_refused(sessions, secret_upload, mallory):
    alice_session = sessions["alice"]
    file_id = secret_upload.manifest.body.file_id.hex()
    for index, payload in enumerate(secret_upload.blocks):
        alice_session.request("PUT", f"/files/{file_id}/versions/1/blocks/{index}", content=payload)
    forged = SignedManifest.create(secret_upload.manifest.body, mallory.signing_private_key)
    response = alice_session.request("PUT", f"/files/{file_id}/versions/1/manifest", json=forged.to_json_dict())
    assert response.status_code == 400


def test_uploaded_block_list_allows_resuming(sessions, secret_upload):
    alice_session = sessions["alice"]
    file_id = secret_upload.manifest.body.file_id.hex()
    alice_session.request("PUT", f"/files/{file_id}/versions/1/blocks/0", content=secret_upload.blocks[0])
    listed = alice_session.request("GET", f"/files/{file_id}/versions/1/blocks").json()
    assert listed == {"0": secret_upload.manifest.body.block_hashes[0].hex()}


def test_requests_without_valid_token_are_rejected(http_client):
    assert http_client.get("/files").status_code == 401
    assert http_client.get("/files", headers={"Authorization": "Bearer inventado"}).status_code == 401


def test_duplicate_registration_and_malicious_ids_are_rejected(http_client, sessions, alice):
    assert http_client.post("/users", json=alice.public.to_json_dict()).status_code == 409
    alice_session = sessions["alice"]
    assert alice_session.request("GET", "/files/..%2F..%2Fetc/manifest").status_code in (404, 422)
    assert alice_session.request("GET", "/users/NOT-HEX").status_code == 422


def test_oversized_block_is_rejected(sessions):
    url = f"/files/{os.urandom(16).hex()}/versions/1/blocks/0"
    response = sessions["alice"].request("PUT", url, content=b"x" * (4 * 1024 * 1024 + 17))
    assert response.status_code == 413
