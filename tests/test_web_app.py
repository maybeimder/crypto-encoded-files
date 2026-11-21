import os
import time

import pytest
from fastapi.testclient import TestClient

from cryptostore.client.file_catalog import list_visible_files
from cryptostore.client.session import ClientSession
from cryptostore.server.api import create_app
from cryptostore.web.app import DEFAULT_ALLOWED_HOSTS, SESSION_COOKIE_NAME, create_web_app
from cryptostore.web.network_access import NetworkAccessPolicy, parse_networks
from cryptostore.web.tls import ensure_self_signed_certificate

PASSWORD = "contraseña de prueba"
TEST_HOSTS = DEFAULT_ALLOWED_HOSTS | {"testserver"}
INTERFACE_HEADER = {"X-Cryptostore": "1"}


@pytest.fixture
def server_app(tmp_path):
    return create_app(str(tmp_path / "servidor"))


@pytest.fixture
def users_directory(tmp_path):
    return tmp_path / "usuarios"


@pytest.fixture
def web_app(users_directory, server_app):
    # Una sola interfaz local para todos los usuarios, hablando con el servidor central
    return create_web_app(str(users_directory), http_client=TestClient(server_app), allowed_hosts=TEST_HOSTS)


@pytest.fixture
def open_browser(web_app):
    def _open() -> TestClient:
        return TestClient(web_app, headers=INTERFACE_HEADER)
    return _open


def register(browser: TestClient, username: str) -> dict:
    response = browser.post("/api/register", json={"username": username, "server_url": "http://testserver",
                                                   "passphrase": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


def wait_for_job(browser: TestClient, job: dict) -> dict:
    while job["status"] == "running":
        time.sleep(0.02)
        job = browser.get(f"/api/jobs/{job['job_id']}").json()
    return job


def upload(browser: TestClient, name: str, content: bytes) -> dict:
    return wait_for_job(browser, browser.post("/api/uploads", params={"name": name}, content=content).json())


def test_login_page_needs_no_token_but_the_api_needs_a_session(open_browser):
    browser = open_browser()
    assert browser.get("/").status_code == 200
    assert browser.get("/api/status").json()["logged_in"] is False
    assert browser.get("/api/files").status_code == 401


def test_register_then_login_in_another_browser(open_browser):
    register(open_browser(), "alice")
    second_browser = open_browser()
    response = second_browser.post("/api/login", json={"username": "alice", "passphrase": PASSWORD})
    assert response.status_code == 200 and response.json()["username"] == "alice"
    cookie_header = response.headers["set-cookie"].lower()
    assert SESSION_COOKIE_NAME in cookie_header and "httponly" in cookie_header and "samesite=strict" in cookie_header
    assert second_browser.get("/api/files").status_code == 200


def test_wrong_password_and_unknown_user_get_the_same_answer(open_browser):
    register(open_browser(), "alice")
    browser = open_browser()
    wrong_password = browser.post("/api/login", json={"username": "alice", "passphrase": "otra cosa"})
    unknown_user = browser.post("/api/login", json={"username": "nadie", "passphrase": PASSWORD})
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["detail"] == unknown_user.json()["detail"]


def test_repeated_failures_lock_the_username(open_browser):
    register(open_browser(), "alice")
    browser = open_browser()
    for _ in range(5):
        browser.post("/api/login", json={"username": "alice", "passphrase": "mal"})
    assert browser.post("/api/login", json={"username": "alice", "passphrase": PASSWORD}).status_code == 429


def test_duplicate_and_malicious_usernames_are_rejected(open_browser):
    register(open_browser(), "alice")
    browser = open_browser()
    assert browser.post("/api/register", json={"username": "alice", "server_url": "http://testserver",
                                               "passphrase": PASSWORD}).status_code == 409
    for bad_name in ("../etc", "Alice", ".oculto", "a" * 40):
        response = browser.post("/api/register", json={"username": bad_name, "server_url": "http://testserver",
                                                       "passphrase": PASSWORD})
        assert response.status_code == 422, bad_name


def test_requests_without_interface_header_or_from_foreign_host_are_rejected(web_app, open_browser):
    register(open_browser(), "alice")
    forged = TestClient(web_app)
    assert forged.post("/api/login", json={"username": "alice", "passphrase": PASSWORD}).status_code == 403
    rebinding = TestClient(web_app, base_url="http://atacante.example", headers=INTERFACE_HEADER)
    assert rebinding.get("/api/status").status_code == 403


def test_logout_forgets_the_session(open_browser):
    browser = open_browser()
    register(browser, "alice")
    browser.post("/api/logout")
    assert browser.get("/api/files").status_code == 401


def test_idle_session_expires(users_directory, server_app):
    app = create_web_app(str(users_directory), http_client=TestClient(server_app), allowed_hosts=TEST_HOSTS,
                         idle_seconds=0.05)
    browser = TestClient(app, headers=INTERFACE_HEADER)
    register(browser, "alice")
    time.sleep(0.1)
    assert browser.get("/api/files").status_code == 401


def test_two_users_share_through_one_interface_with_password_confirmation(open_browser):
    alice, bob = open_browser(), open_browser()
    alice_status, bob_status = register(alice, "alice"), register(bob, "bob")
    alice.post("/api/contacts", json={"alias": "bob", "fingerprint": bob_status["fingerprint"]})
    bob.post("/api/contacts", json={"alias": "alice", "fingerprint": alice_status["fingerprint"]})

    content = os.urandom(3 * (1 << 20) + 7)
    job = upload(alice, "../../plan secreto.bin", content)
    assert job["status"] == "done" and job["result"]["total_blocks"] == 4
    file_id = job["result"]["file_id"]

    # Compartir exige la contraseña de nuevo
    assert alice.post(f"/api/files/{file_id}/share", json={"alias": "bob", "passphrase": "mal"}).status_code == 403
    assert alice.post(f"/api/files/{file_id}/share", json={"alias": "bob", "passphrase": PASSWORD}).status_code == 200
    assert bob.get("/api/files").json()[0]["name"] == "plan secreto.bin"

    assert bob.post(f"/api/files/{file_id}/download", json={"passphrase": "mal"}).status_code == 403
    job = wait_for_job(bob, bob.post(f"/api/files/{file_id}/download", json={"passphrase": PASSWORD}).json())
    assert job["status"] == "done" and "_local_path" not in job["result"]
    # Alice no puede recoger la descarga de bob aunque conozca el id de la tarea
    assert alice.get(f"/api/jobs/{job['job_id']}/file").status_code == 404
    assert bob.get(f"/api/jobs/{job['job_id']}/file").content == content
    assert bob.get(f"/api/jobs/{job['job_id']}/file").status_code == 404

    assert alice.post(f"/api/files/{file_id}/revoke", json={"recipient": "bob", "passphrase": "mal"}).status_code == 403
    revoked = alice.post(f"/api/files/{file_id}/revoke", json={"recipient": "bob", "passphrase": PASSWORD}).json()
    assert "sigue en su equipo" in revoked["message"]
    assert bob.get("/api/files").json() == []


def test_web_and_terminal_see_the_same_folder_and_contacts(open_browser, users_directory, server_app):
    alice, bob = open_browser(), open_browser()
    register(alice, "alice")
    bob_status = register(bob, "bob")
    upload(alice, "nota.txt", b"hola")
    # La terminal abre la misma carpeta que creó la web
    terminal_session = ClientSession.open(str(users_directory / "alice"), PASSWORD, http_client=TestClient(server_app))
    assert [listing.name for listing in list_visible_files(terminal_session)] == ["nota.txt"]
    # Un contacto fijado desde la terminal aparece en la web sin reiniciarla
    terminal_session.trust_store.pin("bob", terminal_session.server_api.get_user(bob_status["user_id"]),
                                     bob_status["fingerprint"])
    assert [contact["alias"] for contact in alice.get("/api/contacts").json()] == ["bob"]


def test_tampered_download_is_reported_as_rejected(open_browser, tmp_path):
    browser = open_browser()
    register(browser, "alice")
    job = upload(browser, "a.bin", os.urandom(5000))
    stored_block = tmp_path / "servidor" / "files" / job["result"]["file_id"] / "v1" / "blocks" / "0"
    stored_block.write_bytes(b"\xff" + stored_block.read_bytes()[1:])
    job = wait_for_job(browser, browser.post(f"/api/files/{job['result']['file_id']}/download",
                                             json={"passphrase": PASSWORD}).json())
    assert job["status"] == "rejected"
    assert browser.get(f"/api/jobs/{job['job_id']}/file").status_code == 404


def test_file_from_unverified_owner_waits_for_verification(open_browser):
    alice, bob = open_browser(), open_browser()
    alice_status, bob_status = register(alice, "alice"), register(bob, "bob")
    alice.post("/api/contacts", json={"alias": "bob", "fingerprint": bob_status["fingerprint"]})
    file_id = upload(alice, "nota.txt", b"hola")["result"]["file_id"]
    alice.post(f"/api/files/{file_id}/share", json={"alias": "bob", "passphrase": PASSWORD})

    # Bob ve que hay algo de "alice", pero no su nombre ni contenido hasta verificar su huella
    pending = bob.get("/api/files").json()[0]
    assert pending["problem_kind"] == "unverified_owner" and pending["name"] is None
    assert pending["owner_claimed_name"] == "alice" and pending["owner_label"] == "alice (sin verificar)"

    bob.post("/api/contacts", json={"alias": "alice", "fingerprint": alice_status["fingerprint"]})
    opened = bob.get("/api/files").json()[0]
    assert opened["problem_kind"] is None and opened["name"] == "nota.txt" and opened["owner_label"] == "alice"


def test_server_user_directory_is_not_exposed(open_browser):
    browser = open_browser()
    register(browser, "alice")
    assert browser.get("/api/users").status_code == 404


# ---------- acceso desde la red ----------


def test_network_keywords_and_ranges():
    policy = NetworkAccessPolicy(parse_networks("local,192.168.1.0/24"), DEFAULT_ALLOWED_HOSTS)
    assert policy.client_allowed("127.0.0.1") and policy.client_allowed("192.168.1.77")
    assert policy.client_allowed("::ffff:192.168.1.77")
    assert not policy.client_allowed("192.168.2.5") and not policy.client_allowed("8.8.8.8")
    assert not policy.client_allowed("no-es-una-ip")
    private = NetworkAccessPolicy(parse_networks("privadas"), DEFAULT_ALLOWED_HOSTS)
    assert private.client_allowed("10.1.2.3") and private.client_allowed("172.18.0.1")
    assert not private.client_allowed("200.1.1.1")


def test_host_header_accepts_ip_literals_but_not_foreign_domains():
    policy = NetworkAccessPolicy(None, DEFAULT_ALLOWED_HOSTS | {"portatil.local"})
    for accepted in ("192.168.1.50:8765", "[::1]:8765", "localhost:8765", "portatil.local", "10.0.0.2"):
        assert policy.host_header_allowed(accepted), accepted
    assert not policy.host_header_allowed("atacante.example:8765")


def test_interface_reachable_from_lan_only_for_allowed_networks(users_directory, server_app):
    app = create_web_app(str(users_directory), http_client=TestClient(server_app),
                         allowed_networks=parse_networks("192.168.1.0/24"))
    from_lan = TestClient(app, base_url="http://192.168.1.50:8765", client=("192.168.1.77", 50000),
                          headers=INTERFACE_HEADER)
    assert from_lan.get("/").status_code == 200
    register(from_lan, "alice")
    assert from_lan.get("/api/files").status_code == 200
    from_other_network = TestClient(app, base_url="http://192.168.1.50:8765", client=("10.9.9.9", 50000))
    assert from_other_network.get("/").status_code == 403


def test_https_mode_marks_the_session_cookie_secure(users_directory, server_app):
    app = create_web_app(str(users_directory), http_client=TestClient(server_app), allowed_hosts=TEST_HOSTS,
                         secure_cookies=True)
    browser = TestClient(app, base_url="https://testserver", headers=INTERFACE_HEADER)
    response = browser.post("/api/register", json={"username": "alice", "server_url": "http://testserver",
                                                   "passphrase": PASSWORD})
    assert "secure" in response.headers["set-cookie"].lower()


def test_self_signed_certificate_covers_given_names_and_is_reused(tmp_path):
    from cryptography import x509
    first = ensure_self_signed_certificate(str(tmp_path), ["192.168.1.50", "portatil.local"])
    certificate = x509.load_pem_x509_certificate(open(first.certificate_path, "rb").read())
    alternative_names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "portatil.local" in alternative_names.get_values_for_type(x509.DNSName)
    assert any(str(address) == "192.168.1.50" for address in alternative_names.get_values_for_type(x509.IPAddress))
    assert ensure_self_signed_certificate(str(tmp_path), ["192.168.1.50", "portatil.local"]).fingerprint == first.fingerprint
    assert oct(os.stat(first.private_key_path).st_mode)[-3:] == "600"
