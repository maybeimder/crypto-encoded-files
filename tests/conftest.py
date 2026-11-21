import pytest

from cryptostore.client.private_identity import PrivateIdentity


@pytest.fixture(scope="session")
def alice():
    return PrivateIdentity.generate("alice")


@pytest.fixture(scope="session")
def bob():
    return PrivateIdentity.generate("bob")


@pytest.fixture(scope="session")
def carol():
    return PrivateIdentity.generate("carol")


@pytest.fixture(scope="session")
def mallory():
    return PrivateIdentity.generate("mallory")


@pytest.fixture
def write_source(tmp_path):
    def _write(content: bytes, name: str = "origen.bin"):
        path = tmp_path / name
        path.write_bytes(content)
        return str(path)
    return _write
