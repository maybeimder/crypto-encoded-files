import json
import os
import stat

import pytest

from cryptostore.client.private_identity import PrivateIdentity
from cryptostore.client.trust_store import TrustStore
from cryptostore.errors import IdentityError
from cryptostore.protocol.public_identity import (
    PublicIdentity,
    compute_fingerprint,
    format_fingerprint_for_humans,
)


@pytest.fixture
def saved_identity(tmp_path, alice):
    path = tmp_path / "alice.identity"
    alice.save(str(path), "correcto caballo batería grapa")
    return path


def test_identity_roundtrip(saved_identity, alice):
    loaded = PrivateIdentity.load(str(saved_identity), "correcto caballo batería grapa")
    assert loaded == alice and loaded.user_id == alice.user_id


def test_identity_file_is_private_and_contains_no_raw_keys(saved_identity, alice):
    assert stat.S_IMODE(os.stat(saved_identity).st_mode) == 0o600
    content = saved_identity.read_bytes()
    assert alice.encryption_private_key.hex().encode() not in content
    assert alice.encryption_private_key not in content


def test_wrong_passphrase_is_rejected(saved_identity):
    with pytest.raises(IdentityError):
        PrivateIdentity.load(str(saved_identity), "otra contraseña")


def test_editing_the_header_breaks_the_file(saved_identity):
    content = json.loads(saved_identity.read_bytes())
    content["header"]["display_name"] = "impostor"
    saved_identity.write_text(json.dumps(content))
    with pytest.raises(IdentityError):
        PrivateIdentity.load(str(saved_identity), "correcto caballo batería grapa")


def test_existing_identity_is_not_overwritten_by_accident(saved_identity, bob):
    with pytest.raises(IdentityError):
        bob.save(str(saved_identity), "x")


def test_fingerprint_covers_both_public_keys(alice):
    public = alice.public
    assert public.user_id == compute_fingerprint(public.encryption_public_key, public.signing_public_key)
    assert len(public.user_id) == 64


def test_pin_accepts_fingerprint_typed_by_a_human(tmp_path, bob):
    trust_store = TrustStore(str(tmp_path / "libreta.json"))
    typed = format_fingerprint_for_humans(bob.user_id).upper()
    trust_store.pin("bob", bob.public, typed)
    assert TrustStore(str(tmp_path / "libreta.json")).find_by_alias("bob") == bob.public


def test_pin_rejects_mismatching_fingerprint(tmp_path, bob, mallory):
    trust_store = TrustStore(str(tmp_path / "libreta.json"))
    impostor = PublicIdentity("bob", mallory.public.encryption_public_key, mallory.public.signing_public_key)
    with pytest.raises(IdentityError):
        trust_store.pin("bob", impostor, bob.user_id)


def test_changed_key_for_known_alias_is_rejected(tmp_path, bob, mallory):
    trust_store = TrustStore(str(tmp_path / "libreta.json"))
    trust_store.pin("bob", bob.public, bob.user_id)
    with pytest.raises(IdentityError):
        trust_store.pin("bob", mallory.public, mallory.user_id)


def test_require_trusted_refuses_unknown_identity(tmp_path, carol):
    with pytest.raises(IdentityError):
        TrustStore(str(tmp_path / "libreta.json")).require_trusted(carol.user_id)
