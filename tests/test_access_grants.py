import os

import pytest

from cryptostore.errors import VerificationError
from cryptostore.protocol.access_grant import AccessGrant
from tests.support import encrypt_for_test


@pytest.fixture
def shared_file(write_source, alice, bob, carol):
    upload = encrypt_for_test(write_source(os.urandom(3000)), alice)
    grants = {
        person.user_id: AccessGrant.issue(
            data_encryption_key=upload.key_material.data_encryption_key,
            manifest=upload.manifest, recipient=person.public)
        for person in (alice, bob, carol)
    }
    return upload, grants


def open_grant(grant, upload, person):
    return grant.open(manifest=upload.manifest, recipient_id=person.user_id,
                      recipient_encryption_private_key=person.encryption_private_key)


def test_every_recipient_recovers_the_same_data_key(shared_file, alice, bob, carol):
    upload, grants = shared_file
    for person in (alice, bob, carol):
        assert open_grant(grants[person.user_id], upload, person) == upload.key_material.data_encryption_key


def test_unauthorized_user_or_wrong_key_cannot_open(shared_file, bob, mallory):
    upload, grants = shared_file
    with pytest.raises(VerificationError):
        open_grant(grants[bob.user_id], upload, mallory)
    with pytest.raises(VerificationError):
        grants[bob.user_id].open(manifest=upload.manifest, recipient_id=bob.user_id,
                                 recipient_encryption_private_key=mallory.encryption_private_key)


def test_grant_cannot_be_moved_to_another_manifest(shared_file, alice, bob, write_source):
    upload, grants = shared_file
    other_upload = encrypt_for_test(write_source(b"otro contenido", "otro.bin"), alice)
    grant_pointed_at_other_file = AccessGrant(
        other_upload.manifest.body.file_id, 1, bob.user_id, grants[bob.user_id].sealed_data_key)
    with pytest.raises(VerificationError):
        open_grant(grant_pointed_at_other_file, other_upload, bob)


def test_grant_size_is_constant_and_independent_of_file_size(shared_file, alice, bob, write_source):
    upload, grants = shared_file
    large_upload = encrypt_for_test(write_source(os.urandom(200_000), "grande.bin"), alice)
    large_grant = AccessGrant.issue(data_encryption_key=large_upload.key_material.data_encryption_key,
                                    manifest=large_upload.manifest, recipient=bob.public)
    sizes = {len(grant.sealed_data_key.encapsulated_key) + len(grant.sealed_data_key.ciphertext)
             for grant in [*grants.values(), large_grant]}
    assert sizes == {32 + 32 + 16}


def test_grant_json_roundtrip(shared_file, bob):
    upload, grants = shared_file
    restored = AccessGrant.from_json_dict(grants[bob.user_id].to_json_dict())
    assert open_grant(restored, upload, bob) == upload.key_material.data_encryption_key
