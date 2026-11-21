import os

import pytest

from cryptostore.errors import FormatError, VerificationError
from cryptostore.protocol.file_blocks import (
    MAXIMUM_FILE_SIZE,
    FileBlockCipher,
    FileKeyMaterial,
    SourceFileEncryptor,
    count_blocks,
)
from tests.support import SMALL_BLOCK_SIZE, decrypt_for_test, encrypt_for_test


def test_empty_file_is_a_single_tag_only_block(write_source, alice):
    upload = encrypt_for_test(write_source(b""), alice)
    assert len(upload.blocks) == 1 and len(upload.blocks[0]) == 16


@pytest.mark.parametrize("file_size", [0, 1, SMALL_BLOCK_SIZE - 1, SMALL_BLOCK_SIZE, SMALL_BLOCK_SIZE + 1,
                                       5 * SMALL_BLOCK_SIZE + 17])
def test_roundtrip_for_boundary_sizes(write_source, tmp_path, alice, file_size):
    original_content = os.urandom(file_size)
    upload = encrypt_for_test(write_source(original_content), alice)
    assert len(upload.blocks) == count_blocks(file_size, SMALL_BLOCK_SIZE)

    destination = tmp_path / "descargado.bin"
    decrypt_for_test(upload.manifest, upload.blocks, upload.key_material.data_encryption_key, alice, destination)
    assert destination.read_bytes() == original_content


def test_nonces_differ_for_every_block():
    key_material = FileKeyMaterial.generate()
    cipher = FileBlockCipher(key_material, total_blocks=1000)
    assert len({cipher._nonce_for(index) for index in range(1000)}) == 1000


def test_associated_data_is_33_bytes_and_marks_last_block():
    cipher = FileBlockCipher(FileKeyMaterial.generate(), total_blocks=3)
    assert len(cipher._associated_data_for(0)) == 33
    assert cipher._associated_data_for(0)[-1] == 0 and cipher._associated_data_for(2)[-1] == 1


def test_same_plaintext_and_position_encrypt_identically_so_retries_are_idempotent():
    key_material = FileKeyMaterial.generate()
    first_attempt = FileBlockCipher(key_material, 2).encrypt_block(0, b"contenido")
    retry = FileBlockCipher(key_material, 2).encrypt_block(0, b"contenido")
    assert first_attempt.payload == retry.payload


def test_block_from_another_version_is_rejected():
    file_id = os.urandom(16)
    version_one = FileKeyMaterial.generate(file_id, content_version=1)
    same_key_claiming_version_two = FileKeyMaterial(
        file_id, 2, version_one.data_encryption_key, version_one.nonce_prefix)
    block = FileBlockCipher(version_one, 1).encrypt_block(0, b"x")
    with pytest.raises(VerificationError):
        FileBlockCipher(same_key_claiming_version_two, 1).decrypt_block(0, block.payload)


def test_file_over_limit_is_refused(tmp_path):
    oversized = tmp_path / "grande.bin"
    with open(oversized, "wb") as handle:
        handle.truncate(MAXIMUM_FILE_SIZE + 1)
    with pytest.raises(FormatError):
        SourceFileEncryptor(str(oversized), FileKeyMaterial.generate())
