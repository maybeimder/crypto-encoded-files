# Toda manipulación de bloques o manifiesto se rechaza sin entregar nada al usuario
import os
from dataclasses import replace

import pytest

from cryptostore.errors import VerificationError
from cryptostore.primitives.symmetric import sha256
from cryptostore.protocol.manifest import SignedManifest
from cryptostore.protocol.verified_download import VerifiedFileAssembler
from tests.support import SMALL_BLOCK_SIZE, decrypt_for_test, encrypt_for_test

NUMBER_OF_BLOCKS = 4


@pytest.fixture
def upload(write_source, alice):
    return encrypt_for_test(write_source(os.urandom(NUMBER_OF_BLOCKS * SMALL_BLOCK_SIZE)), alice)


def assert_rejected_without_output(upload, blocks, owner, tmp_path, data_encryption_key=None,
                                   manifest=None, minimum_content_version=0):
    destination = tmp_path / "destino.bin"
    with pytest.raises(VerificationError):
        decrypt_for_test(manifest or upload.manifest, blocks,
                         data_encryption_key or upload.key_material.data_encryption_key,
                         owner, destination, minimum_content_version)
    assert not destination.exists()
    assert not [leftover for leftover in tmp_path.iterdir() if leftover.name.startswith(".descarga-")]


def test_modified_bit(upload, alice, tmp_path):
    blocks = list(upload.blocks)
    blocks[2] = blocks[2][:5] + bytes([blocks[2][5] ^ 1]) + blocks[2][6:]
    assert_rejected_without_output(upload, blocks, alice, tmp_path)


def test_missing_block(upload, alice, tmp_path):
    assert_rejected_without_output(upload, upload.blocks[:1] + upload.blocks[2:], alice, tmp_path)


def test_truncated_last_block(upload, alice, tmp_path):
    assert_rejected_without_output(upload, upload.blocks[:-1], alice, tmp_path)


def test_duplicated_block(upload, alice, tmp_path):
    blocks = list(upload.blocks)
    blocks[2] = blocks[1]
    assert_rejected_without_output(upload, blocks, alice, tmp_path)


def test_reordered_blocks(upload, alice, tmp_path):
    blocks = list(upload.blocks)
    blocks[1], blocks[2] = blocks[2], blocks[1]
    assert_rejected_without_output(upload, blocks, alice, tmp_path)


def test_block_from_another_file(upload, alice, tmp_path, write_source):
    other_file = encrypt_for_test(write_source(os.urandom(NUMBER_OF_BLOCKS * SMALL_BLOCK_SIZE), "otro.bin"), alice)
    blocks = list(upload.blocks)
    blocks[1] = other_file.blocks[1]
    assert_rejected_without_output(upload, blocks, alice, tmp_path)


def test_reordering_is_caught_by_associated_data_even_with_matching_hashes(upload, tmp_path):
    # Defensa en profundidad: aunque la lista de huellas cuadrara, la posición está atada a cada bloque
    swapped_blocks = list(upload.blocks)
    swapped_blocks[1], swapped_blocks[2] = swapped_blocks[2], swapped_blocks[1]
    forged_body = replace(upload.manifest.body, block_hashes=tuple(sha256(block) for block in swapped_blocks))
    assembler = VerifiedFileAssembler(forged_body, upload.key_material, NUMBER_OF_BLOCKS * SMALL_BLOCK_SIZE)
    destination = tmp_path / "destino.bin"
    with pytest.raises(VerificationError):
        assembler.assemble(lambda index: swapped_blocks[index], str(destination))
    assert not destination.exists()


def test_tampered_manifest_signature_fails(upload, alice, tmp_path):
    forged_body = replace(upload.manifest.body, block_hashes=upload.manifest.body.block_hashes[:-1])
    forged_manifest = SignedManifest(forged_body, upload.manifest.signature)
    assert_rejected_without_output(upload, upload.blocks, alice, tmp_path, manifest=forged_manifest)


def test_manifest_signed_by_someone_else_fails(upload, bob, tmp_path):
    assert_rejected_without_output(upload, upload.blocks, bob, tmp_path)


def test_server_cannot_forge_manifest_with_its_own_key(upload, alice, mallory, tmp_path):
    forged_by_server = SignedManifest.create(upload.manifest.body, mallory.signing_private_key)
    assert_rejected_without_output(upload, upload.blocks, alice, tmp_path, manifest=forged_by_server)


def test_rollback_to_older_version_fails(upload, alice, tmp_path):
    assert_rejected_without_output(upload, upload.blocks, alice, tmp_path, minimum_content_version=2)


def test_wrong_data_key_fails(upload, alice, tmp_path):
    assert_rejected_without_output(upload, upload.blocks, alice, tmp_path, data_encryption_key=os.urandom(32))
