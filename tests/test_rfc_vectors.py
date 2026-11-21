# Las bibliotecas usadas reproducen los vectores oficiales de los RFC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKeyPair

hex_to_bytes = bytes.fromhex


def test_rfc9180_appendix_a2_base_mode():
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)
    recipient_public = suite.kem.deserialize_public_key(
        hex_to_bytes("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"))
    ephemeral_private = suite.kem.deserialize_private_key(
        hex_to_bytes("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"))
    ephemeral_public = suite.kem.deserialize_public_key(
        hex_to_bytes("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"))

    encapsulated_key, context = suite.create_sender_context(
        recipient_public, info=hex_to_bytes("4f6465206f6e2061204772656369616e2055726e"),
        eks=KEMKeyPair(ephemeral_private, ephemeral_public))
    ciphertext = context.seal(hex_to_bytes("4265617574792069732074727574682c20747275746820626561757479"),
                              aad=hex_to_bytes("436f756e742d30"))

    assert encapsulated_key.hex() == "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
    assert ciphertext.hex() == ("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
                                "21993c62ce81883d2dd1b51a28")


def test_rfc8439_section_2_8_2_tag():
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
                 b"the future, sunscreen would be it.")
    output = ChaCha20Poly1305(hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")) \
        .encrypt(hex_to_bytes("070000004041424344454647"), plaintext, hex_to_bytes("50515253c0c1c2c3c4c5c6c7"))
    assert output[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691"


def test_rfc5869_test_case_1():
    output_key = HKDF(hashes.SHA256(), 42, hex_to_bytes("000102030405060708090a0b0c"),
                      hex_to_bytes("f0f1f2f3f4f5f6f7f8f9")).derive(hex_to_bytes("0b" * 22))
    assert output_key.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                "34007208d5b887185865")
