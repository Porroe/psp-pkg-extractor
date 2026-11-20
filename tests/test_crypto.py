import pytest
from psp_pkg_extractor.crypto import aes128_encrypt_block, aes128_decrypt_block, aes_ctr_xor


def test_fips_197():
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    plain = bytes.fromhex('00112233445566778899aabbccddeeff')
    cipher = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    assert aes128_encrypt_block(key, plain) == cipher
    assert aes128_decrypt_block(key, cipher) == plain


def test_nist_sp800_38a_ctr():
    key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    iv = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
    plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51')
    cipher = bytes.fromhex('874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff')
    assert aes_ctr_xor(key, iv, plain) == cipher
    assert aes_ctr_xor(key, iv, cipher) == plain
    assert aes_ctr_xor(key, iv, plain[7:29], 7) == cipher[7:29]


def test_counter_carry_and_overflow():
    key = bytes(16)
    iv = (255).to_bytes(16, 'big')
    assert aes_ctr_xor(key, iv, bytes(16), 16) == aes128_encrypt_block(key, (256).to_bytes(16, 'big'))
    with pytest.raises(ValueError):
        aes_ctr_xor(key, bytes([255]) * 16, bytes(17))
