"""Dependency-free AES-128 encryption and random-access big-endian CTR.

CTR removes the PKG transport layer only; it does not decrypt NPDRM payloads.
This table-based implementation is not designed for secret-key applications.
"""
from functools import lru_cache
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = algorithms = modes = None
try:
    from Crypto.Cipher import AES as _PyCryptoAES
except ImportError:
    _PyCryptoAES = None

PSP_KEY = bytes.fromhex("07f2c68290b50d2c33818d709b60e62b")
PS3_KEY = bytes.fromhex("2e7b71d7c9c9a14ea3221f188828b8f8")


def _mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255
        b >>= 1
    return out


def _sbox(x: int) -> int:
    y = 1
    if x:
        for _ in range(254):
            y = _mul(y, x)
    else:
        y = 0
    return y ^ ((y << 1 | y >> 7) & 255) ^ ((y << 2 | y >> 6) & 255) ^ ((y << 3 | y >> 5) & 255) ^ ((y << 4 | y >> 4) & 255) ^ 0x63


_S = bytes(_sbox(x) for x in range(256))
_INV_S = bytes(next(i for i, value in enumerate(_S) if value == x) for x in range(256))
_X2 = bytes(_mul(x, 2) for x in range(256))
_M9 = bytes(_mul(x, 9) for x in range(256))
_M11 = bytes(_mul(x, 11) for x in range(256))
_M13 = bytes(_mul(x, 13) for x in range(256))
_M14 = bytes(_mul(x, 14) for x in range(256))
_X3 = bytes(_mul(x, 3) for x in range(256))

def _word(a, b, c, d):
    return (a << 24) | (b << 16) | (c << 8) | d

_TE0 = tuple(_word(_X2[_S[x]], _S[x], _S[x], _X3[_S[x]]) for x in range(256))
_TE1 = tuple(_word(_X3[_S[x]], _X2[_S[x]], _S[x], _S[x]) for x in range(256))
_TE2 = tuple(_word(_S[x], _X3[_S[x]], _X2[_S[x]], _S[x]) for x in range(256))
_TE3 = tuple(_word(_S[x], _S[x], _X3[_S[x]], _X2[_S[x]]) for x in range(256))


@lru_cache(maxsize=8)
def _expand(key: bytes) -> tuple[bytes, ...]:
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    expanded = list(key)
    rc = 1
    while len(expanded) < 176:
        t = expanded[-4:]
        if len(expanded) % 16 == 0:
            t = [_S[t[1]] ^ rc, _S[t[2]], _S[t[3]], _S[t[0]]]
            rc = _X2[rc]
        for v in t:
            expanded.append(expanded[-16] ^ v)
    return tuple(bytes(expanded[i:i + 16]) for i in range(0, 176, 16))


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block (FIPS 197)."""
    if len(block) != 16:
        raise ValueError("AES requires a 16-byte block")
    if Cipher is not None:
        return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(block)
    if _PyCryptoAES is not None:
        return _PyCryptoAES.new(key, _PyCryptoAES.MODE_ECB).encrypt(block)
    keys = _expand(key)
    state = [a ^ b for a, b in zip(block, keys[0])]
    for r in range(1, 11):
        s = [_S[state[4 * ((c + row) % 4) + row]] for c in range(4) for row in range(4)]
        if r != 10:
            for c in range(0, 16, 4):
                a, b, d, e = s[c:c + 4]
                t = a ^ b ^ d ^ e
                s[c:c + 4] = [a ^ t ^ _X2[a ^ b], b ^ t ^ _X2[b ^ d], d ^ t ^ _X2[d ^ e], e ^ t ^ _X2[e ^ a]]
        state = [a ^ b for a, b in zip(s, keys[r])]
    return bytes(state)


def aes128_decrypt_block(key: bytes, block: bytes) -> bytes:
    """Decrypt one 16-byte AES-128 block (FIPS 197)."""
    if len(block) != 16:
        raise ValueError("AES requires a 16-byte block")
    if Cipher is not None:
        return Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(block)
    if _PyCryptoAES is not None:
        return _PyCryptoAES.new(key, _PyCryptoAES.MODE_ECB).decrypt(block)
    keys = _expand(key)
    state = [a ^ b for a, b in zip(block, keys[10])]
    for r in range(9, -1, -1):
        # inverse shift rows, then inverse S-box
        shifted = [state[4 * ((c - row) % 4) + row] for c in range(4) for row in range(4)]
        state = [_INV_S[x] for x in shifted]
        state = [a ^ b for a, b in zip(state, keys[r])]
        if r:
            for c in range(0, 16, 4):
                a, b, d, e = state[c:c + 4]
                state[c:c + 4] = [
                    _M14[a] ^ _M11[b] ^ _M13[d] ^ _M9[e], _M9[a] ^ _M14[b] ^ _M11[d] ^ _M13[e],
                    _M13[a] ^ _M9[b] ^ _M14[d] ^ _M11[e], _M11[a] ^ _M13[b] ^ _M9[d] ^ _M14[e],
                ]
    return bytes(state)


def aes_ctr_xor(key: bytes, iv: bytes, data: bytes, offset: int = 0) -> bytes:
    """XOR bytes at a byte offset relative to the encrypted PKG region."""
    if len(key) != 16 or len(iv) != 16 or offset < 0:
        raise ValueError("CTR requires 16-byte key/IV and nonnegative offset")
    base = int.from_bytes(iv, "big")
    if data and base + (offset + len(data) - 1) // 16 >= 1 << 128:
        raise ValueError("CTR counter overflow")
    if Cipher is not None and data:
        start = base + offset // 16
        skip = offset % 16
        padded = (b'\0' * skip) + data
        stream = Cipher(algorithms.AES(key), modes.CTR(start.to_bytes(16, 'big'))).encryptor().update(padded)
        return stream[skip:]
    if _PyCryptoAES is not None and data:
        start = base + offset // 16
        skip = offset % 16
        cipher = _PyCryptoAES.new(key, _PyCryptoAES.MODE_ECB)
        padded = (b'\0' * skip) + data
        # ECB-generated counter stream, retaining the dependency-free CTR semantics.
        stream = b''.join(cipher.encrypt((start + i).to_bytes(16, 'big')) for i in range((len(padded) + 15) // 16))
        return bytes(a ^ b for a, b in zip(padded, stream))[skip:]
    out = bytearray(len(data))
    pos = 0
    while pos < len(data):
        chunk = min(len(data) - pos, 16 * 64)
        first, skip = divmod(offset + pos, 16)
        stream = b''.join(aes128_encrypt_block(key, (base + first + i).to_bytes(16, 'big')) for i in range((skip + chunk + 15) // 16))
        for i in range(chunk):
            out[pos + i] = data[pos + i] ^ stream[skip + i]
        pos += chunk
    return bytes(out)
