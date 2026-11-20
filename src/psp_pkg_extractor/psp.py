"""PSP EBOOT/PBP and NPUMDIMG structural primitives.

The outer PKG transport layer is handled by :mod:`format`.  This module keeps
the inner image format separate so its decryption and decompression stages can
be tested independently against the upstream implementation.
"""
from dataclasses import dataclass
import struct

from .crypto import aes128_decrypt_block, aes128_encrypt_block
from .errors import InvalidPackageError, UnsupportedPackageError

ISO_SECTOR_SIZE = 2048
KIRK7_KEY38 = bytes.fromhex('12468d7e1c42209bba5426835eb03303')
KIRK7_KEY39 = bytes.fromhex('c43bb6d653ee67493ea95fbc0ced6f8a')
KIRK7_KEY63 = bytes.fromhex('9c9b1372f8c640cf1c62f5d592ddb582')
AMCTL_HASHKEY_3 = bytes.fromhex('e350ed1d910a1fd029bb1c3ef34077fb')
AMCTL_HASHKEY_4 = bytes.fromhex('135fa47cab395ba476b8cca98f3a0445')
AMCTL_HASHKEY_5 = bytes.fromhex('678d7fa32a9ca0d1508a d8385e4b017e'.replace(' ', ''))


def aes_cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC (RFC 4493), used by the PSP PSAR header."""
    zero = bytes(16)
    l = aes128_encrypt_block(key, zero)
    def dbl(block):
        carry = 0
        out = bytearray(16)
        for i in range(15, -1, -1):
            value = (block[i] << 1) | carry
            out[i] = value & 255
            carry = value >> 8
        if carry:
            out[15] ^= 0x87
        return bytes(out)
    k1 = dbl(l); k2 = dbl(k1)
    count = max(1, (len(data) + 15) // 16)
    complete = len(data) > 0 and len(data) % 16 == 0
    last = (data[-16:] if complete else data[(count - 1) * 16:] + b'\x80')
    last = bytes(a ^ b for a, b in zip(last.ljust(16, b'\0'), k1 if complete else k2))
    state = zero
    for i in range(count - 1):
        state = aes128_encrypt_block(key, bytes(a ^ b for a, b in zip(state, data[i * 16:i * 16 + 16])))
    return aes128_encrypt_block(key, bytes(a ^ b for a, b in zip(state, last)))


def init_psp_decrypt(mac: bytes, header: bytes, *, eboot: bool, offset1: int, offset2: int):
    """Derive the PSP PSAR block key and IV from upstream's KIRK routine."""
    tmp = header[offset1:offset1 + 16]
    if len(tmp) != 16:
        raise InvalidPackageError("PSP key derivation input is truncated")
    if eboot:
        tmp = aes128_decrypt_block(KIRK7_KEY63, tmp)
    tmp = aes128_decrypt_block(KIRK7_KEY38, tmp)
    iv = bytes(a ^ b ^ c ^ d ^ e for a, b, c, d, e in zip(mac, tmp, header[offset2:offset2 + 16], AMCTL_HASHKEY_3, AMCTL_HASHKEY_5))
    iv = aes128_decrypt_block(KIRK7_KEY39, iv)
    return KIRK7_KEY63, bytes(a ^ b for a, b in zip(iv, AMCTL_HASHKEY_4))


def psp_decrypt(key: bytes, iv: bytes, index: int, data: bytes) -> bytes:
    """Apply the PSP CBC-like block transform used inside NPUMDIMG."""
    if len(data) % 16 or len(iv) != 16:
        raise ValueError("PSP decryption requires aligned data and a 16-byte IV")
    previous = bytes(16) if index == 0 else iv[:12] + index.to_bytes(4, 'little')
    counter = iv[:12] + index.to_bytes(4, 'little')
    out = bytearray()
    for pos in range(0, len(data), 16):
        value = (int.from_bytes(counter[12:], 'little') + 1).to_bytes(4, 'little')
        counter = counter[:12] + value
        stream = aes128_decrypt_block(key, counter)
        block = data[pos:pos + 16]
        out.extend(bytes(a ^ b ^ c for a, b, c in zip(block, previous, stream)))
        previous = counter
    return bytes(out)


class _RangeDecoder:
    def __init__(self, data: bytes, output_size: int):
        if len(data) < 5:
            raise InvalidPackageError("LZRC stream is truncated")
        self.data = data
        self.pos = 5
        self.out = bytearray(output_size)
        self.out_pos = 0
        self.range = 0xffffffff
        self.code = int.from_bytes(data[1:5], "big")
        self.lc = data[0]
        self.match = [[0x80] * 8 for _ in range(8)]
        self.literal = [[0x80] * 256 for _ in range(8)]
        # The upstream C declares 39 entries but traverses the 44-node tree;
        # the extra nodes are required for bounds-safe decoding.
        self.dist_bits = [[0x80] * 51 for _ in range(8)]
        self.dist = [[0x80] * 8 for _ in range(18)]
        self.length = [[0x80] * 31 for _ in range(8)]

    def normalize(self):
        if self.range < 0x01000000:
            if self.pos >= len(self.data):
                raise InvalidPackageError("LZRC range stream is truncated")
            self.range <<= 8
            self.code = (self.code << 8 | self.data[self.pos]) & 0xffffffff
            self.pos += 1

    def bit(self, probs, index):
        self.normalize()
        bound = (self.range >> 8) * probs[index]
        probs[index] -= probs[index] >> 3
        if self.code < bound:
            self.range = bound
            probs[index] += 31
            return 1
        self.code -= bound
        self.range -= bound
        return 0

    def tree(self, probs, limit, base=0):
        number = 1
        while number < limit:
            number = (number << 1) + self.bit(probs, base + number)
        return number

    def number(self, probs, n, base=0):
        number = 1
        if n > 3:
            number = (number << 1) + self.bit(probs, base + 3)
            if n > 4:
                number = (number << 1) + self.bit(probs, base + 3)
                if n > 5:
                    self.normalize()
                    for _ in range(n - 5):
                        self.range >>= 1
                        number <<= 1
                        if self.code < self.range:
                            number += 1
                        else:
                            self.code -= self.range
        if n > 0:
            number = (number << 1) + self.bit(probs, base)
            if n > 1:
                number = (number << 1) + self.bit(probs, base + 1)
                if n > 2:
                    number = (number << 1) + self.bit(probs, base + 2)
        return number


def lzrc_decompress(data: bytes, output_size: int) -> bytes:
    """Decode the LZRC stream used by compressed PSP PSAR blocks."""
    rc = _RangeDecoder(data, output_size)
    if rc.lc & 0x80:
        size = rc.code
        if size > output_size or 5 + size > len(data):
            raise InvalidPackageError("LZRC plain stream exceeds output")
        return data[5:5 + size]
    state = 0
    last = 0
    while True:
        step = 0
        if rc.bit(rc.match[state], step) == 0:
            if state > 0:
                state -= 1
            value = rc.tree(rc.literal[(last >> rc.lc) & 7], 0x100) - 0x100
            if rc.out_pos >= output_size:
                raise InvalidPackageError("LZRC output overflow")
            rc.out[rc.out_pos] = value
            rc.out_pos += 1
            last = value
            continue
        length_bits = 0
        for _ in range(7):
            step += 1
            if rc.bit(rc.match[state], step) == 0:
                break
            length_bits += 1
        if length_bits == 0:
            match_len = 1
        else:
            length_state = ((length_bits - 1) << 2) + ((rc.out_pos << (length_bits - 1)) & 3)
            match_len = rc.number(rc.length[state], length_bits, length_state)
            if match_len == 0xff:
                return bytes(rc.out[:rc.out_pos])
        dist_state, limit = (7, 44) if match_len > 2 else (0, 8)
        dist_bits = rc.tree(rc.dist_bits[length_bits], limit, dist_state) - limit
        match_dist = rc.number(rc.dist[dist_bits], dist_bits) if dist_bits > 0 else 1
        if match_dist > rc.out_pos or rc.out_pos + match_len + 1 > output_size:
            raise InvalidPackageError("LZRC match exceeds output")
        for _ in range(match_len + 1):
            rc.out[rc.out_pos] = rc.out[rc.out_pos - match_dist]
            rc.out_pos += 1
        last = rc.out[rc.out_pos - 1]
        state = 6 + ((rc.out_pos + 1) & 1)


@dataclass(frozen=True)
class PbpHeader:
    version: int
    offsets: tuple[int, ...]

    @property
    def psar_offset(self) -> int:
        return self.offsets[7]


@dataclass(frozen=True)
class PsarHeader:
    block_sectors: int
    iso_start: int
    iso_end: int
    table_offset: int
    mac_region: bytes

    @property
    def image_bytes(self) -> int:
        value = self.iso_end - self.iso_start - 1
        if value <= 0:
            raise InvalidPackageError("PSAR image range is invalid")
        return value

    @property
    def block_count(self) -> int:
        return (self.image_bytes + self.block_sectors - 1) // self.block_sectors


@dataclass(frozen=True)
class PsarBlock:
    offset: int
    size: int
    flags: int


def parse_pbp_header(data: bytes) -> PbpHeader:
    if len(data) < 0x28:
        raise InvalidPackageError("EBOOT.PBP is truncated")
    magic, version, *offsets = struct.unpack_from("<4sI8I", data)
    if magic != b"\0PBP":
        raise InvalidPackageError("EBOOT.PBP has an invalid signature")
    if offsets != sorted(offsets) or offsets[0] < 0x28:
        raise InvalidPackageError("EBOOT.PBP offsets are invalid")
    return PbpHeader(version, tuple(offsets))


def parse_psar_header(data: bytes, image_size: int, *, validate_table: bool = True) -> PsarHeader:
    if len(data) < 0x100 or data[:8] != b"NPUMDIMG":
        raise InvalidPackageError("PBP PSAR has an invalid NPUMDIMG signature")
    block_sectors = struct.unpack_from("<I", data, 0x0C)[0]
    if not 1 <= block_sectors <= 16:
        raise UnsupportedPackageError(f"Unsupported PSAR block size {block_sectors}")
    iso_start = struct.unpack_from("<I", data, 0x54)[0]
    iso_end = struct.unpack_from("<I", data, 0x64)[0]
    table_offset = struct.unpack_from("<I", data, 0x6c)[0]
    header = PsarHeader(block_sectors, iso_start, iso_end, table_offset, data[:0xC0])
    if validate_table:
        table_end = table_offset + header.block_count * 32
        if table_offset < 0x100 or table_end > image_size:
            raise InvalidPackageError("PSAR block table exceeds EBOOT.PBP")
    return header


def parse_psar_block(data: bytes) -> PsarBlock:
    if len(data) != 32:
        raise InvalidPackageError("PSAR block record must be 32 bytes")
    words = struct.unpack("<8I", data)
    offset = words[4] ^ words[2] ^ words[3]
    size = words[5] ^ words[1] ^ words[2]
    flags = words[6] ^ words[0] ^ words[3]
    if offset < 0x100 or size == 0:
        raise InvalidPackageError("PSAR block record has invalid offset or size")
    return PsarBlock(offset, size, flags)


def iter_psar_blocks(data: bytes, header: PsarHeader):
    """Yield validated PSAR blocks from an already decrypted PSAR image."""
    for index in range(header.block_count):
        start = header.table_offset + index * 32
        block = parse_psar_block(data[start:start + 32])
        if block.offset + block.size > len(data):
            raise InvalidPackageError(f"PSAR block {index} exceeds image")
        yield block


def eboot_to_iso(data: bytes) -> bytes:
    """Convert a decrypted PSP EBOOT.PBP/NPUMDIMG payload to ISO bytes."""
    pbp = parse_pbp_header(data[:0x28])
    psar_offset = pbp.psar_offset
    psar = parse_psar_header(data[psar_offset:psar_offset + 0x100], len(data) - psar_offset, validate_table=False)
    header = bytearray(data[psar_offset:psar_offset + 0x100])
    mac = aes_cmac(KIRK7_KEY38, bytes(header[:0xc0]))
    key, iv = init_psp_decrypt(mac, header, eboot=True, offset1=0xc0, offset2=0xa0)
    header[0x40:0xa0] = psp_decrypt(key, iv, 0, bytes(header[0x40:0xa0]))
    # The image range and table pointer are read from the original PSAR
    # header before decrypting its key material, matching pkg2zip.
    psar = parse_psar_header(header, len(data) - psar_offset)
    out = bytearray()
    table_start = psar.table_offset
    for block in iter_psar_blocks(data[psar_offset:], psar):
        encoded = data[psar_offset + block.offset:psar_offset + block.offset + block.size]
        if block.flags & 4 == 0:
            encoded = psp_decrypt(key, iv, block.offset // 16, encoded)
        expected = psar.block_sectors * ISO_SECTOR_SIZE
        decoded = encoded if len(encoded) == expected else lzrc_decompress(encoded, expected)
        if len(decoded) != expected:
            raise InvalidPackageError("PSAR block decompressed to an unexpected size")
        out.extend(decoded)
    # pkg2zip writes complete PSAR blocks, including the final sector padding;
    # the resulting ISO therefore has block_count * block_sectors sectors.
    return bytes(out)


def sfo_title(data: bytes) -> str | None:
    """Read the TITLE string from a PARAM.SFO without external dependencies."""
    if len(data) < 20 or data[:4] != b'\0PSF':
        return None
    _, _, key_off, value_off, count = struct.unpack_from('<4s4I', data)
    for i in range(count):
        pos = 20 + i * 16
        if pos + 16 > len(data):
            break
        key, fmt, length, maximum, value = struct.unpack_from('<HHIII', data, pos)
        end = data.find(b'\0', key_off + key)
        name = data[key_off + key:end if end >= 0 else key_off + key + 64]
        if name == b'TITLE':
            raw = data[value_off + value:value_off + value + length]
            return raw.split(b'\0', 1)[0].decode('utf-8', 'replace')
    return None


def extract_psp_key(data: bytes) -> bytes:
    """Unwrap the 16-byte key emitted by pkg2zip from PSP-KEY.EDAT."""
    if len(data) < 0x190:
        raise InvalidPackageError("PSP-KEY.EDAT is truncated")
    header = data[0x90:0x190]
    if header[:4] != b'\0PGD':
        raise InvalidPackageError("PSP-KEY.EDAT has an invalid PGD header")
    if struct.unpack_from('<II', header, 4) != (1, 1):
        raise UnsupportedPackageError("Unsupported PSP-KEY.EDAT key or DRM type")
    mac = aes_cmac(KIRK7_KEY38, header[:0x70])
    key, iv = init_psp_decrypt(mac, header, eboot=False, offset1=0x70, offset2=0x10)
    decoded = bytearray(header)
    decoded[0x30:0x60] = psp_decrypt(key, iv, 0, bytes(decoded[0x30:0x60]))
    size = struct.unpack_from('<I', decoded, 0x44)[0]
    offset = struct.unpack_from('<I', decoded, 0x4c)[0]
    if (size, offset) != (0x10, 0x90):
        raise UnsupportedPackageError("Unsupported PSP-KEY.EDAT data layout")
    key, iv = init_psp_decrypt(mac, decoded, eboot=False, offset1=0x70, offset2=0x30)
    return psp_decrypt(key, iv, 0, bytes(decoded[0x90:0xa0]))
