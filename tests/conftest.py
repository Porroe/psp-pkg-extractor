"""Generate PKG transport fixtures, containing only invented test bytes."""
import struct
import pytest
from psp_pkg_extractor.crypto import PSP_KEY, PS3_KEY, aes_ctr_xor


def make_pkg(entries=None, *, content_type=7, table_offset=0):
    if entries is None:
        entries = [('USRDIR/CONTENT/CONTENT.DAT', b'synthetic payload', 0x90, 1)]
    iv = bytes.fromhex('00112233445566778899aabbccddeeff')
    data = bytearray(table_offset + 32 * len(entries))
    def append(payload, key):
        while len(data) % 16:
            data.append(0)
        offset = len(data)
        data.extend(aes_ctr_xor(key, iv, payload, offset))
        return offset
    for n, (name, payload, kt, flag) in enumerate(entries):
        key = PSP_KEY if kt == 0x90 else PS3_KEY
        encoded = name.encode('utf-8')
        no = append(encoded, key)
        do = append(payload, key)
        record = struct.pack('>IIQQII', no, len(encoded), do, len(payload), kt << 24 | flag, 0)
        offset = table_offset + n * 32
        data[offset:offset + 32] = aes_ctr_xor(PSP_KEY, iv, record, offset)
    metadata = struct.pack('>III', 2, 4, content_type)
    if table_offset:
        metadata += struct.pack('>IIII', 13, 8, table_offset, 32 * len(entries))
    h = bytearray(320)
    h[:4] = b'\x7fPKG'
    struct.pack_into('>HH4I3Q', h, 4, 0x8000, 2, 256, 2 if table_offset else 1,
                     len(metadata), len(entries), 320 + len(data), 320, len(data))
    content_id = b'UP0001-TEST12345_00-ABCDEFGHIJKLMNOP'
    h[48:48 + len(content_id)] = content_id
    h[112:128] = iv
    h[192:196] = b'\x7fext'
    struct.pack_into('>III', h, 196, 1, 64, 64)
    h[231] = 1
    h[256:256 + len(metadata)] = metadata
    return bytes(h + data)


@pytest.fixture
def pkg_factory(tmp_path):
    def build(entries=None, **kwargs):
        p = tmp_path / 'test.pkg'
        p.write_bytes(make_pkg(entries, **kwargs))
        return p
    return build
