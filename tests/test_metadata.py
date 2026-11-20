import struct
import pytest
from psp_pkg_extractor import inspect_pkg, InvalidPackageError, UnsupportedPackageError


def test_minis_and_nonzero_table(pkg_factory):
    info = inspect_pkg(pkg_factory(content_type=15, table_offset=16))
    assert info.package_type == 'PSP-Minis'
    assert len(info.metadata) == 2


def test_unsupported_content(pkg_factory):
    with pytest.raises(UnsupportedPackageError):
        inspect_pkg(pkg_factory(content_type=21))


@pytest.mark.parametrize('offset,value', [(260, 0xffffffff), (264, 0), (12, 0xffffffff)])
def test_bad_metadata(pkg_factory, offset, value):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    struct.pack_into('>I', data, offset, value)
    path.write_bytes(data)
    with pytest.raises((InvalidPackageError, UnsupportedPackageError)):
        inspect_pkg(path)


def test_duplicate_metadata(pkg_factory):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    struct.pack_into('>II',data,12,2,24)
    data[268:280] = struct.pack('>III',2,4,7)
    path.write_bytes(data)
    with pytest.raises(InvalidPackageError,match='Duplicate'):
        inspect_pkg(path)


def test_unknown_metadata_retained(pkg_factory):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    struct.pack_into('>II',data,12,2,24)
    data[268:280] = struct.pack('>III',99,4,123)
    path.write_bytes(data)
    assert inspect_pkg(path).metadata[-1].data == struct.pack('>I',123)


def test_metadata_cannot_cross_declared_size(pkg_factory):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    struct.pack_into('>I',data,16,8)
    path.write_bytes(data)
    with pytest.raises(InvalidPackageError):
        inspect_pkg(path)
