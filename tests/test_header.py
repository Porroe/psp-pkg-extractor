import struct
import pytest
from psp_pkg_extractor import inspect_pkg, InvalidPackageError, UnsupportedPackageError


def test_valid(pkg_factory):
    info = inspect_pkg(pkg_factory())
    assert info.title_id == 'TEST12345'
    assert info.package_type == 'PSP'
    assert info.header.key_type == 1


@pytest.mark.parametrize('offset,value,error', [(0,b'bad!',InvalidPackageError), (192,b'bad!',InvalidPackageError), (231,b'\x02',UnsupportedPackageError), (4,b'\0\0',UnsupportedPackageError), (48,b'!',InvalidPackageError), (32,struct.pack('>Q',2**64-16),InvalidPackageError)])
def test_bad_header(pkg_factory, offset, value, error):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    data[offset:offset+len(value)] = value
    path.write_bytes(data)
    with pytest.raises(error):
        inspect_pkg(path)


def test_truncation(pkg_factory):
    path = pkg_factory()
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(InvalidPackageError):
        inspect_pkg(path)


@pytest.mark.parametrize('offset,value,error', [
    (196,struct.pack('>I',2),UnsupportedPackageError),
    (200,struct.pack('>I',32),UnsupportedPackageError),
    (204,struct.pack('>I',0xffffffff),InvalidPackageError),
    (208,struct.pack('>I',16),InvalidPackageError),
    (212,struct.pack('>I',0xffffffff),InvalidPackageError),
    (216,struct.pack('>Q',320),InvalidPackageError),
])
def test_extended_header_bounds(pkg_factory,offset,value,error):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    data[offset:offset+len(value)] = value
    path.write_bytes(data)
    with pytest.raises(error):
        inspect_pkg(path)
