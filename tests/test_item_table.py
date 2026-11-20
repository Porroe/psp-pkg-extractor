import struct
import pytest
from psp_pkg_extractor import inspect_pkg, InvalidPackageError, UnsupportedPackageError
from psp_pkg_extractor.crypto import PSP_KEY, aes_ctr_xor


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'C:/escape', 'a\\b', 'a/../b', 'a//b', 'a\0b', 'NUL.txt', 'a.', 'a/'])
def test_unsafe_names(pkg_factory, name):
    with pytest.raises(InvalidPackageError):
        inspect_pkg(pkg_factory([(name,b'x',0x90,1)]))


@pytest.mark.parametrize('names', [('same','same'), ('Same','same'), ('a','a/b'), ('A/x','a/y'), ('é','e\u0301')])
def test_conflicting_paths(pkg_factory, names):
    with pytest.raises(InvalidPackageError):
        inspect_pkg(pkg_factory([(name,b'x',0x90,1) for name in names]))


def test_unsupported_encryption(pkg_factory):
    with pytest.raises(UnsupportedPackageError):
        inspect_pkg(pkg_factory([('x',b'x',0x91,1)]))


@pytest.mark.parametrize('field,value', [(0,0xffffffff), (8,2**64-16), (16,2**64-1), (24,0x900000ff)])
def test_item_bounds_and_flags(pkg_factory, field, value):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    iv = bytes(data[112:128])
    record = bytearray(aes_ctr_xor(PSP_KEY,iv,bytes(data[320:352])))
    struct.pack_into('>Q' if field in (8,16) else '>I',record,field,value)
    data[320:352] = aes_ctr_xor(PSP_KEY,iv,record)
    path.write_bytes(data)
    with pytest.raises((InvalidPackageError, UnsupportedPackageError)):
        inspect_pkg(path)


def test_overlapping_file_and_table(pkg_factory):
    path = pkg_factory()
    data = bytearray(path.read_bytes())
    iv = bytes(data[112:128])
    record = bytearray(aes_ctr_xor(PSP_KEY,iv,bytes(data[320:352])))
    struct.pack_into('>Q',record,8,0)
    data[320:352] = aes_ctr_xor(PSP_KEY,iv,record)
    path.write_bytes(data)
    with pytest.raises(InvalidPackageError,match='Overlapping'):
        inspect_pkg(path)
