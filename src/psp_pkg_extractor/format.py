"""Validated retail PSP PKG structures. All PKG integers are big-endian."""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
import struct
import unicodedata
from typing import BinaryIO

from .crypto import PSP_KEY, PS3_KEY, aes_ctr_xor
from .errors import InvalidPackageError, UnsupportedPackageError

PACKAGE_TYPES = {7: "PSP", 0x0e: "PSP-Go", 0x0f: "PSP-Minis", 0x10: "PSP-NeoGeo"}


@dataclass(frozen=True)
class ExtendedHeader:
    version: int
    size: int
    data_size: int
    headers_hmac_offset: int
    metadata_hmac_offset: int
    tail_offset: int
    key_id: int
    full_header_hmac_offset: int


@dataclass(frozen=True)
class Header:
    revision: int
    platform: int
    metadata_offset: int
    metadata_count: int
    metadata_size: int
    item_count: int
    total_size: int
    data_offset: int
    data_size: int
    content_id: str
    iv: bytes
    extended_header: ExtendedHeader
    key_type: int


@dataclass(frozen=True)
class Metadata:
    type: int
    data: bytes


@dataclass(frozen=True)
class Item:
    path: str
    name_offset: int
    name_size: int
    data_offset: int
    size: int
    key_type: int
    flags: int

    @property
    def is_directory(self) -> bool:
        return self.flags in (4, 18)

    @property
    def payload_type(self) -> str:
        return {1: "NPDRM payload (preserved)", 2: "EDAT (preserved)",
                5: "PSP EDAT (preserved)", 8: "PSP EDAT module (preserved)",
                11: "PBP (preserved)"}.get(self.flags, "plain")

    @property
    def key(self) -> bytes:
        return PSP_KEY if self.key_type == 0x90 else PS3_KEY


@dataclass(frozen=True)
class PackageInfo:
    content_id: str
    package_type: str
    title_id: str | None
    header: Header
    metadata: tuple[Metadata, ...]
    items: tuple[Item, ...]

    @property
    def item_count(self) -> int:
        return len(self.items)

    @property
    def total_bytes(self) -> int:
        return sum(i.size for i in self.items if not i.is_directory)


def check_range(offset: int, size: int, limit: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise InvalidPackageError(f"{label} extends outside its containing region")


def read_at(f: BinaryIO, offset: int, size: int) -> bytes:
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise InvalidPackageError("Truncated package")
    return data


def parse_header(f: BinaryIO, actual_size: int) -> Header:
    b = read_at(f, 0, 256)
    if b[:4] != b'\x7fPKG':
        raise InvalidPackageError("Invalid PKG magic")
    revision, platform = struct.unpack_from(">HH", b, 4)
    if revision != 0x8000 or platform != 2:
        raise UnsupportedPackageError(f"Only retail PSP packages are supported (revision={revision:#x}, platform={platform})")
    mo, mc, ms, count = struct.unpack_from(">4I", b, 8)
    total, off, size = struct.unpack_from(">3Q", b, 24)
    if total != actual_size:
        raise InvalidPackageError("Declared package size does not match file size")
    if off < 256 or off % 16:
        raise InvalidPackageError("Invalid encrypted data offset or alignment")
    check_range(off, size, total, "Encrypted data")
    if mo < 256:
        raise InvalidPackageError("Metadata overlaps main/extended header")
    check_range(mo, ms, off, "Metadata region")
    check_range(0, mc * 8, ms, "Metadata headers")
    if b[192:196] != b'\x7fext':
        raise InvalidPackageError("Invalid extended PSP header magic")
    version, ext_size, ext_data_size, hh, mh, tail, padding, key_id, fh = struct.unpack_from(">5IQ3I", b, 196)
    if version != 1 or ext_size != 64:
        raise UnsupportedPackageError("Unsupported extended header version or size")
    check_range(256, ext_data_size, off, "Extended header data")
    for label, pointer in (("Headers HMAC", hh), ("Metadata HMAC", mh), ("Full header HMAC", fh)):
        if pointer:
            if pointer < 256:
                raise InvalidPackageError(f"{label} overlaps headers")
            check_range(pointer, 16, off, label)
    if tail:
        if tail < off + size:
            raise InvalidPackageError("Package tail overlaps encrypted data")
        check_range(tail, 0x1a0, total, "Package tail")
    ext = ExtendedHeader(version, ext_size, ext_data_size, hh, mh, tail, key_id, fh)
    key_type = key_id & 7
    if key_type != 1:
        raise UnsupportedPackageError(f"Unsupported package key type {key_type}")
    try:
        raw_id = b[48:96].split(b'\0', 1)[0]
        content_id = raw_id.decode("ascii")
    except UnicodeDecodeError as e:
        raise InvalidPackageError("Content ID is not ASCII") from e
    if not re.fullmatch(r"[A-Z]{2}[0-9]{4}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9]{16}", content_id):
        raise InvalidPackageError("Malformed content ID")
    return Header(revision, platform, mo, mc, ms, count, total, off, size,
                  content_id, b[112:128], ext, key_type)


def parse_metadata(f: BinaryIO, h: Header) -> tuple[tuple[Metadata, ...], int, int]:
    records = []
    seen = set()
    offset = h.metadata_offset
    content_type = None
    items_offset = 0
    for _ in range(h.metadata_count):
        check_range(offset, 8, h.metadata_offset + h.metadata_size, "Metadata record")
        kind, size = struct.unpack(">II", read_at(f, offset, 8))
        check_range(offset + 8, size, h.metadata_offset + h.metadata_size, "Metadata payload")
        if size > 1024 * 1024:
            raise InvalidPackageError("Metadata record exceeds 1 MiB safety limit")
        data = read_at(f, offset + 8, size)
        if kind in (2, 13) and kind in seen:
            raise InvalidPackageError(f"Duplicate metadata type {kind}")
        seen.add(kind)
        if kind == 2:
            if size != 4:
                raise InvalidPackageError("Content type metadata must contain 4 bytes")
            content_type = int.from_bytes(data, "big")
        elif kind == 13:
            if size not in (8, 40):
                raise InvalidPackageError("Item table metadata must contain 8 or 40 bytes")
            items_offset, items_size = struct.unpack_from(">II", data)
            check_range(items_offset, items_size, h.data_size, "Item metadata region")
            if items_size < h.item_count * 32:
                raise InvalidPackageError("Item metadata region is smaller than item table")
        records.append(Metadata(kind, data))
        offset += 8 + size
    if content_type is None:
        raise InvalidPackageError("Missing content type metadata")
    if content_type not in PACKAGE_TYPES:
        raise UnsupportedPackageError(f"Unsupported content type {content_type:#x}")
    return tuple(records), content_type, items_offset


def safe_path(path: str) -> str:
    parts = path.split('/')
    if not path or len(path.encode('utf-8')) > 4096 or path.startswith('/'):
        raise InvalidPackageError(f"Unsafe item path: {path!r}")
    for p in parts:
        if (p in ('', '.', '..') or len(p.encode('utf-8')) > 255
                or p.endswith((' ', '.')) or any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in p)
                or p.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}):
            raise InvalidPackageError(f"Unsafe item path: {path!r}")
    return str(PurePosixPath(path))


def path_identity(path: str) -> str:
    return unicodedata.normalize('NFC', path).casefold()


def decrypt_at(f: BinaryIO, h: Header, offset: int, size: int, key: bytes) -> bytes:
    check_range(offset, size, h.data_size, "Encrypted read")
    try:
        return aes_ctr_xor(key, h.iv, read_at(f, h.data_offset + offset, size), offset)
    except ValueError as e:
        raise InvalidPackageError(str(e)) from e


def parse_items(f: BinaryIO, h: Header, table_offset: int) -> tuple[Item, ...]:
    check_range(table_offset, h.item_count * 32, h.data_size, "Item table")
    if table_offset % 16 or h.item_count > 1_000_000:
        raise InvalidPackageError("Invalid item table alignment or excessive item count")
    regions = [(table_offset, table_offset + h.item_count * 32, "item table")] if h.item_count else []
    items = []
    paths: dict[str, Item] = {}
    # Include implicit directories to reject casing/Unicode aliases of parents.
    spellings: dict[str, str] = {}
    for index in range(h.item_count):
        b = decrypt_at(f, h, table_offset + 32 * index, 32, PSP_KEY)
        no, ns, do, ds, flags, reserved = struct.unpack(">IIQQII", b)
        kt, flag = flags >> 24, flags & 255
        if kt not in (0x00, 0x10, 0x90, 0x80):
            raise UnsupportedPackageError(f"Item {index}: unsupported encryption type {kt:#x}")
        # The middle attribute bits are used by retail PSP packages (commonly
        # 0x0200).  The selector and low-byte payload flag are the fields that
        # determine decryption and entry handling; preserve other attributes.
        if reserved or flag not in (1, 2, 3, 4, 5, 6, 8, 9, 11, 18):
            raise UnsupportedPackageError(f"Item {index}: unsupported item flags {flags:#x} or reserved fields")
        if no % 16 or do % 16 or not 1 <= ns <= 4096:
            raise InvalidPackageError(f"Item {index}: invalid alignment or filename length")
        check_range(no, ns, h.data_size, "Item filename")
        check_range(do, ds, h.data_size, "Item data")
        regions.append((no, no + ns, f"item {index} name"))
        if ds:
            regions.append((do, do + ds, f"item {index} data"))
        if flag in (4, 18) and ds:
            raise InvalidPackageError("Directory item contains file data")
        try:
            path = safe_path(decrypt_at(f, h, no, ns, PSP_KEY if kt == 0x90 else PS3_KEY).decode('utf-8'))
        except UnicodeDecodeError as e:
            raise InvalidPackageError(f"Item {index}: filename is not UTF-8") from e
        identity = path_identity(path)
        if identity in paths:
            raise InvalidPackageError(f"Duplicate item path: {path}")
        item = Item(path, no, ns, do, ds, kt, flag)
        paths[identity] = item
        items.append(item)
        components = path.split('/')
        for n in range(1, len(components) + 1):
            prefix = '/'.join(components[:n])
            key = path_identity(prefix)
            if key in spellings and spellings[key] != prefix:
                raise InvalidPackageError(f"Ambiguous path spelling: {path}")
            spellings[key] = prefix
    regions.sort()
    for previous, current in zip(regions, regions[1:]):
        if current[0] < previous[1]:
            raise InvalidPackageError(f"Overlapping encrypted regions: {previous[2]} and {current[2]}")
    for item in items:
        for parent in PurePosixPath(item.path).parents:
            existing = paths.get(path_identity(str(parent)))
            if existing and not existing.is_directory:
                raise InvalidPackageError(f"File is used as a directory: {existing.path}")
    return tuple(items)


def inspect_stream(f: BinaryIO) -> PackageInfo:
    f.seek(0, 2)
    h = parse_header(f, f.tell())
    metadata, kind, table = parse_metadata(f, h)
    items = parse_items(f, h, table)
    return PackageInfo(h.content_id, PACKAGE_TYPES[kind], h.content_id[7:16], h, metadata, items)
