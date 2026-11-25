# psp-pkg-extractor

An offline, dependency-free Python library and CLI for extracting files from
locally supplied retail Sony PSP and PSP Minis PKG containers. Python 3.9+
(including 3.15) is supported. It never downloads packages, contacts PSN,
executes extracted files, or generates licenses. Use only packages you own and
have the right to extract.

## Install and run

```sh
python -m pip install .
python -m psp_pkg_extractor inspect game.pkg
python -m psp_pkg_extractor extract game.pkg --output extracted/
python -m psp_pkg_extractor extract game.pkg --output extracted/ --force
# The installed console command also works:
psp-pkg-extractor inspect game.pkg
```

Use `python3` if your system does not provide `python`. Runtime dependencies
are Python's standard library only. CLI errors go to stderr with status 1;
argument errors return 2 and interruptions return 130.

Inspection validates the package and lists every entry, its size and payload
type, the content ID, package type, title ID derived from the content ID, and
item count. Extraction also reports output paths and total file bytes.

## Python API

```python
from psp_pkg_extractor import inspect_pkg, extract_pkg, PkgError

info = inspect_pkg("game.pkg")
print(info.content_id, info.package_type, info.title_id, info.item_count)
for item in info.items:
    print(item.path, item.size, item.flags, item.key_type, item.payload_type)

result = extract_pkg("game.pkg", "output/", force=False)
print(result.total_bytes, result.paths)
```

`PackageInfo`, `Header`, `ExtendedHeader`, `Metadata`, `Item`, and
`ExtractionResult` are immutable dataclasses. `info.header` exposes parsed main
and extended fields; `info.metadata` retains all metadata payloads, including
unknown records. Expected format/security errors derive from `PkgError`:
`InvalidPackageError`, `UnsupportedPackageError`, and `ExtractionError`.
Filesystem errors propagate as `OSError` in the API.

## Supported contents and limitations

Content types 0x07 (PSP, including PC Engine), 0x0E (PSP-Go), 0x0F (Minis), and
0x10 (NeoGeo) with retail revision 0x8000, platform 2, and package key index 1
are accepted. Debug, PS3, PS1, Vita, and other package/key types fail explicitly.

All package directories and supported files are preserved without renaming.
This includes plain ISO files, `CONTENT.DAT`, `PARAM.SFO`, `ICON0.PNG`,
`PIC0.PNG`, `PSP-KEY.EDAT`, and EBOOT/PBOOT.PBP. The extractor removes the outer
PKG AES-CTR layer, then follows pkg2zip's PSP behavior: an embedded
EBOOT.PBP/NPUMDIMG is converted to an ISO and PSP-KEY.EDAT is unwrapped to its
16-byte key file. Other EDAT/NPDRM payloads remain opaque, and no license is
created.
Recognized license filenames (`*.rif`, `*.rap`, `work.bin`, `license.dat`,
`license.bin`, `act.dat`, `idps`, case-insensitive) cause extraction to fail
before writing. Unknown item encryption/flag types also fail explicitly.

Extraction follows the PSP `pkg2zip` output contract in Python: embedded
EBOOT.PBP/NPUMDIMG images become ISO files, title IDs and names come from the
package SFO, and PSP sidecars are placed under `pspemu/PSP/GAME/<TITLE_ID>`.

This is structural validation, **not signature or authenticity verification**:
CMAC, HMAC, ECDSA and package digests are not verified. Corruption confined to
payload bytes may therefore be undetected. Pure-Python AES is substantially
slower than native AES for large games, and is not constant-time.

## Format

PKG uses big-endian fields. The 0xC0-byte main header contains `7F 50 4B 47`,
revision/platform, metadata offset/count/size, item count, total size, encrypted
data offset/size, a 48-byte content ID field, and a 16-byte CTR IV at 0x70.
The 64-byte extended header at 0xC0 starts with `7F 65 78 74`; its key ID is at
0xE4. The parser validates its version, size, data extent, HMAC pointer ranges,
and optional tail range, retaining these fields without authenticating hashes.

Plain metadata records have a u32 type, u32 payload size, and payload. Type 2
selects content type; optional type 13 supplies the encrypted item table offset
and size (plus an optional digest). Without type 13, the table begins at zero.
Other metadata is retained as bytes. Metadata pointers are bounded to the
plaintext region and encrypted item pointers to the declared encrypted region.

Each 32-byte decrypted item table record contains filename offset/length (u32),
data offset/size (u64), encryption selector at byte 24, flags at byte 27, and
reserved fields. Flags 4/18 mean directory; 1/2/3/5/8/11 identify recognized file
payloads. Accepted selectors are 0x00, 0x10, 0x80, and 0x90. Only **0x90** selects
the PSP key; all other accepted selectors select the PS3 key, following
upstream's selection rule. Entry-table
records always use the PSP key. Filenames and file bytes use the entry key.
CTR counters are the big-endian IV plus the encrypted-region byte offset divided
by 16, with unaligned reads supported. Names and file starts must be aligned.

## Safe extraction and publication

Absolute paths, traversal, backslashes, drive paths, NUL/control characters,
Windows device names, alternate streams, and ambiguous case/Unicode paths are
rejected. Duplicate paths, overlapping regions, file/directory conflicts,
truncation, invalid alignment, and out-of-bounds sizes fail before extraction.
Safety limits are 1 million entries, 4096 UTF-8 filename bytes, 255 bytes per
path component, and 1 MiB per metadata record. These intentionally reject some
unusual packages rather than creating platform-dependent output.

Files are streamed in 64 KiB chunks to a private sibling staging directory.
Existing files are never replaced unless `--force` is given. Existing unrelated
files are preserved by copying the destination into staging; file/directory
conflicts and destination symlinks/special files are rejected even with force.
The input cannot reside inside the output directory. Existing output must be
writable, and staging requires space for the full result plus existing content.

For a new destination, one same-filesystem directory rename publishes the whole
result atomically. For an existing destination, portable Python cannot atomically
exchange two nonempty directories: the old directory is renamed to a sibling
backup, then staging is renamed into place. Ordinary publication failures roll
back the backup. A process crash or power loss between those renames can leave
the output absent and the original in `.OUTPUT.backup-UUID`; recover by renaming
that backup to OUTPUT. No partial extracted tree is published. This is not a
durable transaction, and simultaneous writers or hostile modifications of the
output/parent directories during extraction are unsupported. Use a fresh output
directory when atomic visibility is required.

## Testing

```sh
python -m pip install -e '.[test]'
python -m pytest -q
```

Tests generate invented PKG fixtures and use independent FIPS 197 / NIST
SP 800-38A vectors to verify AES and CTR. They cover headers, metadata, both
keys, nonzero table offsets, flags, traversal, collisions, truncated/invalid
ranges, overwrite rules, rollback, and CLI behavior. No owned/copyrighted PKG
files are included. Set `PSP_PKG_FIXTURES` to run local SHA-256 integration
checks; see [fixtures/README.md](fixtures/README.md). GitHub Actions configures
Linux, macOS, and Windows on Python 3.9 through 3.15. These remote jobs must
run in GitHub; a local test run does not establish results for every platform.

## Attribution

Inspired by [mmozeiko/pkg2zip](https://github.com/mmozeiko/pkg2zip), released into
the public domain under the Unlicense, and the
[PKG format documentation](https://www.psdevwiki.com/ps3/PKG_files).
See [THIRD_PARTY.md](THIRD_PARTY.md) and [LICENSE](LICENSE).
