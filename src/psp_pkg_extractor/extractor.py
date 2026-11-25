"""Offline inspection and staged extraction API."""
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import tempfile
import uuid
from typing import Union

from .errors import ExtractionError
from .format import PackageInfo, decrypt_at, inspect_stream, path_identity
from .psp import eboot_to_iso, extract_psp_key, sfo_title


@dataclass(frozen=True)
class ExtractionResult:
    info: PackageInfo
    output: Path
    paths: tuple[Path, ...]
    total_bytes: int


def inspect_pkg(path: Union[str, os.PathLike[str]]) -> PackageInfo:
    """Validate a local package and return its headers, metadata, and entries."""
    with open(path, 'rb') as f:
        return inspect_stream(f)


def _license(path: str) -> bool:
    name = path.rsplit('/', 1)[-1].casefold()
    return name.endswith(('.rif', '.rap')) or name in {'work.bin', 'license.dat', 'license.bin', 'act.dat', 'idps'}


def _check_destination(output: Path) -> None:
    for p in (output, *output.parents):
        if p.is_symlink():
            raise ExtractionError(f"Destination contains a symbolic link: {p}")
    if output.exists():
        if not output.is_dir():
            raise ExtractionError(f"Destination is not a directory: {output}")
        for root, dirs, files in os.walk(output, followlinks=False):
            for name in dirs + files:
                p = Path(root) / name
                if p.is_symlink() or not (p.is_file() or p.is_dir()):
                    raise ExtractionError(f"Destination contains a link or special file: {p}")


def extract_pkg(path: Union[str, os.PathLike[str]], output: Union[str, os.PathLike[str]], *, force: bool = False,
                format: str = "tree", baseline: bool = False) -> ExtractionResult:
    """Extract transport-decrypted bytes; preserve inner encrypted payloads.

    Existing output is merged in staging. Force replaces conflicting regular
    files only. Whole-directory publication uses rename; existing destinations
    require a backup rename first (see README for the crash-consistency limit).
    """
    if format not in ("tree", "eboot", "iso"):
        raise ExtractionError("format must be 'tree', 'eboot', or 'iso'")
    output = Path(os.path.abspath(output))
    source = Path(path).resolve()
    if source == output or output in source.parents:
        raise ExtractionError("The input package cannot be inside the output directory")
    with open(source, 'rb') as f:
        info = inspect_stream(f)
        eboot = next((i for i in info.items if i.path.casefold() == 'usrdir/content/eboot.pbp'), None)
        pkg2zip_layout = False
        game_title = info.title_id or 'PSP'
        if eboot and eboot.size >= 0x28:
            signature = decrypt_at(f, info.header, eboot.data_offset, 4, eboot.key)
            pkg2zip_layout = signature == b'\0PBP'
        sfo = next((i for i in info.items if i.path.casefold() == 'param.sfo'), None)
        if pkg2zip_layout and sfo:
            title_data = decrypt_at(f, info.header, sfo.data_offset, sfo.size, sfo.key)
            game_title = sfo_title(title_data) or game_title
        if format == "iso" and not any(i.path.casefold().endswith(('.iso', '.cso')) for i in info.items):
            raise ExtractionError("This PKG has no standalone ISO/CSO entry; converting embedded EBOOT.PBP/NPUMDIMG requires PSP-specific conversion")
        def selected(item):
            if not baseline:
                return True
            p = item.path.casefold()
            return p.endswith(('.iso', '.cso')) or p.endswith('/content.dat') or p.endswith('/psp-key.edat') or p.endswith('/eboot.pbp')

        selected_items = tuple(i for i in info.items if selected(i))
        for item in selected_items:
            if _license(item.path):
                raise ExtractionError(f"Refusing to create or modify a license file: {item.path}")
        _check_destination(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Build an inventory before copying or writing anything.
        existing = {}
        if output.exists():
            for root, dirs, files in os.walk(output):
                for name in dirs + files:
                    p = Path(root) / name
                    rel = p.relative_to(output).as_posix()
                    key = path_identity(rel)
                    if key in existing:
                        raise ExtractionError(f"Ambiguous existing path: {rel}")
                    existing[key] = (rel, p.is_dir())
        for item in selected_items:
            parts = item.path.split('/')
            for n in range(1, len(parts) + 1):
                rel = '/'.join(parts[:n])
                prior = existing.get(path_identity(rel))
                if prior:
                    is_dir = n < len(parts) or item.is_directory
                    if prior != (rel, is_dir):
                        raise ExtractionError(f"Destination path conflict: {rel}")
                    if not is_dir and not force:
                        raise ExtractionError(f"File exists (use --force): {output / rel}")
        stage = Path(tempfile.mkdtemp(prefix=f'.{output.name}.stage-', dir=output.parent))
        backup = None
        try:
            if output.exists():
                shutil.copytree(output, stage, dirs_exist_ok=True)
            for item in info.items:
                if format == "iso" and not item.path.casefold().endswith(('.iso', '.cso')):
                    continue
                if format == "eboot" and item.path.casefold().endswith(('.iso', '.cso')):
                    continue
                relative = item.path
                if pkg2zip_layout:
                    lower = item.path.casefold()
                    if lower == 'usrdir/content/eboot.pbp':
                        relative = f'pspemu/ISO/{game_title} [{info.title_id}].iso'
                    elif lower == 'usrdir/content/content.dat':
                        relative = f'pspemu/PSP/GAME/{info.title_id}/CONTENT.DAT'
                    elif lower == 'usrdir/content/psp-key.edat':
                        relative = f'pspemu/PSP/GAME/{info.title_id}/PSP-KEY.EDAT'
                    else:
                        continue
                target = stage / relative
                if item.is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if pkg2zip_layout and item is eboot:
                    payload = decrypt_at(f, info.header, item.data_offset, item.size, item.key)
                    target.write_bytes(eboot_to_iso(payload))
                elif pkg2zip_layout and item.path.casefold() == 'usrdir/content/psp-key.edat':
                    # pkg2zip unwraps the 0x190-byte PGD structure even for
                    # fixtures whose item length omits the trailing aligned
                    # bytes; those bytes remain inside the encrypted region.
                    payload_size = max(item.size, 0x190)
                    payload = decrypt_at(f, info.header, item.data_offset, payload_size, item.key)
                    target.write_bytes(extract_psp_key(payload))
                else:
                    with target.open('wb') as dest:
                        for offset in range(0, item.size, 64 * 1024):
                            size = min(64 * 1024, item.size - offset)
                            dest.write(decrypt_at(f, info.header, item.data_offset + offset, size, item.key))
            _check_destination(output)
            if output.exists():
                backup = output.parent / f'.{output.name}.backup-{uuid.uuid4().hex}'
                output.rename(backup)
            try:
                stage.rename(output)
            except BaseException:
                if backup is not None:
                    backup.rename(output)
                    backup = None
                raise
            if backup is not None:
                shutil.rmtree(backup)
                backup = None
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        return ExtractionResult(info, output, tuple(output / i.path for i in selected_items), info.total_bytes)
