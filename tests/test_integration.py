"""Opt-in reference hashes; packages and manifests stay outside this repo."""
import hashlib
import json
import os
from pathlib import Path
import pytest
from psp_pkg_extractor import extract_pkg
from psp_pkg_extractor.format import safe_path


def test_local_reference_hashes(tmp_path):
    configured = os.environ.get('PSP_PKG_FIXTURES')
    if not configured:
        pytest.skip('Set PSP_PKG_FIXTURES for local integration tests')
    root = Path(configured)
    manifest = json.loads((root/'manifest.json').read_text(encoding='utf-8'))
    assert manifest, 'manifest.json must contain package/hash mappings'
    for index, (package, hashes) in enumerate(manifest.items()):
        safe_path(package)
        assert hashes, f'{package}: missing reference hashes'
        result = extract_pkg(root/package,tmp_path/str(index))
        actual_paths = {i.path for i in result.info.items if not i.is_directory}
        assert actual_paths == set(hashes), f'{package}: reference file set differs'
        for rel, expected in hashes.items():
            safe_path(rel)
            digest = hashlib.sha256()
            with (result.output/rel).open('rb') as f:
                for chunk in iter(lambda: f.read(1024*1024),b''):
                    digest.update(chunk)
            assert digest.hexdigest() == expected.lower(), f'{package}: {rel}'
