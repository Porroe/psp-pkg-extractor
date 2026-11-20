from pathlib import Path
import subprocess
import sys
import os
import pytest
from psp_pkg_extractor import extract_pkg, ExtractionError, InvalidPackageError


def test_both_keys_and_files(pkg_factory, tmp_path):
    entries = [('USRDIR',b'',0x90,4), ('USRDIR/CONTENT.DAT',b'data',0x90,1),
               ('PARAM.SFO',b'sfo',0x80,3), ('ICON0.PNG',b'png',0x80,1),
               ('PIC0.PNG',b'picture',0x90,1), ('PSP-KEY.EDAT',b'opaque',0x90,1),
               ('GAME.ISO',b'plain iso bytes',0x90,1), ('empty',b'',0x90,1)]
    path = pkg_factory(entries)
    result = extract_pkg(path,tmp_path/'out')
    assert result.total_bytes == sum(len(e[1]) for e in entries)
    for name, data, _, flags in entries:
        target = result.output / name
        if flags == 4:
            assert target.is_dir()
        else:
            assert target.read_bytes() == data


def test_force_and_preserve_unrelated(pkg_factory, tmp_path):
    path = pkg_factory([('file',b'new',0x90,1)])
    output = tmp_path/'out'
    output.mkdir()
    (output/'file').write_bytes(b'old')
    (output/'unrelated').write_bytes(b'keep')
    with pytest.raises(ExtractionError):
        extract_pkg(path,output)
    assert (output/'file').read_bytes() == b'old'
    extract_pkg(path,output,force=True)
    assert (output/'file').read_bytes() == b'new'
    assert (output/'unrelated').read_bytes() == b'keep'
    assert not list(tmp_path.glob('.out.*'))


def test_staging_failure_preserves_output(pkg_factory, tmp_path, monkeypatch):
    import psp_pkg_extractor.extractor as module
    path = pkg_factory()
    output = tmp_path/'out'
    output.mkdir()
    (output/'keep').write_text('old')
    def fail(*args):
        raise OSError('simulated read failure')
    monkeypatch.setattr(module, 'decrypt_at', fail)
    with pytest.raises(OSError):
        extract_pkg(path,output)
    assert list(output.iterdir()) == [output/'keep']
    assert not list(tmp_path.glob('.out.*'))


def test_publish_failure_rolls_back(pkg_factory,tmp_path,monkeypatch):
    path = pkg_factory()
    output = tmp_path/'out'
    output.mkdir()
    (output/'keep').write_text('old')
    original = Path.rename
    def rename(self, target):
        if '.stage-' in self.name:
            raise OSError('simulated publish failure')
        return original(self,target)
    monkeypatch.setattr(Path,'rename',rename)
    with pytest.raises(OSError):
        extract_pkg(path,output)
    assert (output/'keep').read_text() == 'old'
    assert not list(tmp_path.glob('.out.*'))


def test_no_output_for_invalid_package(pkg_factory,tmp_path):
    path = pkg_factory([('../escape',b'x',0x90,1)])
    with pytest.raises(InvalidPackageError):
        extract_pkg(path,tmp_path/'out')
    assert not (tmp_path/'out').exists()


@pytest.mark.parametrize('name',['work.bin','a/license.dat','a/x.rif','a/x.rap'])
def test_no_license_writes(pkg_factory,tmp_path,name):
    with pytest.raises(ExtractionError):
        extract_pkg(pkg_factory([(name,b'x',0x90,1)]),tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_symlink_destination(pkg_factory,tmp_path):
    target = tmp_path/'target'
    target.mkdir()
    link = tmp_path/'out'
    try:
        link.symlink_to(target,target_is_directory=True)
    except OSError:
        pytest.skip('Symlinks unavailable')
    with pytest.raises(ExtractionError):
        extract_pkg(pkg_factory(),link,force=True)
    assert not list(target.iterdir())


def test_cli(pkg_factory,tmp_path):
    package = pkg_factory()
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]/'src'))
    inspect = subprocess.run([sys.executable,'-m','psp_pkg_extractor','inspect',str(package)],env=env,capture_output=True,text=True)
    assert inspect.returncode == 0
    assert 'Content ID:' in inspect.stdout
    assert 'Item count: 1' in inspect.stdout
    result = subprocess.run([sys.executable,'-m','psp_pkg_extractor','extract',str(package),'--output',str(tmp_path/'out')],env=env,capture_output=True,text=True)
    assert result.returncode == 0
    assert 'Total extracted bytes:' in result.stdout
    error = subprocess.run([sys.executable,'-m','psp_pkg_extractor','inspect',str(tmp_path/'absent')],env=env,capture_output=True,text=True)
    assert error.returncode == 1 and 'error:' in error.stderr


def test_output_formats(pkg_factory, tmp_path):
    package = pkg_factory([('GAME.ISO', b'iso-bytes', 0x90, 3),
                           ('USRDIR/CONTENT/EBOOT.PBP', b'eboot-bytes', 0x90, 6)])
    iso = extract_pkg(package, tmp_path/'iso', format='iso')
    assert (iso.output/'GAME.ISO').read_bytes() == b'iso-bytes'
    eboot = extract_pkg(package, tmp_path/'eboot', format='eboot')
    assert (eboot.output/'USRDIR/CONTENT/EBOOT.PBP').read_bytes() == b'eboot-bytes'


def test_iso_format_rejects_embedded_pbp(pkg_factory, tmp_path):
    with pytest.raises(ExtractionError, match='standalone ISO'):
        extract_pkg(pkg_factory([('USRDIR/CONTENT/EBOOT.PBP', b'eboot', 0x90, 6)]),
                    tmp_path/'iso', format='iso')




@pytest.mark.parametrize('selector',[0,0x10,0x80,0x90])
@pytest.mark.parametrize('flags',[1,2,3,5,8,11])
def test_known_payloads_preserved(pkg_factory,tmp_path,selector,flags):
    payload = b'opaque payload bytes'
    result = extract_pkg(pkg_factory([('payload',payload,selector,flags)]),tmp_path/'out')
    assert (result.output/'payload').read_bytes() == payload


def test_streaming_across_chunk_boundary(pkg_factory,tmp_path):
    payload = bytes(range(256)) * 257
    result = extract_pkg(pkg_factory([('large',payload,0x90,3)]),tmp_path/'out')
    assert (result.output/'large').read_bytes() == payload


@pytest.mark.parametrize('prior,incoming',[('file','file/child'),('dir/child','dir'),('Name','name')])
def test_existing_path_conflict(pkg_factory,tmp_path,prior,incoming):
    output = tmp_path/'out'
    old = output/prior
    old.parent.mkdir(parents=True)
    old.write_bytes(b'old')
    with pytest.raises(ExtractionError):
        extract_pkg(pkg_factory([(incoming,b'new',0x90,3)]),output,force=True)
    assert old.read_bytes() == b'old'
