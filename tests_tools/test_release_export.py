import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

spec = importlib.util.spec_from_file_location('exporter', Path(__file__).resolve().parents[1]/'scripts/export_release_contract.py')
exporter = importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)


def archive(path, change=None):
    files = {'pyproject.toml': b'[project]\nname="controlplane-keycloak-checks"\nversion="0.24.0"\n', 'keycloak/admin_endpoint.py': b'raise RuntimeError("must not execute")\n', 'keycloak/import/controlplane-realm.json': b'{}\n'}
    if change == 'missing': files.pop('keycloak/import/controlplane-realm.json')
    if change == 'identity': files['pyproject.toml'] = files['pyproject.toml'].replace(b'controlplane-keycloak-checks', b'wrong')
    if change == 'version': files['pyproject.toml'] = files['pyproject.toml'].replace(b'0.24.0', b'0.24.0rc1')
    if change == 'unsafe': files['keycloak/../escape'] = b'bad'
    if change == 'extra': files['unknown.py'] = b'bad'
    if change == 'runtime': files['keycloak/admin_endpoint.py'] += b'# change\n'
    with tarfile.open(path, 'w:gz') as z:
        for name, data in files.items():
            m=tarfile.TarInfo(name);m.size=len(data);m.mode=0o644
            if change == 'mode' and name.startswith('keycloak/'): m.mode=0o755
            if change == 'link' and name.startswith('keycloak/'): m.type=tarfile.SYMTYPE;m.linkname='/tmp/escape';m.size=0
            z.addfile(m, io.BytesIO(data))
        if change == 'duplicate':
            m=tarfile.TarInfo('keycloak/admin_endpoint.py');z.addfile(m)
    return path


def test_export_inspects_without_execution_and_covers_bytes_and_modes(tmp_path):
    original,_=exporter.snapshot(archive(tmp_path/'one.tar.gz'))
    for change in ['runtime','mode']:
        other,_=exporter.snapshot(archive(tmp_path/(change+'.tar.gz'),change));assert original != other


@pytest.mark.parametrize('change',['missing','identity','version','unsafe','extra','link','duplicate'])
def test_invalid_archive_rejected(tmp_path,change):
    with pytest.raises(ValueError): exporter.snapshot(archive(tmp_path/'bad.tar.gz',change))
