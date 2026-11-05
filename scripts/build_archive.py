"""Build and verify a standalone tooling archive without generated files."""
from pathlib import Path
import sys
import gzip
import tarfile

root = Path(__file__).resolve().parents[1]
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
files = [root / name for name in ('README.md', 'AGENTS.md', 'pyproject.toml', 'uv.lock')]
for folder in ('keycloak', 'tests', 'tests_tools', 'scripts'):
    files.extend(p for p in (root / folder).rglob('*')
                 if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
expected = {p.relative_to(root).as_posix(): p for p in files}
archive_path = output / 'controlplane-keycloak.tar.gz'
with archive_path.open('wb') as output_file, gzip.GzipFile(filename='', mode='wb', fileobj=output_file, mtime=0) as compressed:
    with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, path in sorted(expected.items()):
            info = archive.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = 0
            with path.open('rb') as source:
                archive.addfile(info, source)
with tarfile.open(archive_path) as archive:
    members = archive.getmembers()
    assert len(members) == len(expected) and {m.name for m in members} == set(expected)
    for member in members:
        path = expected[member.name]
        assert member.isfile() and archive.extractfile(member).read() == path.read_bytes()
        assert member.mode == path.stat().st_mode & 0o777
    archive.extractall(output / 'extracted', filter='data')
print(f'Verified {len(expected)} archive files and modes')
