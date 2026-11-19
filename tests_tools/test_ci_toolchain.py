"""Toolchain download double: corrupt bytes must never reach extraction or PATH."""
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_corrupt_maven_download_is_removed_without_extracting(tmp_path):
    commands = tmp_path / 'commands'; commands.mkdir()
    curl = commands / 'curl'
    curl.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output ]; then printf corrupt > "$2"; exit 0; fi
  shift
done
exit 1
''')
    curl.chmod(0o755)
    tar = commands / 'tar'
    tar.write_text('#!/bin/sh\ntouch "$RUNNER_TEMP/unsafe-extraction"\n')
    tar.chmod(0o755)
    path_output = tmp_path / 'path-output'; path_output.write_text('existing\n')
    result = subprocess.run(['bash', str(ROOT / 'scripts/install-maven.sh')],
        env={**os.environ, 'PATH': str(commands) + os.pathsep + os.environ['PATH'],
             'RUNNER_TEMP': str(tmp_path), 'GITHUB_PATH': str(path_output)},
        capture_output=True, text=True)
    assert result.returncode != 0
    assert not (tmp_path / 'unsafe-extraction').exists()
    assert path_output.read_text() == 'existing\n'
    assert not list(tmp_path.glob('maven.*.tar.gz'))
