"""Inspect the actual Keycloak tooling archive without executing admin code."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib


def snapshot(path):
    raw = Path(path).read_bytes()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)) or any(not m.isfile() or m.name.startswith('/') or '..' in PurePosixPath(m.name).parts for m in members):
            raise ValueError('Unsafe or duplicate archive member')
        if any(n not in {'LICENSE', 'README.md', 'AGENTS.md', 'pyproject.toml', 'uv.lock'} and not n.startswith(('keycloak/', 'tests/', 'tests_tools/', 'scripts/')) for n in names):
            raise ValueError('Unexpected tooling archive contents')
        if not {'pyproject.toml', 'keycloak/import/controlplane-realm.json', 'keycloak/admin_endpoint.py'} <= set(names):
            raise ValueError('Missing tooling identity or realm')
        project = tomllib.loads(archive.extractfile('pyproject.toml').read().decode())['project']
        version = project['version']
        if project['name'] != 'controlplane-keycloak-checks' or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
            raise ValueError('Invalid tooling identity or version')
        files = {m.name: {'sha256': hashlib.sha256(archive.extractfile(m).read()).hexdigest(), 'mode': m.mode} for m in members if m.name.startswith('keycloak/')}
    encoded = (json.dumps({'schema_version': 1, 'coverage': 'complete Keycloak realm and reconciliation runtime bytes and modes; live realm acceptance is separate', 'packaged_files': files}, sort_keys=True, indent=2)+'\n').encode()
    return encoded, {'schema_version': 1, 'version': version, 'artifact_sha256': hashlib.sha256(raw).hexdigest(), 'contract_sha256': hashlib.sha256(encoded).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); contract, evidence = snapshot(args.archive)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'contract.json').write_bytes(contract)
    (args.output/'evidence.json').write_text(json.dumps(evidence, sort_keys=True, indent=2)+'\n')
