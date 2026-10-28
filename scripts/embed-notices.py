#!/usr/bin/env python3
"""Collect the target's dependency notices before building a release executable."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MAX_NOTICES = 16 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('package_linux', ROOT / 'scripts/package-linux.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    metadata = json.loads(subprocess.check_output([
        'cargo', 'metadata', '--locked', '--format-version', '1', '--filter-platform', args.target,
    ], cwd=ROOT))
    application = next(p for p in metadata['packages']
                       if Path(p['manifest_path']).resolve() == ROOT / 'Cargo.toml')
    destination = Path(metadata['target_directory']) / 'embedded-notices' / args.target
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination) as temporary:
        bundle = Path(temporary)
        package.collect_notices(metadata, application, bundle)
        manifest = bundle / 'THIRD-PARTY.json'
        catalog = json.loads(manifest.read_text(encoding='utf-8'))
        catalog['target'] = args.target
        catalog['description'] = f'{args.target} resolved Cargo packages and their dependency notices.'
        package.write_json(manifest, catalog)
        for name in ('LICENSE', 'NOTICE'):
            package.copy_file(ROOT / name, bundle / name)
        output = bytearray()
        for path in sorted(bundle.rglob('*')):
            if not path.is_file():
                continue
            output.extend(f'\n===== {path.relative_to(bundle).as_posix()} =====\n'.encode())
            output.extend(path.read_bytes())
            if len(output) > MAX_NOTICES:
                raise ValueError('Embedded notices exceed the updater budget')
        # The About viewer displays exact Unicode text, never lossy replacements.
        output.decode('utf-8')
        notices = destination / 'notices.txt'
        notices.write_bytes(output)
    print(notices)


if __name__ == '__main__':
    main()
