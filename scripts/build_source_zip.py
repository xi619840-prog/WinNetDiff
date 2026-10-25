"""Create an exclusive, deterministic source-only archive after local preflight."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import zipfile
from publication_audit import audit, proposed_files
from build_standalone import build_source

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    standalone = ROOT / 'windows_net_diffdiag.py'
    if not standalone.is_file() or standalone.read_text(encoding='utf-8') != build_source():
        parser.error('Standalone source is stale or missing; regenerate it before packaging.')
    _, errors = audit(ROOT)
    if errors:
        for error in errors:
            print(error)
        return 1
    paths = list(proposed_files(ROOT))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    checksum = args.output.with_suffix('.sha256')
    if args.output.exists() or checksum.exists():
        parser.error('Archive or checksum already exists; choose a new output name.')
    with zipfile.ZipFile(args.output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in paths:
            entry = zipfile.ZipInfo('WinNetDiff/' + path.relative_to(ROOT).as_posix(), (2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, path.read_bytes())
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    with checksum.open('x', encoding='utf-8') as stream:
        stream.write(digest + '  ' + args.output.name + '\n')
    print(f'{len(paths)} source files; SHA-256 {digest}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
