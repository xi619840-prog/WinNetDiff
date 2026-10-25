"""Write and strictly verify portable SHA256SUMS filenames and contents."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import re


def checksum_files(root: Path, manifest: str):
    base = root.resolve()
    files = []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path == root/manifest:
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(base):
            raise ValueError('Artifact path escapes root')
        name = path.relative_to(root).as_posix()
        if name != name.strip() or '\n' in name or '\r' in name or '\\' in name:
            raise ValueError('Unsupported checksum filename')
        files.append((name, path))
    return files


def write_checksums(root: Path, manifest='SHA256SUMS.txt'):
    entries = checksum_files(root, manifest)
    if not entries:
        raise ValueError('No artifact files')
    text = ''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+name+'\n' for name,path in entries)
    with (root/manifest).open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(text)
    return len(entries)


def verify_checksums(root: Path, manifest='SHA256SUMS.txt'):
    base = root.resolve()
    actual = dict(checksum_files(root, manifest))
    listed = {}
    for line in (root/manifest).read_text(encoding='utf-8-sig').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('Invalid SHA256SUMS line')
        digest,name = match.groups()
        path = root/name
        if (name in listed or name.casefold() in {n.casefold() for n in listed} or name != name.strip() or
                '\\' in name or Path(name).is_absolute() or '..' in Path(name).parts or
                not path.resolve().is_relative_to(base) or name not in actual):
            raise ValueError('Duplicate, missing or unsafe checksum filename')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('SHA-256 mismatch: '+name)
        listed[name] = digest
    if not listed or set(listed) != set(actual):
        raise ValueError('Checksum manifest does not match the complete artifact set')
    return len(listed)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write',action='store_true');mode.add_argument('--verify',action='store_true')
    args=parser.parse_args()
    try:
        count=write_checksums(args.directory) if args.write else verify_checksums(args.directory)
    except (OSError,ValueError) as exc:
        parser.exit(1,str(exc)+'\n')
    print(f'SHA-256: {count} files '+('written' if args.write else 'verified'))


if __name__=='__main__':
    main()
