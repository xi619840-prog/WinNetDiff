#!/usr/bin/env python3
"""Fail closed on obvious private material among files proposed for publication.

This is a bounded local preflight, not a complete secrets detector. Git-tracked
and non-ignored new files are checked. No file content is sent anywhere.
"""
from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {'.git', '.local_validation', '.build-venv', '.venv', 'venv',
                  '.build', 'build', 'dist', 'release', '__pycache__', '.pytest_cache'}
TEXT_SUFFIXES = {'.py', '.md', '.txt', '.json', '.toml', '.yml', '.yaml', '.ps1', '.cmd', '.csv'}
PRIVATE_PARTS = {'validation', 'results', 'repairs', 'snapshots', 'private', '.local_validation',
                 '.build-venv', '.venv', 'venv', '.build', 'build', 'dist', 'release', '__pycache__'}
FORBIDDEN_SUFFIXES = {'.log', '.etl', '.dmp', '.exe', '.dll', '.pyd', '.pyc', '.zip'}
SECRET_PATTERNS = (
    re.compile(r'gh[pousr]_[A-Za-z0-9_]{25,}'),
    re.compile(r'github_pat_[A-Za-z0-9_]{35,}'),
    re.compile(r'(?i)(?:api[_-]?key|access[_-]?token|password)\s*[=:]\s*["\'](?!<|example|test|fake|synthetic|redacted|password|secret)[A-Za-z0-9_+/=-]{24,}["\']'),
    re.compile(r'S-1-5-21-(?:\d{5,}-){2,}\d{3,}'),
)


def proposed_files(root: Path):
    try:
        result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                                cwd=root, capture_output=True, check=False)
    except OSError:
        result = None
    git_inventory = result is not None and result.returncode == 0
    if git_inventory:
        paths = [root / os.fsdecode(name) for name in result.stdout.split(b'\0') if name]
    else:
        paths = list(root.rglob('*'))
    for path in sorted(set(paths)):
        # A mistakenly tracked ignored directory must still fail. Only the
        # filesystem fallback prunes development output before enumeration.
        excluded = any(part in EXCLUDED_PARTS for part in path.relative_to(root).parts)
        if path.is_file() and (git_inventory or not excluded):
            yield path


def audit(root: Path, additional_patterns=()):
    errors = []
    user_marker = os.environ.get('USERNAME') or os.environ.get('USER') or ''
    personal_markers = list(additional_patterns)
    if len(user_marker) >= 4 and user_marker.lower() not in {'runner', 'runneradmin', 'root', 'user', 'administrator'}:
        personal_markers.append(re.escape(user_marker))
    count = 0
    candidates = list(proposed_files(root))
    candidate_names = {path.relative_to(root).as_posix() for path in candidates}
    builder = root / 'scripts' / 'build_standalone.py'
    if builder.is_file():
        try:
            manifest = ast.parse(builder.read_text(encoding='utf-8'))
            for node in manifest.body:
                if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets):
                    for module in ast.literal_eval(node.value):
                        required = 'winnetdiff/' + module + '.py'
                        if required not in candidate_names:
                            errors.append(required + ': required runtime module is missing from proposed source files')
        except (OSError, SyntaxError, ValueError, TypeError):
            errors.append('scripts/build_standalone.py: cannot verify runtime module manifest')
    for path in candidates:
        count += 1
        relative = path.relative_to(root)
        name = relative.as_posix()
        if relative.parts[0].lower() in PRIVATE_PARTS or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f'{name}: private evidence or binary artifact is included')
            continue
        if path.stat().st_size > 3_000_000:
            errors.append(f'{name}: file exceeds 3 MB source-review limit')
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {'LICENSE', '.gitignore'}:
            continue
        raw = path.read_bytes()
        text = None
        for encoding in ('utf-8-sig', 'cp936'):
            try:
                text = raw.decode(encoding)
                break
            except UnicodeError:
                pass
        if text is None:
            errors.append(f'{name}: unrecognized text encoding')
            continue
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f'{name}: potential secret or device identifier; inspect locally')
                break
        for pattern in personal_markers:
            if re.search(pattern, text, re.I):
                errors.append(f'{name}: personal marker detected; inspect locally')
                break
        # Synthetic test/example fixtures may intentionally exercise profile paths.
        synthetic = relative.parts[0] in {'tests', 'examples'}
        if not synthetic and re.search(r'(?i)[A-Z]:[\\/]+Users[\\/]+(?!<|Public[\\/]|Default[\\/]|example[\\/]|TestUser[\\/])[^\\/\r\n"\']+', text):
            errors.append(f'{name}: concrete personal profile path detected')
        if path.suffix.lower() == '.py':
            try:
                ast.parse(text, filename=name)
            except SyntaxError as exc:
                errors.append(f'{name}:{exc.lineno}: Python syntax error')
    return count, errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--deny-pattern', action='append', default=[], help='additional local regex; never prints matched private values')
    args = parser.parse_args(argv)
    count, errors = audit(args.root.resolve(), args.deny_pattern)
    for error in errors:
        print(error, file=sys.stderr)
    print(f'Publication audit: {count} files, {len(errors)} findings. Manual review is still required.')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
