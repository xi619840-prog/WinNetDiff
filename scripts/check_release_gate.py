"""Stop release workflows until controlled Windows evidence is reviewed."""
import json
import ast
import hashlib
from pathlib import Path
import re
import sys
from build_standalone import build_source


def main():
    root = Path(__file__).resolve().parents[1]
    gate = json.loads((root / 'release-gate.json').read_text(encoding='utf-8'))
    tree = ast.parse((root / 'winnetdiff/core/models.py').read_text(encoding='utf-8'))
    version = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'VERSION' for target in node.targets))
    package_version = re.search(r'^version\s*=\s*"([^"]+)"', (root / 'pyproject.toml').read_text(encoding='utf-8'), re.M)[1]
    source = (root / 'windows_net_diffdiag.py').read_text(encoding='utf-8')
    digest = hashlib.sha256(source.encode('utf-8')).hexdigest()
    if (gate.get('version') != version or package_version != version or source != build_source() or
            gate.get('reviewed_standalone_sha256') != digest or
            gate.get('formal_release_ready') is not True or
            gate.get('windows_controlled_proxy_write_restore') != 'verified' or
            gate.get('clean_windows11_vm_exe_smoke') != 'verified'):
        print('FORMAL RELEASE BLOCKED: controlled proxy restoration and clean Windows VM evidence are incomplete.')
        return 1
    print('Release gate approved; consult the referenced validation evidence.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
