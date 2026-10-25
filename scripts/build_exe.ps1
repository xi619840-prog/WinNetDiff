[CmdletBinding()]
param(
    [string]$Python = '',
    [string]$OutputDirectory = '',
    [switch]$NoInstall,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$venvPython = Join-Path $root '.build-venv\Scripts\python.exe'
Push-Location -LiteralPath $root
try {
    if (-not $Python) {
        if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
            & py -3 -m venv (Join-Path $root '.build-venv')
            if ($LASTEXITCODE -ne 0) { throw 'Could not create isolated build environment.' }
        }
        $Python = $venvPython
    }
    if (-not $NoInstall) {
        & $Python -m pip install --disable-pip-version-check --index-url https://pypi.org/simple -r (Join-Path $root 'requirements-build.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Build dependency installation failed.' }
    }
    & $Python scripts\build_standalone.py --check
    if ($LASTEXITCODE -ne 0) { throw 'Regenerate the standalone source before building.' }
    if (-not $SkipTests) {
        & $Python -m unittest discover -s tests -v
        if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed.' }
        & $Python windows_net_diffdiag.py --self-test
        if ($LASTEXITCODE -ne 0) { throw 'Embedded self-test failed.' }
    }
    & $Python scripts\publication_audit.py
    if ($LASTEXITCODE -ne 0) { throw 'Publication audit failed.' }
    $dist = if ($OutputDirectory) { [System.IO.Path]::GetFullPath($OutputDirectory) } else { Join-Path $root 'dist' }
    $work = Join-Path $root '.build'
    if ((Test-Path -LiteralPath $dist) -and @(Get-ChildItem -LiteralPath $dist -Force).Count) { throw 'Choose a new empty candidate output directory; existing assets are never overwritten.' }
    New-Item -ItemType Directory -Force -Path $dist, $work | Out-Null
    foreach ($mode in @('gui', 'cli')) {
        $name = if ($mode -eq 'gui') { 'WinNetDiff' } else { 'WinNetDiff-CLI' }
        $windowOption = if ($mode -eq 'gui') { '--windowed' } else { '--console' }
        & $Python -m PyInstaller --noconfirm --clean --onefile --noupx $windowOption --name $name --distpath $dist --workpath (Join-Path $work $mode) --specpath $work windows_net_diffdiag.py
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller $mode build failed." }
    }
    Copy-Item -LiteralPath @('windows_net_diffdiag.py','LICENSE','README.md','README.zh-CN.md','README.zh-TW.md','CHANGELOG.md','PRIVACY.md','SECURITY.md','CONTRIBUTING.md','THIRD_PARTY_NOTICES.md','release-gate.json') -Destination $dist
    Copy-Item -LiteralPath docs -Destination $dist -Recurse -Force
    Copy-Item -LiteralPath third_party\TCL_LICENSE.txt, third_party\TK_LICENSE.txt -Destination $dist -Force
    $noticeSource = & $Python -c "import sys; from pathlib import Path; p=Path(sys.base_prefix); print(next((str(x) for x in [p/'LICENSE.txt',p/'LICENSE',p/'Doc'/'license.rst'] if x.is_file()), ''))"
    if ($LASTEXITCODE -ne 0) { throw 'Python notice lookup failed.' }
    if ($noticeSource) {
        Copy-Item -LiteralPath $noticeSource -Destination (Join-Path $dist 'PYTHON_LICENSE.txt') -Force
    } else {
        throw 'Python license notice not found; review interpreter distribution notices before publishing.'
    }
    $buildInfo = @'
import datetime,hashlib,importlib.metadata,json,platform,sys
from pathlib import Path
names=['pyinstaller','pyinstaller-hooks-contrib','setuptools','altgraph','packaging','pefile','pywin32-ctypes']
data={'project':'WinNetDiff','author':'Alden','built_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'python':platform.python_version(),'platform':platform.platform(),'source_sha256':hashlib.sha256(Path('windows_net_diffdiag.py').read_bytes()).hexdigest(),'build_dependencies':{n:importlib.metadata.version(n) for n in names},'code_signed':False,'clean_vm_validated':False,'candidate_only':True,'formal_release_ready':False}
(Path(sys.argv[1])/'BUILD_INFO.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
'@
    & $Python -c $buildInfo $dist
    if ($LASTEXITCODE -ne 0) { throw 'Build manifest generation failed.' }
    & $Python scripts\checksums.py $dist --write
    if ($LASTEXITCODE -ne 0) { throw 'SHA256SUMS generation failed.' }
    & $Python scripts\checksums.py $dist --verify
    if ($LASTEXITCODE -ne 0) { throw 'SHA256SUMS verification failed.' }
    Write-Host "Unsigned Windows artifacts and SHA-256 checksums: $dist"
}
finally {
    Pop-Location
}
