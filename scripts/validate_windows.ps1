[CmdletBinding()]
param([switch]$SkipNetwork, [string]$OutputDirectory = '')
$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root ('.local_validation\acceptance_' + (Get-Date -Format yyyyMMdd_HHmmss))
}
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$oldEncoding = $env:PYTHONIOENCODING
$oldRedteamSource = $env:WINNETDIFF_SOURCE
$checks = New-Object System.Collections.Generic.List[object]
function Invoke-Check([string]$Name, [string[]]$Arguments) {
    $log = Join-Path $output ($Name + '.log')
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & py -3 @Arguments 2>&1 | ForEach-Object { "$_" } | Out-File -LiteralPath $log -Encoding utf8
    $code = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    $checks.Add([pscustomobject]@{name=$Name; exit_code=$code; log=$log})
    Write-Host "$Name exit=$code"
}
Push-Location -LiteralPath $root
try {
    $env:PYTHONIOENCODING = 'utf-8'
    $env:WINNETDIFF_SOURCE = Join-Path $root 'windows_net_diffdiag.py'
    Invoke-Check 'standalone_check' @('scripts\build_standalone.py','--check')
    Invoke-Check 'unit' @('-m','unittest','discover','-s','tests','-v')
    Invoke-Check 'independent_redteam' @('tests\regression\test_winnetdiff_redteam_v2.py')
    Invoke-Check 'self_test' @('windows_net_diffdiag.py','--self-test')
    Invoke-Check 'publication_audit' @('scripts\publication_audit.py')
    foreach ($locale in @('en','zh-CN','zh-TW')) {
        Invoke-Check ('offline_' + $locale) @('windows_net_diffdiag.py','--cli','--lang',$locale,'--no-network','--json',(Join-Path $output ('offline_' + $locale + '.json')))
    }
    if (-not $SkipNetwork) {
        Invoke-Check 'network' @('windows_net_diffdiag.py','--cli','--lang','en','--json',(Join-Path $output 'network.json'))
    }
    [ordered]@{generated_at=(Get-Date).ToString('o'); powershell=$PSVersionTable.PSVersion.ToString(); checks=$checks.ToArray(); scope='Read-only CLI checks and simulated unit tests. No repair, UAC, driver changes or physical disconnection.'} | ConvertTo-Json -Depth 6 | Out-File -LiteralPath (Join-Path $output 'summary.json') -Encoding utf8
    if (@($checks | Where-Object {$_.exit_code -ne 0}).Count) { exit 1 }
}
finally {
    if ($null -eq $oldEncoding) { Remove-Item Env:\PYTHONIOENCODING -ErrorAction SilentlyContinue } else { $env:PYTHONIOENCODING = $oldEncoding }
    if ($null -eq $oldRedteamSource) { Remove-Item Env:\WINNETDIFF_SOURCE -ErrorAction SilentlyContinue } else { $env:WINNETDIFF_SOURCE = $oldRedteamSource }
    Pop-Location
}
