param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$ScriptArgs
)

$ErrorActionPreference = 'Stop'

Write-Host "Подсказка: основной вход теперь через .\\vpn.ps1."
$ForwardArgs = if ($ScriptArgs.Count -eq 0) { @('help') } else { $ScriptArgs }
& (Join-Path $PSScriptRoot 'vpn.ps1') @($ForwardArgs)
exit $LASTEXITCODE
