param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$ScriptArgs
)

$ErrorActionPreference = 'Stop'

Write-Host "Подсказка: основной вход теперь через .\\vpn.ps1 audit."
& (Join-Path $PSScriptRoot 'vpn.ps1') audit @($ScriptArgs)
exit $LASTEXITCODE
