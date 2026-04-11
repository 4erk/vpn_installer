param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$ScriptArgs
)

$ErrorActionPreference = 'Stop'

Write-Host "Подсказка: основной вход теперь через .\\vpn.ps1. Запускаю режим install."
& (Join-Path $PSScriptRoot 'vpn.ps1') install @($ScriptArgs)
exit $LASTEXITCODE
