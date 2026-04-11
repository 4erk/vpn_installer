param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$ScriptArgs
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$RuntimeRoot = Join-Path $RepoRoot '.runtime'
$PythonRoot = Join-Path $RuntimeRoot 'python\windows'
$PortablePython = Join-Path $PythonRoot 'python.exe'
$PortableVersion = if ($env:VPN_BOOTSTRAP_PYTHON_VERSION) { $env:VPN_BOOTSTRAP_PYTHON_VERSION } else { '3.13.13' }

function Show-BootstrapHelp {
  @'
Использование:
  powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
  powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1 --deployment my-vpn

Что делает bootstrap:
  1. Выбирает существующий deployment или создаёт новый
  2. Запрашивает RU и Foreign SSH-подключения
  3. Проверяет SSH, ОС, права sudo/root и текущее состояние обоих серверов
  4. Собирает локальные артефакты
  5. Выполняет install/reinstall/remove/purge по выбранным ролям

Что нужно заранее:
  - 2 VPS на Ubuntu 24.04
  - публичный IPv4 у каждого
  - рабочий SSH-доступ по ключу

Если Python на Windows не установлен:
  bootstrap сам подтянет portable runtime в .runtime\python\windows
'@ | Write-Host
}

function Test-PythonExe {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,
    [string[]]$PrefixArgs = @()
  )

  try {
    $Output = & $Executable @PrefixArgs -c "import sys; assert sys.version_info >= (3, 9); print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $Output) {
      return $true
    }
  } catch {
    return $false
  }

  return $false
}

function Enable-PortablePythonSite {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root
  )

  $Pth = Get-ChildItem -LiteralPath $Root -Filter 'python*._pth' | Select-Object -First 1
  if (-not $Pth) {
    throw "Не найден python*._pth в portable runtime."
  }

  $Updated = foreach ($Line in (Get-Content -LiteralPath $Pth.FullName)) {
    if ($Line -match '^\s*#\s*import site\s*$') {
      'import site'
    } else {
      $Line
    }
  }

  $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($Pth.FullName, $Updated, $Utf8NoBom)
}

function Install-PortablePython {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$Root
  )

  if (Test-Path -LiteralPath $Root) {
    Remove-Item -LiteralPath $Root -Recurse -Force
  }

  $DownloadDir = Join-Path $RuntimeRoot 'downloads'
  New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
  New-Item -ItemType Directory -Path $Root -Force | Out-Null

  $Arch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'win32' }
  $ArchiveName = "python-$Version-embeddable-$Arch.zip"
  $ArchivePath = Join-Path $DownloadDir $ArchiveName
  $Url = if ($env:VPN_BOOTSTRAP_PYTHON_URL) {
    $env:VPN_BOOTSTRAP_PYTHON_URL
  } else {
    "https://www.python.org/ftp/python/$Version/$ArchiveName"
  }

  Write-Host "Локальный Python не найден, загружаю portable runtime: $Url"
  Invoke-WebRequest -Uri $Url -OutFile $ArchivePath
  Expand-Archive -LiteralPath $ArchivePath -DestinationPath $Root -Force
  Enable-PortablePythonSite -Root $Root

  if (-not (Test-Path -LiteralPath (Join-Path $Root 'python.exe'))) {
    throw "Portable Python установился некорректно."
  }
}

function Resolve-Python {
  if (Test-Path -LiteralPath $PortablePython) {
    if (Test-PythonExe -Executable $PortablePython) {
      return @($PortablePython)
    }
  }

  if (Get-Command py -ErrorAction SilentlyContinue) {
    if (Test-PythonExe -Executable 'py' -PrefixArgs @('-3')) {
      return @('py', '-3')
    }
  }

  if (Get-Command python -ErrorAction SilentlyContinue) {
    if (Test-PythonExe -Executable 'python') {
      return @('python')
    }
  }

  Install-PortablePython -Version $PortableVersion -Root $PythonRoot
  if (-not (Test-PythonExe -Executable $PortablePython)) {
    throw "Не удалось запустить portable Python."
  }

  return @($PortablePython)
}

$PythonCommand = Resolve-Python
$ScriptPath = Join-Path $RepoRoot 'scripts\orchestrate.py'

if ($ScriptArgs.Count -gt 0 -and $ScriptArgs[0] -in @('--help', '-h', 'help')) {
  Show-BootstrapHelp
  exit 0
}

& $PythonCommand $ScriptPath bootstrap @ScriptArgs
exit $LASTEXITCODE
