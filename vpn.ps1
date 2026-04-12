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
$ExitCode = 0

function Show-VpnHelp {
  @'
Использование:
  powershell -ExecutionPolicy Bypass -File .\vpn.ps1
  powershell -ExecutionPolicy Bypass -File .\vpn.ps1 install
  powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment my-vpn
  powershell -ExecutionPolicy Bypass -File .\vpn.ps1 reinstall --deployment my-vpn --role ru-gateway

Если запустить без аргументов:
  откроется пошаговое меню с действиями:
  - Установить или обновить VPN
  - Проверить текущее состояние
  - Переустановить
  - Удалить с серверов
  - Полная очистка
  - Локальная очистка
  - Самопроверка

Что нужно заранее:
  - 2 VPS на Ubuntu 24.04
  - публичный IPv4 у каждого
  - SSH-доступ по ключу или паролю
  - установленный Hiddify на устройстве клиента

После успешной установки:
  - URI для Hiddify сохранится локально
  - будет попытка скопировать URI в буфер обмена
  - появится файл NEXT-STEPS.txt с дальнейшими шагами

Подсказка:
  Enter в вопросах с дефолтом оставляет текущее значение.
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

try {
  if ($ScriptArgs.Count -gt 0 -and $ScriptArgs[0] -in @('--help', '-h', 'help')) {
    Show-VpnHelp
    exit 0
  }

  $EffectiveArgs = @($ScriptArgs)
  $PythonCommand = Resolve-Python
  $LauncherPath = Join-Path $RepoRoot 'vpn_installer\launcher.py'
  $CommandLine = @($PythonCommand) + @($LauncherPath) + @($EffectiveArgs)
  if ($CommandLine.Count -le 1) {
    throw "Внутренняя ошибка launcher: пустая команда запуска Python."
  }
  & $CommandLine[0] @($CommandLine[1..($CommandLine.Count - 1)])
  $ExitCode = $LASTEXITCODE

  if ($ExitCode -eq 0) {
    Write-Host ""
    Write-Host "Команда завершена."
  } else {
    Write-Host ""
    Write-Host "Команда завершилась с ошибкой (код $ExitCode)." -ForegroundColor Red
    Write-Host "Проверь сообщение выше. Обычно дальше помогает:" -ForegroundColor Yellow
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\vpn.ps1 status --deployment <имя>"
  }
} catch {
  $ExitCode = 1
  Write-Host ""
  Write-Host "Запуск завершился с ошибкой: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "Проверь сообщение выше и затем попробуй снова через .\vpn.ps1." -ForegroundColor Yellow
} finally {
  if (-not $env:VPN_NO_PAUSE) {
    Write-Host ""
    Read-Host "Нажми Enter, чтобы закрыть окно" | Out-Null
  }
}

exit $ExitCode
