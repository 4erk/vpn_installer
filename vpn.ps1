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
$RuntimeLogDir = Join-Path $RepoRoot 'out\logs\runtime'
$TranscriptStarted = $false
$TranscriptPath = Join-Path $RuntimeLogDir 'latest-transcript.log'

function Show-VpnHelp {
  @'
Использование:
  .\vpn.cmd
  .\vpn.cmd --version
  .\vpn.cmd install
  .\vpn.cmd status --deployment home-vpn

Основные команды:
  install, status, admin, verify live, diagnose, routes,
  reinstall, maintain, remove, purge, cleanup-local, audit

Если запустить без аргументов:
  откроется пошаговое меню с действиями:
  - Установить или обновить VPN
  - Проверить текущее состояние
  - Показать адрес web-admin для двойной схемы
  - Переустановить
  - Удалить с серверов
  - Полная очистка
  - Локальная очистка
  - Самопроверка

Что нужно заранее:
  - один российский или зарубежный сервер для одиночной схемы
  - российский и зарубежный серверы для двойной схемы
  - Ubuntu 24.04 и публичный IPv4 у каждого используемого сервера
  - SSH-доступ по ключу или паролю
  - любой клиент с поддержкой VLESS/Reality

После успешной установки:
  - простой VLESS URI сохранится локально и станет основным профилем
  - будет попытка скопировать URI в буфер обмена
  - появится файл NEXT-STEPS.txt с дальнейшими шагами
  - Список команд: docs\COMMANDS.md
  - Как выбрать серверы: docs\PROVIDERS.md
  - Что внутри проекта: docs\PROJECT.md

Подсказка:
  Enter в вопросах с дефолтом оставляет текущее значение.
  При ошибке подробный лог сохраняется в out\logs\runtime\latest-error.log
  Публичная точка входа Windows: .\vpn.cmd. vpn.ps1 является внутренним bootstrap-файлом.
'@ | Write-Host
}

function Start-VpnTranscript {
  try {
    New-Item -ItemType Directory -Path $RuntimeLogDir -Force | Out-Null
    Start-Transcript -LiteralPath $TranscriptPath -Force | Out-Null
    $script:TranscriptStarted = $true
  } catch {
    $script:TranscriptStarted = $false
  }
}

function Stop-VpnTranscript {
  if (-not $script:TranscriptStarted) {
    return
  }
  try {
    Stop-Transcript | Out-Null
  } catch {
  } finally {
    $script:TranscriptStarted = $false
  }
}

function Write-VpnErrorLog {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Context,
    [Parameter(Mandatory = $true)]
    [object]$ErrorObject
  )

  try {
    New-Item -ItemType Directory -Path $RuntimeLogDir -Force | Out-Null
    $Stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssffffZ')
    $LogPath = Join-Path $RuntimeLogDir "error-$Stamp-powershell.log"
    $LatestPath = Join-Path $RuntimeLogDir 'latest-error.log'
    $Message = if ($ErrorObject.Exception) { $ErrorObject.Exception.Message } else { [string]$ErrorObject }
    $Detail = @(
      "timestamp_utc: $([DateTime]::UtcNow.ToString('o'))"
      "context: $Context"
      "cwd: $RepoRoot"
      "powershell_version: $($PSVersionTable.PSVersion)"
      "script: $PSCommandPath"
      "message: $Message"
      ""
      "details:"
      ($ErrorObject | Out-String).TrimEnd()
      ""
    ) -join [Environment]::NewLine
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($LogPath, $Detail, $Utf8NoBom)
    [System.IO.File]::WriteAllText($LatestPath, $Detail, $Utf8NoBom)
    return $LogPath
  } catch {
    return $null
  }
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

Start-VpnTranscript

try {
  if (-not $env:VPN_WINDOWS_ENTRYPOINT) {
    Write-Warning "vpn.ps1 является внутренним bootstrap-файлом. Для штатного Windows-запуска используй .\vpn.cmd."
  }
  if ($ScriptArgs.Count -gt 0 -and $ScriptArgs[0] -in @('--help', '-h', 'help')) {
    Show-VpnHelp
  } else {
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
    } elseif ($ExitCode -eq 130) {
      Write-Host ""
      Write-Host "Операция отменена пользователем." -ForegroundColor Yellow
    } else {
      Write-Host ""
      Write-Host "Команда завершилась с ошибкой (код $ExitCode)." -ForegroundColor Red
      Write-Host "Проверь сообщение выше. Обычно дальше помогает:" -ForegroundColor Yellow
      Write-Host "  .\vpn.cmd status --deployment <имя>"
    }
  }
} catch {
  $ExitCode = 1
  $LogPath = Write-VpnErrorLog -Context 'powershell-launcher' -ErrorObject $_
  $Message = [string]$_.Exception.Message
  $ShortMessage = $Message -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
  if ([string]::IsNullOrWhiteSpace($ShortMessage)) {
    $ShortMessage = $_.Exception.GetType().Name
  } elseif ($ShortMessage.Length -gt 240) {
    $ShortMessage = $ShortMessage.Substring(0, 237).TrimEnd() + '...'
  }
  Write-Host ""
  Write-Host "Запуск завершился с ошибкой: $ShortMessage" -ForegroundColor Red
  if ($LogPath) {
    Write-Host "Подробности сохранены в: $LogPath" -ForegroundColor Yellow
  }
  Write-Host "Проверь сообщение выше и затем попробуй снова через .\vpn.cmd." -ForegroundColor Yellow
} finally {
  Stop-VpnTranscript
  if (-not $env:VPN_NO_PAUSE -and -not $env:VPN_WINDOWS_ENTRYPOINT) {
    Write-Host ""
    Read-Host "Нажми Enter, чтобы закрыть окно" | Out-Null
  }
}

exit $ExitCode
