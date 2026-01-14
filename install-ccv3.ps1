# ============================================================
# CCv3 Installer v2.0 - Global Install + Project Scanner
# ============================================================
# Instalator CCv3 z automatyczna migracja CCv2/KFG
#
# Flow:
#   1. Sprawdza/instaluje zaleznosci (git, python, node, docker, uv, claude)
#   2. Instaluje hooki globalnie do ~/.claude/ (raz)
#   3. Pyta o folder projektow (np. D:\Projekty)
#   4. Skanuje wszystkie podfoldery i wykrywa CCv2/CCv3
#   5. Migruje CCv2->CCv3 gdzie potrzeba
#   6. Raport koncowy
#
# Uzycie:
#   powershell -ExecutionPolicy Bypass -File install-ccv3.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$Version = "2.0.0"

# ============================================================
# KOLORY I HELPER FUNCTIONS
# ============================================================

# Globalne zmienne do sledzenia wynikow
$script:Stats = @{
    ProjectsScanned = 0
    CCv2Found = 0
    CCv3Found = 0
    CleanFound = 0
    Migrated = 0
    OpcCloned = 0
    Skipped = 0
    Errors = @()
}

function Write-Banner {
    Write-Host ""
    Write-Host "  +===========================================================+" -ForegroundColor Cyan
    Write-Host "  |           CCv3 Installer v$Version                          |" -ForegroundColor Cyan
    Write-Host "  |     Global Install + Project Scanner + Auto-Migration     |" -ForegroundColor Cyan
    Write-Host "  +===========================================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Step, [string]$Description)
    Write-Host ""
    Write-Host "  [$Step] $Description" -ForegroundColor Yellow
    Write-Host "  -------------------------------------------------------------" -ForegroundColor DarkGray
}

function Write-OK {
    param([string]$Message)
    Write-Host "    [OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "    ⚠ $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "    [X] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "    [-] $Message" -ForegroundColor Cyan
}

function Ask-User {
    param([string]$Question)
    Write-Host ""
    Write-Host "    $Question" -ForegroundColor White -NoNewline
    Write-Host " [T/n] " -ForegroundColor Gray -NoNewline
    $response = Read-Host
    return ($response -eq "" -or $response -eq "T" -or $response -eq "t" -or $response -eq "Y" -or $response -eq "y")
}

function Wait-ForKey {
    Write-Host ""
    Write-Host "    Nacisnij dowolny klawisz aby kontynuowac..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================
# KFG/CCv2 DETECTION & CLEANUP
# ============================================================

function Test-KFGInstallation {
    $indicators = @()

    # Check for KFG/CCv2 indicators
    if (Test-Path "logs\CONTINUITY.md") { $indicators += "logs/CONTINUITY.md" }
    if (Test-Path "logs\STATE.md") { $indicators += "logs/STATE.md" }
    if (Test-Path "VALIDATION.md") { $indicators += "VALIDATION.md" }
    if (Test-Path ".log-file-genius") { $indicators += ".log-file-genius/" }

    # Check for old hooks in user profile
    $oldHooks = @(
        "$env:USERPROFILE\.claude\hooks\pre-compact.ps1",
        "$env:USERPROFILE\.claude\hooks\session-start-continuity.ps1",
        "$env:USERPROFILE\.claude\hooks\pre-compact-continuity.sh"
    )
    foreach ($hook in $oldHooks) {
        if (Test-Path $hook) { $indicators += "Old hook: $(Split-Path -Leaf $hook)" }
    }

    return $indicators
}

function Archive-KFGFiles {
    $archiveDir = "_archive_ccv2_$(Get-Date -Format 'yyyy-MM-dd')"

    Write-Info "Tworzenie archiwum: $archiveDir"
    New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null

    # Archive logs/
    if (Test-Path "logs") {
        Move-Item -Path "logs" -Destination "$archiveDir\logs" -Force
        Write-OK "Zarchiwizowano: logs/ -> $archiveDir/logs/"
    }

    # Archive VALIDATION*.md
    Get-ChildItem -Path "." -Filter "VALIDATION*.md" | ForEach-Object {
        Move-Item -Path $_.FullName -Destination "$archiveDir\" -Force
        Write-OK "Zarchiwizowano: $($_.Name)"
    }

    # Archive .log-file-genius
    if (Test-Path ".log-file-genius") {
        Move-Item -Path ".log-file-genius" -Destination "$archiveDir\.log-file-genius" -Force
        Write-OK "Zarchiwizowano: .log-file-genius/"
    }

    return $archiveDir
}

function Remove-OldHooks {
    $oldHookPatterns = @(
        "pre-compact.ps1",
        "pre-compact.sh",
        "session-start-continuity.ps1",
        "session-start-continuity.sh",
        "pre-compact-continuity.sh",
        "post-tool-use-tracker.sh"
    )

    $hooksDir = "$env:USERPROFILE\.claude\hooks"
    $removed = 0

    if (Test-Path $hooksDir) {
        foreach ($pattern in $oldHookPatterns) {
            $hookPath = Join-Path $hooksDir $pattern
            if (Test-Path $hookPath) {
                Remove-Item -Path $hookPath -Force
                Write-OK "Usunieto stary hook: $pattern"
                $removed++
            }
        }
    }

    return $removed
}

# ============================================================
# DETEKCJA TYPU PROJEKTU I SKANOWANIE
# ============================================================

function Get-ProjectType {
    param([string]$ProjectPath)

    # CCv3 indicators (ma opc/ lub thoughts/shared/handoffs/)
    if ((Test-Path "$ProjectPath\opc") -or (Test-Path "$ProjectPath\thoughts\shared\handoffs")) {
        return "CCv3"
    }

    # CCv2/KFG indicators
    $ccv2Indicators = @(
        "$ProjectPath\logs\CONTINUITY.md",
        "$ProjectPath\logs\STATE.md",
        "$ProjectPath\VALIDATION.md",
        "$ProjectPath\.log-file-genius"
    )

    foreach ($indicator in $ccv2Indicators) {
        if (Test-Path $indicator) {
            return "CCv2"
        }
    }

    # Clean project (no CC indicators)
    return "Clean"
}

function Test-IsProject {
    param([string]$FolderPath)

    # Projekt = ma .git/ LUB package.json LUB pyproject.toml LUB Cargo.toml
    $projectIndicators = @(
        "$FolderPath\.git",
        "$FolderPath\package.json",
        "$FolderPath\pyproject.toml",
        "$FolderPath\Cargo.toml",
        "$FolderPath\go.mod",
        "$FolderPath\pom.xml",
        "$FolderPath\build.gradle",
        "$FolderPath\*.sln"
    )

    foreach ($indicator in $projectIndicators) {
        if (Test-Path $indicator) {
            return $true
        }
    }

    return $false
}

function Scan-ProjectsFolder {
    param([string]$RootPath)

    $projects = @()

    # Pobierz wszystkie podfoldery (1 poziom)
    $subfolders = Get-ChildItem -Path $RootPath -Directory -ErrorAction SilentlyContinue

    foreach ($folder in $subfolders) {
        # Pomin ukryte foldery i systemowe
        if ($folder.Name.StartsWith(".") -or $folder.Name -eq "node_modules" -or $folder.Name -eq "__pycache__") {
            continue
        }

        if (Test-IsProject $folder.FullName) {
            $type = Get-ProjectType $folder.FullName
            $projects += @{
                Name = $folder.Name
                Path = $folder.FullName
                Type = $type
            }
        }
    }

    return $projects
}

function Migrate-CCv2Project {
    param([string]$ProjectPath, [string]$ProjectName)

    $result = @{
        Success = $false
        Archived = $false
        Message = ""
    }

    try {
        $archiveDir = "$ProjectPath\_archive_ccv2_$(Get-Date -Format 'yyyy-MM-dd')"

        # Archiwizuj logs/
        if (Test-Path "$ProjectPath\logs") {
            New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
            Move-Item -Path "$ProjectPath\logs" -Destination "$archiveDir\logs" -Force
            $result.Archived = $true
        }

        # Archiwizuj VALIDATION*.md
        Get-ChildItem -Path $ProjectPath -Filter "VALIDATION*.md" -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not (Test-Path $archiveDir)) {
                New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
            }
            Move-Item -Path $_.FullName -Destination "$archiveDir\" -Force
        }

        # Archiwizuj .log-file-genius
        if (Test-Path "$ProjectPath\.log-file-genius") {
            if (-not (Test-Path $archiveDir)) {
                New-Item -ItemType Directory -Path $archiveDir -Force | Out-Null
            }
            Move-Item -Path "$ProjectPath\.log-file-genius" -Destination "$archiveDir\.log-file-genius" -Force
        }

        $result.Success = $true
        $result.Message = if ($result.Archived) { "Zarchiwizowano do $archiveDir" } else { "Brak plikow do archiwizacji" }

    } catch {
        $result.Success = $false
        $result.Message = "Blad: $_"
    }

    return $result
}

function Clone-OpcToProject {
    param([string]$ProjectPath)

    $opcPath = "$ProjectPath\opc"

    if (Test-Path $opcPath) {
        return @{ Success = $true; Message = "opc/ juz istnieje" }
    }

    try {
        Push-Location $ProjectPath

        # Probuj oficjalne repo
        git clone https://github.com/parcadei/Continuous-Claude-v3.git opc 2>&1 | Out-Null
        if (Test-Path $opcPath) {
            Pop-Location
            return @{ Success = $true; Message = "Sklonowano z oficjalnego repo" }
        }

        # Probuj mirror
        git clone https://github.com/kmylpenter/Continuous-Claude-v3-Mirror.git opc 2>&1 | Out-Null
        if (Test-Path $opcPath) {
            Pop-Location
            return @{ Success = $true; Message = "Sklonowano z mirror" }
        }

        Pop-Location
        return @{ Success = $false; Message = "Nie udalo sie sklonowac" }

    } catch {
        Pop-Location
        return @{ Success = $false; Message = "Blad: $_" }
    }
}

# ============================================================
# SPRAWDZANIE ZALEZNOSCI
# ============================================================

function Test-Command {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-VersionNumber {
    param([string]$VersionString)
    # Wyciaga numer wersji z outputu (np. "Python 3.12.1" -> "3.12.1")
    if ($VersionString -match '(\d+\.\d+\.?\d*)') {
        return $Matches[1]
    }
    return $null
}

function Test-VersionMinimum {
    param([string]$Current, [string]$Minimum)
    try {
        $currentParts = $Current.Split('.') | ForEach-Object { [int]$_ }
        $minimumParts = $Minimum.Split('.') | ForEach-Object { [int]$_ }

        for ($i = 0; $i -lt [Math]::Max($currentParts.Count, $minimumParts.Count); $i++) {
            $c = if ($i -lt $currentParts.Count) { $currentParts[$i] } else { 0 }
            $m = if ($i -lt $minimumParts.Count) { $minimumParts[$i] } else { 0 }

            if ($c -gt $m) { return $true }
            if ($c -lt $m) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Check-Dependency {
    param(
        [string]$Name,
        [string]$Command,
        [string]$MinVersion,
        [string]$WingetPackage,
        [string]$AltInstall,
        [string]$VersionFlag = "--version"
    )

    $result = @{
        Name = $Name
        Installed = $false
        Version = $null
        VersionOK = $false
        WingetPackage = $WingetPackage
        AltInstall = $AltInstall
    }

    if (Test-Command $Command) {
        $result.Installed = $true
        try {
            $output = & $Command $VersionFlag 2>&1 | Out-String
            $result.Version = Get-VersionNumber $output
            if ($MinVersion -and $result.Version) {
                $result.VersionOK = Test-VersionMinimum $result.Version $MinVersion
            } else {
                $result.VersionOK = $true
            }
        } catch {
            $result.VersionOK = $true  # Jesli nie mozna sprawdzic, zakladamy OK
        }
    }

    return $result
}

function Install-WithWinget {
    param([string]$Package, [string]$Name)

    Write-Info "Instaluje $Name przez winget..."
    Write-Host ""

    try {
        $process = Start-Process -FilePath "winget" -ArgumentList "install", "--id", $Package, "-e", "--accept-source-agreements", "--accept-package-agreements" -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-OK "$Name zainstalowany pomyslnie"
            Write-Warning "WAZNE: Zamknij i otworz nowy terminal aby zmiany PATH zostaly zaladowane!"
            return $true
        } else {
            Write-Error-Custom "Blad instalacji $Name (kod: $($process.ExitCode))"
            return $false
        }
    } catch {
        Write-Error-Custom "Nie mozna uruchomic winget: $_"
        return $false
    }
}

function Install-WithPip {
    param([string]$Package, [string]$Name)

    Write-Info "Instaluje $Name przez pip..."

    try {
        & pip install $Package 2>&1 | Out-Null
        Write-OK "$Name zainstalowany pomyslnie"
        return $true
    } catch {
        Write-Error-Custom "Blad instalacji ${Name}: $_"
        return $false
    }
}

# ============================================================
# GLOWNA LOGIKA
# ============================================================

Write-Banner

# ============================================================
# KROK 1: SPRAWDZENIE ZALEZNOSCI
# ============================================================

Write-Step "1/6" "Sprawdzanie wymaganych zaleznosci"

$dependencies = @(
    @{
        Name = "Git"
        Command = "git"
        MinVersion = $null
        WingetPackage = "Git.Git"
        AltInstall = $null
    },
    @{
        Name = "Python"
        Command = "python"
        MinVersion = "3.11"
        WingetPackage = "Python.Python.3.12"
        AltInstall = $null
    },
    @{
        Name = "Node.js"
        Command = "node"
        MinVersion = "18"
        WingetPackage = "OpenJS.NodeJS.LTS"
        AltInstall = $null
    },
    @{
        Name = "Docker"
        Command = "docker"
        MinVersion = $null
        WingetPackage = "Docker.DockerDesktop"
        AltInstall = $null
    },
    @{
        Name = "uv"
        Command = "uv"
        MinVersion = $null
        WingetPackage = $null
        AltInstall = "pip install uv"
    },
    @{
        Name = "Claude Code"
        Command = "claude"
        MinVersion = $null
        WingetPackage = $null
        AltInstall = "npm install -g @anthropic-ai/claude-code"
    }
)

$missing = @()
$needsRestart = $false

foreach ($dep in $dependencies) {
    $check = Check-Dependency -Name $dep.Name -Command $dep.Command -MinVersion $dep.MinVersion -WingetPackage $dep.WingetPackage -AltInstall $dep.AltInstall

    if ($check.Installed) {
        if ($check.VersionOK) {
            $versionInfo = if ($check.Version) { "v$($check.Version)" } else { "OK" }
            Write-OK "$($dep.Name): $versionInfo"
        } else {
            Write-Warning "$($dep.Name): v$($check.Version) - wymagane $($dep.MinVersion)+"
            $missing += $check
        }
    } else {
        Write-Error-Custom "$($dep.Name): NIE ZNALEZIONO"
        $missing += $check
    }
}

# ============================================================
# KROK 2: INSTALACJA BRAKUJACYCH
# ============================================================

if ($missing.Count -gt 0) {
    Write-Step "2/6" "Instalacja brakujacych pakietow"

    Write-Host ""
    Write-Host "    Brakujace pakiety:" -ForegroundColor White
    foreach ($m in $missing) {
        Write-Host "      - $($m.Name)" -ForegroundColor Red
    }

    if (Ask-User "Czy chcesz zainstalowac brakujace pakiety?") {
        foreach ($m in $missing) {
            Write-Host ""
            Write-Host "    Instalacja: $($m.Name)" -ForegroundColor Cyan

            $installed = $false

            # Najpierw probuj winget
            if ($m.WingetPackage -and (Test-Command "winget")) {
                $installed = Install-WithWinget -Package $m.WingetPackage -Name $m.Name
                if ($installed) { $needsRestart = $true }
            }

            # Jesli nie winget, probuj alternatywna metode
            if (-not $installed -and $m.AltInstall) {
                Write-Info "Probuje alternatywna metode: $($m.AltInstall)"
                try {
                    Invoke-Expression $m.AltInstall 2>&1 | Out-Null
                    Write-OK "$($m.Name) zainstalowany"
                    $installed = $true
                } catch {
                    Write-Error-Custom "Blad: $_"
                }
            }

            if (-not $installed) {
                Write-Error-Custom "Nie udalo sie zainstalowac $($m.Name)"
                Write-Host ""
                Write-Host "    Instrukcja recznej instalacji:" -ForegroundColor Yellow

                switch ($m.Name) {
                    "Git" {
                        Write-Host "      1. Pobierz: https://git-scm.com/download/win" -ForegroundColor Gray
                        Write-Host "      2. Zainstaluj z domyslnymi opcjami" -ForegroundColor Gray
                    }
                    "Python" {
                        Write-Host "      1. Pobierz: https://www.python.org/downloads/" -ForegroundColor Gray
                        Write-Host "      2. WAZNE: Zaznacz 'Add Python to PATH' podczas instalacji!" -ForegroundColor Gray
                    }
                    "Node.js" {
                        Write-Host "      1. Pobierz: https://nodejs.org/en/download/" -ForegroundColor Gray
                        Write-Host "      2. Wybierz wersje LTS" -ForegroundColor Gray
                    }
                    "Docker" {
                        Write-Host "      1. Pobierz: https://www.docker.com/products/docker-desktop/" -ForegroundColor Gray
                        Write-Host "      2. Zainstaluj Docker Desktop" -ForegroundColor Gray
                        Write-Host "      3. Uruchom i poczekaj az ikona bedzie zielona" -ForegroundColor Gray
                    }
                    "uv" {
                        Write-Host "      Uruchom: pip install uv" -ForegroundColor Gray
                    }
                    "Claude Code" {
                        Write-Host "      Uruchom: npm install -g @anthropic-ai/claude-code" -ForegroundColor Gray
                    }
                }
                Write-Host ""
            }
        }

        if ($needsRestart) {
            Write-Host ""
            Write-Host "  +===========================================================+" -ForegroundColor Yellow
            Write-Host "  |  WAZNE: Zainstalowano nowe pakiety!                       |" -ForegroundColor Yellow
            Write-Host "  |                                                           |" -ForegroundColor Yellow
            Write-Host "  |  1. ZAMKNIJ ten terminal                                  |" -ForegroundColor Yellow
            Write-Host "  |  2. Otworz NOWY terminal (PowerShell/cmd)                 |" -ForegroundColor Yellow
            Write-Host "  |  3. Uruchom ponownie ten instalator                       |" -ForegroundColor Yellow
            Write-Host "  +===========================================================+" -ForegroundColor Yellow
            Write-Host ""
            exit 0
        }
    } else {
        Write-Host ""
        Write-Error-Custom "Instalacja przerwana - brakuje wymaganych pakietow"
        exit 1
    }
} else {
    Write-Step "2/6" "Wszystkie zaleznosci spelnione - pomijam instalacje"
    Write-OK "Wszystkie wymagane pakiety sa zainstalowane"
}

# ============================================================
# KROK 3: SPRAWDZENIE HYPER-V I DOCKER
# ============================================================

Write-Step "3/6" "Sprawdzanie wirtualizacji i Docker Desktop"

# Sprawdz Hyper-V przed Docker
$hyperVEnabled = $false
try {
    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
        $hyperVEnabled = $true
        Write-OK "Hyper-V jest wlaczony"
    }
} catch {}

if (-not $hyperVEnabled) {
    # Sprawdz czy wirtualizacja jest wspierana
    $vmSupport = (Get-CimInstance -ClassName Win32_Processor).VMMonitorModeExtensions

    Write-Warning "Hyper-V nie jest wlaczony!"
    Write-Host ""
    Write-Host "    Docker Desktop wymaga Hyper-V do dzialania." -ForegroundColor White
    Write-Host ""

    if ($vmSupport) {
        Write-Host "    Wirtualizacja CPU: OK (wspierana)" -ForegroundColor Green
        Write-Host ""

        # Sprawdz czy uruchomiono jako Administrator
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdmin) {
            if (Ask-User "Czy chcesz teraz wlaczyc Hyper-V? (wymaga restartu)") {
                Write-Host ""
                Write-Info "Wlaczam Hyper-V..."

                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart | Out-Null
                    Write-OK "Hyper-V wlaczony"
                } catch {
                    Write-Warning "Nie udalo sie wlaczyc Hyper-V: $_"
                }

                try {
                    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart | Out-Null
                    Write-OK "Virtual Machine Platform wlaczony"
                } catch {
                    Write-Warning "Nie udalo sie wlaczyc VirtualMachinePlatform: $_"
                }

                Write-Host ""
                Write-Host "  +===========================================================+" -ForegroundColor Yellow
                Write-Host "  |  Hyper-V zostal wlaczony - wymagany RESTART komputera!    |" -ForegroundColor Yellow
                Write-Host "  |                                                           |" -ForegroundColor Yellow
                Write-Host "  |  Po restarcie uruchom instalator ponownie.                |" -ForegroundColor Yellow
                Write-Host "  +===========================================================+" -ForegroundColor Yellow
                Write-Host ""

                if (Ask-User "Czy chcesz teraz zrestartowac komputer?") {
                    Write-Info "Restartuje komputer za 5 sekund..."
                    Start-Sleep -Seconds 5
                    Restart-Computer -Force
                } else {
                    Write-Info "Zrestartuj komputer recznie i uruchom instalator ponownie."
                    exit 0
                }
            }
        } else {
            Write-Warning "Instalator nie jest uruchomiony jako Administrator!"
            Write-Host ""
            Write-Host "    Aby automatycznie wlaczyc Hyper-V:" -ForegroundColor Yellow
            Write-Host "      1. Zamknij ten terminal" -ForegroundColor Gray
            Write-Host "      2. Kliknij prawym na PowerShell -> Uruchom jako administrator" -ForegroundColor Gray
            Write-Host "      3. Uruchom instalator ponownie" -ForegroundColor Gray
            Write-Host ""
            Write-Host "    Lub recznie wlacz Hyper-V:" -ForegroundColor Yellow
            Write-Host "      Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart" -ForegroundColor Cyan
            Write-Host "      Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart" -ForegroundColor Cyan
            Write-Host "      Restart-Computer" -ForegroundColor Cyan
        }
    } else {
        Write-Error-Custom "Wirtualizacja CPU NIE jest wspierana lub wylaczona w BIOS!"
        Write-Host ""
        Write-Host "    Sprawdz ustawienia BIOS:" -ForegroundColor Yellow
        Write-Host "      1. Uruchom ponownie komputer" -ForegroundColor Gray
        Write-Host "      2. Wejdz do BIOS (F2/F10/Del przy starcie)" -ForegroundColor Gray
        Write-Host "      3. Znajdz: Intel VT-x / AMD-V / SVM Mode" -ForegroundColor Gray
        Write-Host "      4. Wlacz -> Zapisz -> Restart" -ForegroundColor Gray
    }

    Write-Host ""
    if (-not (Ask-User "Czy chcesz kontynuowac bez Docker? (CCv3 zadziala, ale bez kontenerow)")) {
        Write-Host ""
        Write-Info "Wlacz Hyper-V, zrestartuj komputer i uruchom instalator ponownie."
        exit 0
    }

    Write-Warning "Kontynuuje bez Docker - niektore funkcje CCv3 beda niedostepne"
    $skipDocker = $true
} else {
    $skipDocker = $false
}

# Sprawdz i zaktualizuj WSL (jesli Hyper-V OK)
if (-not $skipDocker) {
    Write-Host ""
    Write-Info "Sprawdzam WSL..."

    $wslInstalled = $false
    $wslNeedsUpdate = $false

    try {
        $wslVersion = wsl --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $wslInstalled = $true
            Write-OK "WSL zainstalowany"
        }
    } catch {}

    if (-not $wslInstalled) {
        Write-Warning "WSL nie jest zainstalowany lub wymaga aktualizacji"

        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdmin) {
            if (Ask-User "Czy chcesz zainstalowac/zaktualizowac WSL?") {
                Write-Info "Aktualizuje WSL..."
                try {
                    wsl --update 2>&1 | Out-Null
                    Write-OK "WSL zaktualizowany"

                    # Ustaw WSL2 jako domyslny
                    wsl --set-default-version 2 2>&1 | Out-Null
                    Write-OK "WSL2 ustawiony jako domyslny"
                } catch {
                    Write-Warning "Nie udalo sie zaktualizowac WSL: $_"
                    Write-Host "    Sprobuj recznie: wsl --update" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host ""
            Write-Host "    Aby zaktualizowac WSL, uruchom jako Administrator:" -ForegroundColor Yellow
            Write-Host "      wsl --update" -ForegroundColor Cyan
            Write-Host "      wsl --set-default-version 2" -ForegroundColor Cyan
        }
    }
}

# Sprawdz Docker (jesli Hyper-V OK)
if (-not $skipDocker) {
    $dockerRunning = $false
    try {
        $dockerPs = docker ps 2>&1
        if ($LASTEXITCODE -eq 0) {
            $dockerRunning = $true
            Write-OK "Docker Desktop dziala"
        }
    } catch {}

    if (-not $dockerRunning) {
        Write-Warning "Docker Desktop nie jest uruchomiony!"
        Write-Host ""
        Write-Host "    Instrukcja:" -ForegroundColor White
        Write-Host "      1. Uruchom Docker Desktop z menu Start" -ForegroundColor Gray
        Write-Host "      2. Poczekaj az ikona w tray bedzie ZIELONA" -ForegroundColor Gray
        Write-Host "      3. Moze to zajac 1-2 minuty" -ForegroundColor Gray
        Write-Host ""

        Write-Host "    Czy Docker Desktop jest juz uruchomiony? [T/n] " -ForegroundColor White -NoNewline

        $maxAttempts = 30
        $attempt = 0

        while (-not $dockerRunning -and $attempt -lt $maxAttempts) {
            $response = Read-Host

            if ($response -eq "n" -or $response -eq "N") {
                Write-Info "Uruchom Docker Desktop i wcisnij Enter gdy bedzie gotowy..."
                Read-Host | Out-Null
            }

            try {
                $null = docker ps 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $dockerRunning = $true
                    Write-OK "Docker Desktop dziala!"
                } else {
                    Write-Warning "Docker jeszcze nie gotowy, czekam..."
                    Start-Sleep -Seconds 3
                    $attempt++
                }
            } catch {
                Write-Warning "Docker jeszcze nie gotowy, czekam..."
                Start-Sleep -Seconds 3
                $attempt++
            }
        }

        if (-not $dockerRunning) {
            Write-Error-Custom "Nie mozna polaczyc z Docker. Uruchom Docker Desktop i sprobuj ponownie."
            exit 1
        }
    }
} else {
    Write-Info "Pomijam sprawdzanie Docker (Hyper-V niedostepny)"
}

# ============================================================
# KROK 4: GLOBALNA INSTALACJA HOOKOW CCv3
# ============================================================

Write-Step "4/6" "Globalna instalacja hookow CCv3"

$claudeDir = "$env:USERPROFILE\.claude"
$hooksDir = "$claudeDir\hooks"

# Sprawdz czy hooki CCv3 juz sa zainstalowane
$ccv3HooksInstalled = Test-Path "$hooksDir\ccv3-pre-compact.ps1" -or Test-Path "$hooksDir\pre-compact.sh"

if ($ccv3HooksInstalled) {
    Write-OK "Hooki CCv3 juz zainstalowane w ~/.claude/hooks/"
    Write-Info "Pomijam reinstalacje globalnych hookow"
} else {
    # Usun stare hooki KFG/CCv2
    $removed = Remove-OldHooks
    if ($removed -gt 0) {
        Write-OK "Usunieto $removed starych hookow KFG/CCv2"
    }

    # Utworz strukture folderow
    if (-not (Test-Path $hooksDir)) {
        New-Item -ItemType Directory -Path $hooksDir -Force | Out-Null
        Write-OK "Utworzono folder ~/.claude/hooks/"
    }

    # Klonuj CCv3 tymczasowo zeby skopiowac hooki
    $tempDir = "$env:TEMP\ccv3-hooks-$(Get-Date -Format 'yyyyMMddHHmmss')"
    Write-Info "Pobieram hooki CCv3..."

    $cloned = $false
    try {
        git clone --depth 1 https://github.com/parcadei/Continuous-Claude-v3.git $tempDir 2>&1 | Out-Null
        $cloned = Test-Path $tempDir
    } catch {}

    if (-not $cloned) {
        try {
            git clone --depth 1 https://github.com/kmylpenter/Continuous-Claude-v3-Mirror.git $tempDir 2>&1 | Out-Null
            $cloned = Test-Path $tempDir
        } catch {}
    }

    if ($cloned -and (Test-Path "$tempDir\hooks")) {
        # Kopiuj wszystkie hooki
        Copy-Item -Path "$tempDir\hooks\*" -Destination $hooksDir -Recurse -Force
        Write-OK "Hooki CCv3 zainstalowane do ~/.claude/hooks/"

        # Cleanup
        Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    } else {
        Write-Warning "Nie udalo sie pobrac hookow - zainstaluj recznie pozniej"
    }
}

# ============================================================
# KROK 5: SKANOWANIE PROJEKTOW
# ============================================================

Write-Step "5/6" "Skanowanie i migracja projektow"

Write-Host ""
Write-Host "    Podaj sciezke do folderu z projektami:" -ForegroundColor White
Write-Host "    (np. D:\Projekty lub C:\Users\$env:USERNAME\projekty)" -ForegroundColor Gray
Write-Host ""

# Domyslna sciezka
$defaultPath = "D:\Projekty"
if (-not (Test-Path $defaultPath)) {
    $defaultPath = "$env:USERPROFILE\projekty"
}

Write-Host "    Sciezka [$defaultPath]: " -ForegroundColor Cyan -NoNewline
$projectsRoot = Read-Host
if ([string]::IsNullOrWhiteSpace($projectsRoot)) {
    $projectsRoot = $defaultPath
}

if (-not (Test-Path $projectsRoot)) {
    Write-Error-Custom "Folder nie istnieje: $projectsRoot"
    Write-Host ""
    Write-Host "    Utworz folder lub podaj istniejaca sciezke." -ForegroundColor Gray
    exit 1
}

Write-Host ""
Write-Info "Skanuje: $projectsRoot"
Write-Host ""

$projects = Scan-ProjectsFolder $projectsRoot
$script:Stats.ProjectsScanned = $projects.Count

if ($projects.Count -eq 0) {
    Write-Warning "Nie znaleziono zadnych projektow w $projectsRoot"
    Write-Host ""
    Write-Host "    Projekt = folder z .git/, package.json, pyproject.toml, itp." -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "    Znalezione projekty ($($projects.Count)):" -ForegroundColor White
    Write-Host ""

    # Grupuj projekty wedlug typu
    $ccv2Projects = $projects | Where-Object { $_.Type -eq "CCv2" }
    $ccv3Projects = $projects | Where-Object { $_.Type -eq "CCv3" }
    $cleanProjects = $projects | Where-Object { $_.Type -eq "Clean" }

    $script:Stats.CCv2Found = $ccv2Projects.Count
    $script:Stats.CCv3Found = $ccv3Projects.Count
    $script:Stats.CleanFound = $cleanProjects.Count

    if ($ccv3Projects.Count -gt 0) {
        Write-Host "    [OK] CCv3 (juz zmigrowane): $($ccv3Projects.Count)" -ForegroundColor Green
        foreach ($p in $ccv3Projects) {
            Write-Host "       - $($p.Name)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    if ($ccv2Projects.Count -gt 0) {
        Write-Host "    [~] CCv2/KFG (do migracji): $($ccv2Projects.Count)" -ForegroundColor Yellow
        foreach ($p in $ccv2Projects) {
            Write-Host "       - $($p.Name)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    if ($cleanProjects.Count -gt 0) {
        Write-Host "    [ ] Czyste projekty: $($cleanProjects.Count)" -ForegroundColor Cyan
        foreach ($p in $cleanProjects) {
            Write-Host "       - $($p.Name)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # ============================================================
    # MIGRACJA CCv2 -> CCv3
    # ============================================================

    if ($ccv2Projects.Count -gt 0) {
        Write-Host ""
        Write-Host "    -------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""

        if (Ask-User "Zmigrować $($ccv2Projects.Count) projekty CCv2 do CCv3?") {
            Write-Host ""

            foreach ($project in $ccv2Projects) {
                Write-Host "    [>] $($project.Name)" -ForegroundColor Cyan

                # Archiwizacja
                $migResult = Migrate-CCv2Project -ProjectPath $project.Path -ProjectName $project.Name
                if ($migResult.Success) {
                    if ($migResult.Archived) {
                        Write-OK "Zarchiwizowano logs/ i VALIDATION*.md"
                    }
                    $script:Stats.Migrated++
                } else {
                    Write-Error-Custom $migResult.Message
                    $script:Stats.Errors += "$($project.Name): $($migResult.Message)"
                }
            }

            Write-Host ""
        } else {
            Write-Info "Pominieto migracje CCv2"
            $script:Stats.Skipped = $ccv2Projects.Count
        }
    }

    # ============================================================
    # OPCJONALNE KLONOWANIE OPC
    # ============================================================

    Write-Host ""
    Write-Host "    -------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    Czy chcesz sklonowac opc/ do wybranych projektow?" -ForegroundColor White
    Write-Host "    (pozwala na lokalne konfiguracje per-projekt)" -ForegroundColor Gray
    Write-Host ""

    $projectsWithoutOpc = $projects | Where-Object { -not (Test-Path "$($_.Path)\opc") }

    if ($projectsWithoutOpc.Count -eq 0) {
        Write-Info "Wszystkie projekty maja juz opc/"
    } else {
        Write-Host "    Projekty bez opc/ ($($projectsWithoutOpc.Count)):" -ForegroundColor White
        $i = 1
        foreach ($p in $projectsWithoutOpc) {
            Write-Host "      $i. $($p.Name)" -ForegroundColor Gray
            $i++
        }
        Write-Host ""
        Write-Host "    Wpisz numery projektow oddzielone przecinkami (np. 1,3,5)" -ForegroundColor Gray
        Write-Host "    lub 'all' dla wszystkich, lub Enter aby pominac:" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    Wybor: " -ForegroundColor Cyan -NoNewline
        $selection = Read-Host

        if (-not [string]::IsNullOrWhiteSpace($selection)) {
            $selectedProjects = @()

            if ($selection.ToLower() -eq "all") {
                $selectedProjects = $projectsWithoutOpc
            } else {
                $indices = $selection -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "^\d+$" }
                foreach ($idx in $indices) {
                    $i = [int]$idx - 1
                    if ($i -ge 0 -and $i -lt $projectsWithoutOpc.Count) {
                        $selectedProjects += $projectsWithoutOpc[$i]
                    }
                }
            }

            if ($selectedProjects.Count -gt 0) {
                Write-Host ""
                Write-Info "Klonuje opc/ do $($selectedProjects.Count) projektow..."
                Write-Host ""

                foreach ($project in $selectedProjects) {
                    Write-Host "    [>] $($project.Name)" -ForegroundColor Cyan
                    $cloneResult = Clone-OpcToProject -ProjectPath $project.Path
                    if ($cloneResult.Success) {
                        Write-OK $cloneResult.Message
                        $script:Stats.OpcCloned++
                    } else {
                        Write-Error-Custom $cloneResult.Message
                        $script:Stats.Errors += "$($project.Name): $($cloneResult.Message)"
                    }
                }
            }
        } else {
            Write-Info "Pominieto klonowanie opc/"
        }
    }
}

# ============================================================
# KROK 6: PODSUMOWANIE
# ============================================================

Write-Step "6/6" "Podsumowanie"

Write-Host ""
Write-Host "  +===========================================================+" -ForegroundColor Green
Write-Host "  |           CCv3 Instalacja zakonczona!                     |" -ForegroundColor Green
Write-Host "  +===========================================================+" -ForegroundColor Green
Write-Host ""

# Statystyki
Write-Host "    [#] Statystyki:" -ForegroundColor White
Write-Host ""
Write-Host "       Projektow przeskanowanych: $($script:Stats.ProjectsScanned)" -ForegroundColor Gray
Write-Host "       - CCv3 (gotowe):          $($script:Stats.CCv3Found)" -ForegroundColor Green
Write-Host "       - CCv2/KFG znalezione:    $($script:Stats.CCv2Found)" -ForegroundColor Yellow
Write-Host "       - Czyste projekty:        $($script:Stats.CleanFound)" -ForegroundColor Cyan
Write-Host ""
Write-Host "       Zmigrowanych:             $($script:Stats.Migrated)" -ForegroundColor Green
Write-Host "       Sklonowano opc/:          $($script:Stats.OpcCloned)" -ForegroundColor Cyan
Write-Host "       Pominieto:                $($script:Stats.Skipped)" -ForegroundColor Gray
Write-Host ""

if ($script:Stats.Errors.Count -gt 0) {
    Write-Host "    [!] Bledy ($($script:Stats.Errors.Count)):" -ForegroundColor Yellow
    foreach ($err in $script:Stats.Errors) {
        Write-Host "       - $err" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "    [>] Hooki globalne: ~/.claude/hooks/" -ForegroundColor Gray
Write-Host "    [>] Folder projektow: $projectsRoot" -ForegroundColor Gray
Write-Host ""

Write-Host "    Nastepne kroki:" -ForegroundColor White
Write-Host ""
Write-Host "    1. Uruchom Claude Code w dowolnym projekcie:" -ForegroundColor Cyan
Write-Host "       cd [projekt] && claude" -ForegroundColor Gray
Write-Host ""
Write-Host "    2. Hooki CCv3 dzialaja automatycznie dla wszystkich projektow" -ForegroundColor Cyan
Write-Host ""
Write-Host "    3. Dla projektow z opc/ - uruchom wizard:" -ForegroundColor Cyan
Write-Host "       cd [projekt]/opc && uv sync && uv run python -m scripts.setup.wizard" -ForegroundColor Gray
Write-Host ""
