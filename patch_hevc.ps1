# HEVC Enable Patch for Dell Systems - Dynamic Pattern Matching
# Searches for specific byte patterns to find patch location
# Run as Administrator

param(
    [switch]$Restore,
    [switch]$TestOnly,  # Scan files without patching
    [string]$TestPath   # Test against specific folder (e.g., original DLLs)
)

$ErrorActionPreference = "Stop"

# Pattern definitions
# 64-bit: TEST AL, 0x01; JNZ xx; PUSH RAX; AND [RSI+0x84], 0x43FFFFFF
# 32-bit: TEST CL, 0x01; JNZ xx; PUSH EAX; AND [EAX+0x84], 0x43FFFFFF

$patterns = @{
    "igd11dxva64.dll" = @{
        # A8 01 = TEST AL, 0x01
        # 75 xx = JNZ (target byte to patch)
        # 50 = PUSH RAX
        # 81 A6 84 00 00 00 FF FF FF 43 = AND [RSI+0x84], 0x43FFFFFF
        SearchPattern = @(0xA8, 0x01, 0x75, 0x50, 0x81, 0xA6, 0x84, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x43)
        PatchOffset = 2  # Offset within pattern to the JNZ byte
        Description = "64-bit HEVC capability mask bypass"
    }
    "igd11dxva32.dll" = @{
        # F6 C1 01 = TEST CL, 0x01
        # 75 xx = JNZ (target byte to patch)
        # 50 = PUSH EAX
        # 81 A0 84 00 00 00 FF FF FF 43 = AND [EAX+0x84], 0x43FFFFFF
        SearchPattern = @(0xF6, 0xC1, 0x01, 0x75, 0x50, 0x81, 0xA0, 0x84, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x43)
        PatchOffset = 3  # Offset within pattern to the JNZ byte
        Description = "32-bit HEVC capability mask bypass"
    }
}

$expectedByte = 0x75  # JNZ
$patchByte = 0xEB     # JMP

function Find-Pattern {
    param(
        [byte[]]$Data,
        [byte[]]$Pattern
    )

    $matches = @()
    $patternLen = $Pattern.Length
    $dataLen = $Data.Length

    for ($i = 0; $i -le ($dataLen - $patternLen); $i++) {
        $found = $true
        for ($j = 0; $j -lt $patternLen; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) {
                $found = $false
                break
            }
        }
        if ($found) {
            $matches += $i
        }
    }

    return $matches
}

function Format-Bytes {
    param(
        [byte[]]$Bytes,
        [int]$Highlight = -1
    )

    $result = ""
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        if ($i -eq $Highlight) {
            $result += "[$($Bytes[$i].ToString('X2'))] "
        } else {
            $result += "$($Bytes[$i].ToString('X2')) "
        }
    }
    return $result.TrimEnd()
}

# Header
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "  HEVC Patch - Dynamic Pattern Scanner" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host ""

# Determine target folder
if ($TestPath) {
    $driverFolder = $TestPath
    Write-Host "TEST MODE: Scanning $TestPath" -ForegroundColor Yellow
} else {
    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin -and -not $TestOnly) {
        Write-Host "ERROR: Run as Administrator" -ForegroundColor Red
        exit 1
    }

    # Detect Safe Mode
    $inSafeMode = (Get-WmiObject Win32_ComputerSystem).BootupState -match "Safe"

    if (-not $inSafeMode -and -not $TestOnly) {
        Write-Host "WARNING: Not in Safe Mode" -ForegroundColor Yellow
        Write-Host "DLLs may be locked. Use -TestOnly to scan without patching." -ForegroundColor Yellow
        Write-Host ""
    }

    # Find driver folder
    $driverStorePath = "C:\Windows\System32\DriverStore\FileRepository"
    $intelDrivers = Get-ChildItem $driverStorePath -Directory -Filter "iigd_dch.inf_amd64_*" |
        Sort-Object LastWriteTime -Descending

    if ($intelDrivers.Count -eq 0) {
        Write-Host "ERROR: Intel driver folder not found" -ForegroundColor Red
        exit 1
    }

    $driverFolder = $intelDrivers[0].FullName
}

Write-Host "Target: $driverFolder" -ForegroundColor Gray
Write-Host ""

$allSuccess = $true
$patchResults = @()

foreach ($dllName in $patterns.Keys) {
    $config = $patterns[$dllName]
    $dllPath = Join-Path $driverFolder $dllName
    $backupPath = "$dllPath.hevc_backup"

    Write-Host "--- $dllName ---" -ForegroundColor Yellow
    Write-Host "  $($config.Description)" -ForegroundColor Gray

    if (-not (Test-Path $dllPath)) {
        Write-Host "  SKIP: File not found" -ForegroundColor Gray
        Write-Host ""
        continue
    }

    # Read file
    $bytes = [System.IO.File]::ReadAllBytes($dllPath)
    Write-Host "  File size: $($bytes.Length) bytes" -ForegroundColor Gray

    # Search for pattern
    Write-Host "  Searching for pattern..." -ForegroundColor Gray
    $searchPattern = $config.SearchPattern
    $matchOffsets = Find-Pattern -Data $bytes -Pattern $searchPattern

    Write-Host "  Pattern: $(Format-Bytes $searchPattern $config.PatchOffset)" -ForegroundColor DarkGray

    if ($matchOffsets.Count -eq 0) {
        Write-Host "  ERROR: Pattern not found!" -ForegroundColor Red
        Write-Host "  This DLL version may not be compatible." -ForegroundColor Red
        $allSuccess = $false
        Write-Host ""
        continue
    }

    if ($matchOffsets.Count -gt 1) {
        Write-Host "  ERROR: Multiple matches found ($($matchOffsets.Count))!" -ForegroundColor Red
        Write-Host "  Locations: $($matchOffsets | ForEach-Object { '0x' + $_.ToString('X') })" -ForegroundColor Red
        Write-Host "  Refusing to patch - ambiguous pattern." -ForegroundColor Red
        $allSuccess = $false
        Write-Host ""
        continue
    }

    # Single match found
    $patternOffset = $matchOffsets[0]
    $patchOffset = $patternOffset + $config.PatchOffset
    $currentByte = $bytes[$patchOffset]

    Write-Host "  Found at offset: 0x$($patternOffset.ToString('X'))" -ForegroundColor Green
    Write-Host "  Patch target: 0x$($patchOffset.ToString('X'))" -ForegroundColor Green

    # Show context
    $contextStart = [Math]::Max(0, $patchOffset - 3)
    $contextEnd = [Math]::Min($bytes.Length - 1, $patchOffset + 10)
    $contextBytes = $bytes[$contextStart..$contextEnd]
    $highlightPos = $patchOffset - $contextStart
    Write-Host "  Context: $(Format-Bytes $contextBytes $highlightPos)" -ForegroundColor DarkGray

    # Check current state
    if ($currentByte -eq $patchByte) {
        Write-Host "  STATUS: Already patched (0xEB)" -ForegroundColor Green
        $patchResults += @{ DLL = $dllName; Status = "Already patched"; Offset = $patchOffset }
        Write-Host ""
        continue
    }

    if ($currentByte -ne $expectedByte) {
        Write-Host "  ERROR: Unexpected byte 0x$($currentByte.ToString('X2')) (expected 0x75)" -ForegroundColor Red
        $allSuccess = $false
        Write-Host ""
        continue
    }

    Write-Host "  STATUS: Needs patching (0x75 -> 0xEB)" -ForegroundColor Yellow

    if ($TestOnly) {
        $patchResults += @{ DLL = $dllName; Status = "Patch needed"; Offset = $patchOffset }
        Write-Host ""
        continue
    }

    if ($Restore) {
        if (Test-Path $backupPath) {
            Copy-Item $backupPath $dllPath -Force
            Write-Host "  RESTORED from backup" -ForegroundColor Green
            $patchResults += @{ DLL = $dllName; Status = "Restored"; Offset = $patchOffset }
        } else {
            Write-Host "  No backup available" -ForegroundColor Yellow
        }
        Write-Host ""
        continue
    }

    # Take ownership and patch
    Write-Host "  Taking ownership..." -ForegroundColor Gray
    cmd /c "takeown /f `"$dllPath`"" >$null 2>&1
    cmd /c "icacls `"$dllPath`" /grant Administrators:F" >$null 2>&1

    # Create backup
    if (-not (Test-Path $backupPath)) {
        Copy-Item $dllPath $backupPath -Force
        Write-Host "  Backup created" -ForegroundColor Gray
    }

    # Apply patch
    $bytes[$patchOffset] = $patchByte
    try {
        [System.IO.File]::WriteAllBytes($dllPath, $bytes)
        Write-Host "  PATCHED successfully!" -ForegroundColor Green
        $patchResults += @{ DLL = $dllName; Status = "Patched"; Offset = $patchOffset }
    } catch {
        Write-Host "  FAILED: $_" -ForegroundColor Red
        $allSuccess = $false
    }

    Write-Host ""
}

# Summary
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

foreach ($result in $patchResults) {
    $color = switch ($result.Status) {
        "Patched" { "Green" }
        "Already patched" { "Green" }
        "Patch needed" { "Yellow" }
        "Restored" { "Cyan" }
        default { "White" }
    }
    Write-Host "  $($result.DLL): $($result.Status) @ 0x$($result.Offset.ToString('X'))" -ForegroundColor $color
}

Write-Host ""

if ($TestOnly) {
    Write-Host "Test complete. No files were modified." -ForegroundColor Yellow
} elseif (-not $allSuccess) {
    Write-Host "Some operations failed. Check errors above." -ForegroundColor Red
    exit 1
} elseif (-not $Restore -and -not $TestPath) {
    # Disable Safe Mode if we were patching
    $inSafeMode = (Get-WmiObject Win32_ComputerSystem).BootupState -match "Safe"
    if ($inSafeMode) {
        Write-Host "Disabling Safe Mode boot..." -ForegroundColor Yellow
        cmd /c "bcdedit /deletevalue {current} safeboot" 2>$null

        Write-Host ""
        $confirm = Read-Host "Reboot now? (y/N)"
        if ($confirm -eq "y" -or $confirm -eq "Y") {
            cmd /c "shutdown /r /t 0 /f"
        } else {
            Write-Host "Reboot manually when ready." -ForegroundColor Yellow
        }
    }
}
