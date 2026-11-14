[CmdletBinding()]
param(
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ConfigString {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$PropertyName,
        [Parameter(Mandatory)][string]$Context,
        [switch]$SingleSegment
    )

    $prop = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $prop -or $null -eq $prop.Value -or -not ($prop.Value -is [string]) -or [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
        throw "Invalid configuration in windows-config.json: missing or empty string '$Context.$PropertyName'."
    }

    $value = ([string]$prop.Value).Trim()
    if ($SingleSegment) {
        if ($value -eq '.' -or $value -eq '..' -or $value -match '[\\/:\*?"<>|]') {
            throw "Invalid configuration in windows-config.json: '$Context.$PropertyName' must be a valid single path segment (got '$value')."
        }
    }
    return $value
}

function Read-WindowsConfig {
    param([Parameter(Mandatory)][string]$ConfigPath)

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Configuration file not found: $ConfigPath"
    }

    $rawJson = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($rawJson)) {
        throw "Configuration file is empty: $ConfigPath"
    }

    $config = $rawJson | ConvertFrom-Json
    if ($null -eq $config) {
        throw "Failed to parse JSON configuration: $ConfigPath"
    }

    $installFolderName = Assert-ConfigString -Object $config -PropertyName 'installFolderName' -Context 'root' -SingleSegment

    $binariesProp = $config.PSObject.Properties['binaries']
    if ($null -eq $binariesProp -or $null -eq $binariesProp.Value) {
        throw "Invalid configuration in windows-config.json: missing 'binaries' array."
    }
    $binaries = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @($binariesProp.Value)) {
        if ($null -eq $entry -or -not ($entry -is [string]) -or [string]::IsNullOrWhiteSpace([string]$entry)) {
            throw "Invalid configuration in windows-config.json: 'binaries' entries must be non-empty strings."
        }
        $binaryName = ([string]$entry).Trim()
        if ($binaryName -eq '.' -or $binaryName -eq '..' -or $binaryName -match '[\\/:\*?"<>|]') {
            throw "Invalid configuration in windows-config.json: binary '$binaryName' must be a valid filename."
        }
        $binaries.Add($binaryName)
    }
    if ($binaries.Count -eq 0) {
        throw "Invalid configuration in windows-config.json: 'binaries' must contain at least one binary."
    }

    $shortcutProp = $config.PSObject.Properties['shortcut']
    if ($null -eq $shortcutProp -or $null -eq $shortcutProp.Value) {
        throw "Invalid configuration in windows-config.json: missing 'shortcut' object."
    }
    $shortcutName = Assert-ConfigString -Object $shortcutProp.Value -PropertyName 'name' -Context 'shortcut' -SingleSegment
    $shortcutTargetBinary = Assert-ConfigString -Object $shortcutProp.Value -PropertyName 'targetBinary' -Context 'shortcut' -SingleSegment
    $shortcutDescription = Assert-ConfigString -Object $shortcutProp.Value -PropertyName 'description' -Context 'shortcut'

    $registryShellBase = (Assert-ConfigString -Object $config -PropertyName 'registryShellBase' -Context 'root').TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($registryShellBase)) {
        throw "Invalid configuration in windows-config.json: 'registryShellBase' cannot be empty."
    }

    $verbsProp = $config.PSObject.Properties['explorerVerbs']
    if ($null -eq $verbsProp -or $null -eq $verbsProp.Value) {
        throw "Invalid configuration in windows-config.json: missing 'explorerVerbs' array."
    }
    $verbs = New-Object 'System.Collections.Generic.List[object]'
    $verbIndex = 0
    foreach ($verb in @($verbsProp.Value)) {
        if ($null -eq $verb) {
            throw "Invalid configuration in windows-config.json: explorerVerbs[$verbIndex] cannot be null."
        }
        $ctx = "explorerVerbs[$verbIndex]"
        $keyName = Assert-ConfigString -Object $verb -PropertyName 'keyName' -Context $ctx -SingleSegment
        $label = Assert-ConfigString -Object $verb -PropertyName 'label' -Context $ctx
        $commandBinary = Assert-ConfigString -Object $verb -PropertyName 'commandBinary' -Context $ctx -SingleSegment
        $iconBinary = Assert-ConfigString -Object $verb -PropertyName 'iconBinary' -Context $ctx -SingleSegment
        $arguments = Assert-ConfigString -Object $verb -PropertyName 'arguments' -Context $ctx

        $verbs.Add([PSCustomObject]@{
            keyName       = $keyName
            label         = $label
            commandBinary = $commandBinary
            iconBinary    = $iconBinary
            arguments     = $arguments
        })
        $verbIndex++
    }
    if ($verbs.Count -eq 0) {
        throw "Invalid configuration in windows-config.json: 'explorerVerbs' must contain at least one entry."
    }

    return [PSCustomObject]@{
        installFolderName = $installFolderName
        binaries          = $binaries.ToArray()
        shortcut          = [PSCustomObject]@{
            name         = $shortcutName
            targetBinary = $shortcutTargetBinary
            description  = $shortcutDescription
        }
        registryShellBase = $registryShellBase
        explorerVerbs     = $verbs.ToArray()
    }
}

function Get-NormalizedPathKey {
    param([string]$PathEntry)
    if ([string]::IsNullOrWhiteSpace($PathEntry)) {
        return ''
    }
    $trimmed = $PathEntry.Trim().Trim('"').Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return ''
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($trimmed).Replace('/', '\')
    if ($expanded -notmatch '^[A-Za-z]:\\$' -and $expanded -ne '\') {
        $expanded = $expanded.TrimEnd('\')
    }
    return $expanded.ToLowerInvariant()
}

function Send-EnvironmentSettingChange {
    if (-not ('Hasher.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Hasher {
    public static class NativeMethods {
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr SendMessageTimeout(
            IntPtr hWnd,
            uint Msg,
            UIntPtr wParam,
            string lParam,
            uint fuFlags,
            uint uTimeout,
            out UIntPtr lpdwResult
        );
    }
}
'@
    }

    [UIntPtr]$result = [UIntPtr]::Zero
    [void][Hasher.NativeMethods]::SendMessageTimeout(
        [IntPtr]0xffff,
        [uint32]0x001A,
        [UIntPtr]::Zero,
        'Environment',
        [uint32]0x0002,
        [uint32]5000,
        [ref]$result
    )
}

function Add-UserPathEntry {
    param([Parameter(Mandatory)][string]$TargetDir)

    $targetKey = Get-NormalizedPathKey -PathEntry $TargetDir
    $rawPath = $null
    $valueKind = $null

    $readKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    try {
        if ($null -ne $readKey) {
            $rawPath = $readKey.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($null -ne $rawPath) {
                $valueKind = $readKey.GetValueKind('Path')
            }
        }
    } finally {
        if ($null -ne $readKey) { $readKey.Close() }
    }

    if ($null -eq $rawPath) {
        $rawPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $entries = New-Object 'System.Collections.Generic.List[string]'

    if (-not [string]::IsNullOrWhiteSpace($rawPath)) {
        foreach ($segment in ($rawPath -split ';')) {
            $cleaned = $segment.Trim()
            if ([string]::IsNullOrWhiteSpace($cleaned)) { continue }
            $key = Get-NormalizedPathKey -PathEntry $cleaned
            if ([string]::IsNullOrWhiteSpace($key)) { continue }
            if ($seen.Add($key)) {
                $entries.Add($cleaned)
            }
        }
    }

    $alreadyPresent = $seen.Contains($targetKey)
    if (-not $alreadyPresent) {
        $entries.Add($TargetDir)
    }

    $newPath = ($entries -join ';')
    $changed = (-not $alreadyPresent) -or ($rawPath -cne $newPath)

    if ($changed) {
        if ($valueKind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) {
            $writeKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment', $true)
            try {
                $writeKey.SetValue('Path', $newPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            } finally {
                $writeKey.Close()
            }
        } else {
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        }
        Send-EnvironmentSettingChange
    }

    $sessionHasTarget = $false
    if (-not [string]::IsNullOrWhiteSpace($env:PATH)) {
        foreach ($segment in ($env:PATH -split ';')) {
            if ((Get-NormalizedPathKey -PathEntry $segment) -eq $targetKey) {
                $sessionHasTarget = $true
                break
            }
        }
    }
    if (-not $sessionHasTarget) {
        $env:PATH = if ([string]::IsNullOrWhiteSpace($env:PATH)) {
            $TargetDir
        } else {
            "$($env:PATH.TrimEnd(';'));$TargetDir"
        }
    }

    if ($alreadyPresent) {
        return 'Already present'
    }
    return 'Added'
}

function Register-ExplorerShellVerb {
    param(
        [Parameter(Mandatory)]$Verb,
        [Parameter(Mandatory)][string]$BinDir,
        [Parameter(Mandatory)][string]$RegistryShellBase
    )

    $keyName = ([string]$Verb.keyName).Trim()
    $label = [string]$Verb.label
    $commandBinary = ([string]$Verb.commandBinary).Trim()
    $iconBinary = ([string]$Verb.iconBinary).Trim()
    $arguments = [string]$Verb.arguments

    if ([string]::IsNullOrWhiteSpace($keyName) -or
        [string]::IsNullOrWhiteSpace($label) -or
        [string]::IsNullOrWhiteSpace($commandBinary) -or
        [string]::IsNullOrWhiteSpace($iconBinary) -or
        [string]::IsNullOrWhiteSpace($arguments)) {
        throw 'Explorer verb descriptor is missing a required property.'
    }

    $commandExe = Join-Path $BinDir $commandBinary
    $iconExe = Join-Path $BinDir $iconBinary
    $verbSubKey = "$($RegistryShellBase.TrimEnd('\'))\$keyName"

    # Use .NET Registry API directly so '*' in Software\Classes\*\shell is never treated as a PowerShell wildcard.
    $shellKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($verbSubKey, $true)
    if ($null -eq $shellKey) {
        throw "Failed to create or open registry key: HKCU\$verbSubKey"
    }
    try {
        $shellKey.SetValue('', $label, [Microsoft.Win32.RegistryValueKind]::String)
        $shellKey.SetValue('Icon', "`"$iconExe`",0", [Microsoft.Win32.RegistryValueKind]::String)

        $commandKey = $shellKey.CreateSubKey('command', $true)
        if ($null -eq $commandKey) {
            throw "Failed to create or open registry key: HKCU\$verbSubKey\command"
        }
        try {
            $commandKey.SetValue('', "`"$commandExe`" $arguments", [Microsoft.Win32.RegistryValueKind]::String)
        } finally {
            $commandKey.Close()
        }
    } finally {
        $shellKey.Close()
    }

    return $verbSubKey
}

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$config = Read-WindowsConfig -ConfigPath (Join-Path $scriptDir 'windows-config.json')

if (-not (Test-Path -LiteralPath (Join-Path $repoRoot 'Cargo.toml') -PathType Leaf)) {
    throw "Cargo.toml not found at expected repository root: $repoRoot"
}

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA environment variable is not set.'
}
if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
    throw 'APPDATA environment variable is not set.'
}
if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    throw 'USERPROFILE environment variable is not set.'
}

if (-not $SkipBuild) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo was not found in PATH. Install Rust or pass -SkipBuild if release binaries are already built.'
    }
    Write-Host 'Building release binaries (cargo build --release)...'
    Push-Location -LiteralPath $repoRoot
    try {
        & cargo build --release
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build --release failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host 'Skipping build (-SkipBuild specified).'
}

$releaseDir = Join-Path $repoRoot 'target\release'
$installRoot = Join-Path $env:LOCALAPPDATA $config.installFolderName
$binDir = Join-Path $installRoot 'bin'
$binaryNames = @($config.binaries)

foreach ($name in $binaryNames) {
    $srcPath = Join-Path $releaseDir $name
    if (-not (Test-Path -LiteralPath $srcPath -PathType Leaf)) {
        throw "Release binary not found: $srcPath. Run without -SkipBuild or run 'cargo build --release' first."
    }
}

if (-not (Test-Path -LiteralPath $binDir -PathType Container)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

$installedBinaries = New-Object 'System.Collections.Generic.List[string]'

foreach ($name in $binaryNames) {
    $srcPath = Join-Path $releaseDir $name
    $dstPath = Join-Path $binDir $name
    Copy-Item -LiteralPath $srcPath -Destination $dstPath -Force
    if (-not (Test-Path -LiteralPath $dstPath -PathType Leaf)) {
        throw "Failed to verify installed binary at: $dstPath"
    }
    $installedBinaries.Add($dstPath)
}

$pathStatus = Add-UserPathEntry -TargetDir $binDir

$shortcutTargetExe = Join-Path $binDir $config.shortcut.targetBinary
if (-not (Test-Path -LiteralPath $shortcutTargetExe -PathType Leaf)) {
    throw "Configured shortcut target binary was not installed: $shortcutTargetExe"
}

$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
if (-not (Test-Path -LiteralPath $startMenuDir -PathType Container)) {
    New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null
}
$shortcutPath = Join-Path $startMenuDir $config.shortcut.name

$wsh = $null
$shortcut = $null
try {
    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $shortcutTargetExe
    $shortcut.WorkingDirectory = $env:USERPROFILE
    $shortcut.IconLocation = "$shortcutTargetExe,0"
    $shortcut.Description = $config.shortcut.description
    $shortcut.Save()
} finally {
    if ($null -ne $shortcut) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) }
    if ($null -ne $wsh) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) }
}

if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
    throw "Failed to verify Start Menu shortcut at: $shortcutPath"
}

$registryShellBase = $config.registryShellBase
$registeredMenus = New-Object 'System.Collections.Generic.List[string]'

foreach ($verb in @($config.explorerVerbs)) {
    $commandPath = Join-Path $binDir $verb.commandBinary
    if (-not (Test-Path -LiteralPath $commandPath -PathType Leaf)) {
        throw "Configured Explorer verb command binary was not installed: $commandPath"
    }
    $iconPath = Join-Path $binDir $verb.iconBinary
    if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
        throw "Configured Explorer verb icon binary was not installed: $iconPath"
    }

    $registeredSubKey = Register-ExplorerShellVerb -Verb $verb -BinDir $binDir -RegistryShellBase $registryShellBase
    $registeredMenus.Add("HKCU\$registeredSubKey ($($verb.label))")
}

Write-Host ''
Write-Host 'Hasher installation complete (user scope, no elevation required).'
Write-Host 'Installed binaries:'
foreach ($exe in $installedBinaries) {
    Write-Host "  - $exe"
}
Write-Host "User PATH: $pathStatus ($binDir)"
Write-Host "Start Menu shortcut: $shortcutPath"
Write-Host 'Explorer context menus:'
foreach ($menu in $registeredMenus) {
    Write-Host "  - $menu"
}
