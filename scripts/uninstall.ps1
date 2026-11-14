[CmdletBinding()]
param()

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

function Remove-UserPathEntry {
    param(
        [Parameter(Mandatory)][string]$TargetDir,
        [Parameter(Mandatory)][string]$InstallFolderName
    )

    $targetKey = Get-NormalizedPathKey -PathEntry $TargetDir
    $unexpandedTargetKey = ("%localappdata%\$InstallFolderName\bin").Replace('/', '\').TrimEnd('\').ToLowerInvariant()

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

    $removed = $false
    if (-not [string]::IsNullOrWhiteSpace($rawPath)) {
        $kept = New-Object 'System.Collections.Generic.List[string]'
        foreach ($segment in ($rawPath -split ';')) {
            $cleaned = $segment.Trim()
            if ([string]::IsNullOrWhiteSpace($cleaned)) { continue }
            $key = Get-NormalizedPathKey -PathEntry $cleaned
            $unexpandedSegment = $cleaned.Trim('"').Replace('/', '\').TrimEnd('\').ToLowerInvariant()
            if ($key -eq $targetKey -or $unexpandedSegment -eq $unexpandedTargetKey) {
                $removed = $true
                continue
            }
            $kept.Add($cleaned)
        }

        if ($removed) {
            $newPath = ($kept -join ';')
            if ([string]::IsNullOrWhiteSpace($newPath)) {
                $writeKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
                try {
                    if ($null -ne $writeKey) {
                        $writeKey.DeleteValue('Path', $false)
                    }
                } finally {
                    if ($null -ne $writeKey) { $writeKey.Close() }
                }
            } elseif ($valueKind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) {
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
    }

    if (-not [string]::IsNullOrWhiteSpace($env:PATH)) {
        $sessionKept = New-Object 'System.Collections.Generic.List[string]'
        $sessionChanged = $false
        foreach ($segment in ($env:PATH -split ';')) {
            if ([string]::IsNullOrWhiteSpace($segment)) { continue }
            if ((Get-NormalizedPathKey -PathEntry $segment) -eq $targetKey) {
                $sessionChanged = $true
                continue
            }
            $sessionKept.Add($segment)
        }
        if ($sessionChanged) {
            $env:PATH = ($sessionKept -join ';')
        }
    }

    if ($removed) {
        return 'Removed'
    }
    return 'Not present'
}

function Unregister-ExplorerShellVerb {
    param(
        [Parameter(Mandatory)]$Verb,
        [Parameter(Mandatory)][string]$RegistryShellBase
    )

    $keyName = ([string]$Verb.keyName).Trim()
    if ([string]::IsNullOrWhiteSpace($keyName)) {
        throw 'Explorer verb descriptor is missing keyName.'
    }

    $verbSubKey = "$($RegistryShellBase.TrimEnd('\'))\$keyName"
    $existingMenu = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($verbSubKey, $false)
    if ($null -ne $existingMenu) {
        $existingMenu.Close()
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($verbSubKey, $false)
        return [PSCustomObject]@{
            SubKey = $verbSubKey
            Status = 'Removed'
        }
    }

    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($verbSubKey, $false)
    return [PSCustomObject]@{
        SubKey = $verbSubKey
        Status = 'Not present'
    }
}

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$config = Read-WindowsConfig -ConfigPath (Join-Path $scriptDir 'windows-config.json')

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA environment variable is not set.'
}
if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
    throw 'APPDATA environment variable is not set.'
}

$registryShellBase = $config.registryShellBase
$menuResults = New-Object 'System.Collections.Generic.List[object]'
foreach ($verb in @($config.explorerVerbs)) {
    $menuResults.Add((Unregister-ExplorerShellVerb -Verb $verb -RegistryShellBase $registryShellBase))
}

$shortcutPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$($config.shortcut.name)"
if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
    Remove-Item -LiteralPath $shortcutPath -Force
    $shortcutStatus = 'Removed'
} else {
    $shortcutStatus = 'Not present'
}

$installRoot = Join-Path $env:LOCALAPPDATA $config.installFolderName
$binDir = Join-Path $installRoot 'bin'
$pathStatus = Remove-UserPathEntry -TargetDir $binDir -InstallFolderName $config.installFolderName

if (Test-Path -LiteralPath $installRoot) {
    Remove-Item -LiteralPath $installRoot -Recurse -Force
    $dirStatus = 'Removed'
} else {
    $dirStatus = 'Not present'
}

Write-Host ''
Write-Host 'Hasher uninstall complete.'
Write-Host 'Explorer context menus:'
foreach ($menu in $menuResults) {
    Write-Host "  - $($menu.Status): HKCU\$($menu.SubKey)"
}
Write-Host "Start Menu shortcut: $shortcutStatus ($shortcutPath)"
Write-Host "User PATH entry: $pathStatus ($binDir)"
Write-Host "Install directory: $dirStatus ($installRoot)"
