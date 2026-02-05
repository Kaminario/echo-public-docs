#region Constants
Set-Variable -Name InstallerProduct -Value "{{VERSION_PLACEHOLDER}}" -Option AllScope -Scope Script
Set-Variable -Name MessageCurrentObject -Value "Silk Echo Installer" -Option AllScope -Scope Script

Set-Variable -Name ENUM_ACTIVE_DIRECTORY -Value "active_directory" -Option AllScope -Scope Script
Set-Variable -Name ENUM_CREDENTIALS -Value "credentials" -Option AllScope -Scope Script

# Component versions and installer URLs
. ./orc_component_versions.ps1

# Installer Script Artifacts Directory
$cacheDir = Join-Path $PSScriptRoot "SilkEchoInstallerArtifacts"
Set-Variable -Name SilkEchoInstallerCacheDir -Value $cacheDir -Option AllScope -Scope Script
# Processed hosts file path
$processedHostsFile = Join-Path $cacheDir "processing.json"
Set-Variable -Name processedHostsFile -Value $processedHostsFile -Option AllScope -Scope Script
# Marker
Set-Variable -Name HOSTSETUP_START_MARKER -Value ("MARKER: " + "HOST_INSTALLER_STARTS_HERE") -Option AllScope -Scope Script

# Remote Installation Timeout (2 minutes = 120 seconds)
Set-Variable -Name REMOTE_INSTALL_TIMEOUT_SECONDS -Value 120 -Option AllScope -Scope Script


# Full execution log file path
$fullLogPath = Join-Path $cacheDir "orchestrator_full_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Set-Variable -Name SilkEchoFullLogPath -Value $fullLogPath -Option AllScope -Scope Script

# Development mode detection - true if orchestrator contains actual import lines (not comments)
# Get the orchestrator script path from the call stack
$orchestratorPath = (Get-PSCallStack | Where-Object { $_.ScriptName -like "*orchestrator.ps1" } | Select-Object -First 1).ScriptName
if (-not $orchestratorPath) {
    # Fallback: assume orchestrator.ps1 is in the same directory
    $orchestratorPath = Join-Path $PSScriptRoot "orchestrator.ps1"
}

$orchestratorContent = Get-Content -Path $orchestratorPath -Raw -ErrorAction SilentlyContinue
# Split into lines and check for actual import statements (not in comments)
$lines = $orchestratorContent -split '[\r\n]+'
$importLines = $lines | Where-Object { $_ -match '^\s*\. \./orc_.*\.ps1\s*$' }
$isDevelopmentMode = $importLines.Count -gt 0


Set-Variable -Name IsDevelopmentMode -Value $isDevelopmentMode -Option AllScope -Scope Script

Set-Variable -Name IsDomainUser -Value $false -Option AllScope -Scope Script
#endregion Constants
