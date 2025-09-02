#region Constants
Set-Variable -Name InstallerProduct -Value "{{VERSION_PLACEHOLDER}}" -Option AllScope -Scope Script
Set-Variable -Name MessageCurrentObject -Value "Silk Echo Installer" -Option AllScope -Scope Script

Set-Variable -Name ENUM_ACTIVE_DIRECTORY -Value "active_directory" -Option AllScope -Scope Script
Set-Variable -Name ENUM_CREDENTIALS -Value "credentials" -Option AllScope -Scope Script

# Installer URLs
Set-Variable -Name SilkAgentURL -Value 'https://storage.googleapis.com/silk-public-files/silk-agent-installer-latest.exe' -Option AllScope -Scope Script
Set-Variable -Name SilkVSSURL -Value 'https://storage.googleapis.com/silk-public-files/svss-install.exe' -Option AllScope -Scope Script

# Installer Script Artifacts Directory
$cacheDir = Join-Path $PSScriptRoot "SilkEchoInstallerArtifacts"
Set-Variable -Name SilkEchoInstallerCacheDir -Value $cacheDir -Option AllScope -Scope Script
# Marker
Set-Variable -Name HOSTSETUP_START_MARKER -Value ("MARKER: " + "HOST_INSTALLER_STARTS_HERE") -Option AllScope -Scope Script

# Development mode detection - true if orchestrator contains imports (. ./orc_*.ps1)
$orchestratorContent = Get-Content -Path $PSCommandPath -Raw -ErrorAction SilentlyContinue
$isDevelopmentMode = $orchestratorContent -match '\. \./orc_.*\.ps1'
Set-Variable -Name IsDevelopmentMode -Value $isDevelopmentMode -Option AllScope -Scope Script

Set-Variable -Name IsDomainUser -Value $false -Option AllScope -Scope Script
#endregion Constants
