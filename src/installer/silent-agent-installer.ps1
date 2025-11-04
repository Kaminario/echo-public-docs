<#
.SYNOPSIS
    Installs Silk Echo Node Agent silently.

.DESCRIPTION
    This PowerShell script runs the Silk Node Agent installer silently.
    All parameters (connection strings, tokens, etc.) should be prepared in advance.
    This script only executes the installer and verifies the installation result.

.PARAMETER ConfigFile
    Path to JSON configuration file containing all required installation parameters:
    - agent_path: Path to the agent installer executable
    - sql_connection_string: Pre-validated SQL connection string
    - flex_host_ip: Flex server IP address
    - agent_token: Pre-obtained agent token from Flex
    - mount_points_directory: Directory for mount points
    - install_to_directory: (Optional) Installation directory

.PARAMETER GenerateConfig
    Generate a configuration template file (config.json) in the same directory as this script.

.EXAMPLE
    .\silent-agent-installer.ps1 -ConfigFile "C:\config.json"

    Installs Silk Node Agent silently with the specified configuration file.

.EXAMPLE
    .\silent-agent-installer.ps1 -GenerateConfig

    Generates a configuration template file for agent installation.

.NOTES
    File Name      : silent-agent-installer.ps1
    Version        : 1.3
    Author         : Silk.us, Inc.
    Prerequisite   : PowerShell 5.1 or PowerShell 7+, Administrator privileges
    Copyright      : (c) 2024 Silk.us, Inc.
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,

    [Parameter(Mandatory=$false)]
    [switch]$GenerateConfig
)

# Script version - increment on each change
$ScriptVersion = "1.3"

# Print version at script start
Write-Host "silent-agent-installer.ps1 version $ScriptVersion" -ForegroundColor Cyan

# If GenerateConfig is specified, create template and exit
if ($GenerateConfig) {
    # Get script directory - compatible with PowerShell 5 and 7
    # $PSScriptRoot available in PS3+, fallback for older versions
    if ($PSScriptRoot) {
        $scriptDir = $PSScriptRoot
    } elseif ($MyInvocation.MyCommand.Path) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $scriptDir = $PWD.Path
    }
    $configPath = Join-Path $scriptDir "config.json"

    # Check if config file already exists and ask for confirmation
    if (Test-Path -Path $configPath) {
        Write-Warning "Configuration file already exists: $configPath"
        $overwrite = Read-Host "Do you want to overwrite the existing config file? (y/N)"
        if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
            Write-Host "Configuration template creation cancelled."
            exit 0
        }
    }

    # Create template configuration
    $templateConfig = @{
        agent_path = "C:\path\to\agent-installer.exe"
        sql_connection_string = "Server=localhost,1433;User ID=sql_user;Password=sql_password;Application Name=SilkAgent"
        flex_host_ip = "10.0.0.1"
        agent_token = "your-agent-token-here"
        mount_points_directory = "C:\MountPoints"
        install_to_directory = ""
    }

    try {
        $formattedJson = $templateConfig | ConvertTo-Json -Depth 10
        $formattedJson | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "Configuration template created successfully: $configPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "Please edit the config.json file with your specific values:" -ForegroundColor Yellow
        Write-Host "  - agent_path: Path to the agent installer executable"
        Write-Host "  - sql_connection_string: Pre-validated SQL Server connection string"
        Write-Host "  - flex_host_ip: Flex server IP address"
        Write-Host "  - agent_token: Pre-obtained agent token from Flex"
        Write-Host "  - mount_points_directory: Directory for mount points"
        Write-Host "  - install_to_directory: (Optional) Custom installation directory (leave empty for default)"
        Write-Host ""
    } catch {
        Write-Error "Failed to create configuration template: $_"
        exit 1
    }
    exit 0
}

# Validate ConfigFile parameter is provided when not generating config
if (-not $ConfigFile) {
    Write-Error "ConfigFile parameter is required when not using -GenerateConfig"
    Write-Host "Usage: .\silent-agent-installer.ps1 -ConfigFile `"path\to\config.json`""
    Write-Host "   or: .\silent-agent-installer.ps1 -GenerateConfig"
    exit 1
}

# Validate config file exists
if (-not (Test-Path -Path $ConfigFile)) {
    Write-Error "Configuration file not found at $ConfigFile"
    exit 1
}

# Read and parse JSON configuration from file
# Compatible with both PowerShell 5 and PowerShell 7
try {
    # Use -Raw for PowerShell 3+, fallback to join for older versions
    if ($PSVersionTable.PSVersion.Major -ge 3) {
        $configContent = Get-Content -Path $ConfigFile -Raw
    } else {
        $configContent = (Get-Content -Path $ConfigFile) -join "`n"
    }
    $Config = $configContent | ConvertFrom-Json
} catch {
    Write-Error "Failed to read or parse configuration file: $_"
    exit 1
}

# Extract parameters from config
$SilkAgentPath = $Config.agent_path
$SQLConnectionString = $Config.sql_connection_string
$FlexIP = $Config.flex_host_ip
$AgentToken = $Config.agent_token
$MountPointsDirectory = $Config.mount_points_directory
$DirectoryToInstall = $Config.install_to_directory

# Validate required parameters
if (-not $SilkAgentPath) {
    Write-Error "agent_path is required"
    exit 1
}
if (-not $SQLConnectionString) {
    Write-Error "sql_connection_string is required"
    exit 1
}
if (-not $FlexIP) {
    Write-Error "flex_host_ip is required"
    exit 1
}
if (-not $AgentToken) {
    Write-Error "agent_token is required"
    exit 1
}
if (-not $MountPointsDirectory) {
    Write-Error "mount_points_directory is required"
    exit 1
}

# Verify installer file exists
if (-not (Test-Path -Path $SilkAgentPath)) {
    Write-Error "Installer file not found at $SilkAgentPath"
    exit 1
}

# Determine installation log path (default: same directory as installer)
$SilkAgentDirectory = Split-Path -Path $SilkAgentPath -Parent
$AgentInstallationLogPath = "$SilkAgentDirectory\install.log"

# Build installer arguments
$arguments = @(
    '/S', # Silent installation
    "/DbConnStr='$SQLConnectionString'",
    "/FlexHost='$FlexIP'",
    "/Token='$AgentToken'",
    "/MountPointsDirectory='$MountPointsDirectory'"
)

# Add /Directory parameter if InstallDir is provided
if ($DirectoryToInstall -and $DirectoryToInstall.Trim() -ne "") {
    $arguments += "/Directory='$DirectoryToInstall\SilkAgent'"
}

Write-Host "Installing Silk Node Agent silently..."
Write-Host "Installer: $SilkAgentPath"

# Run installer silently
try {
    $process = Start-Process -FilePath $SilkAgentPath -ArgumentList $arguments -Wait -NoNewWindow -PassThru

    Write-Host "Installer completed with exit code: $($process.ExitCode)"

    if ($process.ExitCode -ne 0) {
        Write-Error "Installer exited with non-zero exit code: $($process.ExitCode)"
        exit $process.ExitCode
    }
} catch {
    Write-Error "Failed to run installer: $_"
    exit 1
}

# Check installation log for success/failure
Write-Host "Checking installation log at $AgentInstallationLogPath"

if (Test-Path -Path $AgentInstallationLogPath) {
    $logContent = Get-Content -Path $AgentInstallationLogPath -Raw

    # Check for success message
    if ($logContent -match "Installation process succeeded\.") {
        Write-Host "Installation completed successfully"
        exit 0
    }

    # Check for errors
    if ($logContent -match "(?i)error") {
        Write-Error "Installation log contains errors. Please check the log file at $AgentInstallationLogPath"
        Write-Host "Log content:"
        Write-Host $logContent
        exit 1
    }

    # If no success message but no errors, assume success
    Write-Host "Installation completed (no errors found in log)"
    exit 0
} else {
    Write-Warning "Installation log file not found at $AgentInstallationLogPath"
    Write-Warning "Installation may have completed, but log verification was not possible"
    exit 0
}
