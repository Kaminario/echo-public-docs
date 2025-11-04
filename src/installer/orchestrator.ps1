<#
.SYNOPSIS
    Silk Echo Installer PowerShell Script - Install Silk Echo on multiple remote hosts using PowerShell.

.DESCRIPTION
    This script installs Silk Echo on multiple remote Windows hosts using PowerShell remoting.
    It reads configuration from a JSON file and performs remote installation on specified hosts.

    The script requires PowerShell version 5 or higher and must be run with administrator privileges.
    It uses an external script 'orc_host_installer.ps1' to perform the actual installation on each host.

.PARAMETER ConfigPath
    Full or relative path to the configuration file in JSON format.
    The configuration file must contain hosts, flex_host_ip, and sdpid fields.

.PARAMETER MaxConcurrency
    Number of hosts to install in parallel. Default value is 10.
    This helps manage resource usage and provides better progress tracking for large deployments.

.PARAMETER Dir
    The target directory for the installers. This parameter will be passed to both the SilkAgent installer (using /D flag) and VSS installer (using /DIR flag).

.PARAMETER DryRun
    Perform validation of connectivity before running actual installation.
    It will validate connectivity from this host to the hosts defined in configuration file.
    After we have all the hosts validated, it will validate connectivity from each host to flex_host_ip and SDP.
    Default value is false.

.PARAMETER CreateConfigTemplate
    Generate a config.json template file based on config-example.json structure.
    When this parameter is used, the script will only create the template file and exit.

.PARAMETER Force
    Force reprocessing of all hosts, ignoring the completed hosts tracking file (processing.json).
    When this parameter is used, all hosts in the configuration will be processed regardless of their previous completion status.
    This is useful for troubleshooting or when you want to reinstall on all hosts.

.PARAMETER Log
    Optional path to a log file where a full transcript of the script execution will be saved.
    If not specified, the default log file location in the cache directory will be used.
    The log file will contain all console output, including debug messages if enabled.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath ".\config.json"

    Installs Silk Echo on hosts specified in the configuration file using default MaxConcurrency of 10.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 5

    Installs Silk Echo on hosts in batches of 5 at a time.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 5 -DryRun

    Performs a dry run validation on hosts in batches of 5 at a time without making any changes.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -Debug

    Runs the installation with debug output enabled.

.EXAMPLE
    Get-Help .\orchestrator.ps1 -Detailed

    Shows detailed help information for this script.

.EXAMPLE
    .\orchestrator.ps1 -CreateConfigTemplate

    Generates a config.json template file based on config-example.json structure.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -Force

    Processes all hosts in configuration, ignoring any previously completed installations.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -Log "C:\Logs\installation.log"

    Runs the installation and saves a full transcript of all output to the specified log file.

.INPUTS
    JSON configuration file with the following structure like generated with parameter -CreateConfigTemplate

.OUTPUTS
    Installation logs and status messages.
    The Per host installation logs are saved in the output directory defined by $SilkEchoInstallerCacheDir variable.
    A summary of installation results is displayed at the end of the script execution.

.NOTES
    File Name      : orchestrator.ps1
    Author         : Ilya.Levin@Silk.US
    Organization   : Silk.us, Inc.
    Version        : {{VERSION_PLACEHOLDER}}
    Copyright      : Copyright (c) 2025 Silk Technologies, Inc.
                     This source code is licensed under the MIT license found in the
                     LICENSE file in the root directory of this source tree.
    Host Types     : Valid for Windows environments

    Prerequisites:
    - PowerShell version 5 or higher
    - Administrator privileges
    - Network access to target hosts

    The WinRemoting feature must be enabled on the target hosts.
    Ensure that the WinRM service is running and properly configured on each host.

    You can use the following command to check the WinRM service status:
    ```powershell
    Get-Service WinRM
    Enable-PSRemoting
    ```

    The WinRm is listening by default to 5985(http) and 5986(https) ports.
    Run to confirm on your target host:
    ```powershell
    WinRM enumerate winrm/config/listener
    ```

.LINK
    https://github.com/Kaminario/echo-public-docs

.FUNCTIONALITY
    Remote installation, System administration, Silk Echo deployment
#>

#region Script Definitions
param (
    [Parameter(Mandatory=$false, HelpMessage="Full or relative path to the configuration file in JSON format")]
    [string]$ConfigPath,

    [Parameter(Mandatory=$false, HelpMessage="Number of hosts to install in parallel")]
    [int]$MaxConcurrency = 10,

    [Parameter(Mandatory=$false, HelpMessage="Perform dry run to validate connectivity before actual installation")]
    [switch]$DryRun,

    [Parameter(Mandatory=$false, HelpMessage="Generate a config.json template file and exit")]
    [switch]$CreateConfigTemplate,

    [Parameter(Mandatory=$false, HelpMessage="Force reprocessing of all hosts, ignoring completed hosts tracking")]
    [switch]$Force,

    [Parameter(Mandatory=$false, HelpMessage="Optional path to a log file for full transcript of script execution")]
    [string]$Log,

    [Parameter(Mandatory=$false, HelpMessage="Upload a file to Flex and exit (requires ConfigPath)")]
    [string]$UploadFile
)

# Handle UploadFile parameter early - upload file and exit without trapping or stdout output
if ($UploadFile) {
    if (-not $ConfigPath) {
        Write-Error "ConfigPath is required when using -UploadFile parameter"
        exit 1
    }

    if (-not (Test-Path $UploadFile)) {
        Write-Error "File not found: $UploadFile"
        exit 1
    }

    # Load minimal required modules for file upload
    . ./orc_constants.ps1
    . ./orc_common.ps1
    . ./orc_logging.ps1
    . ./orc_web_client.ps1
    . ./orc_flex_login.ps1
    . ./orc_log_uploader.ps1
    . ./orc_config.ps1

    # Read config
    $config = ReadConfigFile -ConfigFile $ConfigPath
    if (-not $config) {
        Write-Error "Failed to read configuration file"
        exit 1
    }

    # Upload file silently (no stdout output, errors go to stderr)
    # Redirect stdout to null to suppress all output, but keep stderr for errors
    $success = UploadFile -FlexIP $config.common.flex_host_ip -FilePath $UploadFile -Config $config >$null

    if ($success) {
        exit 0
    } else {
        exit 1
    }
}

Write-Host @"
Copyright (c) 2025 Silk Technologies, Inc.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
https://github.com/Kaminario/echo-public-docs
"@

# Set error action preference to stop on any error
$ErrorActionPreference = "Stop"

# ConvertTo-SecureString should be available by default in PowerShell

if ($DebugPreference -eq 'Continue' -or $VerbosePreference -eq 'Continue') {
    $DebugPreference = 'Continue'
    $VerbosePreference = 'Continue'
} else {
    $DebugPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
}
#endregion

###########################################################################
# Load external scripts first
###########################################################################
# Constants
. ./orc_constants.ps1
# ConvertSecureStringToPlainText, EnsureOutputDirectory
. ./orc_common.ps1
# ErrorMessage, InfoMessage, ImportantMessage, DebugMessage, WarningMessage
. ./orc_logging.ps1

# Validate output directory and write permissions early
InfoMessage "Validating output directory and write permissions..."
if (-not (EnsureOutputDirectory -OutputDir $SilkEchoInstallerCacheDir)) {
    ErrorMessage "Output directory validation failed. Cannot proceed without write access to: $SilkEchoInstallerCacheDir"
    ErrorMessage "Please ensure the directory exists and you have write permissions, or run as administrator."
    return
}

# Start transcript logging to capture all output
try {
    # Determine log path: use -Log parameter if provided, otherwise use default
    $script:TranscriptPath = if ($Log) {
        # Convert to absolute path (PS 5.1+ compatible)
        $resolvedLog = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Log)

        # Truncate the log file (remove existing content)
        try {
            Set-Content -Path $resolvedLog -Value "" -ErrorAction Stop
        } catch {
            Write-Warning "Cannot write to log file: $resolvedLog"
            throw "No write access to specified log file location"
        }

        $resolvedLog
    } else {
        $script:SilkEchoFullLogPath
    }

    Start-Transcript -Path $script:TranscriptPath -Append
    Write-Host "Full execution log will be saved to: $script:TranscriptPath" -ForegroundColor Green


} catch {
    Write-Warning "Could not start transcript logging: $_"
}

#region cleanup_and_upload_logs
function cleanup_and_upload_logs {
    <#
    .SYNOPSIS
        Performs cleanup operations and uploads execution log.

    .DESCRIPTION
        Writes host summary, stops transcript logging, and uploads log file to Flex.
        All errors are handled gracefully and never propagated.

    .PARAMETER Config
        Configuration object containing Flex host IP and credentials.

    .PARAMETER TranscriptPath
        Path to the transcript log file to upload.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory=$true)]
        [string]$TranscriptPath
    )

    try {
        WriteHostsSummary -Hosts $Config.hosts -OutputPath "STDOUT"
    } catch {
        # Ignore errors in summary
    }

    try {
        Stop-Transcript
        InfoMessage "Full execution log saved to: $TranscriptPath"
    } catch {
        # Transcript may not have been started successfully
    }

    try {
        # Upload log file to Flex (optional feature - failures are handled gracefully)
        upload_logs -Config $Config -TranscriptPath $TranscriptPath
    } catch {
        # Ignore errors during log upload
    }
}
#endregion cleanup_and_upload_logs

# Add trap to ensure transcript is stopped on script termination
trap {
    cleanup_and_upload_logs -Config $config -TranscriptPath $script:TranscriptPath
    break
}

# Set script-scope variables for parameter passing
$script:MaxConcurrency = $MaxConcurrency
$script:processedHostsFile = $processedHostsFile


# Start-BatchJobProcessor - generic parallel job processing
. ./orc_generic_batch_processor.ps1
# CallSelfCertEndpoint, CallSDPApi, CallFlexApi
. ./orc_web_client.ps1
# UpdateFlexAuthToken
. ./orc_flex_login.ps1
# UploadFile
. ./orc_log_uploader.ps1
# SkipCertificateCheck
. ./orc_no_verify_cert.ps1
# ReadConfigFile, GenerateConfigTemplate
. ./orc_config.ps1
# EnsureRequirements
. ./orc_requirements.ps1
# UpdateHostSqlConnectionString
. ./orc_mssql.ps1
# UpdateSDPCredentials, GetSDPInfo
. ./orc_sdp.ps1
# EnsureLocalInstallers, UploadInstallersToHosts
. ./orc_uploader.ps1
# InstallSingleHost, FetchJobResult, ProcessSingleJobResult
. ./orc_invoke_remote_install.ps1
# StartBatchInstallation, SaveInstallationResults
. ./orc_batch_installer.ps1
# EnsureHostsConnectivity
. ./orc_host_communication.ps1
# GetHostInstallScript
. ./orc_host_setup_extractor.ps1
# ExpandImportsInline
. ./orc_import_expander.ps1
# LoadCompletedHosts, SaveCompletedHosts, IsHostCompleted, MarkHostCompleted
. ./orc_tracking.ps1
# GetMSSQLHostPorts
. ./orc_mssql_discovery.ps1

#region upload_logs
function upload_logs {
    <#
    .SYNOPSIS
        Uploads execution log to Flex.

    .DESCRIPTION
        Attempts to upload the orchestrator execution transcript log to Flex.
        This function never fails - all errors are handled gracefully and logged as warnings.
        The script execution continues regardless of upload success or failure.

    .PARAMETER Config
        Configuration object containing Flex host IP and credentials.

    .PARAMETER TranscriptPath
        Path to the transcript log file to upload.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory=$true)]
        [string]$TranscriptPath
    )

    try {
        # Check if Flex host IP is configured
        if (-not $Config.common.flex_host_ip) {
            DebugMessage "Skipping log upload: Flex host IP not configured"
            return
        }

        # Check if transcript file exists
        if (-not (Test-Path $TranscriptPath)) {
            DebugMessage "Skipping log upload: Transcript file not found at $TranscriptPath"
            return
        }

        # Try to get token from first host if available, otherwise will be obtained by UploadFile
        $flexToken = $null
        if ($Config.hosts.Count -gt 0 -and $Config.hosts[0].flex_access_token) {
            $flexToken = $Config.hosts[0].flex_access_token
            DebugMessage "Using Flex token from host configuration"
        }

        # Attempt upload - UploadFile handles all errors internally
        UploadFile -FlexIP $Config.common.flex_host_ip -FilePath $TranscriptPath -FlexToken $flexToken -Config $Config
    } catch {
        # Catch any unexpected errors - should never happen due to UploadFile error handling
        # but added as extra safety
        WarningMessage "Unexpected error during log upload: $_"
    }
}
#endregion upload_logs

#region MainOrchestrator
function MainOrchestrator {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$config
    )

    # Skip certificate check for Invoke-WebRequest,
    # this is needed for self-signed certificates of the Flex server
    SkipCertificateCheck

    # Load completed hosts to avoid duplicate installations (unless Force is specified)
    $completedHosts = LoadCompletedHosts -StateFilePath $script:processedHostsFile
    $originalHostCount = $config.hosts.Count

    if ($Force.IsPresent) {
        ImportantMessage "Force mode enabled - processing all $originalHostCount hosts regardless of previous completion status"
        # Clear completed hosts to ensure all hosts are processed
        $completedHosts = @{}
    } else {
        # Filter out already completed hosts
        $hostsToProcess = @()
        $skippedHosts = @()

        foreach ($hostInfo in $config.hosts) {
            if (IsHostCompleted -CompletedHosts $completedHosts -HostAddress $hostInfo.host_addr) {
                $skippedHosts += $hostInfo
            } else {
                $hostsToProcess += $hostInfo
            }
        }

        # Update config with hosts to process
        $config.hosts = $hostsToProcess

        if ($skippedHosts.Count -gt 0) {
            ImportantMessage "Skipping $($skippedHosts.Count) already completed hosts:"
            foreach ($hostInfo in $skippedHosts) {
                InfoMessage "  - $($hostInfo.host_addr) (completed previously)"
            }
        }

        if ($config.hosts.Count -eq 0) {
            ImportantMessage "All hosts have been processed successfully. No work to do."
            ImportantMessage "To reprocess hosts, delete or rename: $script:processedHostsFile"
            ImportantMessage "Or use the -Force parameter to reprocess all hosts."
            return
        }
    }

    ImportantMessage "Processing $($config.hosts.Count) of $originalHostCount total hosts."

    # Download and cache installer files locally (before asking for any credentials)
    InfoMessage "Ensuring installer files are available locally..."
    $localInstallerPaths = EnsureLocalInstallers -Config $config
    if (-not $localInstallerPaths) {
        ErrorMessage "Failed to ensure installer files are available. Cannot proceed with installation."
        return
    }

    $failedHosts = EnsureHostsConnectivity -hostEntries $config.hosts

    if ($failedHosts.Count -eq 0) {
        ImportantMessage "Hosts connectivity check succeeded."
    } else {
        # Log warnings but continue with valid hosts
        WarningMessage "Hosts connectivity check failed for $($failedHosts.Count) hosts:"
        foreach ($hostInfo in $failedHosts) {
            WarningMessage " - $($hostInfo.host_addr): $($hostInfo.issues -join '; ')"
        }
    }

    $hostsWithoutIssues = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })
    if ($hostsWithoutIssues.Count -eq 0) {
        ErrorMessage "No valid hosts remaining after connectivity validation. Cannot proceed."
        return
    }

    # make SQL server authentication string
    $ok = UpdateHostSqlConnectionString -Config $config
    if (-not $ok) {
        ErrorMessage "Failed to prepare SQL connection string. Cannot proceed with installation."
        return
    }

    # Validate SQL credentials by testing connection on each remote host
    InfoMessage "Validating SQL credentials on remote hosts..."
    $ok = ValidateHostSQLCredentials -Config $config
    if (-not $ok) {
        ErrorMessage "SQL credential validation failed. Cannot proceed with installation."
        return
    }

    # Login to Silk Flex and get the token
    $flexToken = UpdateFlexAuthToken -Config $config

    # Get and validate SDP credentials
    UpdateSDPCredentials -Config $config -flexToken $flexToken

    # Only process hosts without issues for installation
    $hostsWithoutIssues = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })
    if ($hostsWithoutIssues.Count -eq 0) {
        ErrorMessage "No valid hosts remaining after connectivity validation. Cannot proceed."
        return
    }

    InfoMessage "The following hosts will be configured:"
    foreach ($hostInfo in $hostsWithoutIssues) {
        InfoMessage "    $($hostInfo.host_addr)"
    }

    # Upload installer files to all hosts
    InfoMessage "Uploading installer files to target hosts..."
    UploadInstallersToHosts -HostInfos $hostsWithoutIssues -LocalPaths $localInstallerPaths -MaxConcurrency $script:MaxConcurrency

    # Check which hosts had upload failures and update remote computers list
    $hostsWithUploads = @($hostsWithoutIssues | Where-Object { $_.remote_installer_paths })
    $hostsWithFailedUploads = @($hostsWithoutIssues | Where-Object { -not $_.remote_installer_paths })

    if ($hostsWithFailedUploads.Count -gt 0) {
        WarningMessage "Upload failed for $($hostsWithFailedUploads.Count) hosts:"
        foreach ($hostInfo in $hostsWithFailedUploads) {
            WarningMessage " - $($hostInfo.host_addr): $($hostInfo.issues -join '; ')"
        }
    }


    # Only proceed with hosts that have successful uploads
    $remoteComputers = $hostsWithUploads

    if ($remoteComputers.Count -eq 0) {
        ErrorMessage "No hosts remain after upload failures. Cannot proceed with installation."
        return
    }

    $HostSetupScript = GetHostInstallScript -OrchestratorPath $PSCommandPath

    # Process imports in development mode
    if ($script:IsDevelopmentMode) {
        InfoMessage "Development mode detected - expanding imports in host script..."
        $HostSetupScript = ExpandImportsInline -ScriptContent $HostSetupScript
        if ($HostSetupScript -eq $null) {
            ErrorMessage "Failed to expand imports in host script."
            return
        }
    }

    # log all variables before call
    DebugMessage "Final configuration before installation:"

    $safeConfig = @{
        remoteComputers = $remoteComputers
        MaxConcurrency  = $script:MaxConcurrency
        DryRun          = $DryRun.IsPresent
        completedHosts  = $completedHosts
        processedHostsFile = $script:processedHostsFile
        HostSetupScript = if ($HostSetupScript) { "Loaded $($HostSetupScript.Length) bytes" } else { "Not Loaded" }
    }

    DebugMessage "Configuration is: $($safeConfig | ConvertTo-Json -Depth 10)"

    # Start batch installation process
    $results = StartBatchInstallation `
        -RemoteComputers   $remoteComputers `
        -Config            $config `
        -CompletedHosts    $completedHosts `
        -ProcessedHostsPath $script:processedHostsFile `
        -HostSetupScript   $HostSetupScript `
        -MaxConcurrency    $script:MaxConcurrency

    try {
        # Save installation results and generate summaries
        SaveInstallationResults `
            -Results $results `
            -Config $config `
            -CacheDirectory $SilkEchoInstallerCacheDir `
            -ProcessedHostsPath $script:processedHostsFile
    }
    catch {
        ErrorMessage "Error during remote installation: $_"
        return
    }
}

#region Start of the Execution

# Local Variables for Summary
[string]$script:HostList      = ""
[int]$script:NumOfHosts       = 0
[int]$script:NumOfSuccessHosts = 0
[int]$script:NumOfFailedHosts = 0

# Check if the user is running as administrator
$MessageCurrentObject = "Orchestrator"

# Header intro with common information
ImportantMessage "=================================================="
ImportantMessage "       Silk Echo Installer - v$($InstallerProduct)"
ImportantMessage "=================================================="

InfoMessage "PowerShell Version is - $($PSVersionTable.PSVersion.Major)"
InfoMessage "PowerShell Edition is - $($PSVersionTable.PSEdition)"
if ($Script:IsDevelopmentMode){
    ImportantMessage "IsDevelopmentMode is ON"
}

# Get current user information
if ($PSVersionTable.Platform -eq "Unix") {
    $userName = $env:USER
    InfoMessage "Current User: $userName"
    InfoMessage "Authentication Type: Local User Account"
    InfoMessage "Computer Name: $env:HOSTNAME"
    InfoMessage "Operating System: $(uname -a)"
    $userName = "$env:USER"
    $isDomainUser = $false
} else {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $currentUser.Name
    $isDomainUser = isActiveDirectoryUser

    InfoMessage "Current User: $userName"
    if ($isDomainUser) {
        InfoMessage "Authentication Type: Active Directory Domain User"
    } else {
        InfoMessage "Authentication Type: Local User Account"
    }
    InfoMessage "Computer Name: $env:COMPUTERNAME"
    InfoMessage "Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption)"
}

# Handle CreateConfigTemplate parameter
if ($CreateConfigTemplate) {
    GenerateConfigTemplate
    exit 0
}

# get the configuration file path from the command line argument -ConfigPath
if (-Not $ConfigPath) {
    ErrorMessage "Configuration file path is required. Please provide it as an argument to the script using -ConfigPath parameter."
    InfoMessage "Usage: .\orchestrator.ps1 -ConfigPath <path_to_config_file>"
    Exit 1
}

$config = ReadConfigFile -ConfigFile $ConfigPath
if (-Not $config) {
    ErrorMessage "Failed to read the configuration file. Please ensure it is a valid JSON file."
    Exit 1
}

$passedPreReqs = EnsureRequirements

if(!$passedPreReqs) {
	InfoMessage "PSVersion is - $($PSVersionTable.PSVersion.Major)"
	InfoMessage "PSEdition is - $($PSVersionTable.PSEdition)"
	WarningMessage "Requirements are not met,`nPlease fix the Requirements.`nGood Bye!"
	ErrorMessage "`n`tPress any key to continue...";
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	return
}

InfoMessage "Script Location: $PSScriptRoot"
InfoMessage "Configuration File: $ConfigPath"
InfoMessage "Max Concurrency: $script:MaxConcurrency hosts"

if ($DryRun) {
    ImportantMessage "Mode: DRY RUN (Validation Only - No Changes)"
} else {
    ImportantMessage "Mode: LIVE INSTALLATION"
}

if ($Force) {
    ImportantMessage "Force Mode: ENABLED (Ignoring completed hosts tracking)"
}

if ( $DebugPreference -eq 'Continue' ) {
    Write-Verbose "Verbose/Debug output is enabled."
    $safeConfig = @{
        installers = $config.installers
        hosts = $config.hosts
    }

    InfoMessage @"
Configuration is:
$($safeConfig | ConvertTo-Json -Depth 4)
"@
}
MainOrchestrator -config $config

if ($DryRun) {
    ImportantMessage "DryRun mode is enabled. No changes were made."
}

# Stop transcript logging and upload logs
cleanup_and_upload_logs -Config $config -TranscriptPath $script:TranscriptPath

exit 0

# MARKER: HOST_INSTALLER_STARTS_HERE

. ./orc_host_installer.ps1
