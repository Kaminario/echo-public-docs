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

.PARAMETER DryRun
    Perform validation of connectivity before running actual installation.
    It will validate connectivity from this host to the hosts defined in configuration file.
    After we have all the hosts validated, it will validate connectivity from each host to flex_host_ip and SDP.
    Default value is false.

.PARAMETER CreateConfigTemplate
    Generate a config.json template file based on config-example.json structure.
    When this parameter is used, the script will only create the template file and exit.

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

.INPUTS
    JSON configuration file with the following structure like generated with parameter -CreateConfigTemplate

.OUTPUTS
    Installation logs and status messages.
    Detailed logs are saved to installation_logs_<timestamp>.json file.

.NOTES
    File Name      : orchestrator.ps1
    Author         : Ilya.Levin@Silk.US
    Organization   : Silk.us, Inc.
    Version        : {{VERSION_PLACEHOLDER}}
    Copyright      : (c) 2024 Silk.us, Inc.
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
    https://github.com/silk-us/echo-public-docs

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
    [switch]$CreateConfigTemplate
)

# Set error action preference to stop on any error
$ErrorActionPreference = "Stop"

# ConvertTo-SecureString should be available by default in PowerShell

# Make MaxConcurrency a global variable accessible from any function
Set-Variable -Name MaxConcurrency -Value $MaxConcurrency -Option AllScope -Scope Script
Set-Variable -Name DryRun -Value $DryRun -Option AllScope -Scope Script

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
# ConvertSecureStringToPlainText
. ./orc_common.ps1
# ErrorMessage, InfoMessage, ImportantMessage, DebugMessage, WarningMessage
. ./orc_logging.ps1
# CallSelfCertEndpoint, CallSDPApi, CallFlexApi
. ./orc_web_client.ps1
# UpdateFlexAuthToken
. ./orc_flex_login.ps1
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
# EnsureHostsConnectivity
. ./orc_host_communication.ps1
# GetHostInstallScript
. ./orc_host_setup_extractor.ps1
# ExpandImportsInline
. ./orc_import_expander.ps1

#region MainOrchestrator
function MainOrchestrator {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$config
    )

    # Skip certificate check for Invoke-WebRequest,
    # this is needed for self-signed certificates of the Flex server
    SkipCertificateCheck

    # Save detailed logs to a file in $SilkEchoInstallerCacheDir
    ensureCacheDir $SilkEchoInstallerCacheDir

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
        # Log errors to stderr but continue execution
        Write-Error "Hosts connectivity check failed:" -ErrorAction Continue
        foreach ($hostInfo in $failedHosts) {
            Write-Error " - $($hostInfo.host_addr): $($hostInfo.host_connectivity_issue)" -ErrorAction Continue
        }
        return
    }

    # make SQL server authentication string
    $ok = UpdateHostSqlConnectionString -Config $config
    if (-not $ok) {
        ErrorMessage "Failed to prepare SQL connection string. Cannot proceed with installation."
        return
    }

    # Login to Silk Flex and get the token
    $flexToken = UpdateFlexAuthToken -Config $config

    # Get and validate SDP credentials
    UpdateSDPCredentials -Config $config -flexToken $flexToken

    # Add hosts to TrustedHosts if needed
    $remoteComputers = @($config.hosts)

    InfoMessage "The following hosts will be configured:"
    foreach ($hostInfo in $remoteComputers) {
        InfoMessage "    $($hostInfo.host_addr)"
    }

    # Upload installer files to all hosts
    InfoMessage "Uploading installer files to target hosts..."
    $uploadSuccess = UploadInstallersToHosts -HostInfos $remoteComputers -LocalPaths $localInstallerPaths -MaxConcurrency $MaxConcurrency
    if (-not $uploadSuccess) {
        ErrorMessage "Failed to upload installers to some hosts. Cannot proceed with installation."
        return
    }

    $HostSetupScript = GetHostInstallScript -OrchestratorPath $PSCommandPath

    # Process imports in development mode
    if ($IsDevelopmentMode) {
        InfoMessage "Development mode detected - expanding imports in host script..."
        $HostSetupScript = ExpandImportsInline -ScriptContent $HostSetupScript
        if ($HostSetupScript -eq $null) {
            ErrorMessage "Failed to expand imports in host script."
            return
        }
    }

    InfoMessage "Starting remote installation on $($remoteComputers.Count) hosts in batches of $MaxConcurrency..."
    try {
        $results = @()
        $totalHosts = $remoteComputers.Count
        $processedHosts = 0

        # Process hosts in chunks
        for ($batchStart = 0; $batchStart -lt $totalHosts; $batchStart += $MaxConcurrency) {
            $batchEnd = [Math]::Min($batchStart + $MaxConcurrency - 1, $totalHosts - 1)
            if ($batchStart -eq $batchEnd) {
                $currentBatch = @($remoteComputers[$batchStart])
            } else {
                $currentBatch = $remoteComputers[$batchStart..$batchEnd]
            }
            $batchNumber = [Math]::Floor($batchStart / $MaxConcurrency) + 1
            $totalBatches = [Math]::Ceiling($totalHosts / $MaxConcurrency)

            InfoMessage "Processing batch $batchNumber of $totalBatches (hosts $($batchStart + 1)-$($batchEnd + 1) of $totalHosts)..."

            # Start jobs for current batch
            $jobs = @()
            foreach ($hostInfo in $currentBatch) {
                $jobInfo = InstallSingleHost -HostInfo $hostInfo -Config $config -FlexToken $hostInfo.flex_access_token -SqlConnectionString $hostInfo.sql_connection_string -SdpCredentials $hostInfo.sdp_credential -HostSetupScript $HostSetupScript
                $jobs += $jobInfo
            }

            InfoMessage "Installation jobs started for batch $batchNumber. Waiting for completion..."

            # Process each job in the current batch
            foreach ($jobInfo in $jobs) {
                $result = ProcessSingleJobResult -JobInfo $jobInfo
                $results += $result

                if ($result.JobState -eq 'Success') {
                    $script:NumOfSuccessHosts++
                } else {
                    $script:NumOfFailedHosts++
                }
                $processedHosts++
            }

            InfoMessage "Batch $batchNumber completed. Progress: $processedHosts/$totalHosts hosts processed."
        }

        $logPath = Join-Path $SilkEchoInstallerCacheDir "installation_logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $logPath
        InfoMessage "Detailed logs saved to: $logPath"

        # Display summary
        InfoMessage "*************************************************"
        InfoMessage "Installation Summary:"
        InfoMessage "Total Hosts: $($remoteComputers.Count)"
        InfoMessage "Successful: $script:NumOfSuccessHosts"

        if ($script:NumOfFailedHosts -gt 0) {
            ErrorMessage "Failed: $script:NumOfFailedHosts"
            foreach ($result in $results | Where-Object { $_.JobState -eq 'Failed' }) {
                ErrorMessage "    $($result.ComputerName)"
            }
            ErrorMessage "Installation failed on $script:NumOfFailedHosts host(s). Check the logs for details. $logPath"
        } else {
            InfoMessage "Installation completed successfully on all hosts."
        }
        InfoMessage "*************************************************"
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
$MessageCurrentObject = "Echo Installer"

# Header intro with common information
ImportantMessage "=================================================="
ImportantMessage "       Silk Echo Installer - v$($InstallerProduct)"
ImportantMessage "=================================================="

InfoMessage "PowerShell Version is - $($PSVersionTable.PSVersion.Major)"
InfoMessage "PowerShell Edition is - $($PSVersionTable.PSEdition)"

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
} else {
    # clear the console
    #clear-host
}

InfoMessage "Script Location: $PSScriptRoot"
InfoMessage "Configuration File: $ConfigPath"
InfoMessage "Max Concurrency: $MaxConcurrency hosts"

if ($DryRun) {
    ImportantMessage "Mode: DRY RUN (Validation Only - No Changes)"
} else {
    ImportantMessage "Mode: LIVE INSTALLATION"
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

exit 0

# MARKER: HOST_INSTALLER_STARTS_HERE

. ./orc_host_installer.ps1
