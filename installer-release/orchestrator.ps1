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
.PARAMETER Upgrade
    Upgrade mode: skip Flex registration, SQL validation, and SDP credential checks.
    Only host connectivity and installer upload are performed, then silent installers are run.
    Use this to upgrade existing installations without re-registering hosts.
    Can be combined with -CreateConfigTemplate to generate a minimal config for upgrades.
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
    .\orchestrator.ps1 -CreateConfigTemplate -Upgrade
    Generates a minimal config-upgrade.json template for upgrade mode (no credentials needed).
.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -Force
    Processes all hosts in configuration, ignoring any previously completed installations.
.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -Log "C:\Logs\installation.log"
    Runs the installation and saves a full transcript of all output to the specified log file.
.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -Upgrade
    Upgrades existing installations on hosts without re-registering with Flex.
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
    Version        : 0.1.11
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
    [Parameter(Mandatory=$false, HelpMessage="Upgrade mode: skip registration and run silent installers only")]
    [switch]$Upgrade
)
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
#region orc_constants
#region Constants
Set-Variable -Name InstallerProduct -Value "0.1.11" -Option AllScope -Scope Script
Set-Variable -Name MessageCurrentObject -Value "Silk Echo Installer" -Option AllScope -Scope Script
Set-Variable -Name ENUM_ACTIVE_DIRECTORY -Value "active_directory" -Option AllScope -Scope Script
Set-Variable -Name ENUM_CREDENTIALS -Value "credentials" -Option AllScope -Scope Script
# Component versions and installer URLs
#region orc_component_versions
# Component versions - update these to lock specific releases
Set-Variable -Name SilkAgentVersion -Value "v1.1.8" -Option AllScope -Scope Script
Set-Variable -Name SvssVersion -Value "2.0.18" -Option AllScope -Scope Script
# Installer URLs
Set-Variable -Name SilkAgentURL -Value "https://storage.googleapis.com/silk-public-files/silk-agent-installer-$SilkAgentVersion.exe" -Option AllScope -Scope Script
Set-Variable -Name SilkVSSURL -Value "https://storage.googleapis.com/silk-public-files/svss-$SvssVersion.exe" -Option AllScope -Scope Script
#endregion orc_component_versions
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
#endregion orc_constants
# ConvertSecureStringToPlainText, EnsureOutputDirectory
#region orc_common
#region Common Utility Functions
#region EnsureOutputDirectory
function EnsureOutputDirectory {
    <#
    .SYNOPSIS
        Validates output directory existence and write permissions for logs and artifacts.
    .DESCRIPTION
        This function ensures that the output directory exists and validates that the current
        user has write permissions to create log files and store installation artifacts.
        This validation happens early in the script to prevent failures during execution.
    .PARAMETER OutputDir
        The directory path where logs and artifacts will be stored.
    .RETURNS
        Boolean - True if directory is valid and writable, False otherwise
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )
    try {
        # Create directory if it doesn't exist
        if (-not (Test-Path $OutputDir)) {
            InfoMessage "Creating output directory: $OutputDir"
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
            InfoMessage "Output directory created successfully."
        } else {
            InfoMessage "Output directory exists: $OutputDir"
        }
        # Test write permissions by creating a temporary test file
        $testFile = Join-Path $OutputDir "write_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').tmp"
        InfoMessage "Testing write permissions in output directory..."
        try {
            # Try to create and write to a test file
            "Write permission test" | Out-File -FilePath $testFile -Encoding UTF8
            # Verify file was created
            if (Test-Path $testFile) {
                InfoMessage "Write permissions validated successfully."
                # Clean up test file
                Remove-Item $testFile -Force
                return $true
            } else {
                ErrorMessage "Failed to verify test file creation in output directory."
                return $false
            }
        } catch {
            ErrorMessage "Write permission test failed: $_"
            return $false
        }
    } catch {
        ErrorMessage "Failed to create or validate output directory: $_"
        return $false
    }
}
#endregion EnsureOutputDirectory
#region ConvertSecureStringToPlainText
function ConvertSecureStringToPlainText {
    param (
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$SecureString
    )
    if (-not $SecureString) {
        return $null
    }
    try {
        # Create a temporary PSCredential to extract the plain text password
        $tempCred = New-Object System.Management.Automation.PSCredential("temp", $SecureString)
        return $tempCred.GetNetworkCredential().Password
    } catch {
        Write-Error "Failed to convert SecureString to plain text: $_"
        return $null
    }
}
#endregion ConvertSecureStringToPlainText
#endregion Common Utility Functions
#endregion orc_common
# ErrorMessage, InfoMessage, ImportantMessage, DebugMessage, WarningMessage
#region orc_logging
#region Logging
Function LogTimeStamp {
    # returns formatted timestamp
	return Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
}
function Sanitize {
    param (
        [string]$Text
    )
    # Reduct password from text, sometimes text contains connection string with password
    # Updated regex to handle both plain connection strings and JSON-embedded strings
    # Match password value until semicolon OR quote OR end of line
    $ReductedText = $Text -replace '(?i)(?<=Password=)[^;"]+', '[reducted]'
    # Replace the value of the $FlexToken variable with '[reducted]' only if it exists and is not empty
    if ($Global:FlexToken -and $Global:FlexToken.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:FlexToken), '[reducted]'
    }
    # Replace the value of the $SDPPassword variable with '[reducted]' only if it exists and is not empty
    if ($Global:SDPPassword -and $Global:SDPPassword.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:SDPPassword), '[reducted]'
    }
    return $ReductedText
}
Function ArgsToSanitizedString {
    $sanitizedArgs = @()
    foreach ($arg in $args) {
        if ($arg -is [System.Management.Automation.ErrorRecord]) {
            $sanitizedArgs += Sanitize -Text $arg.Exception.Message
        } else {
            $sanitizedArgs += Sanitize -Text $arg.ToString()
        }
    }
    return [string]::Join(' ', $sanitizedArgs)
}
Function ErrorMessage {
    $msg = ArgsToSanitizedString @args
    Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [ERROR] $msg" -ForegroundColor Red
    Write-Error "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [ERROR] - $msg" -ErrorAction Continue
}
Function ImportantMessage {
    $msg = ArgsToSanitizedString @args
    Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [INFO] $msg" -ForegroundColor Green
}
Function InfoMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [INFO] $msg"
}
Function DebugMessage {
    if ($DebugPreference -ne 'Continue') {
        return
    }
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [DEBUG] $msg"
}
Function WarningMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [WARN] $msg" -ForegroundColor Yellow
}
#region HostsSummaryReport
function WriteHostsSummary {
    <#
    .SYNOPSIS
        Writes a summary of all hosts with their issues and results to a file.
    .DESCRIPTION
        This function writes hosts summary to a file in a structured format:
        1. First shows all hosts with issues
        2. Then shows all hosts with results
        Format for each host:
        hostname:
          issues:
          - issue1
          - issue2
          result: {json object}
    .PARAMETER Hosts
        Array of host objects to write
    .PARAMETER OutputPath
        Path to the output file where summary will be written. Use "STDOUT" to print to console instead of writing to file
    .EXAMPLE
        WriteHostsSummary -Hosts $config.hosts -OutputPath "hosts_summary.txt"
    .EXAMPLE
        WriteHostsSummary -Hosts $config.hosts -OutputPath "STDOUT"
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Array]$Hosts,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    if ($Hosts.Count -eq 0) {
        if ($OutputPath -eq "STDOUT") {
            Write-Host "No hosts to display"
        } else {
            "No hosts to display" | Out-File -FilePath $OutputPath -Encoding UTF8
            InfoMessage "Hosts summary written to: $OutputPath"
        }
        return
    }
    # Separate hosts with issues and hosts with results
    $hostsWithIssues = @($Hosts | Where-Object { $_.issues.Count -gt 0 })
    $hostsWithResults = @($Hosts | Where-Object { $_.result -ne $null -and $_.issues.Count -eq 0 })
    # Create output content array
    $outputLines = @()
    $outputLines += "=============== HOSTS SUMMARY ==============="
    $outputLines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $outputLines += ""
    # Write hosts with issues first
    if ($hostsWithIssues.Count -gt 0) {
        $outputLines += "HOSTS WITH ISSUES ($($hostsWithIssues.Count)):"
        $outputLines += ""
        foreach ($hostInfo in $hostsWithIssues) {
            $outputLines += "$($hostInfo.host_addr):"
            if ($hostInfo.issues.Count -gt 0) {
                $outputLines += "  issues:"
                foreach ($issue in $hostInfo.issues) {
                    $outputLines += "  - $issue"
                }
            }
            if ($hostInfo.result) {
                $outputLines += "  result:"
                $outputLines += "    Host Address: $($hostInfo.result.HostAddress)"
                $outputLines += "    Job State: $($hostInfo.result.JobState)"
                if ($hostInfo.result.Info -and $hostInfo.result.Info.Count -gt 0) {
                    $outputLines += "    Info:"
                    foreach ($info in $hostInfo.result.Info) {
                        if ($info -and $info.PSObject.Properties.Count -gt 0) {
                            foreach ($prop in $info.PSObject.Properties) {
                                $outputLines += "      $($prop.Name): $($prop.Value)"
                            }
                        }
                    }
                }
                if ($hostInfo.result.Error -and $hostInfo.result.Error.Count -gt 0) {
                    $outputLines += "    Errors:"
                    foreach ($error in $hostInfo.result.Error) {
                        $outputLines += "      - $error"
                    }
                }
            } else {
                $outputLines += "  result: null"
            }
            $outputLines += ""
        }
    }
    # Write hosts with results
    if ($hostsWithResults.Count -gt 0) {
        $outputLines += "HOSTS WITH RESULTS ($($hostsWithResults.Count)):"
        $outputLines += ""
        foreach ($hostInfo in $hostsWithResults) {
            # Skip hosts that were already shown in issues section
            if ($hostInfo.issues.Count -gt 0) {
                continue
            }
            $outputLines += "$($hostInfo.host_addr):"
            $outputLines += "  issues: none"
            $outputLines += "  result:"
            $outputLines += "    Host Address: $($hostInfo.result.HostAddress)"
            $outputLines += "    Job State: $($hostInfo.result.JobState)"
            if ($hostInfo.result.Info -and $hostInfo.result.Info.Count -gt 0) {
                $outputLines += "    Info:"
                foreach ($info in $hostInfo.result.Info) {
                    if ($info -and $info.PSObject.Properties.Count -gt 0) {
                        foreach ($prop in $info.PSObject.Properties) {
                            $outputLines += "      $($prop.Name): $($prop.Value)"
                        }
                    }
                }
            }
            if ($hostInfo.result.Error -and $hostInfo.result.Error.Count -gt 0) {
                $outputLines += "    Errors:"
                foreach ($error in $hostInfo.result.Error) {
                    $outputLines += "      - $error"
                }
            }
            $outputLines += ""
        }
    }
    # Output to console or file
    if ($OutputPath -eq "STDOUT") {
        # Print to console
        foreach ($line in $outputLines) {
            Write-Host $line
        }
    } else {
        # Write to file
        $outputLines | Out-File -FilePath $OutputPath -Encoding UTF8
        InfoMessage "Hosts report written to: $OutputPath"
    }
}
function DisplayInstallationSummary {
    <#
    .SYNOPSIS
        Displays a short summary of installation results to console.
    .DESCRIPTION
        Shows only the counts - how many hosts succeeded, failed, etc.
        For detailed information, use WriteHostsSummary.
    .PARAMETER Hosts
        Array of host objects to summarize
    .EXAMPLE
        DisplayInstallationSummary -Hosts $config.hosts
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Array]$Hosts
    )
    if ($Hosts.Count -eq 0) {
        InfoMessage "No hosts processed"
        return
    }
    $totalHosts = $Hosts.Count
    $successfulHosts = @($Hosts | Where-Object { $_.result.JobState -eq 'Success' }).Count
    $failedHosts = @($Hosts | Where-Object { $_.result.JobState -eq 'Failed' }).Count
    $hostsWithIssues = @($Hosts | Where-Object { $_.issues.Count -gt 0 }).Count
    InfoMessage "=============== INSTALLATION SUMMARY ==============="
    InfoMessage "Total hosts: $totalHosts"
    InfoMessage "Successful: $successfulHosts"
    InfoMessage "Failed: $failedHosts"
    InfoMessage "With issues: $hostsWithIssues"
    InfoMessage "=================================================="
}
#endregion HostsSummaryReport
#endregion Logging
#endregion orc_logging
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
    # Add trap to ensure transcript is stopped on script termination
    trap {
        try {
            WriteHostsSummary -Hosts $config.hosts -OutputPath "STDOUT"
            Stop-Transcript
        } catch { }
        break
    }
} catch {
    Write-Warning "Could not start transcript logging: $_"
}
# Set script-scope variables for parameter passing
$script:MaxConcurrency = $MaxConcurrency
$script:processedHostsFile = $processedHostsFile
# Start-BatchJobProcessor - generic parallel job processing
#region orc_generic_batch_processor
#region Generic Batch Job Processor
<#
.SYNOPSIS
    Generic reusable batch job processor with dynamic concurrency control.
.DESCRIPTION
    Processes jobs in parallel batches with dynamic concurrency management.
    Used by upload, connectivity testing, and installation procedures.
    Implements the core pattern: start jobs when slots open, process results immediately.
.PARAMETER Items
    Array of items to process (hosts, files, etc.)
.PARAMETER JobScriptBlock
    ScriptBlock to execute for each item as a background job
.PARAMETER ResultProcessor
    ScriptBlock to process completed job results
.PARAMETER MaxConcurrency
    Maximum number of concurrent jobs (default: 10)
.PARAMETER JobDescription
    Description for logging (e.g., "upload", "connectivity test", "installation")
#>
function Start-BatchJobProcessor {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$Items,
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$JobScriptBlock,
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ResultProcessor,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10,
        [Parameter(Mandatory=$false)]
        [string]$JobDescription = "job"
    )
    # Animation characters for progress spinner
    $spinnerChars = @('-', '\', '|', '/')
    $spinnerIndex = 0
    InfoMessage "Starting $JobDescription processing for $($Items.Count) item(s) with max concurrency: $MaxConcurrency..."
    # Start jobs using dynamic batch processing pattern
    $jobs = @()
    $processedCount = 0
    $totalItems = $Items.Count
    $startedCount = 0
    $startTime = Get-Date
    foreach ($item in $Items) {
        # DYNAMIC BATCHING PATTERN: Wait if we've reached max concurrency
        while ($jobs.Count -ge $MaxConcurrency) {
            $completedJob = $jobs | Where-Object { $_.Job.State -ne 'Running' } | Select-Object -First 1
            if ($completedJob) {
                # Process completed job immediately
                & $ResultProcessor $completedJob
                $jobs = @($jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id })
                $processedCount++
                # Clear spinner line and show progress message
                Write-Host "`r" + (" " * 80) + "`r" -NoNewline
                $runningCount = $jobs.Count
                InfoMessage "Completed: $processedCount of $totalItems $JobDescription jobs completed, $runningCount running"
            } else {
                # Show spinner animation while waiting
                $elapsed = (Get-Date) - $startTime
                $elapsedStr = "{0:mm\:ss}" -f $elapsed
                Write-Host "`r[$elapsedStr] - $($spinnerChars[$spinnerIndex]) $JobDescription in progress. Completed $processedCount of $totalItems" -NoNewline
                $spinnerIndex = ($spinnerIndex + 1) % $spinnerChars.Count
                Start-Sleep -Seconds 1
            }
        }
        # Start new job when slot is available
        DebugMessage "Starting $JobDescription job for item: $($item | ConvertTo-Json -Compress)"
        $job = Start-Job -ScriptBlock $JobScriptBlock -ArgumentList $item
        $startedCount++
        $jobs += @{
            Job = $job
            Item = $item
        }
        # Progress message when starting jobs
        if ($startedCount % 5 -eq 0 -or $startedCount -eq $totalItems) {
            InfoMessage "Progress: Started $startedCount of [$processedCount/$totalItems] $JobDescription jobs, $($jobs.Count) running"
        }
    }
    # DYNAMIC COMPLETION PATTERN: Wait for remaining jobs to complete
    InfoMessage "Waiting for remaining $JobDescription jobs to complete..."
    while ($jobs.Count -gt 0) {
        $completedJob = $jobs | Where-Object { $_.Job.State -ne 'Running' } | Select-Object -First 1
        if ($completedJob) {
            & $ResultProcessor $completedJob
            $jobs = @($jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id })
            $processedCount++
            # Clear spinner line and show progress message
            Write-Host "`r" + (" " * 80) + "`r" -NoNewline
            $runningCount = $jobs.Count
            InfoMessage "Progress: $processedCount of $totalItems $JobDescription jobs completed, $runningCount remaining"
        } else {
            # Show spinner animation while waiting
            $elapsed = (Get-Date) - $startTime
            $elapsedStr = "{0:mm\:ss}" -f $elapsed
            Write-Host "`r[$elapsedStr] - $($spinnerChars[$spinnerIndex]) $JobDescription in progress. Completed $processedCount of $totalItems" -NoNewline
            $spinnerIndex = ($spinnerIndex + 1) % $spinnerChars.Count
            Start-Sleep -Seconds 1
        }
    }
    # Keep the last spinner line visible by adding a newline
    Write-Host "`n"
    $finalElapsed = (Get-Date) - $startTime
    $finalElapsedStr = "{0:mm\:ss}" -f $finalElapsed
    InfoMessage "Completed $JobDescription processing for $processedCount of $totalItems items in $finalElapsedStr"
}
#endregion Generic Batch Job Processor
#endregion orc_generic_batch_processor
# CallSelfCertEndpoint, CallSDPApi, CallFlexApi
#region orc_web_client
#region NETWORK
#region CallSelfCertEndpoint
function CallSelfCertEndpoint {
    param (
        [string]$URL,
        [string]$HttpMethod,
        [object]$RequestBody,
        [hashtable]$Headers
    )
    DebugMessage "Calling [$HttpMethod]$URL"
    # capitalize the first letter of HttpMethod
    $HttpMethod = $HttpMethod.Substring(0,1).ToUpper() + $HttpMethod.Substring(1).ToLower()
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        if ( $HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
    } else {
        if ($HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            # If no request body is provided
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -ErrorAction Stop
        }
    }
    return $response
}
#endregion CallSelfCertEndpoint
#region CallSDPApi
function CallSDPApi {
    param (
        [string]$SDPHost,
        [string]$SDPPort,
        [string]$ApiEndpoint,
        [System.Management.Automation.PSCredential]$Credential
    )
    $url = "https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"
    DebugMessage "Call SDPApi USERNAME: $($Credential.UserName)"
    $BasicAuthString = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $BasicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($BasicAuthString))
    $_headers = @{
        "Authorization" = "Basic $BasicAuth"
    }
    try {
        $response = CallSelfCertEndpoint -URL $url -HttpMethod "GET" -RequestBody $null -Headers $_headers
        if ($response.StatusCode -ne 200) {
            ErrorMessage "Failed to call SDP API at $url. Status code: $($response.StatusCode)"
            return $null
        }
        DebugMessage "Response from SDP API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling SDP API: $_"
        return $null
    }
}
#endregion CallSDPApi
#region CallFlexApi
function CallFlexApi {
        param (
        [string]$FlexIP,
        [string]$FlexToken,
        [string]$ApiEndpoint,
        [string]$HttpMethod,
        [string]$RequestBody
    )
    $flexApiUrl = "https://$FlexIP$ApiEndpoint"
    $headers = @{ "Authorization" = "Bearer $FlexToken" }
    DebugMessage "Calling Flex API at $flexApiUrl with method $HttpMethod"
    try {
        $response = CallSelfCertEndpoint -URL $flexApiUrl -HttpMethod $HttpMethod -RequestBody $RequestBody -Headers $headers
        DebugMessage "Response from Flex API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling Flex API: $_"
        return $null
    }
}
#endregion CallFlexApi
#endregion NETWORK
#endregion orc_web_client
# UpdateFlexAuthToken
#region orc_flex_login
#region FlexLogin
#region getFlexCredentials
function getFlexCredentials {
    WarningMessage "Please provide Silk Flex credentials."
    $cred = Get-Credential -Message "Enter your Silk Flex credentials"
    if (-not $cred) {
        ErrorMessage "No credentials provided. Exiting."
        Exit 1
    }
    return $cred
}
#endregion getFlexCredentials
#region loginToFlex
function loginToFlex {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexIP,
        [string]$FlexUser,
        [string]$FlexPass
    )
    <#
        curl 'https://52.151.194.250/api/v1/auth/local/login' \
        -X POST \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-raw 'password=*****&username=kaminario'
        response = {"access_token":"******","expiresIn":604800,"expiresOn":"2025-07-08 14:32:43"}
    #>
    # Use provided credentials or ask user for them
    if ($FlexUser -and $FlexPass) {
        $username = $FlexUser
        $password = $FlexPass
    } else {
        $cred = getFlexCredentials
        $username = $cred.UserName
        $password = $cred.GetNetworkCredential().Password
    }
    $body = @{
        username = $username
        password = $password
    }
    $url = "https://$FlexIP/api/v1/auth/local/login"
    $headers = @{
        'Accept' = 'application/json'
        'Content-Type' = 'application/x-www-form-urlencoded'
    }
    try {
        $response = CallSelfCertEndpoint -URL $url -HttpMethod 'POST' -RequestBody $body -Headers $headers
        if ($response.StatusCode -eq 200) {
            InfoMessage "Successfully logged in to Silk Flex at $FlexIP"
            # Parse the response content to extract the access token
            $JsonResponse = $response.Content | ConvertFrom-Json
            return $JsonResponse.access_token
        } else {
            ErrorMessage "Failed to log in to Silk Flex: $($response.StatusDescription)"
            return ""
        }
    } catch {
        ErrorMessage "Error during login to Silk Flex: $_"
        return ""
    }
}
#endregion UpdateFlexAuthToken
function UpdateFlexAuthToken {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    # Use flex credentials from common section or prompt user
    InfoMessage "Processing Flex credentials..."
    $flexIP = $Config.common.flex_host_ip
    $flexUser = $Config.common.flex_user
    $flexPass = if ($Config.common.flex_pass) {
        ConvertSecureStringToPlainText -SecureString $Config.common.flex_pass
    } else {
        $null
    }
    # Get access token from Flex
    $flexToken = $null
    while (-not $flexToken) {
        $flexToken = loginToFlex -FlexIP $flexIP -FlexUser $flexUser -FlexPass $flexPass
        if (-not $flexToken) {
            InfoMessage "Please re-enter credentials."
            $flexUser = $null
            $flexPass = $null
        }
    }
    # Apply the access token to all hosts
    foreach ($hostInfo in $Config.hosts) {
        $hostInfo | Add-Member -MemberType NoteProperty -Name "flex_access_token" -Value $flexToken -Force
    }
    InfoMessage "Successfully obtained and assigned Flex token for $flexIP to $($Config.hosts.Count) host(s)"
    return $flexToken
}
#endregion UpdateFlexAuthToken
#endregion orc_flex_login
# SkipCertificateCheck
#region orc_security
#region SetTLSVersion
function SetTLSVersion {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        # if Powershell version is 7 or higher, set both TLS 1.2 and TLS 1.3
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
            Write-Host "Enabled TLS 1.2 and TLS 1.3."
        }
        catch {
            Write-Host "TLS 1.3 not supported, enabling only TLS 1.2."
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Write-Host "Enabled TLS 1.2."
        }
    } else {
        # for Windows PowerShell, set only TLS 1.2
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Write-Host "Enabled TLS 1.2."
    }
}
#endregion SetTLSVersion
#region SkipCertificateCheck
function SkipCertificateCheck {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        # if Powershell version is 7 or higher, set SkipCertificateCheck
        return
    }
    # set policy only once per powershell sessions
    $currentPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    if ($currentPolicy -eq $null -or ($currentPolicy.GetType().FullName -ne "TrustAllCertsPolicy")) {
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    } else {
        Write-Host "Certificate policy already set to $([System.Net.ServicePointManager]::CertificatePolicy). skipping."
    }
}
#endregion SkipCertificateCheck
#endregion orc_security
# ReadConfigFile, GenerateConfigTemplate
#region orc_config
#region ConfigFile
function GenerateConfigTemplate {
    $configPath = Join-Path $PSScriptRoot "config.json"
    # Check if config.json already exists and ask for confirmation
    if (Test-Path -Path $configPath) {
        WarningMessage "Configuration file already exists: $configPath"
        $overwrite = Read-Host "Do you want to overwrite the existing config.json file? (y/N)"
        if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
            InfoMessage "Configuration template creation cancelled."
            Exit 0
        }
    }
    $useKerberos = Read-Host "Would you like to use Active Directory authentication for the hosts? (Y/n)"
    if ($useKerberos -eq 'Y' -or $useKerberos -eq 'y' -or $useKerberos -eq '') {
        $UseKerberos = $true
    } else {
        $UseKerberos = $false
    }
    $installVss = Read-Host "Would you like to install Silk VSS Provider on the hosts? (Y/n)"
    if ($installVss -eq 'Y' -or $installVss -eq 'y' -or $installVss -eq '') {
        $InstallVSS = $true
    } else {
        $InstallVSS = $false
    }
    Write-Host ""
    Write-Host "Installation Directory Configuration:" -ForegroundColor Yellow
    Write-Host "  - Leave empty to use system default installation paths"
    Write-Host "  - Provide a path (e.g., 'C:\CustomPath') to install components to a custom directory"
    $installDir = Read-Host "Target installation directory (press Enter for default)"
    $InstallToDirectory = $installDir.Trim()
    $templateConfigJson = '{"installers":{"agent":{"path": ""},"vss": {"path": ""}},"common":{"install_agent":true,"install_vss":true,"install_to_directory":"","sdp_id":"sdp_id","sdp_user":"sdp_user","sdp_pass":"sdp_pass","sql_user":"sql_user","sql_pass":"sql_pass","sql_server":"host,port","flex_host_ip":"flex-ip","flex_user":"flex_user","flex_pass":"flex_pass","host_user":"host_user","host_pass":"host_pass","host_auth":"unset","mount_points_directory":"C:\\MountPoints"},"hosts":[{"host_addr":"host_ip","sql_user":"sql_user_1","sql_pass":"sql_pass_1"},"host_ip","host_ip"]}'
    # load template as json, make chages, and dump in a pretty way
    $ConfObj = $templateConfigJson | ConvertFrom-Json
    $ConfObj.common.install_vss = $InstallVSS
    $ConfObj.common.install_to_directory = $InstallToDirectory
    if ($UseKerberos) {
        $ConfObj.common.host_auth = $ENUM_ACTIVE_DIRECTORY
        if ($ConfObj.common.PSObject.Properties['host_user']) {
            $ConfObj.common.PSObject.Properties.Remove('host_pass')
        }
        if ($ConfObj.common.PSObject.Properties['host_user']) {
            $ConfObj.common.PSObject.Properties.Remove('host_user')
        }
        # update hosts with <hostname> instead of <host_ip>
        for ($i = 0; $i -lt $ConfObj.hosts.Count; $i++) {
            $hostEntry = $ConfObj.hosts[$i]
            if ($hostEntry -is [string]) {
                # Replace string with hostname
                $ConfObj.hosts[$i] = "hostname"
            } else {
                # It's an object, remove host_user and host_pass properties and update host
                if ($hostEntry.PSObject.Properties['host_user']) {
                    $hostEntry.PSObject.Properties.Remove('host_user')
                }
                if ($hostEntry.PSObject.Properties['host_pass']) {
                    $hostEntry.PSObject.Properties.Remove('host_pass')
                }
                $hostEntry.host_addr = "hostname"
            }
        }
    } else {
        $ConfObj.common.host_auth = $ENUM_CREDENTIALS
    }
    try {
        $formattedJson = $ConfObj | ConvertTo-Json -Depth 2
        $formattedJson | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "Configuration template created successfully: $configPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "Please edit the config.json file with your specific values." -ForegroundColor Yellow
        Write-Host "- Update SQL credentials and mount point directories as needed"
        Write-Host "- Add or remove hosts as required"
        Write-Host ""
    } catch {
        Write-Error "Failed to create configuration template: $_"
        Exit 1
    }
    Exit 0
}
function GenerateUpgradeConfigTemplate {
    $configPath = Join-Path $PSScriptRoot "config-upgrade.json"
    # Check if file already exists
    if (Test-Path -Path $configPath) {
        WarningMessage "Configuration file already exists: $configPath"
        $overwrite = Read-Host "Do you want to overwrite the existing file? (y/N)"
        if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
            InfoMessage "Configuration template creation cancelled."
            Exit 0
        }
    }
    Write-Host ""
    Write-Host "Generating UPGRADE mode configuration template..." -ForegroundColor Yellow
    Write-Host "This template contains only fields required for upgrading existing installations." -ForegroundColor Yellow
    Write-Host ""
    $useKerberos = Read-Host "Would you like to use Active Directory authentication for the hosts? (Y/n)"
    if ($useKerberos -eq 'Y' -or $useKerberos -eq 'y' -or $useKerberos -eq '') {
        $UseKerberos = $true
    } else {
        $UseKerberos = $false
    }
    $installVss = Read-Host "Would you like to upgrade Silk VSS Provider on the hosts? (Y/n)"
    if ($installVss -eq 'Y' -or $installVss -eq 'y' -or $installVss -eq '') {
        $InstallVSS = $true
    } else {
        $InstallVSS = $false
    }
    # Minimal template for upgrade mode
    $templateConfigJson = '{"installers":{"agent":{"path":""},"vss":{"path":""}},"common":{"install_agent":true,"install_vss":true,"host_user":"host_user","host_pass":"host_pass","host_auth":"unset"},"hosts":["host_ip","host_ip","host_ip"]}'
    $ConfObj = $templateConfigJson | ConvertFrom-Json
    $ConfObj.common.install_vss = $InstallVSS
    if ($UseKerberos) {
        $ConfObj.common.host_auth = $ENUM_ACTIVE_DIRECTORY
        $ConfObj.common.PSObject.Properties.Remove('host_pass')
        $ConfObj.common.PSObject.Properties.Remove('host_user')
        $ConfObj.hosts = @("hostname", "hostname", "hostname")
    } else {
        $ConfObj.common.host_auth = $ENUM_CREDENTIALS
    }
    try {
        $formattedJson = $ConfObj | ConvertTo-Json -Depth 2
        $formattedJson | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "Upgrade configuration template created: $configPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "Please edit the file with your specific values." -ForegroundColor Yellow
        Write-Host "- Update installer paths (or leave empty to use default URLs)"
        Write-Host "- Add or remove hosts as required"
        Write-Host ""
        Write-Host "Usage: .\orchestrator.ps1 -ConfigPath config-upgrade.json -Upgrade" -ForegroundColor Cyan
        Write-Host ""
    } catch {
        Write-Error "Failed to create configuration template: $_"
        Exit 1
    }
    Exit 0
}
function constructHosts {
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$CommonConfig,
        [Parameter(Mandatory=$true)]
        [Array]$HostEntries
    )
    # for each host in a list create an object that contains all common properties
    $processedHosts = @()
    foreach ($hostEntry in $HostEntries) {
        $hostObject = New-Object -TypeName PSObject
        # Add all common properties to the new object
        foreach ($property in $CommonConfig.PSObject.Properties) {
            Add-Member -InputObject $hostObject -MemberType NoteProperty -Name $property.Name -Value $property.Value
        }
        if ($hostEntry -is [string]) {
            # If the host is just a string (IP or hostname)
            Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "host_addr" -Value $hostEntry -Force
        } elseif ($hostEntry -is [psobject]) {
            # If the host is an object with specific properties
            foreach ($property in $hostEntry.PSObject.Properties) {
                Add-Member -InputObject $hostObject -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force
            }
        }
        # convert host_pass to secure string
        if ($hostObject.host_pass) {
            $hostObject.host_pass = ConvertTo-SecureString $hostObject.host_pass -AsPlainText -Force
        }
        if ($hostObject.sql_pass) {
            $hostObject.sql_pass = ConvertTo-SecureString $hostObject.sql_pass -AsPlainText -Force
        }
        if ($hostObject.sdp_pass) {
            $hostObject.sdp_pass = ConvertTo-SecureString $hostObject.sdp_pass -AsPlainText -Force
        }
        if ($hostObject.flex_pass) {
            $hostObject.flex_pass = ConvertTo-SecureString $hostObject.flex_pass -AsPlainText -Force
        }
        # Convert to boolean if host overrides with non-boolean value (inherited values are already boolean from common)
        if ($hostObject.install_agent -isnot [bool]) {
            $hostObject.install_agent = [bool]$hostObject.install_agent
        }
        if ($hostObject.install_vss -isnot [bool]) {
            $hostObject.install_vss = [bool]$hostObject.install_vss
        }
        # Validate that at least one component is being installed (after any host-level overrides)
        if (-not $hostObject.install_agent -and -not $hostObject.install_vss) {
            ErrorMessage "Host '$($hostObject.host_addr)' has both install_agent and install_vss set to false. At least one component must be installed."
            return $null
        }
        # Initialize issues field for tracking connectivity and upload problems
        Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "issues" -Value @() -Force
        # remote_installer_paths
        Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "remote_installer_paths" -Value @() -Force
        # sql_connection_string
        Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "sql_connection_string" -Value $null -Force
        # sql_connection_params (parsed connection parameters hashtable)
        Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "sql_connection_params" -Value $null -Force
        # sdp_credentials
        Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "sdp_credential" -Value $null -Force
        if (-not $hostObject.sql_user) {
            Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "sql_user" -Value $null -Force
        }
        if (-not $hostObject.sql_pass) {
            Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "sql_pass" -Value $null -Force
        }
        # Initialize result field for storing job result after installation
        Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "result" -Value $null -Force
        $processedHosts += $hostObject
    }
    return $processedHosts
}
function ReadConfigFile {
    # read the configuration file passed as parameter to this scipt "-Config"
    # ConfigFile can be a full or relative path to the JSON file
    # {
    # "installers": {
    #     "agent": {
    #         "url": "remote_url",
    #         "path": ""
    #     },
    #     "vss": {
    #         "url": "remote_url",
    #         "path": ""
    #     }
    # },
    # "common": {
    #     "sdp_id": "sdp_id",
    #     "sdp_user": "sdp_user",
    #     "sdp_pass": "sdp_pass",
    #     "sql_user": "sql_user",
    #     "sql_pass": "sql_pass",
    #     "sql_server": "host,port",
    #     "flex_host_ip": "flex_host_ip",
    #     "flex_user": "flex_user",
    #     "flex_pass": "flex_pass",
    #     "host_user": "host_user",
    #     "host_pass": "host_pass",
    #     "host_auth": "credentials",  // or "active_directory"
    #     "mount_points_directory": "C:\\MountPoints"
    # },
    # "hosts": [
    #     {
    #     "host_addr": "10.30.40.50",
    #     "sql_user": "sql_user_1",
    #     "sql_pass": "sql_pass_1",
    #     },
    #     "10.30.40.51",
    #     "10.30.40.52"
    #     ]
    # }
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConfigFile,
        [Parameter(Mandatory=$false)]
        [switch]$Upgrade
    )
    if (-Not (Test-Path -Path $ConfigFile)) {
        Write-Error -Message "Configuration file not found: $ConfigFile"
        Exit 1
    }
    try {
        $config = Get-Content -Path $ConfigFile | ConvertFrom-Json
    } catch {
        return $null
    }
    # Get the common configuration
    $commonConfig = $config.common
    # Upgrade mode: only require hosts list
    if ($Upgrade.IsPresent) {
        if (-not $config.hosts) {
            ErrorMessage "Configuration file must contain 'hosts' field"
            return $null
        }
    } else {
        # Full install mode: require all credential fields
        if (-not ($config.hosts -and
              $commonConfig.flex_host_ip -and
              $commonConfig.sdp_id -and
              $commonConfig.mount_points_directory -and
              $commonConfig.mount_points_directory -ne "")) {
            ErrorMessage "Configuration file must contain 'hosts', 'flex_host_ip', 'sdp_id', and 'mount_points_directory' fields"
            return $null
        }
    }
    # Validate hosts array is not empty
    if ($config.hosts.Count -eq 0) {
        ErrorMessage "Configuration file must contain at least one host"
        return $null
    }
    # Set default values in common section before constructing hosts (so hosts inherit these defaults)
    if (-not $commonConfig.PSObject.Properties['install_agent']) {
        Add-Member -InputObject $commonConfig -MemberType NoteProperty -Name "install_agent" -Value $true
    } elseif ($commonConfig.install_agent -isnot [bool]) {
        # Convert to boolean only if not already boolean
        $commonConfig.install_agent = [bool]$commonConfig.install_agent
    }
    if (-not $commonConfig.PSObject.Properties['install_vss']) {
        Add-Member -InputObject $commonConfig -MemberType NoteProperty -Name "install_vss" -Value $true
    } elseif ($commonConfig.install_vss -isnot [bool]) {
        # Convert to boolean only if not already boolean
        $commonConfig.install_vss = [bool]$commonConfig.install_vss
    }
    if (-not $commonConfig.PSObject.Properties['install_to_directory']) {
        Add-Member -InputObject $commonConfig -MemberType NoteProperty -Name "install_to_directory" -Value ""
    }
    # Validate at least one component is enabled in common section
    if (-not $commonConfig.install_agent -and -not $commonConfig.install_vss) {
        ErrorMessage "Both install_agent and install_vss are set to false in common section. At least one component must be enabled."
        return $null
    }
    $config.hosts = constructHosts -CommonConfig $commonConfig -HostEntries $config.hosts
    # convert all common.pass to ConvertTo-SecureString
    if ($commonConfig.sdp_pass) {
        $commonConfig.sdp_pass = ConvertTo-SecureString -String $commonConfig.sdp_pass -AsPlainText -Force
    }
    if ($commonConfig.sql_pass) {
        $commonConfig.sql_pass = ConvertTo-SecureString -String $commonConfig.sql_pass -AsPlainText -Force
    }
    if ($commonConfig.flex_pass) {
        $commonConfig.flex_pass = ConvertTo-SecureString -String $commonConfig.flex_pass -AsPlainText -Force
    }
    if ($commonConfig.host_pass) {
        $commonConfig.host_pass = ConvertTo-SecureString -String $commonConfig.host_pass -AsPlainText -Force
    }
    # Check common section for installation flags (default to true if not specified)
    $installAgent = $true
    $installVSS = $true
    if ($commonConfig.PSObject.Properties['install_agent']) {
        $installAgent = [bool]$commonConfig.install_agent
    }
    if ($commonConfig.PSObject.Properties['install_vss']) {
        $installVSS = [bool]$commonConfig.install_vss
    }
    # Validate at least one component is enabled at common level
    if (-not $installAgent -and -not $installVSS) {
        ErrorMessage "Both install_agent and install_vss are set to false in common section. At least one component must be enabled."
        return $null
    }
    # Only ensure installer defaults for components that might be installed
    if ($installAgent) {
        ensureInstallerDefault -Config $config -InstallerName "agent" -DefaultUrl $SilkAgentURL
    } else {
        InfoMessage "Agent installation disabled in common config - skipping agent installer validation"
    }
    if ($installVSS) {
        ensureInstallerDefault -Config $config -InstallerName "vss" -DefaultUrl $SilkVSSURL
    } else {
        InfoMessage "VSS installation disabled in common config - skipping VSS installer validation"
    }
    # the sql connection script is optional.
    # Validate that all hosts have unique addresses
    $hostAddresses = @()
    foreach ($hostInfo in $config.hosts) {
        if ($hostAddresses -contains $hostInfo.host_addr) {
            ErrorMessage "Duplicate host address found: '$($hostInfo.host_addr)'. All hosts must have unique IP addresses or hostnames."
            return $null
        }
        $hostAddresses += $hostInfo.host_addr
    }
    # all hosts must have "host_auth"; "flex_host_ip" only required for full install
    foreach ($hostInfo in $config.hosts) {
        if (-not $hostInfo.host_auth) {
            ErrorMessage "Host '$($hostInfo.host_addr)' is missing 'host_auth' property. Update the host or a common section."
            return $null
        }
        # flex_host_ip validation only in full install mode
        if (-not $Upgrade.IsPresent) {
            if (-not $hostInfo.flex_host_ip) {
                ErrorMessage "Host '$($hostInfo.host_addr)' is missing 'flex_host_ip' property. Update the host or a common section."
                return $null
            }
            # Validate flex_host_ip is a valid IP address
            if (-not ($hostInfo.flex_host_ip -as [IPAddress])) {
                ErrorMessage "Host '$($hostInfo.host_addr)' has invalid flex_host_ip '$($hostInfo.flex_host_ip)'. Must be a valid IP address."
                return $null
            }
        }
    }
    return $config
}
#region ensureInstallerDefault
function ensureInstallerDefault {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [string]$InstallerName,
        [Parameter(Mandatory=$true)]
        [string]$DefaultUrl
    )
    try {
        $url = $Config.installers.$InstallerName.url
        if (-not $url) { throw }
    } catch {
        InfoMessage "$InstallerName installer URL missing. Using default: $DefaultUrl"
        if (-not $Config.installers) { $Config | Add-Member -NotePropertyName "installers" -NotePropertyValue @{} -Force }
        if (-not $Config.installers.$InstallerName) { $Config.installers | Add-Member -NotePropertyName $InstallerName -NotePropertyValue @{} -Force }
        $Config.installers.$InstallerName | Add-Member -NotePropertyName "url" -NotePropertyValue $DefaultUrl -Force
    }
}
#endregion ensureInstallerDefault
#endregion ConfigFile
#endregion orc_config
# EnsureRequirements
#region orc_requirements
#region checkAdminPrivileges
function checkAdminPrivileges {
    # CheckAdminPrivileges Function - Checking the current user in Windows and Linux environment. You must run as administrator (Windows)
    if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))	{
        return $false
    } else {
        DebugMessage "Running as an Administrator, on Windows OS version - $((Get-CimInstance Win32_OperatingSystem).version)"
	    return $true
    }
}
#endregion checkAdminPrivileges
#region EnsureRequirements
function EnsureRequirements {
    $PSVersion = $PSVersionTable.PSVersion.Major
    $ShellEdition = $PSVersionTable.PSEdition
    $passedPreReqs = $true
    # Check if running on Linux platform - not supported for this Windows-based installation
    if ($PSVersionTable.Platform -eq "Unix") {
        ErrorMessage "This installer is designed for Windows environments only."
        ErrorMessage "PowerShell remoting to Windows hosts from Linux is not supported by this script."
        ErrorMessage "Please run this script from a Windows machine with PowerShell 5.1 or 7.x."
        passedPreReqs = $false
    }
    if ($PSVersion -lt 5) {
        WarningMessage "PowerShell version is $PSVersion, but version 5 or higher is required."
        $passedPreReqs = $false
    }
    if ($ShellEdition -ne "Core" -and $ShellEdition -ne "Desktop") {
        WarningMessage "PowerShell edition is $ShellEdition, but only Core or Desktop editions are supported."
        $passedPreReqs = $false
    }
    InfoMessage "Checking if the script is running with elevated privileges..."
    if (-not (CheckAdminPrivileges)) {
        WarningMessage "The script is not running with elevated privileges. Please run the script as an administrator."
        $passedPreReqs = $false
    }
    # Host installer script is now extracted dynamically by GetHostInstallScript function
    DebugMessage "Host installer will be extracted dynamically from orchestrator content."
    return $passedPreReqs
}
#endregion
#endregion orc_requirements
# UpdateHostSqlConnectionString
#region orc_mssql
#region SQL
#region TestSQLConnectionRemote
function TestSQLConnectionRemote {
    <#
    .SYNOPSIS
        Tests SQL Server connection on a remote host via PowerShell remoting.
    .DESCRIPTION
        Executes SQL connection test on the remote host where SQL Server is running.
        Uses existing host authentication (Active Directory or Credentials).
    .PARAMETER HostInfo
        Host object containing connection information and credentials
    .PARAMETER ConnectionString
        SQL Server connection string to test
    .OUTPUTS
        Returns $true if connection succeeds, $false otherwise
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$HostInfo,
        [Parameter(Mandatory=$true)]
        [string]$ConnectionString
    )
    $scriptBlock = {
        param($ConnString)
        try {
            $sqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnString)
            $sqlConnection.Open()
            $sqlConnection.Close()
            return @{ Success = $true; Error = $null }
        } catch {
            return @{ Success = $false; Error = $_.Exception.Message }
        }
    }
    try {
        # Use the same authentication method already validated by EnsureHostsConnectivity
        if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
            # Use current domain credentials (Kerberos)
            $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                     -ScriptBlock $scriptBlock `
                                     -ArgumentList $ConnectionString `
                                     -ErrorAction Stop
        }
        elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Use explicit credentials
            $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
            $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                     -Credential $credential `
                                     -SessionOption $sessionOption `
                                     -ScriptBlock $scriptBlock `
                                     -ArgumentList $ConnectionString `
                                     -ErrorAction Stop
        }
        else {
            ErrorMessage "Invalid host_auth value for $($HostInfo.host_addr): $($HostInfo.host_auth)"
            return $false
        }
        if ($result.Success) {
            InfoMessage "SQL credential validation successful for $($HostInfo.host_addr)"
            return $true
        } else {
            DebugMessage "SQL credential validation failed for $($HostInfo.host_addr): $($result.Error)"
            return $false
        }
    } catch {
        ErrorMessage "Failed to test SQL connection on $($HostInfo.host_addr): $_"
        return $false
    }
}
#endregion TestSQLConnectionRemote
#region TestSQLCredentialsInParallel
function TestSQLCredentialsInParallel {
    <#
    .SYNOPSIS
        Tests SQL credentials in parallel across multiple hosts.
    .DESCRIPTION
        Executes SQL connection tests concurrently using the batch job processor.
        Updates host issues array with connection failures.
    .PARAMETER HostEntries
        Array of host objects to test
    .PARAMETER MaxConcurrency
        Maximum number of concurrent tests (default: 10)
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Array]$HostEntries,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )
    # SQL connection test job logic
    $sqlTestJobScript = {
        param($HostInfo, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS, $GetMSSQLHostPortsScript)
        function InfoMessageSQL { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - SQLJob - [INFO] $message"}
        function DebugMessageSQL { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - SQLJob - [DEBUG] $message"}
        function WarningMessageSQL { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - SQLJob - [WARN] $message"}
        # Remote script that will execute on target host
        $remoteTestScript = {
            param($ConnectionString, $GetMSSQLHostPortsScript)
            # Define logging functions (used by both this script and GetMSSQLHostPorts)
            function InfoMessage { param($m) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [INFO] $m" }
            function DebugMessage { param($m) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [DEBUG] $m" }
            function WarningMessage { param($m) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [WARN] $m" }
            # Define GetMSSQLHostPorts in remote scope
            $GetMSSQLHostPortsFunc = [ScriptBlock]::Create($GetMSSQLHostPortsScript)
            function GetMSSQLHostPorts { & $GetMSSQLHostPortsFunc }
            # Parse connection string
            $baseParams = @{}
            $parts = $ConnectionString.Trim() -split ';'
            foreach ($part in $parts) {
                if ($part.Trim()) {
                    $key, $value = $part -split '=', 2
                    $baseParams[$key.Trim()] = $value.Trim()
                }
            }
            # Build list of servers to test
            $serversToTest = @()
            if ($baseParams.ContainsKey('Server') -and $baseParams['Server'] -ne '') {
                # Case 1: Server specified - list with only one item
                InfoMessage "Server specified: $($baseParams['Server'])"
                $serversToTest = @($baseParams['Server'])
            } else {
                # Case 2: Server missing - discover and return list
                InfoMessage "No server specified, performing auto-discovery..."
                try {
                    $serversToTest = GetMSSQLHostPorts
                } catch {
                    return @{ Success = $false; Error = "Auto-discovery failed: $($_.Exception.Message)"; ErrorType = 'connection_error' }
                }
            }
            if ($serversToTest.Count -eq 0) {
                return @{ Success = $false; Error = "No SQL Server endpoints found"; ErrorType = 'connection_error' }
            }
            InfoMessage "Testing $($serversToTest.Count) endpoint(s)..."
            # Test each server in the list
            $lastError = $null
            $lastErrorType = 'unknown'
            foreach ($serverEndpoint in $serversToTest) {
                $testParams = $baseParams.Clone()
                $testParams['Server'] = $serverEndpoint
                $testConnString = ($testParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'
                DebugMessage "Testing: $serverEndpoint"
                try {
                    $sqlConn = New-Object System.Data.SqlClient.SqlConnection($testConnString)
                    $sqlConn.Open()
                    $sqlConn.Close()
                    InfoMessage "Success at: $serverEndpoint"
                    return @{ Success = $true; Error = $null; ErrorType = $null; ConnectionString = $testConnString }
                } catch {
                    $errorMessage = $_.Exception.Message
                    DebugMessage "Failed: $errorMessage"
                    # Categorize error type
                    if ($errorMessage -match 'Login failed|password|authentication|user') {
                        $lastErrorType = 'credential_error'
                        DebugMessage "Error categorized as: credential_error"
                    } elseif ($errorMessage -match 'server|timeout|network|could not open a connection|connection|host|address|endpoint') {
                        $lastErrorType = 'connection_error'
                        DebugMessage "Error categorized as: connection_error"
                    } else {
                        $lastErrorType = 'unknown'
                        DebugMessage "Error categorized as: unknown"
                    }
                    $lastError = $errorMessage
                }
            }
            return @{ Success = $false; Error = "Failed to connect to any SQL Server endpoint. Last error: $lastError"; ErrorType = $lastErrorType }
        }
        try {
            InfoMessageSQL "Testing SQL credentials for host $($HostInfo.host_addr)..."
            # Execute remote test
            $result = $null
            if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                         -ScriptBlock $remoteTestScript `
                                         -ArgumentList $HostInfo.sql_connection_string, $GetMSSQLHostPortsScript `
                                         -ErrorAction Stop
            }
            elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                         -Credential $credential `
                                         -SessionOption $sessionOption `
                                         -ScriptBlock $remoteTestScript `
                                         -ArgumentList $HostInfo.sql_connection_string, $GetMSSQLHostPortsScript `
                                         -ErrorAction Stop
            }
            else {
                return @{ Success = $false; Error = "Invalid host_auth value"; ErrorType = 'connection_error' }
            }
            if ($result.Success) {
                InfoMessageSQL "SQL validation successful for $($HostInfo.host_addr)"
                return @{ Success = $true; Error = $null; ErrorType = $null; ConnectionString = $result.ConnectionString }
            } else {
                return @{ Success = $false; Error = $result.Error; ErrorType = $result.ErrorType }
            }
        } catch {
            return @{ Success = $false; Error = "Remote test failed: $($_.Exception.Message)"; ErrorType = 'connection_error' }
        }
    }
    # Result processor
    $resultProcessor = {
        param($JobInfo)
        $job = $JobInfo.Job
        $hostInfo = $JobInfo.Item
        if ($job.State -eq 'Completed') {
            $testResult = Receive-Job -Job $job
            if ($testResult -and $testResult.Success) {
                $sanitizedConnString = Sanitize $testResult.ConnectionString
                DebugMessage "SQL validation succeeded for $($hostInfo.host_addr), returned connection string: $sanitizedConnString"
                InfoMessage "SQL credential validation successful for $($hostInfo.host_addr)"
            } else {
                $errorMsg = if ($testResult.Error) { $testResult.Error } else { "Unknown SQL connection error" }
                $errorType = if ($testResult.ErrorType) { $testResult.ErrorType } else { "unknown" }
                DebugMessage "SQL validation failed for $($hostInfo.host_addr) - ErrorType: $errorType, Error: $errorMsg"
                # ALWAYS add to issues with error type embedded in the message
                # Format: "SQL validation failed [error_type]: error message"
                $issueMsg = "SQL validation failed [$errorType]: $errorMsg"
                DebugMessage "Adding to issues: $issueMsg"
                $hostInfo.issues += $issueMsg
                # Log appropriate message based on error type
                if ($errorType -eq 'connection_error') {
                    WarningMessage "SQL connection failed for $($hostInfo.host_addr) due to server configuration issue: $errorMsg"
                } else {
                    WarningMessage "SQL credential validation failed for $($hostInfo.host_addr): $errorMsg"
                }
            }
        } else {
            $stdErrOut = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            $errorMsg = "SQL validation job failed for $($hostInfo.host_addr). State: $($job.State). $stdErrOut"
            DebugMessage "Job state is $($job.State), adding to issues"
            $hostInfo.issues += "SQL validation failed [unknown]: $errorMsg"
        }
        DebugMessage ">>>>>>>>>>>>Removing job $($job.Id)"
        Remove-Job -Job $job -Force
        DebugMessage "<<<<<<<<<<<<Job $($job.Id) removed"
    }
    # Get GetMSSQLHostPorts function definition as string to pass to remote job
    $getMSSQLHostPortsFunc = Get-Command GetMSSQLHostPorts
    $getMSSQLHostPortsScript = $getMSSQLHostPortsFunc.Definition
    # Enhanced job script that includes constants and discovery function
    $jobScriptWithConstants = {
        param($hostInfo)
        & ([ScriptBlock]::Create($using:sqlTestJobScript)) $hostInfo $using:ENUM_ACTIVE_DIRECTORY $using:ENUM_CREDENTIALS $using:getMSSQLHostPortsScript
    }
    # Use generic batch processor
    Start-BatchJobProcessor -Items $HostEntries -JobScriptBlock $jobScriptWithConstants -ResultProcessor $resultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "SQLValidation"
}
#endregion TestSQLCredentialsInParallel
#region ValidateHostSQLCredentials
function ValidateHostSQLCredentials {
    <#
    .SYNOPSIS
        Validates SQL credentials for all hosts requiring Agent installation.
    .DESCRIPTION
        Tests SQL Server connection for each host using TestSQLConnectionRemote.
        Prompts for new credentials if validation fails and retries until successful.
        Only retests hosts that previously failed validation.
        User can press Ctrl+C to abort the process.
    .PARAMETER Config
        Configuration object containing all host information
    .OUTPUTS
        Returns $true if all SQL credentials are valid, $false if user cancels
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    $goodHost = @($Config.hosts | Where-Object { $_.issues.Count -eq 0 })
    # Check if any hosts need Agent installation
    $hostsNeedingAgent = @($goodHost | Where-Object { $_.install_agent -eq $true })
    if ($hostsNeedingAgent.Count -eq 0) {
        InfoMessage "No hosts require Agent installation - skipping SQL credential validation"
        return $true
    }
    InfoMessage "Validating SQL credentials for $($hostsNeedingAgent.Count) host(s)..."
    $attempt = 1
    while ($hostsNeedingAgent.Count -gt 0) {
        # Test SQL credentials in parallel for remaining hosts
        InfoMessage "Testing SQL credentials in parallel (Attempt $attempt)..."
        TestSQLCredentialsInParallel -HostEntries $hostsNeedingAgent -MaxConcurrency $script:MaxConcurrency
        # Collect hosts that failed validation (have issues)
        $failedHosts = @($hostsNeedingAgent | Where-Object { $_.issues.Count -gt 0 })
        $successfulHosts = @($hostsNeedingAgent | Where-Object { $_.issues.Count -eq 0 })
        # Show progress after each attempt
        InfoMessage "SQL validation attempt $attempt results: $($successfulHosts.Count) successful, $($failedHosts.Count) failed"
        # Only clear issues and retry for hosts with credential_error
        # All other errors (connection_error, unknown) are not retriable
        $hostsToRetry = @()
        foreach ($hostInfo in $failedHosts) {
            $hasCredentialError = $false
            foreach ($issue in $hostInfo.issues) {
                if ($issue -match '\[credential_error\]') {
                    $hasCredentialError = $true
                    break
                }
            }
            if ($hasCredentialError) {
                # Credential error - clear issues and retry
                DebugMessage "Host $($hostInfo.host_addr) has credential_error, clearing issues for retry"
                $hostInfo.issues = @()
                $hostsToRetry += $hostInfo
            } else {
                # Non-retriable error - keep issues, don't retry
                DebugMessage "Host $($hostInfo.host_addr) has non-retriable error, keeping issue - host will be skipped"
                WarningMessage "Host $($hostInfo.host_addr) has non-retriable SQL validation error and will be skipped"
            }
        }
        # Update to only retry hosts with credential errors
        $hostsNeedingAgent = @($hostsToRetry)
        # If all hosts passed, we're done
        if ($hostsNeedingAgent.Count -eq 0) {
            # Generate comprehensive validation summary
            $allHostsNeedingAgent = @($Config.hosts | Where-Object { $_.install_agent -eq $true })
            $successfulHosts = @($allHostsNeedingAgent | Where-Object { $_.issues.Count -eq 0 })
            $failedHosts = @($allHostsNeedingAgent | Where-Object { $_.issues.Count -gt 0 })
            if ($failedHosts.Count -eq 0) {
                ImportantMessage "SQL credential validation completed successfully for all hosts"
            } else {
                ImportantMessage "SQL credential validation completed with some failures"
            }
            InfoMessage "Validation Summary:"
            InfoMessage "  Successful hosts: $($successfulHosts.Count)"
            InfoMessage "  Failed hosts: $($failedHosts.Count)"
            InfoMessage "  Total hosts requiring Agent: $($allHostsNeedingAgent.Count)"
            if ($successfulHosts.Count -gt 0) {
                InfoMessage "Hosts with successful SQL validation:"
                foreach ($h in $successfulHosts) {
                    InfoMessage "  - $($h.host_addr)"
                }
            }
            if ($failedHosts.Count -gt 0) {
                WarningMessage "Hosts with SQL validation failures (will be skipped):"
                foreach ($h in $failedHosts) {
                    $issues = $h.issues -join '; '
                    WarningMessage "  - $($h.host_addr) - $issues"
                }
            }
            return $true
        }
        # Prompt for new credentials
        $failedAddresses = $hostsNeedingAgent | ForEach-Object { $_.host_addr }
        WarningMessage "SQL credential validation failed for hosts: $($failedAddresses -join ', ')"
        WarningMessage "Please provide new SQL credentials (press Ctrl+C to abort)"
        $newCred = Get-Credential -Message "Enter SQL Server credentials"
        if (-not $newCred) {
            ErrorMessage "User cancelled SQL credential prompt. Cannot proceed without valid SQL Server credentials."
            return $false
        }
        # Update only failed hosts with new credentials and rebuild connection strings
        $newUser = $newCred.UserName
        $newPass = $newCred.GetNetworkCredential().Password
        foreach ($hostInfo in $hostsNeedingAgent) {
            # Update credentials
            $hostInfo.sql_user = $newUser
            $hostInfo.sql_pass = $newPass
            # Update credentials in the stored connection params hashtable
            $hostInfo.sql_connection_params['User ID'] = $newUser
            $hostInfo.sql_connection_params['Password'] = $newPass
            # Rebuild connection string from updated params
            $connectionStringParts = $hostInfo.sql_connection_params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
            $hostInfo.sql_connection_string = [string]::Join(';', $connectionStringParts)
            $LogSqlConnectionString = Sanitize $hostInfo.sql_connection_string
            DebugMessage "Updated SQL connection string for host $($hostInfo.host_addr): $LogSqlConnectionString"
        }
        $attempt++
    }
    # Should never reach here, but just in case
    return $true
}
#endregion ValidateHostSQLCredentials
#region UpdateHostSqlConnectionString
function UpdateHostSqlConnectionString {
    param (
        [PSCustomObject]$Config
    )
    # each host in $config.hosts can contain "sql_user", and "sql_pass"
    # if missing ask for credentials and use it for all hosts without credentials
    # create a connectrion string for each host and update $config.hosts with "sql_connection_string"
    DebugMessage "Checking SQL credentials for each host..."
    $defaultSqlUser = $null
    $defaultSqlPass = $null
    $shouldPromptForCredentials = $false
    $goodHost = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })
    # Check if any hosts need Agent installation
    $hostsNeedingAgent = @($goodHost | Where-Object { $_.install_agent -eq $true })
    if ($hostsNeedingAgent.Count -eq 0) {
        InfoMessage "No hosts require Agent installation - skipping SQL credential collection"
        return $true
    }
    # Check if any hosts requiring Agent are missing SQL credentials
    foreach ($hostInfo in $hostsNeedingAgent) {
        DebugMessage "Checking host $($hostInfo.host_addr) - sql_user='$($hostInfo.sql_user)' sql_pass='$($hostInfo.sql_pass)'"
        if ([string]::IsNullOrEmpty($hostInfo.sql_user) -or [string]::IsNullOrEmpty($hostInfo.sql_pass)) {
            DebugMessage "Host $($hostInfo.host_addr) missing credentials, setting shouldPromptForCredentials=true"
            $shouldPromptForCredentials = $true
            break
        }
    }
    InfoMessage "Should prompt for SQL credentials: $shouldPromptForCredentials"
    # If any hosts are missing credentials, prompt user for credentials
    if ($shouldPromptForCredentials) {
        DebugMessage "Prompting user for SQL credentials"
        WarningMessage "Some hosts are missing SQL credentials. Please provide credentials to use for all hosts with missing credentials."
        $credSQL = Get-Credential -Message "Enter SQL Server credentials"
        if (-not $credSQL) {
            DebugMessage "User cancelled credential prompt"
            ErrorMessage "No credentials provided. Cannot proceed without valid SQL Server credentials."
            return $false
        }
        DebugMessage "Credentials received, extracting username and password"
        $defaultSqlUser = $credSQL.UserName
        $defaultSqlPass = $credSQL.GetNetworkCredential().Password
        DebugMessage "Applying credentials to hosts with missing sql_user or sql_pass"
        # Apply credentials to all hosts that are missing either username or password
        foreach ($hostInfo in $Config.hosts) {
            if ([string]::IsNullOrEmpty($hostInfo.sql_user) -or [string]::IsNullOrEmpty($hostInfo.sql_pass)) {
                DebugMessage "Updating both sql_user and sql_pass for host $($hostInfo.host_addr)"
                $hostInfo.sql_user = $defaultSqlUser
                $hostInfo.sql_pass = $defaultSqlPass
            }
        }
    }
    foreach ($hostInfo in $Config.hosts) {
        # Build connection string parameters
        $hostSqlPass = if ($hostInfo.sql_pass -is [System.Security.SecureString]) {
            DebugMessage "Retrieving SQL password for host $($hostInfo.host_addr)"
            ConvertSecureStringToPlainText -SecureString $hostInfo.sql_pass
        } else {
            $hostInfo.sql_pass
        }
        $connectionParams = @{
            'User ID' = $hostInfo.sql_user
            'Password' = $hostSqlPass
            'Application Name' = 'SilkAgent'
        }
        # Add SQL Server parameter if specified (bypasses endpoint discovery)
        if ($hostInfo.sql_server) {
            $connectionParams['Server'] = $hostInfo.sql_server
            InfoMessage "Using specified SQL Server for host $($hostInfo.host_addr): $($hostInfo.sql_server)"
        } else {
            InfoMessage "No SQL Server specified for host $($hostInfo.host_addr), endpoint discovery will be performed during installation"
        }
        # Store parsed connection parameters for later reuse
        $hostInfo.sql_connection_params = $connectionParams
        # Build the connection string
        $connectionStringParts = $connectionParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)
        # Add connection string to host object
        $hostInfo.sql_connection_string = $connectionString
        # Log the connection string (with masked password)
        $LogSqlConnectionString = Sanitize $connectionString
        DebugMessage "Prepared SQL connection string for host $($hostInfo.host_addr): $LogSqlConnectionString"
    }
    ImportantMessage "Successfully prepared SQL connection strings for all hosts"
    return $true
}
#endregion UpdateHostSqlConnectionString
#endregion SQL
#endregion orc_mssql
# UpdateSDPCredentials, GetSDPInfo
#region orc_sdp
#region SDP
#region validateSDPConnection
function validateSDPConnection {
    param (
        [string]$SDPHost,
        [string]$SDPPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ApiEndpoint = 'system/state'
    DebugMessage "validateSDPConnection USERNAME: $($Credential.UserName)"
    $response = CallSDPApi -SDPHost $SDPHost -SDPPort $SDPPort -ApiEndpoint $ApiEndpoint -Credential $Credential
    if (-not $response) {
        ErrorMessage "Failed to call SDP API at https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"
        return $false
    }
    return $true
}
#endregion validateSDPConnection
#region getSDPCredentials
function getSDPCredentials {
    param (
        [PSCustomObject]$HostInfo,
        [string]$SDPHost,
        [string]$SDPPort
    )
    # Use SDP credentials from common section or prompt user
    $sdp_id = $HostInfo.sdp_id
    $sdpUser = if ($HostInfo.sdp_user) { $HostInfo.sdp_user } else { $null }
    $sdpPass = if ($HostInfo.sdp_pass) { $HostInfo.sdp_pass } else { $null }
    # Get validated SDP credentials
    $SDPCredential = $null
    $SdpConnectionValid = $false
    while (-not $SdpConnectionValid) {
        # Try with provided credentials first, then prompt if needed
        if ($sdpUser -and $sdpPass) {
            $SDPCredential = New-Object System.Management.Automation.PSCredential($sdpUser, $sdpPass)
        } else {
            WarningMessage "Please provide SDP (Silk Data Platform) credentials for the installation"
            $SDPCredential = Get-Credential -Message "Enter your SDP credentials"
            if (-not $SDPCredential) {
                Continue
            }
        }
        $SdpConnectionValid = validateSDPConnection -SDPHost $SDPHost -SDPPort $SDPPort -Credential $SDPCredential
        if (-not $SdpConnectionValid) {
            ErrorMessage "Failed to validate SDP connection. Please check your credentials and try again."
            # Reset credentials to force prompt on next iteration
            $sdpUser = $null
            $sdpPass = $null
        }
    }
    InfoMessage "SDP credentials retrieved successfully."
    return $SDPCredential
}
#endregion getSDPCredentials
#region UpdateSDPCredentials
function UpdateSDPCredentials {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [string]$flexToken
    )
    InfoMessage "Processing SDP credentials..."
    $goodHost = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })
    # Check if any hosts need VSS installation
    $hostsNeedingVSS = @($goodHost | Where-Object { $_.install_vss -eq $true })
    if ($hostsNeedingVSS.Count -eq 0) {
        InfoMessage "No hosts require VSS installation - skipping SDP credential collection"
        return
    }
    # get all different SDPId from hosts that need VSS
    $SDPIDs = $hostsNeedingVSS | ForEach-Object { $_.sdp_id } | Sort-Object -Unique
    # get sdpInfo for each SDPId (floating IP and port from Flex)
    $SDPInfo = @{}
    foreach ($SDPID in $SDPIDs) {
        $sdp = GetSDPInfo -FlexIP $config.common.flex_host_ip -FlexToken $flexToken -SDPID $SDPID
        if (-not $sdp) {
            ErrorMessage "Failed to get SDP info for SDP ID $SDPID from Flex. Unable to continue."
            Exit 1
        }
        $SDPInfo[$SDPID] = $sdp
        InfoMessage "SDP ID: $($sdp.id), Version: $($sdp.version), Floating IP: $($sdp.mc_floating_ip), HTTPS Port: $($sdp.mc_https_port)"
    }
    foreach ($hostInfo in $Config.hosts) {
        if ($SDPInfo[$hostInfo.sdp_id].credentials -eq $null) {
            # we already veryfied user and pass for that sdp
            $SDPCredential = getSDPCredentials -HostInfo $hostInfo -SDPHost $SDPInfo[$hostInfo.sdp_id].mc_floating_ip -SDPPort $SDPInfo[$hostInfo.sdp_id].mc_https_port
            if (-not $SDPCredential) {
                ErrorMessage "Failed to get SDP credentials for host $($hostInfo.name)."
                Exit 1
            }
            $SDPInfo[$hostInfo.sdp_id].credentials = $SDPCredential
        }
        $hostInfo.sdp_credential = $SDPInfo[$hostInfo.sdp_id].credentials
    }
}
#endregion UpdateSDPCredentials
#region GetSDPInfo
function GetSDPInfo {
    # we should have sdp floating ip, username and password for vss provider
    param (
        [string]$FlexIP,
        [string]$FlexToken,
        [string]$SDPID = ""
    )
    $ApiEndpoint = '/api/v1/pages/dashboard'
    try {
        $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "GET" -RequestBody $null
        if ($response.StatusCode -ne 200) {
            ErrorMessage "Failed to get SDP info from Flex. Status code: $($response.StatusCode)"
            return $null
        }
        $responseContent = $response.Content | ConvertFrom-Json
        if (-not $responseContent.k2xs) {
            ErrorMessage "No k2xs found in the response from Flex."
            return $null
        }
        if (-not $SDPID) {
            # if SDPID not provided, take the first k2x id
            $SDPID = $responseContent.k2xs[0].id
            InfoMessage "No SDP ID provided. Using first k2x ID: $SDPID"
        }
        # case insensitive search for k2x with given SDPID
        $SDPID = $SDPID.ToLower()
        DebugMessage "Searching for k2x with ID: $SDPID"
        $k2x = $responseContent.k2xs | Where-Object { $_.id.ToLower() -eq $SDPID }
        if (-not $k2x) {
            ErrorMessage "No k2x found with ID $SDPID in the response from Flex."
            return $null
        }
        $sdpInfo = @{
            "id" = $k2x.id
            "version" = $k2x.version
            "mc_floating_ip" = $k2x.mc_floating_ip
            "mc_https_port" = $k2x.mc_https_port
        }
        InfoMessage "Found k2x with ID $($sdpInfo.id) and version $($sdpInfo.version)"
        return $sdpInfo
    } catch {
        ErrorMessage "Error getting SDP info from Flex: $_"
        return $null
    }
}
#endregion GetSDPInfo
#endregion SDP
#endregion orc_sdp
# EnsureLocalInstallers, UploadInstallersToHosts
#region orc_uploader
#region InstallerUploader
#region EnsureLocalInstallers
function EnsureLocalInstallers {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    # Ensure installers present in local directory
    $localPaths = @{}
    $requiredInstallers = @('agent', 'vss')
    $installFlags = @{}
    $installFlags['agent'] = $Config.common.install_agent
    $installFlags['vss'] = $Config.common.install_vss
    # Process all required installers
    foreach ($installerType in $requiredInstallers) {
        if ( -not $installFlags[$installerType]) {
            InfoMessage "Skipping $installerType installer"
            $localPaths[$installerType] = $null
            continue
        }
        $installerConfig = $Config.installers.$installerType
        if (-not $installerConfig) {
            ErrorMessage "Missing required $installerType installer configuration in config.installers"
            return $null
        }
        # If path is provided and file exists, use it directly
        if ($installerConfig.path) {
            if (Test-Path $installerConfig.path) {
                InfoMessage "Using existing $installerType installer at: $($installerConfig.path)"
                $installerPath = $installerConfig.path
            } else {
                # If path is provided but doesn't exist
                ErrorMessage "$installerType installer path specified but file not found: $($installerConfig.path)"
                return $null
            }
        } else {
            if (-not $installerConfig.url) {
                ErrorMessage "No URL specified for $installerType installer in configuration"
                return $null
            }
            $installerPath = downloadInstaller -InstallerURL $installerConfig.url -CacheDir $SilkEchoInstallerCacheDir -InstallerType $installerType
        }
        if ($installerPath) {
            $localPaths[$installerType] = $installerPath
        } else {
            ErrorMessage "Failed to ensure $installerType installer is available locally"
            return $null
        }
    }
    InfoMessage "All installers are available locally"
    return $localPaths
}
#endregion EnsureLocalInstallers
#region downloadInstaller
function downloadInstaller {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InstallerURL,
        [Parameter(Mandatory=$true)]
        [string]$CacheDir,
        [Parameter(Mandatory=$true)]
        [string]$InstallerType
    )
    if (-not $InstallerURL) {
        ErrorMessage "No URL specified for $InstallerType installer in configuration"
        return $null
    }
    # If URL is provided, download to cache
    $fileName = "$InstallerType-installer.exe"
    $localPath = Join-Path $CacheDir $fileName
    # Check if already cached
    if (Test-Path $localPath) {
        InfoMessage "$InstallerType installer already cached at: $localPath"
        return $localPath
    }
    InfoMessage "Downloading $InstallerType installer from: $($InstallerURL)"
    try {
        # Use Invoke-WebRequest to download the file
        Invoke-WebRequest -Uri $InstallerURL -OutFile $localPath -UseBasicParsing
        if (Test-Path $localPath) {
            $fileSize = (Get-Item $localPath).Length
            InfoMessage "Downloaded $InstallerType installer ($fileSize bytes) to: $localPath"
            return $localPath
        } else {
            ErrorMessage "Download completed but file not found at: $localPath"
        }
    } catch {
        ErrorMessage "Failed to download $InstallerType installer: $_"
    }
    return $null
}
#endregion downloadInstaller
#region UploadInstallersToHosts
function UploadInstallersToHosts {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$HostInfos,
        [Parameter(Mandatory=$true)]
        [hashtable]$LocalPaths,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )
    # Upload job logic
    $uploadJobScript = {
        param($HostInfo, $LocalPaths, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS)
        $stdErrOut = @()
        # Simplified inline version of copyInstallersToHost
        $remoteRelDir = "Temp\silk-echo-install-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $remoteDir = "C:\$remoteRelDir"
        $remotePaths = @{}
        try {
            # Create remote directory
            $scriptBlock = {
                param($RemoteDir)
                if (-not (Test-Path $RemoteDir)) {
                    New-Item -ItemType Directory -Path $RemoteDir -Force | Out-Null
                    Write-Output "Created remote directory: $RemoteDir"
                }
                return $RemoteDir
            }
            $stdErrOut += "Preparing remote directory on $($HostInfo.host_addr)..."
            if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ArgumentList $remoteDir -ErrorAction Stop
            } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ArgumentList $remoteDir -ErrorAction Stop
            }
            $stdErrOut += "Remote directory prepared on $($HostInfo.host_addr): $remoteDir"
            # Copy each installer file
            foreach ($installerType in $LocalPaths.Keys) {
                $localPath = $LocalPaths[$installerType]
                # Skip if path is null (installer not needed)
                if ($null -eq $localPath) {
                    $stdErrOut += "Skipping $installerType installer (not required for this host)"
                    continue
                }
                $fileName = Split-Path $localPath -Leaf
                $stdErrOut += "Copying $installerType installer to $($HostInfo.host_addr)..."
                $remotePath = "$remoteDir\$fileName"
                if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                    $remotePathUnc = "\\$($HostInfo.host_addr)\C$\$remoteRelDir\$fileName"
                    Copy-Item -Path $localPath -Destination $remotePathUnc -Force -ErrorAction Stop
                } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                    $session = New-PSSession -ComputerName $HostInfo.host_addr -Credential $credential -SessionOption $sessionOption -ErrorAction Stop
                    Copy-Item -Path $localPath -Destination $remotePath -ToSession $session -Force -ErrorAction Stop
                    Remove-PSSession $session -ErrorAction SilentlyContinue
                }
                $remotePaths[$installerType] = $remotePath
                $stdErrOut += "Copied $installerType installer to: $remotePath"
            }
            $stdErrOut += "All installers uploaded to $($HostInfo.host_addr)"
            $out = $stdErrOut -join "`n"
            return @{ Success = $true; Error = $null; RemotePaths = $remotePaths; StdErrOut = $out }
        } catch {
            $out = $stdErrOut -join "`n"
            return @{ Success = $false; Error = $_.Exception.Message; RemotePaths = $null; StdErrOut = $out }
        }
    }
    # Result processor
    $resultProcessor = {
        param($JobInfo)
        $job = $JobInfo.Job
        $hostInfo = $JobInfo.Item
        try {
            $testResult = Receive-Job -Job $job
            # write all job debug/info/error messages in to the main script log
            Write-Output $testResult.StdErrOut
            if ($job.State -eq 'Completed') {
                if ($testResult -and $testResult.Success) {
                    # Store remote paths in host object for use by InstallSingleHost
                    $hostInfo.remote_installer_paths = $testResult.RemotePaths
                    InfoMessage "Successfully uploaded installers to $($hostInfo.host_addr)"
                } else {
                    $issue = if ($testResult.Error) { $testResult.Error } else { "Unknown Upload error" }
                    $hostInfo.issues += "Failed to upload installers. $issue"
                    ErrorMessage "Failed to upload installers to $($hostInfo.host_addr). $issue"
                }
            } else {
                $errors = $job.ChildJobs | ForEach-Object { $_.Error } | Where-Object { $_ } | ForEach-Object { $_.ToString() }
                $issue = "Job failed: $($errors | Out-String)"
                $hostInfo.issues += ("Job failed to complete. State: $($job.State)" + $errors)
                ErrorMessage "Upload job failed for $($hostInfo.host_addr): State $($job.State), $issue"
            }
        } catch {
            $hostInfo.issues += "Error while receiving job output: $(_.Exception.Message)"
            ErrorMessage "Upload job failed for $($hostInfo.host_addr): State $($job.State), $issue"
        }
        Remove-Job -Job $job -Force
    }
    # Enhanced job script that includes constants and LocalPaths
    $jobScriptWithParams = {
        param($hostInfo)
        $ENUM_ACTIVE_DIRECTORY = "active_directory"
        $ENUM_CREDENTIALS = "credentials"
        & ([ScriptBlock]::Create($using:uploadJobScript)) $hostInfo $using:LocalPaths $ENUM_ACTIVE_DIRECTORY $ENUM_CREDENTIALS
    }
    # Use generic batch processor
    Start-BatchJobProcessor -Items $HostInfos -JobScriptBlock $jobScriptWithParams -ResultProcessor $resultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "upload"
    # Check upload results and provide summary
    $successfulUploads = @($HostInfos | Where-Object { $_.remote_installer_paths })
    $failedUploads = @($HostInfos | Where-Object { -not $_.remote_installer_paths })
    if ($failedUploads.Count -gt 0) {
        WarningMessage "Upload failed for $($failedUploads.Count) hosts:"
        foreach ($hostInfo in $failedUploads) {
            WarningMessage " - $($hostInfo.host_addr)"
        }
    }
    if ($successfulUploads.Count -gt 0) {
        InfoMessage "Successfully uploaded installers to $($successfulUploads.Count) hosts"
    } else {
        ErrorMessage "Failed to upload installers to any hosts"
    }
}
#endregion UploadInstallersToHosts
#endregion InstallerUploader
#endregion orc_uploader
# InstallSingleHost, FetchJobResult, ProcessSingleJobResult
#region orc_invoke_remote_install
#region FetchJobResult
function FetchStream {
    param (
        [Parameter(Mandatory=$true)]
        [object]$stream
    )
    if ($stream) {
        $lines = $stream | ForEach-Object {
            if ($_.MessageData) {
                $_.MessageData.ToString().Trim()
            } else {
                $_.ToString().Trim()
            }
        } | Where-Object { -not [string]::IsNullOrEmpty($_) }
    }
    else {
        $lines = @()
    }
    return $lines
}
function FetchJobResult {
    param (
        [Parameter(Mandatory=$true)]
        [string]$hostAddress,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$jobResult,
        [string]$JobState
    )
    # Initialize arrays for different output types
    InfoMessage "Fetching job result for $hostAddress with state $JobState"
    $outputLines = @()
    $errorLines = @()
    if ($jobResult) {
        $outputLines = FetchStream -Stream $jobResult.Information
    }
    if ($jobResult.Error) {
        $errorLines = FetchStream -Stream $jobResult.Error
    }
    # Determine status based on presence of errors
    $JState = if ($JobState -eq 'Completed') {
        'Success'
    } else {
        'Failed'
    }
    $result = [PSCustomObject]@{
                HostAddress = $hostAddress
                JobState = $JState
                Info = $outputLines
                Error = $errorLines
            }
    InfoMessage "Job result for $hostAddress`: $($result.JobState)"
    return $result
}
#endregion FetchJobResult
#region ProcessSingleJobResult
function ProcessSingleJobResult {
    <#
    .SYNOPSIS
        Processes the result of a single remote installation job safely.
    .DESCRIPTION
        This function handles all aspects of processing a completed job including:
        - Waiting for job completion
        - Receiving job output and errors
        - Fetching detailed job results
        - Error handling to prevent script termination
        - Cleanup of job resources
    .PARAMETER JobInfo
        The job information object containing the job and computer name
    .OUTPUTS
        PSCustomObject containing the processed job result
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$JobInfo
    )
    $hostAddress = $JobInfo.HostAddress
    $job = $JobInfo.Job
    InfoMessage "Waiting for job completion on $hostAddress (timeout: $REMOTE_INSTALL_TIMEOUT_SECONDS seconds)..."
    try {
        $waitResult = $job | Wait-Job -Timeout $REMOTE_INSTALL_TIMEOUT_SECONDS
        if ($waitResult) {
            InfoMessage "Job completed on $hostAddress."
        } else {
            WarningMessage "Job timed out after $REMOTE_INSTALL_TIMEOUT_SECONDS seconds on $hostAddress"
            # Stop the timed-out job gracefully to allow log collection
            try {
                $job | Stop-Job
                DebugMessage "Stopped timed-out job on $hostAddress"
            } catch {
                WarningMessage "Failed to stop timed-out job on $hostAddress`: $_"
            }
        }
    } catch {
        ErrorMessage "Error while waiting for job completion on $hostAddress`: $_"
    }
    # read job errors if any - wrap in try-catch to prevent script termination
    $jobErrors = $null
    try {
        Receive-Job -Job $job -Keep -ErrorVariable jobErrors -ErrorAction SilentlyContinue
        DebugMessage "Job state for $hostAddress`: $($job.State)"
    } catch {
        ErrorMessage "Error while receiving job output from $hostAddress`: $_"
        $jobErrors = @($_.Exception.Message)
    }
    $jobResult = $null
    try {
        $jobResult = $job.ChildJobs[0]
    } catch {
        WarningMessage "Error accessing child job for $hostAddress`: $_"
    }
    # Fetch logs from the job result - wrap in try-catch
    try {
        $result = FetchJobResult -hostAddress $hostAddress -jobResult $jobResult -JobState $job.State
    } catch {
        WarningMessage "Error fetching job result for $hostAddress`: $_"
        # Create a fallback result object
        $result = [PSCustomObject]@{
            HostAddress = $hostAddress
            JobState = 'Failed'
            Info = @()
            Error = @("Error fetching job result: $($_.Exception.Message)")
        }
    }
    # add jobErrors to the result if any - ensure result.Error is an array
    if ($jobErrors) {
        if (-not $result.Error) {
            $result.Error = @()
        }
        $result.Error += $jobErrors | ForEach-Object { $_.ToString().Trim() }
    }
    # Clean up the job
    try {
        $job | Remove-Job
        DebugMessage "Cleaned up job for $hostAddress"
    } catch {
        WarningMessage "Error cleaning up job for $hostAddress`: $_"
    }
    return $result
}
#endregion ProcessSingleJobResult
#endregion orc_invoke_remote_install
# StartBatchInstallation, SaveInstallationResults
#region orc_batch_installer
#region Batch Installation Orchestration
<#
.SYNOPSIS
    Handles batch installation orchestration across multiple remote hosts.
.DESCRIPTION
    This module manages the parallel installation process across multiple hosts using dynamic
    batch processing. It coordinates installation jobs, tracks progress, manages completion
    state persistence, and generates comprehensive results.
.NOTES
    File Name      : orc_batch_installer.ps1
    Author         : Silk.us, Inc.
    Prerequisite   : PowerShell version 5 or higher
    Copyright      : (c) 2024 Silk.us, Inc.
.FUNCTIONALITY
    Batch installation orchestration, Dynamic job processing, State tracking, Results management
#>
#region StartBatchInstallation
function StartBatchInstallation {
    param (
        [Parameter(Mandatory=$true)]
        [Object[]]$RemoteComputers,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$CompletedHosts,
        [Parameter(Mandatory=$true)]
        [string]$ProcessedHostsPath,
        [Parameter(Mandatory=$true)]
        [string]$HostSetupScript,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )
    # Installation job logic - direct remote installation (like upload/connectivity pattern)
    $installationJobScript = {
        param($hostInfo, $Config, $HostSetupScript, $ENUM_ACTIVE_DIRECTORY, $IsDryRun, $IsDebug)
        function InfoMessageIJS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [INFO] $message" -ForegroundColor Green }
        function DebugMessageIJS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [DEBUG] $message" -ForegroundColor Gray }
        function ErrorMessageIJS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [ERROR] $message" -ForegroundColor Red }
        try {
            $HostAddress = $hostInfo.host_addr
            InfoMessageIJS "Starting installation on $HostAddress..."
            # Use uploaded installer paths
            DebugMessageIJS "Remote installer paths: $($hostInfo.remote_installer_paths | ConvertTo-Json -Compress)"
            $agentPath = $hostInfo.remote_installer_paths.agent
            $vssPath = $hostInfo.remote_installer_paths.vss
            DebugMessageIJS "Installer paths: $($hostInfo.remote_installer_paths | ConvertTo-Json -Depth 3)"
            $agentPath = if ($hostInfo.install_agent) { $agentPath } else { "none" }
            $vssPath = if ($hostInfo.install_vss) { $vssPath } else { "none" }
            # Validate that required installer paths are not null
            $missingPaths = @()
            if ($hostInfo.install_agent -and -not $agentPath) {
                ErrorMessageIJS "Agent path is null or empty but agent installation is required."
                $missingPaths += "agent"
            }
            if ($hostInfo.install_vss -and -not $vssPath) {
                ErrorMessageIJS "VSS path is null or empty but VSS installation is required."
                $missingPaths += "vss"
            }
            # do not continue if required paths are missing
            if ($missingPaths.Count -gt 0) {
                $hostInfo.issues += "Missing required installer paths: $($missingPaths -join ', ')"
                return
            }
            DebugMessageIJS "Preparing to run installation script on $HostAddress"
            DebugMessageIJS "Using Flex IP: $($hostInfo.flex_host_ip)"
            DebugMessageIJS "Using Flex Token: [REDACTED]"
            DebugMessageIJS "Using SQL Connection String: [REDACTED]"
            DebugMessageIJS "Using agent path: $agentPath"
            DebugMessageIJS "Using VSS path: $vssPath"
            DebugMessageIJS "Using SDP ID: $($hostInfo.sdp_id)"
            DebugMessageIJS "Using SDP Username: $($hostInfo.sdp_credential.UserName)"
            DebugMessageIJS "Using SDP Password: [REDACTED]"
            DebugMessageIJS "Dry Run Mode: $IsDryRun"
            DebugMessageIJS "Mount Points Directory: $($hostInfo.mount_points_directory)"
            DebugMessageIJS "Install Directory: $($hostInfo.install_to_directory)"
            # Create the remote scriptblock for installation
            $remoteInstallationScript = {
                param($ConfigJson, $Script)
                function InfoMessageRIS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [INFO] $message"}
                function DebugMessageRIS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [DEBUG] $message"}
                function ErrorMessageRIS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [ERROR] $message"}
                # Parse config to set debug preferences
                try {
                    $config = $ConfigJson | ConvertFrom-Json
                    if ($config.is_debug) {
                        $DebugPreference = 'Continue'
                        $VerbosePreference = 'Continue'
                    } else {
                        $DebugPreference = 'SilentlyContinue'
                        $VerbosePreference = 'SilentlyContinue'
                    }
                    InfoMessageRIS "Running installation script... (Debug: $($config.is_debug), DryRun: $($config.is_dry_run))"
                } catch {
                    ErrorMessageRIS "Failed to parse ConfigJson: $_"
                    return @{ Success = $false; Output = $null; Error = "Failed to parse configuration" }
                }
                # Create a new function with the script content and pass ConfigJson directly
                $function = [ScriptBlock]::Create($Script)
                # Execute function with ConfigJson parameter
                try {
                    $result = & $function -ConfigJson $ConfigJson
                    return @{ Success = $true; Output = $result; Error = $null }
                } catch {
                    ErrorMessageRIS "Installation script execution failed: $_"
                    return @{ Success = $false; Output = $null; Error = $_.Exception.Message }
                }
            }
            # Build configuration JSON with conditional fields
            $installConfig = @{
                flex_host_ip = $hostInfo.flex_host_ip
                flex_access_token = $hostInfo.flex_access_token
                sql_connection_string = $hostInfo.sql_connection_string
                agent_path = $agentPath
                vss_path = $vssPath
                sdp_id = $hostInfo.sdp_id
                sdp_username = if ($hostInfo.sdp_credential) { $hostInfo.sdp_credential.UserName } else { $null }
                sdp_password = if ($hostInfo.sdp_credential) { $hostInfo.sdp_credential.GetNetworkCredential().Password } else { $null }
                mount_points_directory = $hostInfo.mount_points_directory
                install_to_directory = $hostInfo.install_to_directory
                is_debug = $IsDebug
                is_dry_run = $IsDryRun
                install_agent = $hostInfo.install_agent
                install_vss = $hostInfo.install_vss
                upgrade_mode = $hostInfo.upgrade_mode
            }
            # Skip validation in upgrade mode - only installer paths are needed
            if ($hostInfo.upgrade_mode) {
                # In upgrade mode, only validate installer paths
                if ($hostInfo.install_agent -and -not $installConfig['agent_path']) {
                    ErrorMessageIJS "Agent path is required for upgrade"
                    return @{ Success = $false; HostAddress = $HostAddress; Output = $null; Error = "Missing agent path for upgrade" }
                }
                if ($hostInfo.install_vss -and -not $installConfig['vss_path']) {
                    ErrorMessageIJS "VSS path is required for upgrade"
                    return @{ Success = $false; HostAddress = $HostAddress; Output = $null; Error = "Missing VSS path for upgrade" }
                }
            } else {
                # Validate required fields based on what's being installed
                if ($hostInfo.install_agent) {
                    $agentFields = @('flex_host_ip', 'flex_access_token', 'sql_connection_string', 'agent_path')
                    foreach ($field in $agentFields) {
                        if ($null -eq $installConfig[$field] -or $installConfig[$field] -eq '') {
                            ErrorMessageIJS "Required field for agent installation '$field' is null or empty"
                            return @{ Success = $false; HostAddress = $HostAddress; Output = $null; Error = "Missing required field: $field" }
                        }
                    }
                }
                if ($hostInfo.install_vss) {
                    $vssFields = @('vss_path', 'sdp_id', 'sdp_username', 'sdp_password')
                    foreach ($field in $vssFields) {
                        if ($null -eq $installConfig[$field] -or $installConfig[$field] -eq '') {
                            ErrorMessageIJS "Required field for VSS installation '$field' is null or empty"
                            return @{ Success = $false; HostAddress = $HostAddress; Output = $null; Error = "Missing required field: $field" }
                        }
                    }
                }
            }
            $ConfigJson = $installConfig | ConvertTo-Json -Compress
            # Prepare argument list with ConfigJson and Script
            $ArgumentList = @($ConfigJson, $HostSetupScript)
            # Prepare invoke command parameters - DIRECT EXECUTION (NO -AsJob)
            $invokeParams = @{
                ComputerName = $HostAddress
                ScriptBlock = $remoteInstallationScript
                ArgumentList = $ArgumentList
            }
            # Add credential parameter only if not using Kerberos
            if ($hostInfo.host_auth -ne $ENUM_ACTIVE_DIRECTORY) {
                $credential = New-Object System.Management.Automation.PSCredential($hostInfo.host_user, $hostInfo.host_pass)
                $invokeParams['Credential'] = $credential
            }
            InfoMessageIJS "Invoking installation script on $HostAddress..."
            $installResult = Invoke-Command @invokeParams -ErrorAction Stop
            if ($installResult -and $installResult.Success) {
                InfoMessageIJS "Installation completed successfully on $HostAddress"
                return @{ Success = $true; HostAddress = $HostAddress; Output = $installResult.Output; Error = $null }
            } else {
                $errorMsg = if ($installResult.Error) { $installResult.Error } else { "Unknown installation error" }
                ErrorMessageIJS "Installation failed on ${HostAddress}: $errorMsg"
                return @{ Success = $false; HostAddress = $HostAddress; Output = $null; Error = $errorMsg }
            }
        } catch {
            $hostInfo.issues += "Installation error: $($_.Exception.Message)"
            ErrorMessageIJS "Installation job failed for ${HostAddress}: $_"
            return @{ Success = $false; HostAddress = $HostAddress; Output = $null; Error = $_.Exception.Message }
        }
    }
    # Result processor - handles completed installation jobs (like upload/connectivity pattern)
    $installationResultProcessor = {
        param($JobInfo)
        $job = $JobInfo.Job
        $hostInfo = $JobInfo.Item
        if ($job.State -eq 'Completed') {
            $installResult = Receive-Job -Job $job
            if ($installResult -and $installResult.Success) {
                InfoMessage "Installation completed successfully on $($hostInfo.host_addr)"
                # Create result object in expected format for compatibility
                $result = [PSCustomObject]@{
                    HostAddress = $installResult.HostAddress
                    JobState = 'Success'
                    Info = @($installResult.Output)
                    Error = @()
                }
                $script:results += $result
                # Update the corresponding host's result field in both collections
                $hostToUpdate = $script:remoteComputers | Where-Object { $_.host_addr -eq $result.HostAddress }
                if ($hostToUpdate) {
                    $hostToUpdate.result = $result
                }
                # Also update config.hosts collection for progress file
                $configHostToUpdate = $script:config.hosts | Where-Object { $_.host_addr -eq $result.HostAddress }
                if ($configHostToUpdate) {
                    $configHostToUpdate.result = $result
                }
                $script:NumOfSuccessHosts++
                # Mark host as completed immediately (only in live mode)
                if (-not $DryRun.IsPresent) {
                    MarkHostCompleted -CompletedHosts $script:completedHosts -HostAddress $result.HostAddress
                    SaveCompletedHosts -StateFilePath $script:processedHostsPath -CompletedHosts $script:completedHosts | Out-Null
                }
            } else {
                # Check if we have enhanced timeout information from our updated functions
                $errorMsg = $null
                if ($installResult.Output -and $installResult.Output.Message) {
                    # Enhanced result object with timeout information
                    $errorMsg = $installResult.Output.Message
                    if ($installResult.Output.Reason -eq "Timeout") {
                        InfoMessage "Timeout detected for $($hostInfo.host_addr): $errorMsg"
                    }
                } elseif ($installResult.Error) {
                    $errorMsg = $installResult.Error
                } else {
                    $errorMsg = "Unknown installation error"
                }
                ErrorMessage "Installation failed on $($hostInfo.host_addr): $errorMsg"
                # Add error to host issues for progress tracking in both collections
                $hostToUpdate = $script:remoteComputers | Where-Object { $_.host_addr -eq $hostInfo.host_addr }
                # Create failure result object
                $result = [PSCustomObject]@{
                    HostAddress = $hostInfo.host_addr
                    JobState = 'Failed'
                    Info = @()
                    Error = @($errorMsg)
                }
                $script:results += $result
                # Update the corresponding host's result field in both collections
                if ($hostToUpdate) {
                    $hostToUpdate.result = $result
                }
                if ($configHostToUpdate) {
                    $configHostToUpdate.result = $result
                }
                $script:NumOfFailedHosts++
            }
        } else {
            $stdErrOut = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            $errorMsg = "Installation job failed for $($hostInfo.host_addr). State: $($job.State). $stdErrOut"
            ErrorMessage $errorMsg
            # Create failure result object
            $result = [PSCustomObject]@{
                HostAddress = $hostInfo.host_addr
                JobState = 'Failed'
                Info = @()
                Error = @($errorMsg)
            }
            $script:results += $result
            # Update the corresponding host's result field in both collections
            if ($hostToUpdate) {
                $hostToUpdate.result = $result
            }
            if ($configHostToUpdate) {
                $configHostToUpdate.result = $result
            }
            $script:NumOfFailedHosts++
        }
        Remove-Job -Job $job -Force
    }
    # Initialize script-scope variables for result processor access
    $script:results = @()
    $script:remoteComputers = $RemoteComputers
    $script:config = $Config
    $script:completedHosts = $CompletedHosts
    $script:processedHostsPath = $ProcessedHostsPath
    # Enhanced job script that includes constants (like upload/connectivity pattern)
    $jobScriptWithConstants = {
        param($hostInfo)
        & ([ScriptBlock]::Create($using:installationJobScript)) `
            $hostInfo `
            $using:Config `
            $using:HostSetupScript `
            $using:ENUM_ACTIVE_DIRECTORY `
            $using:DryRun.IsPresent `
            ($using:DebugPreference -eq 'Continue')
    }
    # Use dynamic batch processor for installations
    Start-BatchJobProcessor -Items $RemoteComputers -JobScriptBlock $jobScriptWithConstants -ResultProcessor $installationResultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "installation"
    # Return the results
    return $script:results
}
#endregion StartBatchInstallation
#region SaveInstallationResults
function SaveInstallationResults {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$Results,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [string]$CacheDirectory,
        [Parameter(Mandatory=$true)]
        [string]$ProcessedHostsPath
    )
    try {
        # Display short summary to console
        DisplayInstallationSummary -Hosts $Config.hosts
        InfoMessage ""
        if ($script:NumOfFailedHosts -gt 0) {
            ErrorMessage "Installation failed on $script:NumOfFailedHosts host(s). Check the logs for details."
        } else {
            InfoMessage "Installation completed successfully on all hosts."
        }
        InfoMessage "Completed hosts saved to: $ProcessedHostsPath"
        InfoMessage "To reprocess all hosts, delete the completed hosts file above."
        InfoMessage "*************************************************"
    }
    catch {
        ErrorMessage "Error saving installation results: $_"
        throw
    }
}
#endregion SaveInstallationResults
#endregion Batch Installation Orchestration
#endregion orc_batch_installer
# EnsureHostsConnectivity
#region orc_host_communication
#region addHostsToTrustedHosts
function addHostsToTrustedHosts {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )
    $hostsToAdd = @()
    foreach ($hostInfo in $hostEntries){
        $hostsToAdd += $hostInfo.host_addr
    }
    if($hostsToAdd.Count -eq 0){
        DebugMessage "No hosts to add to TrustedHosts list."
        return
    }
    $currentTrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts
    $newHosts = @($hostsToAdd | Where-Object { $_ -notin $currentTrustedHosts.Value.Split(',') })
    if ($newHosts.Count -eq 0) {
        InfoMessage "All hosts are already in TrustedHosts list"
        return
    }
    InfoMessage "Adding the following hosts to TrustedHosts:"
    foreach ($hostAddr in $newHosts) {
        InfoMessage "  - $hostAddr"
    }
    $hostsToAddString = $newHosts -join ','
    if ($currentTrustedHosts.Value) {
        $newValue = "$($currentTrustedHosts.Value),$hostsToAddString"
    } else {
        $newValue = $hostsToAddString
    }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newValue -Force
    InfoMessage "Successfully added hosts to TrustedHosts"
}
#endregion addHostsToTrustedHosts
#region ensureHostCredentials
function ensureHostCredentials {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )
    # Check if any hosts with credentials auth are missing username or password
    $missingCredHosts = @($hostEntries | Where-Object {
        $_.host_auth -eq $ENUM_CREDENTIALS -and (
            [string]::IsNullOrEmpty($_.host_user) -or [string]::IsNullOrEmpty($_.host_pass)
        )
    })
    # return if no missing
    if ($missingCredHosts.Count -eq 0) {
        return
    }
    ImportantMessage "Missing credentials detected for some hosts with credentials authentication."
    ImportantMessage "The provided username and password will be used for all hosts with missing credentials:"
    foreach ($hostInfo in $missingCredHosts) {
        ImportantMessage "$($hostInfo.host_addr)"
    }
    $cred = Get-Credential -Message "Enter Host's username and password"
    if (-not $cred) {
        ErrorMessage "No credentials provided. Cannot proceed without valid credentials for all hosts."
        Exit 1
    }
    foreach ($hostInfo in $missingCredHosts) {
        if (-not $hostInfo.host_user) {
            Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "host_user" -Value $cred.UserName -Force
        }
        if (-not $hostInfo.host_pass) {
            Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "host_pass" -Value $cred.GetNetworkCredential().Password -Force
        }
    }
    # convert all hosts with auth credentials to secured credentials
    foreach ($hostInfo in $hostEntries) {
        if ($hostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Only convert if it's not already a SecureString
            if ($hostInfo.host_pass -is [string]) {
                $hostInfo.host_pass = ConvertTo-SecureString $hostInfo.host_pass -AsPlainText -Force
            }
        }
    }
}
#endregion ensureHostCredentials
#region resolveIPToHostname
function resolveIPToHostname {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    try {
        $hostname = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        if ($hostname -and $hostname -ne $IPAddress) {
            InfoMessage "Resolved IP $IPAddress to hostname: $hostname"
            return $hostname
        }
    } catch {
        DebugMessage "Failed to resolve IP $IPAddress to hostname: $_"
    }
    return $null
}
#endregion resolveIPToHostname
#region isActiveDirectoryUser
function isActiveDirectoryUser {
    # Check if the current user is logged in to Active Directory
    try {
        # Try multiple methods for cross-version compatibility
        $isDomainUser = $false
        # Method 1: Check environment variables (works in both PS 5.1 and 7)
        $userDomain = $env:USERDOMAIN
        $computerName = $env:COMPUTERNAME
        if ($userDomain -and $userDomain -ne $computerName) {
            $isDomainUser = $true
        }
        # Method 2: Try .NET method
        if (-not $isDomainUser) {
            try {
                $adUser = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                if ($adUser) {
                    $isDomainUser = $true
                }
            } catch {
                # Ignore errors, continue with other methods
            }
        }
        # Method 3: Check using WMI/CIM
        if (-not $isDomainUser) {
            try {
                if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                } else {
                    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
                }
                if ($computerSystem -and $computerSystem.PartOfDomain) {
                    $isDomainUser = $true
                }
            } catch {
                # Ignore errors
            }
        }
        if ($isDomainUser) {
            InfoMessage "Current user is logged in to Active Directory domain: $userDomain"
            return $true
        } else {
            InfoMessage "Current user is not logged in to Active Directory."
            return $false
        }
    } catch {
        DebugMessage "Failed to check Active Directory login status: $_"
        return $false
    }
}
#endregion isActiveDirectoryUser
#region isHostConnectivityValid
function isHostConnectivityValid {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$HostInfo
    )
    # Execute simple command on the host using defined authentication
    try {
        $scriptBlock = {
            try {
                Get-Date
            } catch {
                "ERROR: $($_.Exception.Message)"
            }
        }
        if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
            # Use current credentials for Active Directory authentication
            InfoMessage "Testing connectivity to $($HostInfo.host_addr) using $ENUM_ACTIVE_DIRECTORY authentication..."
            $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ErrorAction Stop
        } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Create credential object for explicit authentication
            $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
            # Use session options for better compatibility
            $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            InfoMessage "Testing connectivity to $($HostInfo.host_addr) using $ENUM_CREDENTIALS authentication..."
            $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ErrorAction Stop
        } else {
            return $false
        }
        InfoMessage "Successfully connected to $($HostInfo.host_addr) with result: $result"
        # Check if result indicates an error
        if ($result -and $result.ToString().StartsWith("ERROR:")) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}
#endregion isHostConnectivityValid
#region EnsureHostsConnectivity
function EnsureHostsConnectivity {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )
    # Fulfill credentials for hosts
    ensureHostCredentials -hostEntries $hostEntries
    # Check that all hosts have proper host_auth values
    foreach ($hostInfo in $hostEntries) {
        if ($hostInfo.host_auth -ne $ENUM_ACTIVE_DIRECTORY -and $hostInfo.host_auth -ne $ENUM_CREDENTIALS) {
            $hostInfo.issues += "Invalid host_auth value. Must be '$ENUM_ACTIVE_DIRECTORY' or '$ENUM_CREDENTIALS'"
            continue
        }
    }
    # Handle active_directory authentication
    $adHosts = @($hostEntries | Where-Object { $_.host_auth -eq $ENUM_ACTIVE_DIRECTORY })
    if ($adHosts.Count -gt 0) {
        # Ensure current user is domain user
        if (-not (isActiveDirectoryUser)) {
            foreach ($hostInfo in $adHosts) {
                $hostInfo.issues += "Current user is not logged in to Active Directory"
            }
        } else {
            foreach ($hostInfo in $adHosts) {
                # Check if host is IP address and try to resolve to hostname
                if ($hostInfo.host_addr -as [IPAddress]) {
                    $resolvedHostname = resolveIPToHostname -IPAddress $hostInfo.host_addr
                    if ($resolvedHostname) {
                        # Update host_addr to use the resolved hostname
                        $hostInfo.host_addr = $resolvedHostname
                        InfoMessage "Using resolved hostname $resolvedHostname for Active Directory authentication"
                    } else {
                        $hostInfo.issues += "Could not resolve IP $($hostInfo.host_addr) to hostname for $ENUM_ACTIVE_DIRECTORY auth"
                        continue
                    }
                }
            }
        }
    }
    # Handle credentials authentication
    $credHosts = @($hostEntries | Where-Object { $_.host_auth -eq $ENUM_CREDENTIALS })
    if ($credHosts.Count -gt 0) {
        # validate all host entries has an IP addresses
        $isError = $false
        foreach ($hostInfo in $credHosts) {
            if (-not ($hostInfo.host_addr -as [IPAddress])) {
                $hostInfo.issues += "Invalid host address '$($hostInfo.host_addr)'. Must be an IP address for $ENUM_CREDENTIALS authentication."
                $isError = $true
            }
        }
        if ($isError) {
            return @($hostEntries | Where-Object { $_.issues.Count -gt 0 })
        }
        try{
            addHostsToTrustedHosts -hostEntries $credHosts
        } catch {
            # print exception mesage
            ErrorMessage "$_"
            ErrorMessage "Failed to add hosts to TrustedHosts. Cannot proceed with $ENUM_CREDENTIALS authentication."
            Exit 1
        }
    }
    # Perform parallel connectivity testing for all hosts that passed validation
    $hostsToTest = @($hostEntries | Where-Object { $_.issues.Count -eq 0 })
    if ($hostsToTest.Count -gt 0) {
        testHostsConnectivityInParallel -hostEntries $hostsToTest -MaxConcurrency $script:MaxConcurrency
    }
    $badHosts = @($hostEntries | Where-Object { $_.issues.Count -gt 0 })
    return $badHosts
}
#endregion EnsureHostsConnectivity
#region testHostsConnectivityInParallel
function testHostsConnectivityInParallel {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )
    # Connectivity test job logic
    $connectivityJobScript = {
        param($HostInfo, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS)
        function InfoMessageCJS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - ConnJob - [INFO] $message"}
        # Connectivity test logic (same as isHostConnectivityValid but in job)
        try {
            $scriptBlock = {
                try {
                    Get-Date
                } catch {
                    "ERROR: $($_.Exception.Message)"
                }
            }
            if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                InfoMessageCJS "Testing connectivity to $($HostInfo.host_addr) using $ENUM_ACTIVE_DIRECTORY authentication..."
                $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ErrorAction Stop
            } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                InfoMessageCJS "Testing connectivity to $($HostInfo.host_addr) using $ENUM_CREDENTIALS authentication..."
                $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ErrorAction Stop
            } else {
                return @{ Success = $false; Error = "Invalid authentication method" }
            }
            InfoMessageCJS "Successfully connected to $($HostInfo.host_addr) with result: $result"
            # Check if result indicates an error
            if ($result -and $result.ToString().StartsWith("ERROR:")) {
                return @{ Success = $false; Error = "Remote command execution failed: $result" }
            }
            return @{ Success = $true; Error = $null }
        } catch {
            return @{ Success = $false; Error = $_.Exception.Message }
        }
    }
    # Result processor
    $resultProcessor = {
        param($JobInfo)
        $job = $JobInfo.Job
        $hostInfo = $JobInfo.Item
        if ($job.State -eq 'Completed') {
            $testResult = Receive-Job -Job $job
            if ($testResult -and $testResult.Success) {
                InfoMessage "Successfully verified connectivity to $($hostInfo.host_addr)"
            } else {
                $errorMsg = if ($testResult.Error) { $testResult.Error } else { "Unknown connectivity error" }
                $hostInfo.issues += "Failed to connect to host using $($hostInfo.host_auth) authentication: $errorMsg"
                }
        } else {
            $stdErrOut = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            $errorMsg = "Connectivity test job failed for $($hostInfo.host_addr). State: $($job.State). $stdErrOut"
            $hostInfo.issues += $errorMsg
        }
        Remove-Job -Job $job -Force
    }
    # Enhanced job script that includes constants
    $jobScriptWithConstants = {
        param($hostInfo)
        & ([ScriptBlock]::Create($using:connectivityJobScript)) $hostInfo $using:ENUM_ACTIVE_DIRECTORY $using:ENUM_CREDENTIALS
    }
    # Use generic batch processor
    Start-BatchJobProcessor -Items $hostEntries -JobScriptBlock $jobScriptWithConstants -ResultProcessor $resultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "ConnectivityTest"
}
#endregion testHostsConnectivityInParallel
#endregion orc_host_communication
# GetHostInstallScript
#region orc_host_setup_extractor
#region GetHostInstallScript
function GetHostInstallScript {
    <#
    .SYNOPSIS
        Extracts the host installation script from the orchestrator.
    .DESCRIPTION
        This function reads the orchestrator script content and extracts the host installer
        portion after the HOSTSETUP_START_MARKER.
    .PARAMETER OrchestratorPath
        Path to the orchestrator script. If not specified, uses the script that called this function.
    .OUTPUTS
        String containing the host installation script content
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$OrchestratorPath
    )
    try {
        DebugMessage "Extracting host installation script from orchestrator..."
        # Read the orchestrator script content
        $orchestratorContent = Get-Content -Path $OrchestratorPath -Raw
        # Extract content after the HOSTSETUP_START_MARKER
        $hostScriptContent = $orchestratorContent -split $HOSTSETUP_START_MARKER | Select-Object -Last 1
        $hostScriptContent = $hostScriptContent.Trim()
        if ([string]::IsNullOrWhiteSpace($hostScriptContent)) {
            ErrorMessage "Failed to extract host installer script content from orchestrator."
            return $null
        }
        DebugMessage "Host installation script extracted successfully."
        return $hostScriptContent
    }
    catch {
        ErrorMessage "Failed to extract host installation script: $_"
        return $null
    }
}
#endregion GetHostInstallScript
#endregion orc_host_setup_extractor
# ExpandImportsInline
#region orc_import_expander
#region ExpandImportsInline
function ExpandImportsInline {
    <#
    .SYNOPSIS
        Expands dot-sourced imports by replacing them with actual file content.
    .DESCRIPTION
        This function replaces dot-sourced imports (. ./orc_*.ps1) with actual file content.
        It processes imports up to 3 times to handle nested dependencies.
        This creates a self-contained script with all dependencies embedded inline.
    .PARAMETER ScriptContent
        The script content containing imports to process
    .OUTPUTS
        String containing the processed script content with imports replaced
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptContent
    )
    try {
        DebugMessage "Expanding imports inline..."
        $processedContent = $ScriptContent
        # Process imports up to 3 times to handle nested dependencies
        for ($iteration = 1; $iteration -le 3; $iteration++) {
            DebugMessage "Expanding imports - iteration $iteration"
            $lines = $processedContent -split '[\r\n]+'
            $newLines = [System.Collections.Generic.List[string]]::new()
            $importsProcessed = 0
            foreach ($line in $lines) {
                if ($line -match "^\s*\.\s+(\./orc_[\w-]+\.ps1)\s*$") {
                    $fileName = $matches[1]
                    $filePath = Join-Path $PSScriptRoot $fileName
                    # remove ps1 from filename
                    $fileName = $fileName -replace "\.ps1$",""
                    # remove starting ./
                    $fileName = $fileName -replace "^\./",""
                    if (Test-Path $filePath) {
                        $orcContent = Get-Content -Path $filePath -Raw
                        $newLines.Add("#region $fileName")
                        # Split the content into lines and add each line separately
                        $contentLines = $orcContent.TrimEnd() -split '[\r\n]+'
                        foreach ($contentLine in $contentLines) {
                            if ($contentLine.Trim() -ne '') {
                                $newLines.Add($contentLine)
                            }
                        }
                        $newLines.Add("#endregion $fileName")
                        $importsProcessed++
                        DebugMessage "Expanded import for $fileName"
                    } else {
                        WarningMessage "Could not find import file: $fileName. Keeping original import line."
                        $newLines.Add($line)
                    }
                } else {
                    $newLines.Add($line)
                }
            }
            $processedContent = $newLines -join [System.Environment]::NewLine
            DebugMessage "Iteration $iteration completed. Processed $importsProcessed imports."
            if ($importsProcessed -eq 0) {
                DebugMessage "No more imports to process. Breaking early."
                break
            }
        }
        DebugMessage "Import expansion completed successfully."
        return $processedContent
    }
    catch {
        ErrorMessage "Failed to expand imports inline: $_"
        return $ScriptContent
    }
}
#endregion ExpandImportsInline
#endregion orc_import_expander
# LoadCompletedHosts, SaveCompletedHosts, IsHostCompleted, MarkHostCompleted
#region orc_tracking
#region Simple Host Completion Tracking
#region LoadCompletedHosts
function LoadCompletedHosts {
    <#
    .SYNOPSIS
        Loads the list of completed hosts from processing.json file.
    .DESCRIPTION
        Loads a simple list of completed hosts with timestamps to avoid duplicate installations.
    .PARAMETER StateFilePath
        Path to the processing.json state file
    .RETURNS
        PSCustomObject containing completed hosts or empty object if file doesn't exist
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$StateFilePath
    )
    try {
        if (Test-Path $StateFilePath) {
            InfoMessage "Loading completed hosts from: $StateFilePath"
            $stateContent = Get-Content -Path $StateFilePath -Raw -Encoding UTF8
            $state = $stateContent | ConvertFrom-Json
            if ($state -and $state.completed_hosts) {
                $completedCount = ($state.completed_hosts | Get-Member -MemberType NoteProperty).Count
                InfoMessage "Found $completedCount previously completed hosts."
                return $state.completed_hosts
            }
        }
        # Return empty object if file doesn't exist or is invalid
        InfoMessage "No previous completed hosts found. Starting fresh."
        return [PSCustomObject]@{}
    } catch {
        WarningMessage "Failed to load completed hosts: $_"
        InfoMessage "Starting with empty completed hosts list."
        return [PSCustomObject]@{}
    }
}
#endregion LoadCompletedHosts
#region SaveCompletedHosts
function SaveCompletedHosts {
    <#
    .SYNOPSIS
        Saves the completed hosts list to processing.json file.
    .DESCRIPTION
        Saves the simple completed hosts list to JSON file.
    .PARAMETER StateFilePath
        Path to the processing.json state file
    .PARAMETER CompletedHosts
        The completed hosts object to save
    .RETURNS
        Boolean indicating success/failure
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$StateFilePath,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$CompletedHosts
    )
    try {
        # Create simple state object
        $state = [PSCustomObject]@{
            last_updated = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            completed_hosts = $CompletedHosts
        }
        # Convert to JSON with proper formatting
        $jsonContent = $state | ConvertTo-Json -Depth 3 -Compress:$false
        # Save to file with UTF8 encoding
        $jsonContent | Out-File -FilePath $StateFilePath -Encoding UTF8
        DebugMessage "Completed hosts saved to: $StateFilePath"
        return $true
    } catch {
        WarningMessage "Failed to save completed hosts: $_"
        return $false
    }
}
#endregion SaveCompletedHosts
#region IsHostCompleted
function IsHostCompleted {
    <#
    .SYNOPSIS
        Checks if a host has already been completed.
    .DESCRIPTION
        Simple check to see if host exists in completed hosts list.
    .PARAMETER CompletedHosts
        The completed hosts object to check
    .PARAMETER HostAddress
        The host address/name to check
    .RETURNS
        Boolean indicating if host is already completed
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$CompletedHosts,
        [Parameter(Mandatory=$true)]
        [string]$HostAddress
    )
    try {
        if ($CompletedHosts.PSObject.Properties[$HostAddress]) {
            $timestamp = $CompletedHosts.PSObject.Properties[$HostAddress].Value
            InfoMessage "Host $HostAddress already completed on $timestamp. Skipping."
            return $true
        }
        return $false
    } catch {
        WarningMessage "Error checking completion for $HostAddress`: $_"
        return $false
    }
}
#endregion IsHostCompleted
#region MarkHostCompleted
function MarkHostCompleted {
    <#
    .SYNOPSIS
        Marks a host as completed with current timestamp.
    .DESCRIPTION
        Adds or updates a host in the completed hosts list with current timestamp.
    .PARAMETER CompletedHosts
        The completed hosts object to update
    .PARAMETER HostAddress
        The host address/name to mark as completed
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$CompletedHosts,
        [Parameter(Mandatory=$true)]
        [string]$HostAddress
    )
    try {
        $timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        $CompletedHosts | Add-Member -MemberType NoteProperty -Name $HostAddress -Value $timestamp -Force
        InfoMessage "Marked host $HostAddress as completed at $timestamp"
    } catch {
        WarningMessage "Failed to mark host $HostAddress as completed: $_"
    }
}
#endregion MarkHostCompleted
#endregion Simple Host Completion Tracking
#endregion orc_tracking
# GetMSSQLHostPorts
#region orc_mssql_discovery
#region SQL Server Discovery
#region GetMSSQLHostPorts
function GetMSSQLHostPorts {
    <#
    .SYNOPSIS
        Discovers SQL Server endpoints on the local host.
    .DESCRIPTION
        Scans for SQL Server listeners on the local machine and returns prioritized
        list of endpoints to try. Prioritizes localhost, then hostname, then IPs.
        Filters by sqlservr.exe process to exclude Browser service (port 1434).
    .OUTPUTS
        Returns array of server endpoints in "host,port" format, prioritized:
        1. localhost (loopback addresses)
        2. hostname (wildcard and hostname IP listeners)
        3. Specific IPs
    .NOTES
        Requires SQL Server to be running on the local machine.
        Standard port 1433 is prioritized when available.
    #>
    $listener = Get-NetTCPConnection -State Listen | Where-Object {
        (Get-Process -Id $_.OwningProcess).ProcessName -eq "sqlservr" -and
        $_.LocalAddress -match '^\d{1,3}(\.\d{1,3}){3}$'
    }
    if (-not $listener) {
        DebugMessage "No SQL Server listener found. Please ensure SQL Server is running."
        return @()
    }
    # write all options to the log
    foreach ($item in $listener) {
        DebugMessage "Found SQL Server listener: LocalAddress=$($item.LocalAddress), LocalPort=$($item.LocalPort)"
    }
    # Get hostname and resolve it to IP
    $hostname = $env:COMPUTERNAME
    $hostnameIP = $null
    try {
        $hostnameIP = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 -ExpandProperty IPAddressToString
        InfoMessage "Resolved hostname '$hostname' to IP: $hostnameIP"
    } catch {
        WarningMessage "Failed to resolve hostname '$hostname' to IP: $_"
    }
    # Phase 1: Filter listeners - prioritize standard ports 1433
    $standardPortListeners = $listener | Where-Object { $_.LocalPort -eq 1433 }
    $candidateListeners = if ($standardPortListeners) {
        InfoMessage "Found SQL Server listeners on standard ports, prioritizing them"
        $standardPortListeners
    } else {
        InfoMessage "No standard ports found, using all available listeners"
        $listener
    }
    # Phase 2: Build prioritized list of all potential server addresses
    $prioritizedServers = @()
    # Priority 1: loopback addresses
    $loopbackListeners = $candidateListeners | Where-Object { $_.LocalAddress -like "127.*" }
    foreach ($listener in $loopbackListeners) {
        $prioritizedServers += "localhost,$($listener.LocalPort)"
    }
    # Priority 2: wildcard listeners (0.0.0.0) - use hostname
    $wildcardListeners = $candidateListeners | Where-Object { $_.LocalAddress -eq "0.0.0.0" }
    foreach ($listener in $wildcardListeners) {
        $prioritizedServers += "${hostname},$($listener.LocalPort)"
    }
    # Priority 3: hostname IP listeners - use hostname
    if ($hostnameIP) {
        $hostnameIPListeners = $candidateListeners | Where-Object { $_.LocalAddress -eq $hostnameIP }
        foreach ($listener in $hostnameIPListeners) {
            $prioritizedServers += "${hostname},$($listener.LocalPort)"
        }
    }
    # Priority 4: all other listeners - use actual IP
    $otherListeners = $candidateListeners | Where-Object {
        $_.LocalAddress -notlike "127.*" -and
        $_.LocalAddress -ne "0.0.0.0" -and
        $_.LocalAddress -ne $hostnameIP
    }
    foreach ($listener in $otherListeners) {
        $prioritizedServers += "$($listener.LocalAddress),$($listener.LocalPort)"
    }
    InfoMessage "Discovered $($prioritizedServers.Count) SQL Server endpoints to try"
    return $prioritizedServers
}
#endregion GetMSSQLHostPorts
#endregion SQL Server Discovery
#endregion orc_mssql_discovery
#region MainOrchestrator
function MainOrchestrator {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$config
    )
    # Skip certificate check for Invoke-WebRequest,
    # this is needed for self-signed certificates of the Flex server
    SetTLSVersion
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
    # Upgrade mode: skip all validation, just upload and run silent installers
    if ($Upgrade.IsPresent) {
        ImportantMessage "Upgrade mode: skipping registration and credential validation"
        # Set upgrade_mode flag on all hosts
        foreach ($hostInfo in $hostsWithoutIssues) {
            $hostInfo | Add-Member -NotePropertyName "upgrade_mode" -NotePropertyValue $true -Force
        }
    } else {
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
    }
    InfoMessage "The following hosts will be $(if ($Upgrade.IsPresent) { 'upgraded' } else { 'configured' }):"
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
    if ($Upgrade) {
        GenerateUpgradeConfigTemplate
    } else {
        GenerateConfigTemplate
    }
    exit 0
}
# get the configuration file path from the command line argument -ConfigPath
if (-Not $ConfigPath) {
    ErrorMessage "Configuration file path is required. Please provide it as an argument to the script using -ConfigPath parameter."
    InfoMessage "Usage: .\orchestrator.ps1 -ConfigPath <path_to_config_file>"
    Exit 1
}
if ($Upgrade) {
    $config = ReadConfigFile -ConfigFile $ConfigPath -Upgrade
} else {
    $config = ReadConfigFile -ConfigFile $ConfigPath
}
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
} elseif ($Upgrade) {
    ImportantMessage "Mode: UPGRADE (Silent installers only)"
} else {
    ImportantMessage "Mode: LIVE INSTALLATION"
}
if ($Force) {
    ImportantMessage "Force Mode: ENABLED (Ignoring completed hosts tracking)"
}
if ($Upgrade) {
    ImportantMessage "Upgrade Mode: ENABLED (Skipping registration and validation)"
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
# Stop transcript logging
try {
    WriteHostsSummary -Hosts $config.hosts -OutputPath "STDOUT"
    Stop-Transcript
    InfoMessage "Full execution log saved to: $script:TranscriptPath"
} catch {
    # Transcript may not have been started successfully
}
exit 0
# MARKER: HOST_INSTALLER_STARTS_HERE
#region orc_host_installer
<#
.SYNOPSIS
    Installs Silk Echo components (Node Agent and VSS Provider) on a remote host.
.DESCRIPTION
    This PowerShell script installs the Silk Node Agent and Silk VSS Provider service on a remote Windows host.
    It connects to Silk Flex to register the host, downloads the required installers, and performs the installation
    with the provided configuration parameters.
    The script requires administrative privileges and assumes that all necessary prerequisites are in place.
.PARAMETER FlexIP
    The IP address of the Silk Flex server.
.PARAMETER FlexToken
    The authentication token for accessing the Silk Flex API.
.PARAMETER DBConnectionString
    The SQL Server connection string for the Silk Node Agent.
.PARAMETER SilkAgentPath
    The local file path to the Silk Node Agent installer.
.PARAMETER SilkVSSPath
    The local file path to the Silk VSS Provider installer.
.PARAMETER SDPId
    The SDP (Silk Data Platform) identifier.
.PARAMETER SDPUsername
    The username for SDP authentication.
.PARAMETER SDPPassword
    The password for SDP authentication.
.PARAMETER MountPointsDirectory
    The directory where mount points for the Silk Node Agent will be created.
.PARAMETER DirectoryToInstall
    The target directory for the installers. This parameter will be passed to both the SilkAgent installer (using /D flag) and VSS installer (using /DIR flag).
.PARAMETER DryRun
    Perform validation and connectivity tests without actually installing the components.
    When enabled, the script will verify downloads, connections, and prerequisites but skip the actual installation steps.
.EXAMPLE
    .\orc_host_installer.ps1 -FlexIP "10.0.0.1" -FlexToken "abc123" -DBConnectionString "server=localhost;..." -SilkAgentPath "C:\Temp\SilkInstallers\agent-installer.exe" -SilkVSSPath "C:\Temp\SilkInstallers\vss-installer.exe" -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password"
    Installs Silk Echo components with the specified parameters.
.EXAMPLE
    .\orc_host_installer.ps1 -FlexIP "10.0.0.1" -FlexToken "abc123" -DBConnectionString "server=localhost;..." -SilkAgentPath "C:\Temp\SilkInstallers\agent-installer.exe" -SilkVSSPath "C:\Temp\SilkInstallers\vss-installer.exe" -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password" -DryRun
    Performs validation and connectivity tests without installing the components.
.NOTES
    File Name      : orc_host_installer.ps1
    Author         : Silk.us, Inc.
    Prerequisite   : PowerShell version 5 or higher, Administrator privileges
    Copyright      : (c) 2024 Silk.us, Inc.
.INPUTS
    String parameters for configuration and authentication.
.OUTPUTS
    Installation status messages and logs.
.FUNCTIONALITY
    Remote installation, System administration, Silk Echo deployment
#>
# PowerShell script to install Echo on a remote host
# This script assumes you have the necessary permissions and prerequisites in place.
# It installs the Silk Node Agent and the Silk VSS Provider service.
# Make sure to run this script with administrative privileges.
param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigJson
)
# Parse JSON configuration
try {
    $Config = $ConfigJson | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse ConfigJson parameter: $_"
    throw
}
# Extract parameters from config
$FlexIP = $Config.flex_host_ip
$FlexToken = $Config.flex_access_token
$DBConnectionString = $Config.sql_connection_string
$SilkAgentPath = $Config.agent_path
$SilkVSSPath = $Config.vss_path
$SDPId = $Config.sdp_id
$SDPUsername = $Config.sdp_username
$SDPPassword = $Config.sdp_password
$MountPointsDirectory = $Config.mount_points_directory
$DirectoryToInstall = $Config.install_to_directory
$DryRun = [switch]$Config.is_dry_run
$InstallAgent = [bool]$Config.install_agent
$InstallVSS = [bool]$Config.install_vss
$UpgradeMode = [bool]$Config.upgrade_mode
# print info about params
Write-Host "Parameters:"
Write-Host "  FlexIP: $FlexIP"
Write-Host "  DryRun: $DryRun"
Write-Host "  SilkAgentPath: $SilkAgentPath"
Write-Host "  SilkVSSPath: $SilkVSSPath"
Write-Host "  InstallAgent: $InstallAgent"
Write-Host "  InstallVSS: $InstallVSS"
Write-Host "  DirectoryToInstall: $DirectoryToInstall"
Write-Host "  UpgradeMode: $UpgradeMode"
if ($DebugPreference -eq 'Continue' -or $VerbosePreference -eq 'Continue') {
    Write-Host "Debug and Verbose output enabled."
    $DebugPreference = 'Continue'
    $VerbosePreference = 'Continue'
} else {
    Write-Host "Debug and Verbose output disabled."
    $DebugPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
}
# suppress progress bar
$ProgressPreference = 'SilentlyContinue'
# ErrorMessage, InfoMessage, DebugMessage, WarningMessage
#region orc_logging_on_host
#region Logging
Function LogTimeStamp {
    # returns formatted timestamp
	return Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
}
function Sanitize {
    param (
        [string]$Text
    )
    # Reduct password from text, sometimes text contains connection string with password
    $ReductedText = $Text -replace '(?i)(?<=Password=)[^; ]+', '[reducted]'
    $ReductedText = $ReductedText -replace '(?i)(?<=Token=)[^; ]+', '[reducted]'
    # Replace the value of the $FlexToken variable with '[reducted]' only if it exists and is not empty
    if ($Global:FlexToken -and $Global:FlexToken.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:FlexToken), '[reducted]'
    }
    # Replace the value of the $SDPPassword variable with '[reducted]' only if it exists and is not empty
    if ($Global:SDPPassword -and $Global:SDPPassword.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:SDPPassword), '[reducted]'
    }
    return $ReductedText
}
Function ArgsToSanitizedString {
    $sanitizedArgs = @()
    foreach ($arg in $args) {
        if ($arg -is [System.Management.Automation.ErrorRecord]) {
            $sanitizedArgs += Sanitize -Text $arg.Exception.Message
        } else {
            $sanitizedArgs += Sanitize -Text $arg.ToString()
        }
    }
    return [string]::Join(' ', $sanitizedArgs)
}
Function ErrorMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - [ERROR] - $msg"
}
Function InfoMessage {
    $msg = ArgsToSanitizedString @args
    Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - [INFO] $msg"
}
Function DebugMessage {
    if ($DebugPreference -ne 'Continue') {
        return
    }
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - [DEBUG] - $msg"
}
Function DebugMessageRaw {
    if ($DebugPreference -ne 'Continue') {
        return
    }
    $msg = [string]::Join(' ', $args)
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - [DEBUG] (RAW) - $msg"
}
Function WarningMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - [WARN] - $msg"
}
#endregion Logging
#endregion orc_logging_on_host
# SkipCertificateCheck
#region orc_security
#region SetTLSVersion
function SetTLSVersion {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        # if Powershell version is 7 or higher, set both TLS 1.2 and TLS 1.3
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
            Write-Host "Enabled TLS 1.2 and TLS 1.3."
        }
        catch {
            Write-Host "TLS 1.3 not supported, enabling only TLS 1.2."
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Write-Host "Enabled TLS 1.2."
        }
    } else {
        # for Windows PowerShell, set only TLS 1.2
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Write-Host "Enabled TLS 1.2."
    }
}
#endregion SetTLSVersion
#region SkipCertificateCheck
function SkipCertificateCheck {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        # if Powershell version is 7 or higher, set SkipCertificateCheck
        return
    }
    # set policy only once per powershell sessions
    $currentPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    if ($currentPolicy -eq $null -or ($currentPolicy.GetType().FullName -ne "TrustAllCertsPolicy")) {
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    } else {
        Write-Host "Certificate policy already set to $([System.Net.ServicePointManager]::CertificatePolicy). skipping."
    }
}
#endregion SkipCertificateCheck
#endregion orc_security
# CallSelfCertEndpoint, CallSDPApi, CallFlexApi
#region orc_web_client
#region NETWORK
#region CallSelfCertEndpoint
function CallSelfCertEndpoint {
    param (
        [string]$URL,
        [string]$HttpMethod,
        [object]$RequestBody,
        [hashtable]$Headers
    )
    DebugMessage "Calling [$HttpMethod]$URL"
    # capitalize the first letter of HttpMethod
    $HttpMethod = $HttpMethod.Substring(0,1).ToUpper() + $HttpMethod.Substring(1).ToLower()
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        if ( $HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
    } else {
        if ($HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            # If no request body is provided
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -ErrorAction Stop
        }
    }
    return $response
}
#endregion CallSelfCertEndpoint
#region CallSDPApi
function CallSDPApi {
    param (
        [string]$SDPHost,
        [string]$SDPPort,
        [string]$ApiEndpoint,
        [System.Management.Automation.PSCredential]$Credential
    )
    $url = "https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"
    DebugMessage "Call SDPApi USERNAME: $($Credential.UserName)"
    $BasicAuthString = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $BasicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($BasicAuthString))
    $_headers = @{
        "Authorization" = "Basic $BasicAuth"
    }
    try {
        $response = CallSelfCertEndpoint -URL $url -HttpMethod "GET" -RequestBody $null -Headers $_headers
        if ($response.StatusCode -ne 200) {
            ErrorMessage "Failed to call SDP API at $url. Status code: $($response.StatusCode)"
            return $null
        }
        DebugMessage "Response from SDP API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling SDP API: $_"
        return $null
    }
}
#endregion CallSDPApi
#region CallFlexApi
function CallFlexApi {
        param (
        [string]$FlexIP,
        [string]$FlexToken,
        [string]$ApiEndpoint,
        [string]$HttpMethod,
        [string]$RequestBody
    )
    $flexApiUrl = "https://$FlexIP$ApiEndpoint"
    $headers = @{ "Authorization" = "Bearer $FlexToken" }
    DebugMessage "Calling Flex API at $flexApiUrl with method $HttpMethod"
    try {
        $response = CallSelfCertEndpoint -URL $flexApiUrl -HttpMethod $HttpMethod -RequestBody $RequestBody -Headers $headers
        DebugMessage "Response from Flex API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling Flex API: $_"
        return $null
    }
}
#endregion CallFlexApi
#endregion NETWORK
#endregion orc_web_client
# Constants for installer
#region orc_constants_installer
#region Constants
# Internal Installation Process Timeout (110 seconds)
Set-Variable -Name INTERNAL_INSTALL_TIMEOUT_SECONDS -Value 110 -Option AllScope -Scope Script
#endregion Constants
#endregion orc_constants_installer
# GetMSSQLHostPorts
#region orc_mssql_discovery
#region SQL Server Discovery
#region GetMSSQLHostPorts
function GetMSSQLHostPorts {
    <#
    .SYNOPSIS
        Discovers SQL Server endpoints on the local host.
    .DESCRIPTION
        Scans for SQL Server listeners on the local machine and returns prioritized
        list of endpoints to try. Prioritizes localhost, then hostname, then IPs.
        Filters by sqlservr.exe process to exclude Browser service (port 1434).
    .OUTPUTS
        Returns array of server endpoints in "host,port" format, prioritized:
        1. localhost (loopback addresses)
        2. hostname (wildcard and hostname IP listeners)
        3. Specific IPs
    .NOTES
        Requires SQL Server to be running on the local machine.
        Standard port 1433 is prioritized when available.
    #>
    $listener = Get-NetTCPConnection -State Listen | Where-Object {
        (Get-Process -Id $_.OwningProcess).ProcessName -eq "sqlservr" -and
        $_.LocalAddress -match '^\d{1,3}(\.\d{1,3}){3}$'
    }
    if (-not $listener) {
        DebugMessage "No SQL Server listener found. Please ensure SQL Server is running."
        return @()
    }
    # write all options to the log
    foreach ($item in $listener) {
        DebugMessage "Found SQL Server listener: LocalAddress=$($item.LocalAddress), LocalPort=$($item.LocalPort)"
    }
    # Get hostname and resolve it to IP
    $hostname = $env:COMPUTERNAME
    $hostnameIP = $null
    try {
        $hostnameIP = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 -ExpandProperty IPAddressToString
        InfoMessage "Resolved hostname '$hostname' to IP: $hostnameIP"
    } catch {
        WarningMessage "Failed to resolve hostname '$hostname' to IP: $_"
    }
    # Phase 1: Filter listeners - prioritize standard ports 1433
    $standardPortListeners = $listener | Where-Object { $_.LocalPort -eq 1433 }
    $candidateListeners = if ($standardPortListeners) {
        InfoMessage "Found SQL Server listeners on standard ports, prioritizing them"
        $standardPortListeners
    } else {
        InfoMessage "No standard ports found, using all available listeners"
        $listener
    }
    # Phase 2: Build prioritized list of all potential server addresses
    $prioritizedServers = @()
    # Priority 1: loopback addresses
    $loopbackListeners = $candidateListeners | Where-Object { $_.LocalAddress -like "127.*" }
    foreach ($listener in $loopbackListeners) {
        $prioritizedServers += "localhost,$($listener.LocalPort)"
    }
    # Priority 2: wildcard listeners (0.0.0.0) - use hostname
    $wildcardListeners = $candidateListeners | Where-Object { $_.LocalAddress -eq "0.0.0.0" }
    foreach ($listener in $wildcardListeners) {
        $prioritizedServers += "${hostname},$($listener.LocalPort)"
    }
    # Priority 3: hostname IP listeners - use hostname
    if ($hostnameIP) {
        $hostnameIPListeners = $candidateListeners | Where-Object { $_.LocalAddress -eq $hostnameIP }
        foreach ($listener in $hostnameIPListeners) {
            $prioritizedServers += "${hostname},$($listener.LocalPort)"
        }
    }
    # Priority 4: all other listeners - use actual IP
    $otherListeners = $candidateListeners | Where-Object {
        $_.LocalAddress -notlike "127.*" -and
        $_.LocalAddress -ne "0.0.0.0" -and
        $_.LocalAddress -ne $hostnameIP
    }
    foreach ($listener in $otherListeners) {
        $prioritizedServers += "$($listener.LocalAddress),$($listener.LocalPort)"
    }
    InfoMessage "Discovered $($prioritizedServers.Count) SQL Server endpoints to try"
    return $prioritizedServers
}
#endregion GetMSSQLHostPorts
#endregion SQL Server Discovery
#endregion orc_mssql_discovery
# global variables
# ============================================================================
# Create SDP credential from passed parameters (only if installing VSS)
if ($InstallVSS -and $SDPUsername -and $SDPPassword) {
    $SDPCredential = New-Object System.Management.Automation.PSCredential($SDPUsername, (ConvertTo-SecureString $SDPPassword -AsPlainText -Force))
} else {
    $SDPCredential = $null
}
Set-Variable -Name SDPCredential -Value $SDPCredential -Scope Global
Set-Variable -Name IsDryRun -Value $DryRun.IsPresent -Scope Global
Set-Variable -Name InstallAgent -Value $InstallAgent -Scope Global
Set-Variable -Name InstallVSS -Value $InstallVSS -Scope Global
Set-Variable -Name UpgradeMode -Value $UpgradeMode -Scope Global
Set-Variable -Name AgentInstallationLogPath -Scope Global
Set-Variable -Name SVSSInstallationLogPath -Scope Global
Set-Variable -Name HostID -Value "$(hostname)" -Scope Global
Set-Variable -Name FlexToken -Value $FlexToken -Scope Global
$SilkAgentDirectory = Split-Path -Path $SilkAgentPath -Parent
Set-Variable -Name AgentInstallationLogPath -Value "$SilkAgentDirectory\install.log" -Scope Global
$SilkVSSDirectory = Split-Path -Path $SilkVSSPath -Parent
Set-Variable -Name SVSSInstallationLogPath -Value "$SilkVSSDirectory\SilkVSSProviderInstall.log" -Scope Global
DebugMessage "Agent installation log path: $AgentInstallationLogPath"
DebugMessage "SVSS installation log path: $SVSSInstallationLogPath"
#region TestFlexConnectivity
function TestFlexConnectivity {
    param (
        [string]$FlexIP,
        [string]$FlexToken
    )
    $ApiEndpoint = '/api/v2/flex/info'
    try {
        $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "GET" -RequestBody $null
        if ($response.StatusCode -eq 200) {
            return $true
        } else {
            ErrorMessage "Failed to call Flex API at $flexApiUrl. Status code: $($response.StatusCode)"
            return $false
        }
    } catch {
        ErrorMessage "Error connecting to Flex: $_"
        return $false
    }
    return $false
}
#endregion TestFlexConnectivity
#region RegisterHostAtFlex
function RegisterHostAtFlex {
    param (
        [string]$FlexIP,
        [string]$FlexToken
    )
    InfoMessage "Registering host at Flex... $HostID"
    $ApiEndpoint = "/api/hostess/v1/hosts/${HostID}"
    InfoMessage "Unregister if exists"
    $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "DELETE" -RequestBody $null
    if ($response.StatusCode -ne 204) {
        ErrorMessage "Failed to unregister host at Flex. Status code: $($response.StatusCode)"
        return ""
    }
    # Register the host at Flex with hostname and db_vendor, hostname like it return from pwsh hostname (not $env:COMPUTERNAME because it is always UPPERCASE)
    $RequestBody = @{
        "db_vendor" = "mssql"
    } | ConvertTo-Json
    try {
        $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "PUT" -RequestBody $RequestBody
        DebugMessage "Response from Flex API: $($response.StatusCode) - $($response.StatusDescription)"
        if ($response.StatusCode -eq 201) {
            #read token from response and return it { "host_id": "string", "db_vendor": "mssql", "token": "string"}
            $responseContent = $response.Content | ConvertFrom-Json
            $token = $responseContent.token
            InfoMessage "Successfully registered host at Flex as $HostID."
            return $token
        } else {
            ErrorMessage "Failed to register host at Flex. Status code: $($response)"
            return ""
        }
    } catch {
        ErrorMessage "Error registering host at Flex: $_"
        return ""
    }
}
#endregion RegisterHostAtFlex
#region createAndTestConnectionString
function createAndTestConnectionString {
    param (
        [string]$DBConnectionString
    )
    # Parse input connection string
    $baseParams = @{}
    $DBConnectionString = $DBConnectionString.Trim()
    $parts = $DBConnectionString -split ';'
    foreach ($part in $parts) {
        if ($part.Trim()) {
            $key, $value = $part -split '=', 2
            $baseParams[$key.Trim()] = $value.Trim()
        }
    }
    # Set application name to SilkAgent
    $baseParams['Application Name'] = 'SilkAgent'
    # currently we support only credentials authentication and will failed if there is no User ID and Password
    if (-not $baseParams.ContainsKey('User ID') -or -not $baseParams.ContainsKey('Password')) {
        ErrorMessage "Connection string must include User ID and Password for SQL authentication"
        return $null
    }
    # If Server is already specified, test that connection first
    if ($baseParams.ContainsKey('Server') -and $baseParams['Server'] -ne '') {
        $connectionStringParts = $baseParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)
        InfoMessage "Testing provided server: $($baseParams['Server'])"
        if (TestSQLConnection -ConnectionString $connectionString) {
            InfoMessage "Successfully connected to provided server"
            return $connectionString
        } else {
            WarningMessage "Failed to connect to provided server, will try auto-discovery"
        }
    }
    # Auto-discover SQL Server instances and test each one
    $discoveredServers = GetMSSQLHostPorts
    if ($discoveredServers.Count -eq 0) {
        ErrorMessage "No SQL Server instances discovered. Please ensure SQL Server is running."
        return $null
    }
    InfoMessage "Testing $($discoveredServers.Count) discovered SQL Server endpoints..."
    foreach ($serverEndpoint in $discoveredServers) {
        $testParams = $baseParams.Clone()
        $testParams['Server'] = $serverEndpoint
        $connectionStringParts = $testParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)
        InfoMessage "Testing connection to: $serverEndpoint"
        if (TestSQLConnection -ConnectionString $connectionString) {
            InfoMessage "Successfully connected to SQL Server at: $serverEndpoint"
            return $connectionString
        }
    }
    ErrorMessage "Failed to connect to any discovered SQL Server instances"
    return $null
}
#endregion createAndTestConnectionString
#region TestSQLConnection
function TestSQLConnection {
    param (
        [string]$ConnectionString
    )
    try {
        $sqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        $sqlConnection.Open()
        $sqlConnection.Close()
        return $true
    } catch {
        DebugMessage "Connection failed: $($_.Exception.Message)"
        return $false
    }
}
#endregion TestSQLConnection
#region PrintAgentInstallationLog
function PrintAgentInstallationLog {
    InfoMessage "======== Agent Installation Log ========"
    if (Test-Path -Path $AgentInstallationLogPath) {
        $logContent = Get-Content -Path $AgentInstallationLogPath
        foreach ($line in $logContent) {
            InfoMessage $line
        }
    } else {
        InfoMessage "No installation log found at $AgentInstallationLogPath"
    }
    InfoMessage "======== End Agent Installation Log ========"
}
#endregion PrintAgentInstallationLog
#region PrintSVSSInstallationLog
function PrintSVSSInstallationLog {
    InfoMessage "======== SVSS Installation Log ========"
    if (Test-Path -Path $SVSSInstallationLogPath) {
        $logContent = Get-Content -Path $SVSSInstallationLogPath
        foreach ($line in $logContent) {
            InfoMessage $line
        }
    } else {
        InfoMessage "No installation log found at $SVSSInstallationLogPath"
    }
    InfoMessage "======== End SVSS Installation Log ========"
}
#endregion PrintSVSSInstallationLog
#region CleanupInstallerFiles
function CleanupInstallerFiles {
    # Remove all files in the directory including the directory itself
    # if install_agent is true remove SilkAgentDirectory
    if ($InstallAgent -and (Test-Path -Path $SilkAgentDirectory)) {
        try {
            Remove-Item -Path $SilkAgentDirectory -Recurse -Force
            InfoMessage "Cleaned up installer files in directory: $SilkAgentDirectory"
        } catch {
            WarningMessage "Failed to cleanup installer files in directory $SilkAgentDirectory`: $_"
        }
    }
    if ($InstallVSS -and (Test-Path -Path $SilkVSSDirectory)) {
        try {
            Remove-Item -Path $SilkVSSDirectory -Recurse -Force
            InfoMessage "Cleaned up installer files in directory: $SilkVSSDirectory"
        } catch {
            WarningMessage "Failed to cleanup installer files in directory $SilkVSSDirectory`: $_"
        }
    }
}
#endregion CleanupInstallerFiles
#region EscapePowershellParameter
function EscapePowershellParameter {
    param (
        [string]$Parameter
    )
    # Spaces and special characters should be handled by PowerShell automatically, but we can ensure they are escaped
    $escapedParameter = $Parameter -replace '([;,])', '`$1'
    return $escapedParameter
}
#endregion EscapePowershellParameter
#region StartProcessWithTimeout
function StartProcessWithTimeout {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [array]$ArgumentList,
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 90,
        [Parameter(Mandatory=$true)]
        [string]$ProcessName
    )
    InfoMessage "Starting installation of $ProcessName from $FilePath with timeout of $TimeoutSeconds seconds"
    try {
        # Convert ArgumentList array to JSON string for safe job parameter passing
        $argsJson = $ArgumentList | ConvertTo-Json -Compress
        # Start installation process with timeout
        $installJob = Start-Job -ScriptBlock {
            param($InstallerPath, $ArgsJson)
            try {
                # Convert JSON back to array
                $Args = $ArgsJson | ConvertFrom-Json
                # Ensure it's an array even if single element
                if ($Args -is [string]) {
                    $Args = @($Args)
                }
                $process = Start-Process -FilePath $InstallerPath -ArgumentList $Args -Wait -NoNewWindow -PassThru
                Write-Host "Process completed with exit code: $($process.ExitCode)"
                return $process.ExitCode
            } catch {
                Write-Error "Process failed: $_"
                return 999
            }
        } -ArgumentList $FilePath, $argsJson
        DebugMessage "Started job with ID $($installJob.Id) for $ProcessName installation"
        # Wait for job completion with timeout
        $waitResult = $installJob | Wait-Job -Timeout $TimeoutSeconds
        if ($waitResult) {
            # Job completed within timeout
            $exitCode = Receive-Job -Job $installJob
            Remove-Job -Job $installJob -Force
            InfoMessage "$ProcessName installation completed with exit code [$exitCode]"
            return @{
                Success = ($exitCode -eq 0)
                Reason = "Completed"
                ExitCode = $exitCode
                ProcessName = $ProcessName
            }
        } else {
            # Installation timed out
            ErrorMessage "$ProcessName installation timed out after $TimeoutSeconds seconds"
            Stop-Job -Job $installJob -ErrorAction SilentlyContinue
            Remove-Job -Job $installJob -Force -ErrorAction SilentlyContinue
            return @{
                Success = $false
                Reason = "Timeout"
                TimeoutSeconds = $TimeoutSeconds
                ProcessName = $ProcessName
            }
        }
    } catch {
        ErrorMessage "Error installing $ProcessName`: $_"
        return @{
            Success = $false
            Reason = "Error"
            ErrorMessage = $_.Exception.Message
            ProcessName = $ProcessName
        }
    }
}
#endregion StartProcessWithTimeout
#region InstallSilkNodeAgent
function InstallSilkNodeAgent {
    param (
        [string]$InstallerFilePath,
        [string]$SQLConnectionString,
        [string]$FlexIP,
        [string]$AgentToken,
        [string]$MountPointsDirectory,
        [string]$InstallDir
    )
    InfoMessage "InstallSilkNodeAgent: executable $InstallerFilePath"
    # execute InstallerFilePath
    if (-not (Test-Path -Path $InstallerFilePath)) {
        InfoMessage "Installer file not found at $InstallerFilePath. Exiting script."
        return $false
    }
    # pass argumnets as /DbConnStr='"$sqlConn"'
    InfoMessage "Building arguments with SQLConnectionString='$SQLConnectionString', FlexIP='$FlexIP', AgentToken='[REDACTED]', MountPointsDirectory='$MountPointsDirectory', InstallDir='$InstallDir'"
    $arguments = @(
        '/S', # Silent installation
        "/DbConnStr='$SQLConnectionString'",
        "/FlexHost='$FlexIP'",
        "/Token='$AgentToken'",
        "/MountPointsDirectory='$MountPointsDirectory'"
    )
    # Add /D parameter if InstallDir is provided
    if ($InstallDir -and $InstallDir.Trim() -ne "") {
        $arguments += "/Directory='$InstallDir\SilkAgent'"
    }
    DebugMessage "Arguments array: $($arguments -join ' ')"
    # Run installation with timeout
    $installResult = StartProcessWithTimeout `
                        -FilePath $InstallerFilePath `
                        -ArgumentList $arguments `
                        -TimeoutSeconds $INTERNAL_INSTALL_TIMEOUT_SECONDS `
                        -ProcessName "Silk Node Agent"
    if (-not $installResult.Success) {
        # Return detailed failure information to caller
        return @{
            Success = $false
            Reason = $installResult.Reason
            Details = $installResult
            Message = switch ($installResult.Reason) {
                "Timeout" { "Silk Node Agent installation timed out after $($installResult.TimeoutSeconds) seconds" }
                "Error" { "Silk Node Agent installation failed with error: $($installResult.ErrorMessage)" }
                default { "Silk Node Agent installation failed" }
            }
        }
    }
    # error handling
    InfoMessage "Silk Node Agent installation completed. Checking installation log at $AgentInstallationLogPath"
    # test log file do not contain "error"
    # if "Installation process succeeded." in log means we are ok
    if (Test-Path -Path $AgentInstallationLogPath) {
        $logContent = Get-Content -Path $AgentInstallationLogPath
        $successMsgFound = $false
        if ($logContent -match "Installation process succeeded.") {
            $successMsgFound = $true
        }
        if (-not $successMsgFound -and $logContent -match "(?i)error") {
            ErrorMessage "Installation log contains errors. Please check the log file at $AgentInstallationLogPath"
            return @{
                Success = $false
                Reason = "LogError"
                Message = "Silk Node Agent installation log contains errors. Check $AgentInstallationLogPath."
                LogPath = $AgentInstallationLogPath
            }
        } else {
            DebugMessage "Silk Node Agent installed successfully."
            return @{
                Success = $true
                Reason = "Completed"
                Message = "Silk Node Agent installed successfully"
                ExitCode = $installResult.ExitCode
            }
        }
    } else {
        ErrorMessage "Installation log file not found at $AgentInstallationLogPath. Installation may have failed."
        return @{
            Success = $false
            Reason = "LogNotFound"
            Message = "Installation log file not found at $AgentInstallationLogPath"
            LogPath = $AgentInstallationLogPath
        }
    }
}
#endregion InstallSilkNodeAgent
#region GetSDPInfo
function GetSDPInfo {
    # we should have sdp floating ip, username and password for vss provider
    param (
        [string]$FlexIP,
        [string]$FlexToken,
        [string]$SDPID = ""
    )
    $ApiEndpoint = '/api/v1/pages/dashboard'
    try {
        $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "GET" -RequestBody $null
        if ($response.StatusCode -ne 200) {
            ErrorMessage "Failed to get SDP info from Flex. Status code: $($response.StatusCode)"
            return $null
        }
        $responseContent = $response.Content | ConvertFrom-Json
        if (-not $responseContent.k2xs) {
            ErrorMessage "No k2xs found in the response from Flex."
            return $null
        }
        if (-not $SDPID) {
            # if SDPID not provided, take the first k2x id
            $SDPID = $responseContent.k2xs[0].id
            InfoMessage "No SDP ID provided. Using first k2x ID: $SDPID"
        }
        # case insensitive search for k2x with given SDPID
        $SDPID = $SDPID.ToLower()
        DebugMessage "Searching for k2x with ID: $SDPID"
        $k2x = $responseContent.k2xs | Where-Object { $_.id.ToLower() -eq $SDPID }
        if (-not $k2x) {
            ErrorMessage "No k2x found with ID $SDPID in the response from Flex."
            return $null
        }
        $sdpInfo = @{
            "id" = $k2x.id
            "version" = $k2x.version
            "mc_floating_ip" = $k2x.mc_floating_ip
            "mc_https_port" = $k2x.mc_https_port
            "credentials" = $null
        }
        DebugMessage "Found k2x with ID $($sdpInfo.id) and version $($sdpInfo.version)"
        return $sdpInfo
    } catch {
        ErrorMessage "Error getting SDP info from Flex: $_"
        return $null
    }
}
#endregion GetSDPInfo
#region ValidateSDPConnection
function ValidateSDPConnection {
    param (
        [string]$SDPHost,
        [string]$SDPPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ApiEndpoint = 'system/state'
    DebugMessage "Validating SDP connection for username: $($Credential.UserName)"
    $response = CallSDPApi -SDPHost $SDPHost -SDPPort $SDPPort -ApiEndpoint $ApiEndpoint -Credential $Credential
    if (-not $response) {
        ErrorMessage "Failed to call SDP API at https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"
        return $false
    }
    return $true
}
#endregion ValidateSDPConnection
#region InstallSilkVSSProvider
function InstallSilkVSSProvider {
    param (
        [string]$InstallerFilePath,
        [string]$SDPID,
        [string]$SDPHost,
        [string]$SDPPort,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$InstallDir
    )
    InfoMessage "Installing Silk VSS Provider from $InstallerFilePath"
    # execute InstallerFilePath
    if (-not (Test-Path -Path $InstallerFilePath)) {
        InfoMessage "Installer file not found at $InstallerFilePath. Exiting script."
        return $false
    }
    $arguments = @(
        '/VERYSILENT',
        "/external_ip=$SDPHost",
        "/host_name=$(hostname)",
        "/username=$($Credential.UserName)",
        "/password=$($Credential.GetNetworkCredential().Password)",
        "/log_level_provider=info",
        "/log_level_json=info",
        "/log_level_configurator=info",
        '/check_vg_full=false',
        '/snap_prefix=snap',
        '/retention_policy=Best_Effort_Retention',
        "/LOG=$SVSSInstallationLogPath"
    )
    # Add /DIR parameter if InstallDir is provided
    if ($InstallDir -and $InstallDir.Trim() -ne "") {
        $arguments += "/DIR=$InstallDir\SilkVSS"
    }
    InfoMessage "Silk VSS Provider installation arguments: $arguments"
    # Run installation with timeout
    $installResult = StartProcessWithTimeout `
                        -FilePath $InstallerFilePath `
                        -ArgumentList $arguments `
                        -TimeoutSeconds $INTERNAL_INSTALL_TIMEOUT_SECONDS `
                        -ProcessName "Silk VSS"
    if (-not $installResult.Success) {
        InfoMessage "Silk VSS Provider installation failed. $($installResult | Out-String)"
        # Return detailed failure information to caller
        return @{
            Success = $false
            Reason = $installResult.Reason
            Details = $installResult
            Message = switch ($installResult.Reason) {
                "Timeout" { "Silk VSS Provider installation timed out after $($installResult.TimeoutSeconds) seconds" }
                "Error" { "Silk VSS Provider installation failed with error: $($installResult.ErrorMessage)" }
                default { "Silk VSS Provider installation failed" }
            }
        }
    }
    # error handling
    InfoMessage "Silk VSS Provider installation completed. Checking installation log at $SVSSInstallationLogPath"
    # test log file do not contain "error"
    if (Test-Path -Path $SVSSInstallationLogPath) {
        $logContent = Get-Content -Path $SVSSInstallationLogPath
        $successMsgFound = $false
        if ($logContent -match "Installation process succeeded.") {
            $successMsgFound = $true
        }
        # split log content into lines and find all lines containing "error" or "out of memory" (case insensitive)
        if ( -not $successMsgFound -and $logContent -match "(?i)error") {
            ErrorMessage "Installation log contains errors. Please check the log file at $SVSSInstallationLogPath"
            return @{
                Success = $false
                Reason = "LogError"
                Message = "Silk VSS Provider installation log contains errors. Check $SVSSInstallationLogPath, $($errors -join '; ')"
                LogPath = $SVSSInstallationLogPath
            }
        } else {
            InfoMessage "Silk VSS Provider installed successfully."
            return @{
                Success = $true
                Reason = "Completed"
                Message = "Silk VSS Provider installed successfully"
                ExitCode = $installResult.ExitCode
            }
        }
    } else {
        ErrorMessage "Installation log file not found at $SVSSInstallationLogPath. Installation may have failed."
        return @{
            Success = $false
            Reason = "LogNotFound"
            Message = "Installation log file not found at $SVSSInstallationLogPath"
            LogPath = $SVSSInstallationLogPath
        }
    }
}
#endregion InstallSilkVSSProvider
#region setup_agent
function setup_agent {
    <#
    .SYNOPSIS
        Sets up and installs the Silk Node Agent component only.
    .DESCRIPTION
        This function handles all prerequisites and installation steps for the Silk Node Agent:
        - Creates and validates SQL Server connection string
        - Registers host at Flex to obtain agent token
        - Installs the Silk Node Agent
    .OUTPUTS
        Returns $null on success, or an error message string on failure.
    #>
    InfoMessage "Starting Silk Node Agent setup..."
    # Verify Agent installer exists
    if (-not (Test-Path $SilkAgentPath)) {
        ErrorMessage "Silk Node Agent installer not found at $SilkAgentPath"
        return "Unable to find Silk Node Agent installer at $SilkAgentPath"
    }
    InfoMessage "Silk Node Agent installer found at $SilkAgentPath"
    # Validate and create SQL Server connection string
    $ConnectionString = createAndTestConnectionString -DBConnectionString $DBConnectionString
    if (-not $ConnectionString) {
        ErrorMessage "Failed to create and test connection string"
        return "Unable to establish connection with any available SQL Server instance. Check SQL Server availability and credentials"
    }
    InfoMessage "Successfully established SQL Server connection with connection string: $ConnectionString"
    # If dry run, skip actual installation
    if ($IsDryRun) {
        InfoMessage "Dry run mode enabled. Skipping Silk Node Agent installation."
        return $null
    }
    # Register host at Flex to obtain agent token
    $AgentToken = RegisterHostAtFlex -FlexIP $FlexIP -FlexToken $FlexToken
    if (-not $AgentToken) {
        ErrorMessage "Failed to register host at Flex"
        return "Failed to register host $HostID with Flex and obtain agent token"
    }
    # Install Silk Node Agent
    $installResult = InstallSilkNodeAgent -InstallerFilePath $SilkAgentPath `
                                        -SQLConnectionString $ConnectionString `
                                        -FlexIP $FlexIP `
                                        -AgentToken $AgentToken `
                                        -MountPointsDirectory $MountPointsDirectory `
                                        -InstallDir $DirectoryToInstall
    # Print installation log immediately after installation attempt
    PrintAgentInstallationLog
    if (-not $installResult.Success) {
        ErrorMessage "Failed to install Silk Node Agent: $($installResult.Reason)"
        return $installResult.Message
    }
    InfoMessage "Silk Node Agent installation completed successfully"
    return $null
}
#endregion setup_agent
#region setup_vss
function setup_vss {
    <#
    .SYNOPSIS
        Sets up and installs the Silk VSS Provider component only.
    .DESCRIPTION
        This function handles all prerequisites and installation steps for the Silk VSS Provider:
        - Retrieves SDP information from Flex
        - Validates SDP connection
        - Installs the Silk VSS Provider
    .OUTPUTS
        Returns $null on success, or an error message string on failure.
    #>
    InfoMessage "Starting Silk VSS Provider setup..."
    # Verify VSS installer exists
    if (-not (Test-Path $SilkVSSPath)) {
        ErrorMessage "Silk VSS Provider installer not found at $SilkVSSPath"
        return "Unable to find Silk VSS Provider installer at $SilkVSSPath"
    }
    InfoMessage "Silk VSS Provider installer found at $SilkVSSPath"
    # Get SDP information from Flex
    $SDPInfo = GetSDPInfo -FlexIP $FlexIP -FlexToken $FlexToken -SDPID $SDPId
    if (-not $SDPInfo) {
        ErrorMessage "Failed to get SDP info from Flex"
        return "Unable to retrieve SDP information from Flex server"
    }
    $SDPID = $SDPInfo["id"]
    $SDPVersion = $SDPInfo["version"]
    $SDPHost = $SDPInfo["mc_floating_ip"]
    $SDPPort = $SDPInfo["mc_https_port"]
    InfoMessage "Successfully retrieved SDP info from Flex $SDPID ($SDPVersion) at ${SDPHost}:$SDPPort"
    # Validate SDP connection
    $SdpConnectionValid = ValidateSDPConnection -SDPHost $SDPHost -SDPPort $SDPPort -Credential $SDPCredential
    if (-not $SdpConnectionValid) {
        ErrorMessage "Failed to validate SDP connection"
        return "Unable to establish connection with SDP at ${SDPHost}:${SDPPort}"
    }
    InfoMessage "Successfully validated SDP connection"
    # If dry run, skip actual installation
    if ($IsDryRun) {
        InfoMessage "Dry run mode enabled. Skipping Silk VSS Provider installation."
        return $null
    }
    # Install Silk VSS Provider
    $vssResult = InstallSilkVSSProvider -InstallerFilePath $SilkVSSPath `
                                        -SDPID $SDPID `
                                        -SDPHost $SDPHost `
                                        -SDPPort $SDPPort `
                                        -Credential $SDPCredential `
                                        -InstallDir $DirectoryToInstall
    # Print installation log immediately after installation attempt
    PrintSVSSInstallationLog
    if (-not $vssResult.Success) {
        ErrorMessage "Failed to install Silk VSS Provider: $($vssResult.Reason)"
        return $vssResult.Message
    }
    InfoMessage "Silk VSS Provider installation completed successfully"
    return $null
}
#endregion setup_vss
#region upgrade_only
function upgrade_only {
    <#
    .SYNOPSIS
        Performs upgrade-only installation of Silk Echo components.
    .DESCRIPTION
        This function runs the installers in silent mode without any parameters.
        Used for upgrading existing installations where configuration is already in place.
        Skips all registration and validation steps.
    .OUTPUTS
        Returns $null on success, or an error message string on failure.
    #>
    InfoMessage "Starting Silk Echo upgrade (silent mode)..."
    # Validate that at least one component is enabled
    if (-not $InstallAgent -and -not $InstallVSS) {
        ErrorMessage "No components selected for upgrade. At least one of InstallAgent or InstallVSS must be true."
        return "No components selected for upgrade"
    }
    # Dry run - just validate installers exist
    if ($IsDryRun) {
        InfoMessage "Dry run mode enabled for upgrade."
        if ($InstallAgent) {
            if (-not (Test-Path $SilkAgentPath)) {
                ErrorMessage "Agent installer not found at $SilkAgentPath"
                return "Agent installer not found at $SilkAgentPath"
            }
            InfoMessage "Agent installer found at $SilkAgentPath"
        }
        if ($InstallVSS) {
            if (-not (Test-Path $SilkVSSPath)) {
                ErrorMessage "VSS installer not found at $SilkVSSPath"
                return "VSS installer not found at $SilkVSSPath"
            }
            InfoMessage "VSS installer found at $SilkVSSPath"
        }
        InfoMessage "Dry run: upgrade validation passed"
        return $null
    }
    # Upgrade Agent if enabled
    if ($InstallAgent) {
        InfoMessage "Upgrading Silk Node Agent from $SilkAgentPath..."
        if (-not (Test-Path $SilkAgentPath)) {
            ErrorMessage "Agent installer not found at $SilkAgentPath"
            return "Agent installer not found at $SilkAgentPath"
        }
        $result = StartProcessWithTimeout `
            -FilePath $SilkAgentPath `
            -ArgumentList @('/S') `
            -TimeoutSeconds $INTERNAL_INSTALL_TIMEOUT_SECONDS `
            -ProcessName "Silk Node Agent Upgrade"
        PrintAgentInstallationLog
        if (-not $result.Success) {
            ErrorMessage "Agent upgrade failed: $($result.Reason)"
            return "Agent upgrade failed: $($result.Reason)"
        }
        InfoMessage "Silk Node Agent upgrade completed successfully"
    }
    # Upgrade VSS if enabled
    if ($InstallVSS) {
        InfoMessage "Upgrading Silk VSS Provider from $SilkVSSPath..."
        if (-not (Test-Path $SilkVSSPath)) {
            ErrorMessage "VSS installer not found at $SilkVSSPath"
            return "VSS installer not found at $SilkVSSPath"
        }
        $result = StartProcessWithTimeout `
            -FilePath $SilkVSSPath `
            -ArgumentList @('/VERYSILENT', "/LOG=$SVSSInstallationLogPath") `
            -TimeoutSeconds $INTERNAL_INSTALL_TIMEOUT_SECONDS `
            -ProcessName "Silk VSS Provider Upgrade"
        PrintSVSSInstallationLog
        if (-not $result.Success) {
            ErrorMessage "VSS upgrade failed: $($result.Reason)"
            return "VSS upgrade failed: $($result.Reason)"
        }
        InfoMessage "Silk VSS Provider upgrade completed successfully"
    }
    # Success
    $upgradedComponents = @()
    if ($InstallAgent) { $upgradedComponents += "Silk Node Agent" }
    if ($InstallVSS) { $upgradedComponents += "Silk VSS Provider" }
    InfoMessage "$($upgradedComponents -join ' and ') upgrade completed successfully."
    return $null
}
#endregion upgrade_only
#region setup
function setup{
    <#
    .SYNOPSIS
        Main orchestrator function for Silk Echo component installation.
    .DESCRIPTION
        This function orchestrates the installation of Silk Echo components based on configuration:
        - Tests Flex connectivity (common prerequisite)
        - Calls setup_agent() if InstallAgent is enabled
        - Calls setup_vss() if InstallVSS is enabled
        In upgrade mode, delegates to upgrade_only() which skips registration and validation.
    .OUTPUTS
        Returns $null on success, or an error message string on failure.
    #>
    # Upgrade mode - skip all validation and registration, just run silent installers
    if ($UpgradeMode) {
        return upgrade_only
    }
    InfoMessage "Starting Silk Echo installation setup..."
    # Validate that at least one component is enabled
    if (-not $InstallAgent -and -not $InstallVSS) {
        ErrorMessage "No components selected for installation. At least one of InstallAgent or InstallVSS must be true."
        return "No components selected for installation"
    }
    # Test Flex connectivity (common prerequisite for both components)
    if (-not (TestFlexConnectivity -FlexIP $FlexIP -FlexToken $FlexToken)) {
        ErrorMessage "Flex connectivity test failed"
        return "Failed to establish connection with Flex server at $FlexIP"
    }
    InfoMessage "Successfully connected to Flex"
    # Validate installation directory if specified
    if ($DirectoryToInstall -and $DirectoryToInstall.Trim() -ne "") {
        if (-not (Test-Path -Path $DirectoryToInstall -PathType Container)) {
            ErrorMessage "Installation directory does not exist: $DirectoryToInstall"
            return "Installation directory '$DirectoryToInstall' does not exist or is not a directory"
        }
        InfoMessage "Installation directory validated: $DirectoryToInstall"
    }
    # Install Agent if enabled
    $agentError = $null
    if ($InstallAgent) {
        InfoMessage "Agent installation is enabled"
        $agentError = setup_agent
        if ($agentError) {
            ErrorMessage "Agent setup failed: $agentError"
            return $agentError
        }
    } else {
        InfoMessage "Skipping Silk Node Agent installation (InstallAgent=false)"
    }
    # Install VSS if enabled
    $vssError = $null
    if ($InstallVSS) {
        InfoMessage "VSS installation is enabled"
        $vssError = setup_vss
        if ($vssError) {
            ErrorMessage "VSS setup failed: $vssError"
            return $vssError
        }
    } else {
        InfoMessage "Skipping Silk VSS Provider installation (InstallVSS=false)"
    }
    # Success message
    if ($IsDryRun) {
        InfoMessage "Dry run validation completed successfully. No actual installation was performed."
    } else {
        $installedComponents = @()
        if ($InstallAgent) { $installedComponents += "Silk Node Agent" }
        if ($InstallVSS) { $installedComponents += "Silk VSS Provider" }
        InfoMessage "$($installedComponents -join ' and ') installation completed successfully."
    }
    # Return $null to indicate success
    return $null
}
#endregion setup
#region SetupHost
function SetupHost {
    InfoMessage "Starting Silk Node Agent and VSS Provider installation script..."
    try {
        SetTLSVersion
        SkipCertificateCheck
        $error = setup
    } catch {
        $error = $_.Exception.Message
        ErrorMessage "Unexpected error during setup: $error"
    }
    if ($error) {
        ErrorMessage "Setup completed with errors. Please check the logs for details: $($error)"
        ErrorMessage "Process log files located at:"
        if ($InstallAgent) {
            ErrorMessage " - Silk Node Agent installation log: $AgentInstallationLogPath"
        }
        if ($InstallVSS) {
            ErrorMessage " - Silk VSS Provider installation log: $SVSSInstallationLogPath"
        }
        throw "Setup failed on Host[$env:COMPUTERNAME]. $($error)"
    } else {
        CleanupInstallerFiles
        InfoMessage "Setup completed successfully."
    }
}
SetupHost
#endregion SetupHost
#endregion orc_host_installer
