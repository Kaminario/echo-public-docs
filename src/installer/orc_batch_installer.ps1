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
