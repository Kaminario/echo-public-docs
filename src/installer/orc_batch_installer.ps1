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
            # Validate that remote installer paths are not null
            if (-not $agentPath) {
                ErrorMessageIJS "Agent path is null or empty. Remote installer paths may not be properly set."
            }
            if (-not $vssPath) {
                ErrorMessageIJS "VSS path is null or empty. Remote installer paths may not be properly set."
            }

            # do not continue if the paths are null, add issue and return
            if (-not $agentPath -or -not $vssPath) {
                $hostInfo.issues += "Failed to upload installers. $issue"
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
                param($FlexIP,
                      $FlexToken,
                      $DBConnectionString,
                      $SilkAgentPath,
                      $SilkVSSPath,
                      $SDPId,
                      $SDPUsername,
                      $SDPPassword,
                      $DebugMode,
                      $DryRunMode,
                      $MountPointsDirectory,
                      $InstallDir,
                      $Script)

                function InfoMessageRIS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [INFO] $message"}
                function DebugMessageRIS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [DEBUG] $message"}
                function ErrorMessageRIS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [ERROR] $message"}
                # Set debug preferences in the remote session based on the debug mode
                if ($DebugMode) {
                    $DebugPreference = 'Continue'
                    $VerbosePreference = 'Continue'
                } else {
                    $DebugPreference = 'SilentlyContinue'
                    $VerbosePreference = 'SilentlyContinue'
                }

                # Create a new function with the script content
                $function = [ScriptBlock]::Create($Script)
                InfoMessageRIS "Running installation script... (Debug: $DebugMode, DryRun: $DryRunMode)"

                # Prepare base arguments
                $functionArgs = @{
                    FlexIP = $FlexIP
                    FlexToken = $FlexToken
                    DBConnectionString = $DBConnectionString
                    SilkAgentPath = $SilkAgentPath
                    SilkVSSPath = $SilkVSSPath
                    SDPId = $SDPId
                    SDPUsername = $SDPUsername
                    SDPPassword = $SDPPassword
                    MountPointsDirectory = $MountPointsDirectory
                    Dir = $hostInfo.install_to_directory
                }

                # Add DryRun parameter if in dry run mode
                if ($DryRunMode) {
                    $functionArgs.Add('DryRun', $true)
                    InfoMessageRIS "Dry run mode is enabled, no changes will be made."
                }

                # Execute function with prepared arguments using splatting
                try {
                    $result = & $function @functionArgs
                    return @{ Success = $true; Output = $result; Error = $null }
                } catch {
                    ErrorMessageRIS "Installation script execution failed: $_"
                    return @{ Success = $false; Output = $null; Error = $_.Exception.Message }
                }
            }

            # Prepare argument list with null checks
            $ArgumentList = @(
                $hostInfo.flex_host_ip,
                $hostInfo.flex_access_token,
                $hostInfo.sql_connection_string,
                $agentPath,
                $vssPath,
                $hostInfo.sdp_id,
                $hostInfo.sdp_credential.UserName,
                $hostInfo.sdp_credential.GetNetworkCredential().Password,
                $IsDebug,
                $IsDryRun,
                $hostInfo.mount_points_directory,
                $hostInfo.install_to_directory,
                $HostSetupScript
            )

            # Validate ArgumentList for null values (install_to_directory can be empty string)
            for ($i = 0; $i -lt $ArgumentList.Count; $i++) {
                if ($null -eq $ArgumentList[$i]) {
                    $paramNames = @('flex_host_ip', 'flex_access_token', 'sql_connection_string', 'agentPath', 'vssPath', 'sdp_id', 'sdp_username', 'sdp_password', 'IsDebug', 'IsDryRun', 'mount_points_directory', 'install_to_directory', 'HostSetupScript')
                    # Allow install_to_directory (index 11) to be null or empty
                    if ($i -ne 11) {
                        ErrorMessageIJS "Null value found in ArgumentList at index $i (parameter: $($paramNames[$i]))"
                        return @{ Success = $false; HostAddress = $HostAddress; Output = $null; Error = "Null parameter: $($paramNames[$i])" }
                    }
                }
            }

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
