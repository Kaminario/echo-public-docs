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
        [Array]$RemoteComputers,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [Array]$HostsWithUploads,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$CompletedHosts,
        [Parameter(Mandatory=$true)]
        [string]$ProcessedHostsPath,
        [Parameter(Mandatory=$true)]
        [string]$HostSetupScript,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )


    # Installation job logic - starts installation on a single host
    $installationJobScript = {
        param($hostInfo)
        
        # Ensure InstallSingleHost and its dependencies are available (in case running in dev mode)
        function DebugMessage { param($message) Write-Host "[DEBUG] $message" -ForegroundColor Gray }
        function InfoMessage { param($message) Write-Host "[INFO] $message" -ForegroundColor Green }
        function ErrorMessage { param($message) Write-Host "[ERROR] $message" -ForegroundColor Red }
        function ImportantMessage { param($message) Write-Host "[IMPORTANT] $message" -ForegroundColor Yellow }
                
        #region InstallSingleHost
        function InstallSingleHost {
            param (
                [Parameter(Mandatory=$true)]
                [PSCustomObject]$HostInfo,
                [Parameter(Mandatory=$true)]
                [PSCustomObject]$Config,
                [Parameter(Mandatory=$true)]
                [string]$FlexToken,
                [Parameter(Mandatory=$true)]
                [string]$SqlConnectionString,
                [Parameter(Mandatory=$true)]
                [System.Management.Automation.PSCredential]$SdpCredentials,
                [Parameter(Mandatory=$true)]
                [string]$HostSetupScript
            )

            $HostAddress = $HostInfo.host_addr
            InfoMessage "Starting installation on $HostAddress..."

            $IsDebug = $DebugPreference -eq 'Continue'
            $IsDryRun = $DryRun.IsPresent
            # Use uploaded installer paths instead of URLs
            $agentPath = if ($HostInfo.remote_installer_paths.agent) { $HostInfo.remote_installer_paths.agent } else { $Config.agent }
            $vssPath = if ($HostInfo.remote_installer_paths.vss) { $HostInfo.remote_installer_paths.vss } else { $Config.svss }

            $ArgumentList = @(
                $HostInfo.flex_host_ip,
                $FlexToken,
                $SqlConnectionString,
                $agentPath,
                $vssPath,
                $HostInfo.sdp_id,
                $SdpCredentials.UserName,
                $SdpCredentials.GetNetworkCredential().Password,
                $IsDebug,
                $IsDryRun,
                $HostInfo.mount_points_directory
            )

            DebugMessage "Preparing to run installation script on $HostAddress"
            DebugMessage "Using Flex IP: $($HostInfo.flex_host_ip)"
            DebugMessage "Using Flex Token: [REDACTED]"
            DebugMessage "Using SQL Connection String: [REDACTED]"
            DebugMessage "Using agent path: $agentPath"
            DebugMessage "Using VSS path: $vssPath"
            DebugMessage "Using SDP ID: $($HostInfo.sdp_id)"
            DebugMessage "Using SDP Username: $($SdpCredentials.UserName)"
            DebugMessage "Using SDP Password: [REDACTED]"
            DebugMessage "Dry Run Mode: $($IsDryRun)"
            DebugMessage "Mount Points Directory: $($HostInfo.mount_points_directory)"

            # Read the script content and convert it to a scriptblock
            $installScript = [ScriptBlock]::Create(($HostSetupScript))

            # Create the remote scriptblock
            $scriptBlock = {
                param($FlexIP, $FlexToken, $DBConnectionString, $SilkAgentPath, $SilkVSSPath, $SDPId, $SDPUsername, $SDPPassword, $DebugMode, $DryRunMode, $MountPointsDirectory, $Script)

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
                Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [INFO] - Running installation (Debug: $DebugMode)"

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
                }

                # Add DryRun parameter if in dry run mode
                if ($DryRunMode) {
                    $functionArgs.Add('DryRun', $true)
                    InfoMessage "Dry run mode is enabled, no changes will be made."
                }

                # Execute function with prepared arguments using splatting
                try {
                    & $function @functionArgs
                } catch {
                    ErrorMessage "Installation script execution failed on host $env:COMPUTERNAME: $_"
                    throw
                }
            }

            # Add the script content to the argument list
            $ArgumentList += @($installScript.ToString())

            # Prepare invoke command parameters
            $invokeParams = @{
                ComputerName = $HostAddress
                AsJob = $true
                ScriptBlock = $scriptBlock
                ArgumentList = $ArgumentList
            }

            # Add credential parameter only if not using Kerberos
            if ($HostInfo.host_auth -ne $ENUM_ACTIVE_DIRECTORY) {
                $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                $invokeParams['Credential'] = $credential
            }
            InfoMessage "Invoking installation script on $HostAddress..."
            $job = Invoke-Command @invokeParams
            InfoMessage "Installation script invoked on $HostAddress, job ID: $($job.Id)"
            return [PSCustomObject]@{
                HostAddress = $HostAddress
                Job = $job
            }
        }
        #endregion InstallSingleHost

        
        # Return the job info from InstallSingleHost directly
        $jobInfo = InstallSingleHost -HostInfo $using:hostInfo -Config $using:Config -FlexToken $using:hostInfo.flex_access_token -SqlConnectionString $using:hostInfo.sql_connection_string -SdpCredentials $using:hostInfo.sdp_credential -HostSetupScript $using:HostSetupScript
        return $jobInfo
    }

    # Result processor - handles completed installation jobs
    $installationResultProcessor = {
        param($BatchJobInfo)

        $hostInfo = $BatchJobInfo.Item
        $batchJob = $BatchJobInfo.Job

        # Get the actual installation job info from the batch job result
        $jobInfo = Receive-Job -Job $batchJob
        Remove-Job -Job $batchJob -Force

        if ($jobInfo -and $jobInfo.Job) {
            # Process the actual installation job result
            $result = ProcessSingleJobResult -JobInfo $jobInfo
            $script:results += $result

            # Update the corresponding host's result field
            $hostToUpdate = $script:hostsWithUploads | Where-Object { $_.host_addr -eq $result.HostAddress }
            if ($hostToUpdate) {
                SetHostResultWithProgress -HostInfo $hostToUpdate -Result $result -AllHosts $script:config.hosts
            }

            if ($result.JobState -eq 'Success') {
                $script:NumOfSuccessHosts++
                # Mark host as completed immediately
                MarkHostCompleted -CompletedHosts $script:completedHosts -HostAddress $result.HostAddress
                SaveCompletedHosts -StateFilePath $script:processedHostsPath -CompletedHosts $script:completedHosts | Out-Null
            } else {
                $script:NumOfFailedHosts++
            }
        } else {
            # Handle case where job creation failed
            $script:NumOfFailedHosts++
            ErrorMessage "Failed to create installation job for host: $($hostInfo.host_addr)"
        }
    }

    # Initialize script-scope variables for result processor access
    $script:results = @()
    $script:hostsWithUploads = $HostsWithUploads
    $script:config = $Config
    $script:completedHosts = $CompletedHosts
    $script:processedHostsPath = $ProcessedHostsPath

    # Use dynamic batch processor for installations
    Start-BatchJobProcessor -Items $RemoteComputers -JobScriptBlock $installationJobScript -ResultProcessor $installationResultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "installation"

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
        [string]$ProgressFilePath,
        [Parameter(Mandatory=$true)]
        [string]$ProcessedHostsPath
    )

    try {
        # Save detailed logs
        $logPath = Join-Path $CacheDirectory "installation_logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $Results | ConvertTo-Json -Depth 4 | Out-File -FilePath $logPath

        # Final checkpoint: Save complete progress summary
        WriteHostsSummaryToFile -Hosts $Config.hosts -OutputPath $ProgressFilePath

        # Display short summary to console
        DisplayHostsSummary -Hosts $Config.hosts

        InfoMessage ""
        InfoMessage "Detailed logs saved to: $logPath"

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
