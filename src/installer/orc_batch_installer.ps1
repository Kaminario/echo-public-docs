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
        [hashtable]$CompletedHosts,
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
