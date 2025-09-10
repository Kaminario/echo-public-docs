#region FetchJobResult
function fetchStream {
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
        $outputLines = fetchStream -Stream $jobResult.Information
    }

    if ($jobResult.Error) {
        $errorLines = fetchStream -Stream $jobResult.Error
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
            Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [INFO] - Dry run mode is enabled, no changes will be made."
        }

        # Execute function with prepared arguments using splatting
        try {
            & $function @functionArgs
        } catch {
            Write-Error "Failed to execute host_installer script: $_"
            throw
        }
    }

    # Add the script content to the argument list
    $ArgumentList += @($installScript.ToString())

    # Prepare invoke command parameters
    $invokeParams = @{
        HostAddress = $HostAddress
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
        WarningMessage "Error while waiting for job completion on $hostAddress`: $_"
    }

    # read job errors if any - wrap in try-catch to prevent script termination
    $jobErrors = $null
    try {
        Receive-Job -Job $job -Keep -ErrorVariable jobErrors -ErrorAction SilentlyContinue
        DebugMessage "Job state for $hostAddress`: $($job.State)"
    } catch {
        WarningMessage "Error while receiving job output from $hostAddress`: $_"
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
        $result = FetchJobResult -ComputerName $hostAddress -jobResult $jobResult -JobState $job.State
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
