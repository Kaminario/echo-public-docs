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
