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

    InfoMessage "Starting parallel $JobDescription processing for $($Items.Count) item(s) with max concurrency: $MaxConcurrency..."

    # Start jobs using dynamic batch processing pattern
    $jobs = @()
    $processedCount = 0
    $totalItems = $Items.Count
    $startedCount = 0

    foreach ($item in $Items) {
        # DYNAMIC BATCHING PATTERN: Wait if we've reached max concurrency
        while ($jobs.Count -ge $MaxConcurrency) {
            $completedJob = $jobs | Where-Object { $_.Job.State -ne 'Running' } | Select-Object -First 1
            if ($completedJob) {
                # Process completed job immediately
                & $ResultProcessor $completedJob
                $jobs = @($jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id })
                $processedCount++
                # Progress message: show completed and running counts
                $runningCount = $jobs.Count
                InfoMessage "Progress: $processedCount of $totalItems $JobDescription jobs completed, $runningCount running"
            } else {
                Start-Sleep -Milliseconds 100
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
            InfoMessage "Progress: Started $startedCount of $totalItems $JobDescription jobs, $($jobs.Count) running"
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
            # Progress message: show completed and remaining counts
            $runningCount = $jobs.Count
            InfoMessage "Progress: $processedCount of $totalItems $JobDescription jobs completed, $runningCount remaining"
        } else {
            Start-Sleep -Milliseconds 100
        }
    }

    InfoMessage "Completed $JobDescription processing for $processedCount of $totalItems items"
}
#endregion Generic Batch Job Processor
