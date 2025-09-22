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
