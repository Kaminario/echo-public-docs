<#
.SYNOPSIS
    Refreshes a Silk Echo database from a new snapshot of its source.

.DESCRIPTION
    This script finds the source database for a given Echo database,
    takes a new snapshot of the source, and then replaces (refreshes) the Echo
    database with the newly created snapshot.

.PARAMETER EchoDbNames
    One or more Echo databases to refresh. All must share the same source database.

.PARAMETER EchoDbHostName
    The name of the host where the target Echo database resides.

.PARAMETER FlexIp
    The IP address of the Flex server. Can also be set via the $env:FLEX_IP environment variable.

.PARAMETER FlexToken
    The authentication token for the Flex API. Can also be set via the $env:FLEX_TOKEN environment variable.

.PARAMETER SnapshotPrefix
    An optional prefix for the name of the new snapshot.

.PARAMETER ConsistencyLevel
    The consistency level for the snapshot. Must be either 'crash' or 'application'. Defaults to 'crash'.

.EXAMPLE
    # Basic refresh
    .\refresh_echo_db.ps1 -EchoDbNames "sales_db_clone" -EchoDbHostName "dev-host-1"

.EXAMPLE
    # Refresh multiple clones that share a source database
    .\refresh_echo_db.ps1 -EchoDbNames moti_1,test_1 -EchoDbHostName primary -FlexIp 10.0.0.15 -FlexToken sometoken

.NOTES
    Requires PowerShell 5.1 or higher.
    Ensure FLEX_IP and FLEX_TOKEN environment variables are set, or pass them as parameters.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Alias('EchoDbName')]
    [string[]]$EchoDbNames,

    [Parameter(Mandatory = $true)]
    [string]$EchoDbHostName,

    [Parameter(HelpMessage = "Base Flex URL, e.g. https://flex.example.com")]
    [string]$FlexUrl,

    [Parameter(HelpMessage = "Flex API host or IP address")]
    [ValidatePattern('^$|^([0-9]{1,3}\.){3}[0-9]{1,3}$')]
    [string]$FlexIp = $env:FLEX_IP,

    [Parameter(HelpMessage = "Flex API bearer token")]
    [string]$FlexToken = $env:FLEX_TOKEN,

    [string]$SnapshotPrefix = "refresh-snap-",

    [ValidateSet('crash', 'application')]
    [string]$ConsistencyLevel = "crash",

    [ValidateRange(1, 300)]
    [int]$PollSeconds = 5,

    [ValidateRange(1, 240)]
    [int]$TimeoutMinutes = 60,

    [switch]$ValidateOnly,

    [switch]$Quiet
)

$script:QuietMode = $Quiet.IsPresent
$script:PollSeconds = $PollSeconds
$script:TimeoutMinutes = $TimeoutMinutes
$script:MaxApiAttempts = 3
$script:RetryableStatusCodes = @(429, 500, 502, 503, 504)
$script:RetryBackoffSeconds = 2
$scriptStart = Get-Date

if (-not $FlexUrl -and -not $FlexIp) {
    throw "Provide -FlexUrl or -FlexIp (or set FLEX_IP) so the script can reach Flex."
}

if (-not $FlexToken) {
    throw "Flex token not provided. Set -FlexToken or FLEX_TOKEN environment variable."
}

$EchoDbNames = $EchoDbNames |
    Where-Object { $_ -ne $null } |
    ForEach-Object { $_ -split ',' } |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ }
if (-not $EchoDbNames) {
    throw "At least one Echo database name must be provided."
}

$resolvedFlexUrl = if ($FlexUrl) { $FlexUrl.TrimEnd('/') } else { "https://$FlexIp" }
$script:FlexBaseUrl = $resolvedFlexUrl

$ErrorActionPreference = "Stop"

#region Helper Functions

function Write-Info {
    param (
        [string]$Message
    )

    if (-not $script:QuietMode) {
        Write-Host $Message
    }
}

# Disables SSL certificate validation for self-signed certs
try {
    # Allow self-signed certificates when Flex environments use private CAs
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    # Ensure TLS 1.2 is enabled for older environments
    if ([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls12 -ne [System.Net.SecurityProtocolType]::Tls12) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    }
    Write-Verbose "Disabled SSL certificate validation and enforced TLS 1.2."
}
catch {
    Write-Warning "Could not update certificate validation or TLS settings. This may cause issues with self-signed certificates."
}

function Invoke-FlexApi {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [string]$Method = "GET",
        [object]$Body
    )

    $headers = @{
        "Authorization" = "Bearer $FlexToken"
        "hs-ref-id"     = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
        "Accept"        = "application/json"
    }

    $invokeParams = @{
        Method      = $Method
        Headers     = $headers
        ContentType = "application/json"
    }

    if ((Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')) {
        $invokeParams.SkipCertificateCheck = $true
    }

    if ($PSBoundParameters.ContainsKey('Body')) {
        $invokeParams.Body = ($Body | ConvertTo-Json -Depth 5)
    }

    $attempt = 0
    $delaySeconds = $script:RetryBackoffSeconds

    while ($true) {
        $attempt++
        $targetUri = if ($Uri -match '^https?://') { $Uri } else { "$($script:FlexBaseUrl)$Uri" }
        $invokeParams.Uri = $targetUri

        try {
            Write-Verbose "Invoking Flex API ($Method): $targetUri"
            return Invoke-RestMethod @invokeParams
        }
        catch {
            $response = $_.Exception.Response
            $statusCode = $null
            $errorMessage = $_.Exception.Message

            if ($null -ne $response) {
                if ($response -is [System.Net.Http.HttpResponseMessage]) {
                    try {
                        $errorMessage = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    }
                    catch {
                        $errorMessage = $_.Exception.Message
                    }
                    $statusCode = [int]$response.StatusCode
                }
                elseif ($response -is [System.Net.HttpWebResponse]) {
                    $errorMessage = $response.GetResponseStream() | ForEach-Object {
                        $reader = New-Object System.IO.StreamReader($_)
                        $reader.ReadToEnd()
                    }
                    $statusCode = [int]$response.StatusCode
                }
                else {
                    $errorMessage = $response.ToString()
                    if ($response.PSObject.Properties.Match('StatusCode').Count -gt 0) {
                        $statusCode = [int]$response.StatusCode
                    }
                }
            }

            $shouldRetry = $false
            if ($statusCode -and $script:RetryableStatusCodes -contains $statusCode) {
                $shouldRetry = $true
            }
            elseif (-not $statusCode -and $errorMessage -match '(timed out|temporarily unavailable|connection was closed)') {
                $shouldRetry = $true
            }

            if ($shouldRetry -and $attempt -lt $script:MaxApiAttempts) {
                Write-Warning "Flex API call to '$targetUri' failed with status $statusCode. Retrying in $delaySeconds second(s)..."
                Start-Sleep -Seconds $delaySeconds
                $delaySeconds = [Math]::Min($delaySeconds * 2, 30)
                continue
            }

            $statusDisplay = if ($statusCode) { $statusCode } else { "(no response)" }
            Write-Error "API call failed for '$targetUri'. Status: $statusDisplay. Response: $errorMessage"
            throw
        }
    }
}

function Wait-For-Task {
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Task
    )

    if ($Task.location -match '^https?://') {
        $taskPath = $Task.location
    }
    else {
        $taskPath = if ($Task.location.StartsWith('/')) { $Task.location } else { '/' + $Task.location }
    }

    Write-Info "Waiting for task '$($Task.command_type)' to complete (ID: $($Task.request_id))..."

    $currentTask = $Task
    $deadline = (Get-Date).AddMinutes($script:TimeoutMinutes)

    while ($currentTask.state -eq 'running') {
        if ([DateTime]::UtcNow -gt $deadline.ToUniversalTime()) {
            throw "Task '$($Task.command_type)' exceeded the timeout window of $script:TimeoutMinutes minute(s)."
        }

        Start-Sleep -Seconds $script:PollSeconds

        if (-not $script:QuietMode) {
            Write-Host "." -NoNewline
        }

        $currentTask = Invoke-FlexApi -Uri $taskPath
    }

    if (-not $script:QuietMode) {
        Write-Host "" # Newline after the dots
    }

    if ($currentTask.state -ne 'completed') {
        throw "Task '$($currentTask.command_type)' failed with state '$($currentTask.state)'. Error: $($currentTask.error)"
    }

    Write-Info "Task '$($currentTask.command_type)' completed successfully."
    return $currentTask
}

function Get-EchoDbSourceInfo {
    param (
        [Parameter(Mandatory = $true)][PSCustomObject]$EchoDb,
        [Parameter(Mandatory = $true)][object[]]$Topology
    )

    $sourceHostId = $EchoDb.source_host_id
    $sourceDbId = $EchoDb.source_db_id
    $sourceDbName = $EchoDb.source_db_name

    if (-not $sourceHostId -and $EchoDb.parent -and $EchoDb.parent.src_host_id) {
        $sourceHostId = $EchoDb.parent.src_host_id
    }

    if (-not $sourceDbId -and $EchoDb.parent -and $EchoDb.parent.src_db_id) {
        $sourceDbId = $EchoDb.parent.src_db_id
    }

    if (-not $sourceDbName -and $sourceDbId) {
        $sourceDbName = (
            $Topology
            | ForEach-Object { $_.databases | Where-Object { $_.id -eq $sourceDbId } }
            | Select-Object -First 1
        ).name
    }

    if (-not $sourceDbName -and $sourceDbId) {
        $sourceDbName = $sourceDbId
    }

    return [pscustomobject]@{
        SourceHostId = $sourceHostId
        SourceDbId   = $sourceDbId
        SourceDbName = $sourceDbName
    }
}

function Remove-StaleSnapshots {
    param (
        [Parameter(Mandatory = $true)][string]$SourceHostId,
        [Parameter(Mandatory = $true)][string]$SourceDbId,
        [Parameter(Mandatory = $true)][string]$SnapshotToKeep
    )

    Write-Info "Removing unused snapshots from source database '$SourceDbId' on host '$SourceHostId'..."

    $totalDeleted = 0
    $remainingSnapshots = @()

    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        $topology = Invoke-FlexApi -Uri "/api/ocie/v1/topology"
        $sourceHost = $topology | Where-Object { $_.host.id -eq $SourceHostId }
        if (-not $sourceHost) {
            Write-Warning "Could not locate host '$SourceHostId' when cleaning up snapshots."
            return [pscustomobject]@{ Deleted = $totalDeleted; Remaining = @() }
        }

        $sourceDb = $sourceHost.databases | Where-Object { $_.id -eq $SourceDbId }
        if (-not $sourceDb) {
            Write-Warning "Could not locate source database '$SourceDbId' when cleaning up snapshots."
            return [pscustomobject]@{ Deleted = $totalDeleted; Remaining = @() }
        }

        $snapshotSet = @($sourceDb.db_snapshots | Where-Object { $_.id })
        $remainingSnapshots = @($snapshotSet | Where-Object { $_.id -ne $SnapshotToKeep })
        $deletableSnapshots = @($remainingSnapshots | Where-Object { $_.deletable -eq $true -or $_.deletable -eq 'True' })

        if (-not $deletableSnapshots) {
            break
        }

        foreach ($snapshot in $deletableSnapshots) {
            $snapshotId = $snapshot.id
            Write-Info "Deleting snapshot '$snapshotId'..."
            Write-Verbose "Issuing DELETE for snapshot '$snapshotId'."
            $deleteTask = Invoke-FlexApi -Uri "/flex/api/v1/db_snapshots/$snapshotId" -Method "DELETE"
            if ($deleteTask -and $deleteTask.PSObject.Properties.Name -contains 'location') {
                try {
                    $null = Wait-For-Task -Task $deleteTask
                }
                catch {
                    Write-Warning "Snapshot '$snapshotId' deletion task failed: $($_.Exception.Message)"
                    continue
                }
            }
            $totalDeleted++
        }
    }

    $remainingIds = if ($remainingSnapshots) {
        @($remainingSnapshots | Select-Object -ExpandProperty id)
    }
    else {
        @()
    }

    if ($remainingIds.Count -gt 0) {
        Write-Info "Snapshot(s) still present on source database '$SourceDbId': $($remainingIds -join ', ')"
    }
    else {
        Write-Info "All snapshots except '$SnapshotToKeep' removed from source database '$SourceDbId'."
    }

    return [pscustomobject]@{
        Deleted   = $totalDeleted
        Remaining = $remainingIds
    }
}

#endregion Helper Functions

# --- Main Script Logic ---

# 1. Fetch System Topology
Write-Info "Fetching system topology from $($script:FlexBaseUrl)..."
$topology = Invoke-FlexApi -Uri "/api/ocie/v1/topology"

# 2. Find the Echo DBs and their source
$cloneListDisplay = ($EchoDbNames -join "', '")
Write-Info "Searching for Echo DB(s) '$cloneListDisplay' on host '$EchoDbHostName'..."
$echoHost = $topology | Where-Object { $_.host.name -eq $EchoDbHostName }
if (-not $echoHost) {
    throw "Host '$EchoDbHostName' not found in topology."
}

$resolvedClones = @()
foreach ($cloneName in $EchoDbNames) {
    $echoDb = $echoHost.databases | Where-Object { $_.name -eq $cloneName }
    if (-not $echoDb) {
        throw "Database '$cloneName' not found on host '$EchoDbHostName'."
    }

    $sourceInfo = Get-EchoDbSourceInfo -EchoDb $echoDb -Topology $topology

    if (-not $sourceInfo.SourceHostId -or -not $sourceInfo.SourceDbId) {
        throw "Database '$cloneName' on host '$EchoDbHostName' is not an Echo database or is missing source information."
    }

    $resolvedClones += [pscustomobject]@{
        Name          = $cloneName
        EchoDb        = $echoDb
        SourceHostId  = $sourceInfo.SourceHostId
        SourceDbId    = $sourceInfo.SourceDbId
        SourceDbName  = $sourceInfo.SourceDbName
    }
}

$uniqueSources = $resolvedClones | Select-Object SourceHostId, SourceDbId -Unique
if ($uniqueSources.Count -ne 1) {
    $sourceDetails = $resolvedClones | ForEach-Object { "{0}:{1}" -f $_.SourceHostId, $_.SourceDbId } | Sort-Object -Unique
    throw "All Echo databases must share the same source. Found sources: $($sourceDetails -join ', ')"
}

$sourceHostId = $uniqueSources[0].SourceHostId
$sourceDbId = $uniqueSources[0].SourceDbId
$sourceDbName = ($resolvedClones | Select-Object -First 1).SourceDbName

Write-Info "Found $($resolvedClones.Count) Echo DB(s). Source is '$sourceDbName' (ID: $sourceDbId) on host ID '$sourceHostId'."

# 3. Create New Snapshot of Source
Write-Info "Creating a new '$ConsistencyLevel' snapshot of the source database..."
$snapshotBody = @{
    source_host_id    = $sourceHostId
    database_ids      = @($sourceDbId)
    name_prefix       = $SnapshotPrefix
    consistency_level = $ConsistencyLevel
}

$snapshotTask = Invoke-FlexApi -Uri "/flex/api/v1/db_snapshots" -Method "POST" -Body $snapshotBody
if ($snapshotTask.PSObject.Properties.Name -contains 'request_id') {
    Write-Verbose "Snapshot task request id: $($snapshotTask.request_id)"
}
$completedSnapshotTask = Wait-For-Task -Task $snapshotTask

$newSnapshotId = $completedSnapshotTask.result.db_snapshot.id
if (-not $newSnapshotId) {
    throw "Failed to get new snapshot ID from the completed task."
}
Write-Info "Successfully created new snapshot with ID: $newSnapshotId"

# 4. Replace (Refresh) the Echo Database(s)
if ($ValidateOnly.IsPresent) {
    Write-Info "Validating refresh of Echo DB(s) '$cloneListDisplay' with snapshot $newSnapshotId..."
}
else {
    Write-Info "Refreshing Echo DB(s) '$cloneListDisplay' with the new snapshot..."
}
$replaceBody = @{
    snapshot_id = $newSnapshotId
    db_names    = $EchoDbNames
    keep_backup = $false
}

$replaceEndpoint = if ($ValidateOnly.IsPresent) {
    "/flex/api/v1/hosts/$($echoHost.host.id)/databases/_replace/__validate"
} else {
    "/flex/api/v1/hosts/$($echoHost.host.id)/databases/_replace"
}

$replaceTask = Invoke-FlexApi -Uri $replaceEndpoint -Method "POST" -Body $replaceBody
$actionVerb = if ($ValidateOnly.IsPresent) { "validated" } else { "refreshed" }
$replaceTaskId = if ($replaceTask.PSObject.Properties.Name -contains 'request_id') { $replaceTask.request_id } else { $null }
Write-Verbose "Replace task request id: $replaceTaskId"
$completedReplaceTask = Wait-For-Task -Task $replaceTask

Write-Info "Successfully $actionVerb Echo DB(s) '$cloneListDisplay' on host '$EchoDbHostName'."
Write-Info "Refresh complete."

if ($ValidateOnly.IsPresent) {
    Write-Info "Validate-only run; no changes were applied to clones: $cloneListDisplay."
}

$cleanupResult = $null
if (-not $ValidateOnly.IsPresent) {
    $cleanupResult = Remove-StaleSnapshots -SourceHostId $sourceHostId -SourceDbId $sourceDbId -SnapshotToKeep $newSnapshotId
}

$removedSnapshotCount = if ($cleanupResult) { $cleanupResult.Deleted } else { 0 }
$remainingSnapshotIds = if ($cleanupResult) { @($cleanupResult.Remaining) } else { @() }

$durationSeconds = [Math]::Round(((Get-Date) - $scriptStart).TotalSeconds, 2)

[pscustomobject]@{
    SnapshotId         = $newSnapshotId
    ReplaceTaskId      = if ($completedReplaceTask.PSObject.Properties.Name -contains 'request_id') { $completedReplaceTask.request_id } else { $replaceTaskId }
    Databases          = $EchoDbNames
    DatabaseList       = $cloneListDisplay
    Host               = $EchoDbHostName
    SourceDatabase     = $sourceDbName
    Consistency        = $ConsistencyLevel
    ValidationOnly     = $ValidateOnly.IsPresent
    PollSeconds        = $script:PollSeconds
    TimeoutMinutes     = $script:TimeoutMinutes
    DurationSeconds    = $durationSeconds
    SnapshotsDeleted   = $removedSnapshotCount
    RemainingSnapshots = $remainingSnapshotIds
    CloneCount         = $EchoDbNames.Count
}
