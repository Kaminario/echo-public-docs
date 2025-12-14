# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

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

.PARAMETER FlexUrl
    The base URL for the Flex server, e.g., https://flex.example.com.

.PARAMETER FlexIp
    The IP address of the Flex server. Can also be set via the $env:FLEX_IP environment variable.

.PARAMETER FlexToken
    The authentication token for the Flex API. Can also be set via the $env:FLEX_TOKEN environment variable.

.PARAMETER SnapshotPrefix
    An optional prefix for the name of the new snapshot.

.PARAMETER ConsistencyLevel
    The consistency level for the snapshot. Must be either 'crash' or 'application'. Defaults to 'crash'.

.PARAMETER PollSeconds
    The interval in seconds to poll for task completion. Defaults to 5.

.PARAMETER TimeoutMinutes
    The maximum time in minutes to wait for a task to complete. Defaults to 60.

.PARAMETER SqlUsername
    The SQL Server username for removing replication. Must have sysadmin server role. Can also be set via the $env:ECHO_MSSQL_USER environment variable.

.PARAMETER SqlPassword
    The SQL Server password for removing replication. Can also be set via the $env:ECHO_MSSQL_PASSWORD environment variable.

.PARAMETER SkipReplicationCleanup
    If set, skips SQL replication removal operations. SQL credentials are not required when this flag is set.

.PARAMETER Quiet
    If set, suppresses all non-essential output.

.EXAMPLE
    # Basic refresh
    .\refresh_echo_db.ps1 -EchoDbNames "sales_db_clone" -EchoDbHostName "dev-host-1"

.EXAMPLE
    # Refresh multiple clones that share a source database
    .\refresh_echo_db.ps1 -EchoDbNames moti_1,test_1 -EchoDbHostName primary -FlexIp 10.0.0.15 -FlexToken sometoken

.NOTES
    Requires PowerShell 5.1 or higher.
    Ensure FLEX_IP and FLEX_TOKEN environment variables are set, or pass them as parameters.
    SQL credentials (ECHO_MSSQL_USER and ECHO_MSSQL_PASSWORD) are only required if -SkipReplicationCleanup is not specified.
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

    [Parameter(HelpMessage = "SQL Server username")]
    [string]$SqlUsername = $env:ECHO_MSSQL_USER,

    [Parameter(HelpMessage = "SQL Server password")]
    [string]$SqlPassword = $env:ECHO_MSSQL_PASSWORD,

    [Parameter(HelpMessage = "Skip SQL replication removal")]
    [switch]$SkipReplicationCleanup,

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

#region Certificate and TLS Configuration

function Set-TlsConfiguration {
    <#
    .SYNOPSIS
        Configures TLS settings and disables certificate validation for self-signed certs.
    #>
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7

    # Configure TLS protocols
    try {
        if ($IsPowerShell7) {
            # PowerShell 7+ supports TLS 1.3
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
                Write-Verbose "Enabled TLS 1.2 and TLS 1.3."
            }
            catch {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                Write-Verbose "Enabled TLS 1.2."
            }
        }
        else {
            # PowerShell 5.1 - Force TLS 1.2
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Write-Verbose "Enabled TLS 1.2 for PowerShell 5.1."
        }
    }
    catch {
        Write-Warning "Could not configure TLS protocol. This may cause connection issues."
    }

    # Disable certificate validation
    if ($IsPowerShell7) {
        # PowerShell 7+ uses ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            Write-Verbose "Disabled certificate validation using ServerCertificateValidationCallback."
        }
        catch {
            Write-Warning "Could not set ServerCertificateValidationCallback."
        }
    }
    else {
        # PowerShell 5.1 uses CertificatePolicy
        $currentPolicy = [System.Net.ServicePointManager]::CertificatePolicy
        if ($null -eq $currentPolicy -or $currentPolicy.GetType().FullName -ne "TrustAllCertsPolicy") {
            try {
                Add-Type @"
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
                Write-Verbose "Disabled certificate validation using CertificatePolicy for PowerShell 5.1."
            }
            catch {
                # Type might already be loaded from a previous run
                if ($_.Exception.Message -match "already exists") {
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                    Write-Verbose "Certificate policy already defined. Applied existing TrustAllCertsPolicy."
                }
                else {
                    Write-Warning "Could not set certificate policy: $($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Verbose "Certificate policy already set. Skipping."
        }
    }
}

# Apply TLS and certificate configuration at script initialization
Set-TlsConfiguration

#endregion Certificate and TLS Configuration

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
        $matchingDb = $Topology | ForEach-Object {
            $_.databases | Where-Object { $_.id -eq $sourceDbId }
        } | Select-Object -First 1

        if ($matchingDb) {
            $sourceDbName = $matchingDb.name
        }
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

function New-SqlConnectionString {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SqlServerInstance,
        [Parameter(Mandatory = $true)]
        [string]$SqlUsername,
        [Parameter(Mandatory = $true)]
        [string]$SqlPassword,
        [string]$Database = "master"
    )

    return "Server=$SqlServerInstance;Database=$Database;User Id=$SqlUsername;Password=$SqlPassword;TrustServerCertificate=True;"
}

function Test-SqlSysadminPermission {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConnectionString,
        [Parameter(Mandatory = $true)]
        [string]$SqlUsername,
        [Parameter(Mandatory = $true)]
        [string]$SqlServerInstance
    )

    Write-Info "Validating sysadmin permissions for SQL user '$SqlUsername' on '$SqlServerInstance'..."

    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        $connection.Open()

        $command = $connection.CreateCommand()
        $command.CommandText = "SELECT IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin"
        $command.CommandTimeout = 30

        $result = $command.ExecuteScalar()
        $connection.Close()
        $connection.Dispose()

        if ($result -eq 1) {
            Write-Info "User '$SqlUsername' has sysadmin permissions."
            return $true
        }
        elseif ($result -eq 0) {
            Write-Error "User '$SqlUsername' does not have sysadmin permissions on '$SqlServerInstance'."
            return $false
        }
        else {
            Write-Warning "Could not determine sysadmin status for user '$SqlUsername'. Result: $result"
            return $false
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        $innerException = $_.Exception.InnerException

        # Check for SQL authentication errors
        if ($errorMessage -match "Login failed|authentication|password|credential|user.*not.*found|Cannot open database" -or
            ($innerException -and $innerException.Message -match "Login failed|authentication|password|credential")) {
            Write-Error "SQL Server authentication failed for user '$SqlUsername' on '$SqlServerInstance'. Please verify the username and password are correct."
            throw "SQL Server authentication failed: $errorMessage"
        }

        # Connection errors
        if ($errorMessage -match "timeout|connection|network|unreachable|refused") {
            Write-Error "Failed to connect to SQL Server '$SqlServerInstance'. Please verify the server is accessible."
            throw "SQL Server connection failed: $errorMessage"
        }

        # Other errors
        Write-Error "Failed to validate sysadmin permissions: $errorMessage"
        throw
    }
}

function EnsureSQLUser {
    param (
        [Parameter(Mandatory = $true)]
        [string]$SqlServerInstance,
        [Parameter(Mandatory = $true)]
        [string]$SqlUsername,
        [Parameter(Mandatory = $true)]
        [string]$SqlPassword
    )

    Write-Info "Validating SQL Server credentials and permissions..."

    # Validate parameters
    if (-not $SqlUsername -or -not $SqlPassword) {
        throw "SQL Server credentials not provided. Set -SqlUsername and -SqlPassword parameters or ECHO_MSSQL_USER and ECHO_MSSQL_PASSWORD environment variables."
    }

    # Create connection string
    $connectionString = New-SqlConnectionString -SqlServerInstance $SqlServerInstance -SqlUsername $SqlUsername -SqlPassword $SqlPassword

    # Validate permissions
    try {
        $hasSysadmin = Test-SqlSysadminPermission -ConnectionString $connectionString -SqlUsername $SqlUsername -SqlServerInstance $SqlServerInstance
        if (-not $hasSysadmin) {
            throw "SQL permission validation failed: User '$SqlUsername' does not have sysadmin permissions on '$SqlServerInstance'. The script requires sysadmin privileges to remove replication."
        }
    }
    catch {
        # Test-SqlSysadminPermission already provides detailed error messages for authentication/connection failures
        # Re-throw with context if it's a permission error
        if ($_.Exception.Message -notmatch "authentication|connection|Login failed") {
            throw "SQL permission validation failed: $($_.Exception.Message)"
        }
        # Re-throw authentication/connection errors as-is (they already have good messages)
        throw
    }

    Write-Info "SQL Server credentials and permissions validated successfully."

    # Return connection string for reuse
    return $connectionString
}

function Remove-SqlReplication {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConnectionString,
        [Parameter(Mandatory = $true)]
        [string[]]$DatabaseNames
    )

    Write-Info "Removing SQL Server replication from database(s): $($DatabaseNames -join ', ')..."

    foreach ($dbName in $DatabaseNames) {
        try {
            Write-Info "Executing sp_removedbreplication on '$dbName'..."

            $connection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
            $connection.Open()

            $command = $connection.CreateCommand()
            $command.CommandText = "EXEC sp_removedbreplication @dbname = @dbname"
            $command.Parameters.AddWithValue("@dbname", $dbName) | Out-Null
            $command.CommandTimeout = 300

            $null = $command.ExecuteNonQuery()

            $connection.Close()
            $connection.Dispose()

            Write-Info "Successfully removed replication from '$dbName'."
        }
        catch {
            Write-Warning "Failed to remove replication from '$dbName': $($_.Exception.Message)"
            # Continue with other databases even if one fails
        }
    }
}

#endregion Helper Functions

#region Refresh Flow Helpers

function Get-FlexTopology {
    Write-Info "Fetching system topology from $($script:FlexBaseUrl)..."
    return Invoke-FlexApi -Uri "/api/ocie/v1/topology"
}

function Resolve-EchoClonePlan {
    param (
        [Parameter(Mandatory = $true)][object[]]$Topology,
        [Parameter(Mandatory = $true)][string]$EchoDbHostName,
        [Parameter(Mandatory = $true)][string[]]$EchoDbNames
    )

    $cloneListDisplay = ($EchoDbNames -join ', ')
    Write-Info "Searching for Echo DB(s) '$cloneListDisplay' on host '$EchoDbHostName'..."

    $echoHost = $Topology | Where-Object { $_.host.name -eq $EchoDbHostName }
    if (-not $echoHost) {
        throw "Host '$EchoDbHostName' not found in topology."
    }

    $resolvedClones = @()
    foreach ($cloneName in $EchoDbNames) {
        $echoDb = $echoHost.databases | Where-Object { $_.name -eq $cloneName }
        if (-not $echoDb) {
            throw "Database '$cloneName' not found on host '$EchoDbHostName'."
        }

        $sourceInfo = Get-EchoDbSourceInfo -EchoDb $echoDb -Topology $Topology

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

    # Check that all clones share the same source
    $sourceDetails = $resolvedClones | ForEach-Object { "{0}:{1}" -f $_.SourceHostId, $_.SourceDbId } | Sort-Object -Unique
    if ($sourceDetails.Count -ne 1) {
        throw "All Echo databases must share the same source. Found sources: $($sourceDetails -join ', ')"
    }

    # All clones share the same source, so use the first one
    $sourceHostId = $resolvedClones[0].SourceHostId
    $sourceDbId = $resolvedClones[0].SourceDbId
    $sourceDbName = $resolvedClones[0].SourceDbName

    Write-Info "Found $($resolvedClones.Count) Echo DB(s). Source is '$sourceDbName' (ID: $sourceDbId) on host ID '$sourceHostId'."

    return [pscustomobject]@{
        EchoHost         = $echoHost
        ResolvedClones   = $resolvedClones
        SourceHostId     = $sourceHostId
        SourceDbId       = $sourceDbId
        SourceDbName     = $sourceDbName
        CloneListDisplay = $cloneListDisplay
        CloneCount       = $resolvedClones.Count
    }
}

function New-SourceSnapshot {
    param (
        [Parameter(Mandatory = $true)][string]$SourceHostId,
        [Parameter(Mandatory = $true)][string]$SourceDbId,
        [Parameter(Mandatory = $true)][string]$ConsistencyLevel,
        [Parameter(Mandatory = $true)][string]$SnapshotPrefix
    )

    Write-Info "Creating a new '$ConsistencyLevel' snapshot of the source database..."
    $snapshotBody = @{
        source_host_id    = $SourceHostId
        database_ids      = @($SourceDbId)
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

    return [pscustomobject]@{
        SnapshotId = $newSnapshotId
        Task       = $completedSnapshotTask
    }
}

function Invoke-DatabaseRefresh {
    param (
        [Parameter(Mandatory = $true)][pscustomobject]$EchoHost,
        [Parameter(Mandatory = $true)][string[]]$EchoDbNames,
        [Parameter(Mandatory = $true)][string]$CloneListDisplay,
        [Parameter(Mandatory = $true)][string]$SnapshotId
    )

    Write-Info "Refreshing Echo DB(s) '$CloneListDisplay' with the new snapshot..."
    $replaceBody = @{
        snapshot_id = $SnapshotId
        db_names    = $EchoDbNames
        keep_backup = $false
    }

    $replaceEndpoint = "/flex/api/v1/hosts/$($EchoHost.host.id)/databases/_replace"

    $replaceTask = Invoke-FlexApi -Uri $replaceEndpoint -Method "POST" -Body $replaceBody
    $replaceTaskId = if ($replaceTask.PSObject.Properties.Name -contains 'request_id') { $replaceTask.request_id } else { $null }
    Write-Verbose "Replace task request id: $replaceTaskId"
    $completedReplaceTask = Wait-For-Task -Task $replaceTask

    Write-Info "Successfully refreshed Echo DB(s) '$CloneListDisplay' on host '$($EchoHost.host.name)'."
    Write-Info "Refresh complete."

    return [pscustomobject]@{
        OriginalTask  = $replaceTask
        CompletedTask = $completedReplaceTask
        RequestId     = $replaceTaskId
    }
}

function Invoke-RefreshCleanup {
    param (
        [Parameter(Mandatory = $true)][string]$SourceHostId,
        [Parameter(Mandatory = $true)][string]$SourceDbId,
        [Parameter(Mandatory = $true)][string]$SnapshotId
    )

    return Remove-StaleSnapshots -SourceHostId $SourceHostId -SourceDbId $SourceDbId -SnapshotToKeep $SnapshotId
}

function New-RefreshSummary {
    param (
        [Parameter(Mandatory = $true)][pscustomobject]$Plan,
        [Parameter(Mandatory = $true)][pscustomobject]$SnapshotInfo,
        [Parameter(Mandatory = $true)][pscustomobject]$RefreshInfo,
        [Parameter()][pscustomobject]$CleanupResult,
        [Parameter(Mandatory = $true)][string[]]$EchoDbNames,
        [Parameter(Mandatory = $true)][string]$ConsistencyLevel,
        [Parameter(Mandatory = $true)][datetime]$ScriptStart
    )

    $removeSummary = if ($CleanupResult) { $CleanupResult } else { [pscustomobject]@{ Deleted = 0; Remaining = @() } }
    $durationSeconds = [Math]::Round(((Get-Date) - $ScriptStart).TotalSeconds, 2)
    $completedTask = $RefreshInfo.CompletedTask
    $replaceRequestId = if ($completedTask -and $completedTask.PSObject.Properties.Name -contains 'request_id') {
        $completedTask.request_id
    }
    elseif ($RefreshInfo.RequestId) {
        $RefreshInfo.RequestId
    }
    else {
        $null
    }

    return [pscustomobject]@{
        SnapshotId         = $SnapshotInfo.SnapshotId
        ReplaceTaskId      = $replaceRequestId
        Databases          = $EchoDbNames
        DatabaseList       = $Plan.CloneListDisplay
        Host               = $Plan.EchoHost.host.name
        SourceDatabase     = $Plan.SourceDbName
        Consistency        = $ConsistencyLevel
        PollSeconds        = $script:PollSeconds
        TimeoutMinutes     = $script:TimeoutMinutes
        DurationSeconds    = $durationSeconds
        SnapshotsDeleted   = $removeSummary.Deleted
        RemainingSnapshots = if ($removeSummary.Remaining) { @($removeSummary.Remaining) } else { @() }
        CloneCount         = $Plan.CloneCount
    }
}

#endregion Refresh Flow Helpers

# --- Main Script Logic ---

$topology = Get-FlexTopology
$plan = Resolve-EchoClonePlan -Topology $topology -EchoDbHostName $EchoDbHostName -EchoDbNames $EchoDbNames

# Handle replication operations if not skipped
if (-not $SkipReplicationCleanup) {
    # Add SQL Server default port 1433 to hostname
    $sqlServerInstance = "$EchoDbHostName,1433"

    # Validate SQL Server credentials and permissions BEFORE any replication operations
    $sqlConnectionString = EnsureSQLUser -SqlServerInstance $sqlServerInstance -SqlUsername $SqlUsername -SqlPassword $SqlPassword

    Remove-SqlReplication -ConnectionString $sqlConnectionString -DatabaseNames $EchoDbNames
}
else {
    Write-Info "Skipping SQL replication removal (SkipReplicationCleanup flag is set)."
}

$snapshotInfo = New-SourceSnapshot -SourceHostId $plan.SourceHostId -SourceDbId $plan.SourceDbId -ConsistencyLevel $ConsistencyLevel -SnapshotPrefix $SnapshotPrefix
$refreshInfo = Invoke-DatabaseRefresh -EchoHost $plan.EchoHost -EchoDbNames $EchoDbNames -CloneListDisplay $plan.CloneListDisplay -SnapshotId $snapshotInfo.SnapshotId
$cleanupResult = Invoke-RefreshCleanup -SourceHostId $plan.SourceHostId -SourceDbId $plan.SourceDbId -SnapshotId $snapshotInfo.SnapshotId

New-RefreshSummary -Plan $plan -SnapshotInfo $snapshotInfo -RefreshInfo $refreshInfo -CleanupResult $cleanupResult -EchoDbNames $EchoDbNames -ConsistencyLevel $ConsistencyLevel -ScriptStart $scriptStart
