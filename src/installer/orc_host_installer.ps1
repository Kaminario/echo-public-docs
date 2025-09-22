<#
.SYNOPSIS
    Installs Silk Echo components (Node Agent and VSS Provider) on a remote host.

.DESCRIPTION
    This PowerShell script installs the Silk Node Agent and Silk VSS Provider service on a remote Windows host.
    It connects to Silk Flex to register the host, downloads the required installers, and performs the installation
    with the provided configuration parameters.

    The script requires administrative privileges and assumes that all necessary prerequisites are in place.

.PARAMETER FlexIP
    The IP address of the Silk Flex server.

.PARAMETER FlexToken
    The authentication token for accessing the Silk Flex API.

.PARAMETER DBConnectionString
    The SQL Server connection string for the Silk Node Agent.

.PARAMETER SilkAgentPath
    The local file path to the Silk Node Agent installer.

.PARAMETER SilkVSSPath
    The local file path to the Silk VSS Provider installer.

.PARAMETER SDPId
    The SDP (Silk Data Platform) identifier.

.PARAMETER SDPUsername
    The username for SDP authentication.

.PARAMETER SDPPassword
    The password for SDP authentication.

.PARAMETER MountPointsDirectory
    The directory where mount points for the Silk Node Agent will be created.

.PARAMETER DryRun
    Perform validation and connectivity tests without actually installing the components.
    When enabled, the script will verify downloads, connections, and prerequisites but skip the actual installation steps.

.EXAMPLE
    .\orc_host_installer.ps1 -FlexIP "10.0.0.1" -FlexToken "abc123" -DBConnectionString "server=localhost;..." -SilkAgentPath "C:\Temp\SilkInstallers\agent-installer.exe" -SilkVSSPath "C:\Temp\SilkInstallers\vss-installer.exe" -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password"

    Installs Silk Echo components with the specified parameters.

.EXAMPLE
    .\orc_host_installer.ps1 -FlexIP "10.0.0.1" -FlexToken "abc123" -DBConnectionString "server=localhost;..." -SilkAgentPath "C:\Temp\SilkInstallers\agent-installer.exe" -SilkVSSPath "C:\Temp\SilkInstallers\vss-installer.exe" -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password" -DryRun

    Performs validation and connectivity tests without installing the components.

.NOTES
    File Name      : orc_host_installer.ps1
    Author         : Silk.us, Inc.
    Prerequisite   : PowerShell version 5 or higher, Administrator privileges
    Copyright      : (c) 2024 Silk.us, Inc.

.INPUTS
    String parameters for configuration and authentication.

.OUTPUTS
    Installation status messages and logs.

.FUNCTIONALITY
    Remote installation, System administration, Silk Echo deployment
#>

# PowerShell script to install Echo on a remote host
# This script assumes you have the necessary permissions and prerequisites in place.
# It installs the Silk Node Agent and the Silk VSS Provider service.
# Make sure to run this script with administrative privileges.

param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$FlexIP,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$FlexToken,

    [Parameter(Mandatory=$true)]
    [string]$DBConnectionString,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SilkAgentPath,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SilkVSSPath,

    [Parameter(Mandatory=$true)]
    [string]$SDPId,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SDPUsername,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SDPPassword,

    [string]$MountPointsDirectory = "",
    [switch]$DryRun
)

if ($DebugPreference -eq 'Continue' -or $VerbosePreference -eq 'Continue') {
    Write-Host "Debug and Verbose output enabled."
    $DebugPreference = 'Continue'
    $VerbosePreference = 'Continue'
} else {
    Write-Host "Debug and Verbose output disabled."
    $DebugPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
}

# suppress progress bar
$ProgressPreference = 'SilentlyContinue'


# ErrorMessage, InfoMessage, DebugMessage, WarningMessage
. ./orc_logging_on_host.ps1
# SkipCertificateCheck
. ./orc_no_verify_cert.ps1
# CallSelfCertEndpoint, CallSDPApi, CallFlexApi
. ./orc_web_client.ps1
# Constants for installer
. ./orc_constants_installer.ps1

# global variables
# ============================================================================

# Create SDP credential from passed parameters
$SDPCredential = New-Object System.Management.Automation.PSCredential($SDPUsername, (ConvertTo-SecureString $SDPPassword -AsPlainText -Force))

Set-Variable -Name SDPCredential -Value $SDPCredential -Scope Global
Set-Variable -Name IsDryRun -Value $DryRun.IsPresent -Scope Global
Set-Variable -Name AgentInstallationLogPath -Scope Global
Set-Variable -Name SVSSInstallationLogPath -Scope Global
Set-Variable -Name HostID -Value "$(hostname)" -Scope Global
Set-Variable -Name FlexToken -Value $FlexToken -Scope Global

$SilkAgentDirectory = Split-Path -Path $SilkAgentPath -Parent
Set-Variable -Name AgentInstallationLogPath -Value "$SilkAgentDirectory\install.log" -Scope Global
$SilkVSSDirectory = Split-Path -Path $SilkVSSPath -Parent
Set-Variable -Name SVSSInstallationLogPath -Value "$SilkVSSDirectory\SilkVSSProviderInstall.log" -Scope Global

DebugMessage "Agent installation log path: $AgentInstallationLogPath"
DebugMessage "SVSS installation log path: $SVSSInstallationLogPath"


#region TestFlexConnectivity
function TestFlexConnectivity {
    param (
        [string]$FlexIP,
        [string]$FlexToken
    )
    $ApiEndpoint = '/api/v2/flex/info'
    try {
        $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "GET" -RequestBody $null
        if ($response.StatusCode -eq 200) {
            return $true
        } else {
            ErrorMessage "Failed to call Flex API at $flexApiUrl. Status code: $($response.StatusCode)"
            return $false
        }
    } catch {
        ErrorMessage "Error connecting to Flex: $_"
        return $false
    }
    return $false
}
#endregion TestFlexConnectivity


#region RegisterHostAtFlex
function RegisterHostAtFlex {
    param (
        [string]$FlexIP,
        [string]$FlexToken
    )
    InfoMessage "Registering host at Flex... $HostID"


    $ApiEndpoint = "/api/hostess/v1/hosts/${HostID}"

    InfoMessage "Unregister if exists"
    $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "DELETE" -RequestBody $null
    if ($response.StatusCode -ne 204) {
        ErrorMessage "Failed to unregister host at Flex. Status code: $($response.StatusCode)"
        return ""
    }

    # Register the host at Flex with hostname and db_vendor, hostname like it return from pwsh hostname (not $env:COMPUTERNAME because it is always UPPERCASE)
    $RequestBody = @{
        "db_vendor" = "mssql"
    } | ConvertTo-Json

    try {
        $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "PUT" -RequestBody $RequestBody
        DebugMessage "Response from Flex API: $($response.StatusCode) - $($response.StatusDescription)"
        if ($response.StatusCode -eq 201) {
            #read token from response and return it { "host_id": "string", "db_vendor": "mssql", "token": "string"}
            $responseContent = $response.Content | ConvertFrom-Json
            $token = $responseContent.token
            InfoMessage "Successfully registered host at Flex as $HostID."
            return $token
        } else {
            ErrorMessage "Failed to register host at Flex. Status code: $($response)"
            return ""
        }
    } catch {
        ErrorMessage "Error registering host at Flex: $_"
        return ""
    }
}
#endregion RegisterHostAtFlex

#region GetMSSQLHostPorts
function GetMSSQLHostPorts {
    $listener = Get-NetTCPConnection -State Listen | Where-Object {
        (Get-Process -Id $_.OwningProcess).ProcessName -eq "sqlservr" -and
        $_.LocalAddress -match '^\d{1,3}(\.\d{1,3}){3}$'
    }

    if (-not $listener) {
        DebugMessage "No SQL Server listener found. Please ensure SQL Server is running."
        return @()
    }

    # write all options to the log
    foreach ($item in $listener) {
        DebugMessage "Found SQL Server listener: LocalAddress=$($item.LocalAddress), LocalPort=$($item.LocalPort)"
    }

    # Get hostname and resolve it to IP
    $hostname = $env:COMPUTERNAME
    $hostnameIP = $null
    try {
        $hostnameIP = [System.Net.Dns]::GetHostAddresses($hostname) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 -ExpandProperty IPAddressToString
        InfoMessage "Resolved hostname '$hostname' to IP: $hostnameIP"
    } catch {
        WarningMessage "Failed to resolve hostname '$hostname' to IP: $_"
    }

    # Phase 1: Filter listeners - prioritize standard ports 1433
    $standardPortListeners = $listener | Where-Object { $_.LocalPort -eq 1433 }
    $candidateListeners = if ($standardPortListeners) {
        InfoMessage "Found SQL Server listeners on standard ports, prioritizing them"
        $standardPortListeners
    } else {
        InfoMessage "No standard ports found, using all available listeners"
        $listener
    }

    # Phase 2: Build prioritized list of all potential server addresses
    $prioritizedServers = @()

    # Priority 1: loopback addresses
    $loopbackListeners = $candidateListeners | Where-Object { $_.LocalAddress -like "127.*" }
    foreach ($listener in $loopbackListeners) {
        $prioritizedServers += "localhost,$($listener.LocalPort)"
    }

    # Priority 2: wildcard listeners (0.0.0.0) - use hostname
    $wildcardListeners = $candidateListeners | Where-Object { $_.LocalAddress -eq "0.0.0.0" }
    foreach ($listener in $wildcardListeners) {
        $prioritizedServers += "${hostname},$($listener.LocalPort)"
    }

    # Priority 3: hostname IP listeners - use hostname
    if ($hostnameIP) {
        $hostnameIPListeners = $candidateListeners | Where-Object { $_.LocalAddress -eq $hostnameIP }
        foreach ($listener in $hostnameIPListeners) {
            $prioritizedServers += "${hostname},$($listener.LocalPort)"
        }
    }

    # Priority 4: all other listeners - use actual IP
    $otherListeners = $candidateListeners | Where-Object {
        $_.LocalAddress -notlike "127.*" -and
        $_.LocalAddress -ne "0.0.0.0" -and
        $_.LocalAddress -ne $hostnameIP
    }
    foreach ($listener in $otherListeners) {
        $prioritizedServers += "$($listener.LocalAddress),$($listener.LocalPort)"
    }

    InfoMessage "Discovered $($prioritizedServers.Count) SQL Server endpoints to try"
    return $prioritizedServers
}
#endregion GetMSSQLHostPorts


#region createAndTestConnectionString
function createAndTestConnectionString {
    param (
        [string]$DBConnectionString
    )

    # Parse input connection string
    $baseParams = @{}
    $DBConnectionString = $DBConnectionString.Trim()
    $parts = $DBConnectionString -split ';'
    foreach ($part in $parts) {
        if ($part.Trim()) {
            $key, $value = $part -split '=', 2
            $baseParams[$key.Trim()] = $value.Trim()
        }
    }

    # Set application name to SilkAgent
    $baseParams['Application Name'] = 'SilkAgent'

    # If Server is already specified, test that connection first
    if ($baseParams.ContainsKey('Server') -and $baseParams['Server'] -ne '') {
        $connectionStringParts = $baseParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)

        InfoMessage "Testing provided server: $($baseParams['Server'])"
        if (TestSQLConnection -ConnectionString $connectionString) {
            InfoMessage "Successfully connected to provided server"
            return $connectionString
        } else {
            WarningMessage "Failed to connect to provided server, will try auto-discovery"
        }
    }

    # Auto-discover SQL Server instances and test each one
    $discoveredServers = GetMSSQLHostPorts
    if ($discoveredServers.Count -eq 0) {
        ErrorMessage "No SQL Server instances discovered. Please ensure SQL Server is running."
        return $null
    }

    InfoMessage "Testing $($discoveredServers.Count) discovered SQL Server endpoints..."

    foreach ($serverEndpoint in $discoveredServers) {
        $testParams = $baseParams.Clone()
        $testParams['Server'] = $serverEndpoint

        $connectionStringParts = $testParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)

        InfoMessage "Testing connection to: $serverEndpoint"
        if (TestSQLConnection -ConnectionString $connectionString) {
            InfoMessage "Successfully connected to SQL Server at: $serverEndpoint"
            return $connectionString
        }
    }

    ErrorMessage "Failed to connect to any discovered SQL Server instances"
    return $null
}
#endregion createAndTestConnectionString


#region TestSQLConnection
function TestSQLConnection {
    param (
        [string]$ConnectionString
    )
    try {
        $sqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        $sqlConnection.Open()
        $sqlConnection.Close()
        return $true
    } catch {
        DebugMessage "Connection failed: $($_.Exception.Message)"
        return $false
    }
}
#endregion TestSQLConnection


#region PrintAgentInstallationLog
function PrintAgentInstallationLog {
    InfoMessage "======== Agent Installation Log ========"
    if (Test-Path -Path $AgentInstallationLogPath) {
        $logContent = Get-Content -Path $AgentInstallationLogPath
        foreach ($line in $logContent) {
            InfoMessage $line
        }
    } else {
        InfoMessage "No installation log found at $AgentInstallationLogPath"
    }
    InfoMessage "======== End Agent Installation Log ========"
}
#endregion PrintAgentInstallationLog


#region PrintSVSSInstallationLog
function PrintSVSSInstallationLog {
    InfoMessage "======== SVSS Installation Log ========"
    if (Test-Path -Path $SVSSInstallationLogPath) {
        $logContent = Get-Content -Path $SVSSInstallationLogPath
        foreach ($line in $logContent) {
            InfoMessage $line
        }
    } else {
        InfoMessage "No installation log found at $SVSSInstallationLogPath"
    }
    InfoMessage "======== End SVSS Installation Log ========"
}
#endregion PrintSVSSInstallationLog


#region CleanupInstallerFiles
function CleanupInstallerFiles {
    # Remove all files in the directory including the directory itself
    if (Test-Path -Path $SilkAgentDirectory) {
        try {
            Remove-Item -Path $SilkAgentDirectory -Recurse -Force
            InfoMessage "Cleaned up installer files in directory: $SilkAgentDirectory"
        } catch {
            WarningMessage "Failed to cleanup installer files in directory $SilkAgentDirectory`: $_"
        }
    }
    if (Test-Path -Path $SilkVSSDirectory) {
        try {
            Remove-Item -Path $SilkVSSDirectory -Recurse -Force
            InfoMessage "Cleaned up installer files in directory: $SilkVSSDirectory"
        } catch {
            WarningMessage "Failed to cleanup installer files in directory $SilkVSSDirectory`: $_"
        }
    }
}
#endregion CleanupInstallerFiles

#region EscapePowershellParameter
function EscapePowershellParameter {
    param (
        [string]$Parameter
    )
    # Spaces and special characters should be handled by PowerShell automatically, but we can ensure they are escaped
    $escapedParameter = $Parameter -replace '([;,])', '`$1'
    return $escapedParameter
}
#endregion EscapePowershellParameter

#region StartProcessWithTimeout
function StartProcessWithTimeout {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [array]$ArgumentList,

        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 90,

        [Parameter(Mandatory=$true)]
        [string]$ProcessName
    )

    InfoMessage "Starting installation of $ProcessName from $FilePath with timeout of $TimeoutSeconds seconds"
    try {
        # Convert ArgumentList array to JSON string for safe job parameter passing
        $argsJson = $ArgumentList | ConvertTo-Json -Compress

        # Start installation process with timeout
        $installJob = Start-Job -ScriptBlock {
            param($InstallerPath, $ArgsJson)
            try {
                # Convert JSON back to array
                $Args = $ArgsJson | ConvertFrom-Json
                # Ensure it's an array even if single element
                if ($Args -is [string]) {
                    $Args = @($Args)
                }

                $process = Start-Process -FilePath $InstallerPath -ArgumentList $Args -Wait -NoNewWindow -PassThru
                Write-Host "Process completed with exit code: $($process.ExitCode)"
                return $process.ExitCode
            } catch {
                Write-Error "Process failed: $_"
                return 999
            }
        } -ArgumentList $FilePath, $argsJson

        DebugMessage "Started job with ID $($installJob.Id) for $ProcessName installation"

        # Wait for job completion with timeout
        $waitResult = $installJob | Wait-Job -Timeout $TimeoutSeconds

        if ($waitResult) {
            # Job completed within timeout
            $exitCode = Receive-Job -Job $installJob
            Remove-Job -Job $installJob -Force
            InfoMessage "$ProcessName installation completed with exit code [$exitCode]"
            return @{
                Success = ($exitCode -eq 0)
                Reason = "Completed"
                ExitCode = $exitCode
                ProcessName = $ProcessName
            }
        } else {
            # Installation timed out
            ErrorMessage "$ProcessName installation timed out after $TimeoutSeconds seconds"
            Stop-Job -Job $installJob -ErrorAction SilentlyContinue
            Remove-Job -Job $installJob -Force -ErrorAction SilentlyContinue
            return @{
                Success = $false
                Reason = "Timeout"
                TimeoutSeconds = $TimeoutSeconds
                ProcessName = $ProcessName
            }
        }
    } catch {
        ErrorMessage "Error installing $ProcessName`: $_"
        return @{
            Success = $false
            Reason = "Error"
            ErrorMessage = $_.Exception.Message
            ProcessName = $ProcessName
        }
    }
}
#endregion StartProcessWithTimeout

#region InstallSilkNodeAgent
function InstallSilkNodeAgent {
    param (
        [string]$InstallerFilePath,
        [string]$SQLConnectionString,
        [string]$FlexIP,
        [string]$AgentToken,
        [string]$MountPointsDirectory
    )
    InfoMessage "InstallSilkNodeAgent: executable $InstallerFilePath"
    # execute InstallerFilePath
    if (-not (Test-Path -Path $InstallerFilePath)) {
        InfoMessage "Installer file not found at $InstallerFilePath. Exiting script."
        return $false
    }
    # pass argumnets as /DbConnStr='"$sqlConn"'
    InfoMessage "Building arguments with SQLConnectionString='$SQLConnectionString', FlexIP='$FlexIP', AgentToken='[REDACTED]', MountPointsDirectory='$MountPointsDirectory'"
    $arguments = @(
        '/S', # Silent installation
        "/DbConnStr='$SQLConnectionString'",
        "/FlexHost='$FlexIP'",
        "/Token='$AgentToken'",
        "/MountPointsDirectory='$MountPointsDirectory'"
    )
    DebugMessage "Arguments array: $($arguments -join ' ')"

    # Run installation with timeout
    $installResult = StartProcessWithTimeout `
                        -FilePath $InstallerFilePath `
                        -ArgumentList $arguments `
                        -TimeoutSeconds $INTERNAL_INSTALL_TIMEOUT_SECONDS `
                        -ProcessName "Silk Node Agent"

    if (-not $installResult.Success) {
        # Return detailed failure information to caller
        return @{
            Success = $false
            Reason = $installResult.Reason
            Details = $installResult
            Message = switch ($installResult.Reason) {
                "Timeout" { "Silk Node Agent installation timed out after $($installResult.TimeoutSeconds) seconds" }
                "Error" { "Silk Node Agent installation failed with error: $($installResult.ErrorMessage)" }
                default { "Silk Node Agent installation failed" }
            }
        }
    }

    # error handling

    InfoMessage "Silk Node Agent installation completed. Checking installation log at $AgentInstallationLogPath"

    # test log file do not contain "error"
    if (Test-Path -Path $AgentInstallationLogPath) {
        $logContent = Get-Content -Path $AgentInstallationLogPath
        if ($logContent -match "(?i)error") {
            ErrorMessage "Installation log contains errors. Please check the log file at $AgentInstallationLogPath"
            return @{
                Success = $false
                Reason = "LogError"
                Message = "Silk Node Agent installation log contains errors. Check $AgentInstallationLogPath."
                LogPath = $AgentInstallationLogPath
            }
        } else {
            DebugMessage "Silk Node Agent installed successfully."
            return @{
                Success = $true
                Reason = "Completed"
                Message = "Silk Node Agent installed successfully"
                ExitCode = $installResult.ExitCode
            }
        }
    } else {
        ErrorMessage "Installation log file not found at $AgentInstallationLogPath. Installation may have failed."
        return @{
            Success = $false
            Reason = "LogNotFound"
            Message = "Installation log file not found at $AgentInstallationLogPath"
            LogPath = $AgentInstallationLogPath
        }
    }
}
#endregion InstallSilkNodeAgent


#region GetSDPInfo
function GetSDPInfo {
    # we should have sdp floating ip, username and password for vss provider
    param (
        [string]$FlexIP,
        [string]$FlexToken,
        [string]$SDPID = ""
    )
    $ApiEndpoint = '/api/v1/pages/dashboard'
    try {
        $response = CallFlexApi -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint $ApiEndpoint -HttpMethod "GET" -RequestBody $null
        if ($response.StatusCode -ne 200) {
            ErrorMessage "Failed to get SDP info from Flex. Status code: $($response.StatusCode)"
            return $null
        }

        $responseContent = $response.Content | ConvertFrom-Json
        if (-not $responseContent.k2xs) {
            ErrorMessage "No k2xs found in the response from Flex."
            return $null
        }

        if (-not $SDPID) {
            # if SDPID not provided, take the first k2x id
            $SDPID = $responseContent.k2xs[0].id
            InfoMessage "No SDP ID provided. Using first k2x ID: $SDPID"
        }

        # case insensitive search for k2x with given SDPID
        $SDPID = $SDPID.ToLower()
        DebugMessage "Searching for k2x with ID: $SDPID"
        $k2x = $responseContent.k2xs | Where-Object { $_.id.ToLower() -eq $SDPID }
        if (-not $k2x) {
            ErrorMessage "No k2x found with ID $SDPID in the response from Flex."
            return $null
        }

        $sdpInfo = @{
            "id" = $k2x.id
            "version" = $k2x.version
            "mc_floating_ip" = $k2x.mc_floating_ip
            "mc_https_port" = $k2x.mc_https_port
            "credentials" = $null
        }

        DebugMessage "Found k2x with ID $($sdpInfo.id) and version $($sdpInfo.version)"
        return $sdpInfo
    } catch {
        ErrorMessage "Error getting SDP info from Flex: $_"
        return $null
    }
}
#endregion GetSDPInfo


#region ValidateSDPConnection
function ValidateSDPConnection {
    param (
        [string]$SDPHost,
        [string]$SDPPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ApiEndpoint = 'system/state'
    DebugMessage "Validating SDP connection for username: $($Credential.UserName)"
    $response = CallSDPApi -SDPHost $SDPHost -SDPPort $SDPPort -ApiEndpoint $ApiEndpoint -Credential $Credential
    if (-not $response) {
        ErrorMessage "Failed to call SDP API at https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"
        return $false
    }

    return $true
}
#endregion ValidateSDPConnection


#region InstallSilkVSSProvider
function InstallSilkVSSProvider {
    param (
        [string]$InstallerFilePath,
        [string]$SDPID,
        [string]$SDPHost,
        [string]$SDPPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    InfoMessage "Installing Silk VSS Provider from $InstallerFilePath"
    # execute InstallerFilePath
    if (-not (Test-Path -Path $InstallerFilePath)) {
        InfoMessage "Installer file not found at $InstallerFilePath. Exiting script."
        return $false
    }

    $arguments = @(
        '/silent',
        "/external_ip=$SDPHost",
        "/host_name=$(hostname)",
        "/username=$($Credential.UserName)",
        "/password=$($Credential.GetNetworkCredential().Password)",
        "/log_level_provider=info",
        "/log_level_json=info",
        "/log_level_configurator=info",
        '/check_vg_full=false',
        '/snap_prefix=snap',
        '/retention_policy=Best_Effort_Retention',
        "/log=$SVSSInstallationLogPath"
    )

    InfoMessage "Silk VSS Provider installation arguments: $arguments"

    # Run installation with timeout
    $installResult = StartProcessWithTimeout `
                        -FilePath $InstallerFilePath `
                        -ArgumentList $arguments `
                        -TimeoutSeconds $INTERNAL_INSTALL_TIMEOUT_SECONDS `
                        -ProcessName "Silk VSS"

    if (-not $installResult.Success) {
        InfoMessage "Silk VSS Provider installation failed. $($installResult | Out-String)"
        # Return detailed failure information to caller
        return @{
            Success = $false
            Reason = $installResult.Reason
            Details = $installResult
            Message = switch ($installResult.Reason) {
                "Timeout" { "Silk VSS Provider installation timed out after $($installResult.TimeoutSeconds) seconds" }
                "Error" { "Silk VSS Provider installation failed with error: $($installResult.ErrorMessage)" }
                default { "Silk VSS Provider installation failed" }
            }
        }
    }

    # error handling
    InfoMessage "Silk VSS Provider installation completed. Checking installation log at $SVSSInstallationLogPath"

    # test log file do not contain "error"
    if (Test-Path -Path $SVSSInstallationLogPath) {
        $logContent = Get-Content -Path $SVSSInstallationLogPath
        # split log content into lines and find all lines containing "error" or "out of memory" (case insensitive)
        if ($logContent -match "(?i)error") {
            ErrorMessage "Installation log contains errors. Please check the log file at $SVSSInstallationLogPath"
            return @{
                Success = $false
                Reason = "LogError"
                Message = "Silk VSS Provider installation log contains errors. Check $SVSSInstallationLogPath, $($errors -join '; ')"
                LogPath = $SVSSInstallationLogPath
            }
        } else {
            InfoMessage "Silk VSS Provider installed successfully."
            return @{
                Success = $true
                Reason = "Completed"
                Message = "Silk VSS Provider installed successfully"
                ExitCode = $installResult.ExitCode
            }
        }
    } else {
        ErrorMessage "Installation log file not found at $SVSSInstallationLogPath. Installation may have failed."
        return @{
            Success = $false
            Reason = "LogNotFound"
            Message = "Installation log file not found at $SVSSInstallationLogPath"
            LogPath = $SVSSInstallationLogPath
        }
    }
}
#endregion InstallSilkVSSProvider


#region setup
function setup{

    try {
        SkipCertificateCheck


        if (-not (TestFlexConnectivity -FlexIP $FlexIP -FlexToken $FlexToken)) {
            InfoMessage "Flex connectivity test failed"
            return "Failed to establish connection with Flex server at $FlexIP"
        }

        InfoMessage "Successfully connected to Flex"

        # get sdp username and password from flex
        $SDPInfo = GetSDPInfo -FlexIP $FlexIP -FlexToken $FlexToken -SDPID $SDPId

        if (-not $SDPInfo) {
            ErrorMessage "Failed to get SDP info from Flex"
            return "Unable to retrieve SDP information from Flex server"
        }

        $SDPID = $SDPInfo["id"]
        $SDPVersion = $SDPInfo["version"]
        $SDPHost = $SDPInfo["mc_floating_ip"]
        $SDPPort = $SDPInfo["mc_https_port"]
        InfoMessage "Successfully retrieved SDP info from Flex $SDPID ($SDPVersion) at ${SDPHost}:$SDPPort"

        $SdpConnectionValid = ValidateSDPConnection -SDPHost $SDPHost -SDPPort $SDPPort -Credential $SDPCredential
        if (-not $SdpConnectionValid) {
            ErrorMessage "Failed to validate SDP connection"
            return "Unable to establish connection with SDP at ${SDPHost}:${SDPPort}"
        }

        $ConnectionString = createAndTestConnectionString -DBConnectionString $DBConnectionString

        if (-not $ConnectionString) {
            ErrorMessage "Failed to create and test connection string"
            return "Unable to establish connection with any available SQL Server instance. Check SQL Server availability and credentials"
        }

        InfoMessage "Successfully established SQL Server connection with connection string: $ConnectionString"

        if (-not (Test-Path $SilkAgentPath)) {
            ErrorMessage "Silk Node Agent installer not found at $SilkAgentPath"
            return "Unable to find Silk Node Agent installer at $SilkAgentPath"
        } else {
            InfoMessage "Silk Node Agent installer found at $SilkAgentPath"
        }

        if (-not (Test-Path $SilkVSSPath)) {
            ErrorMessage "Silk VSS Provider installer not found at $SilkVSSPath"
            return "Unable to find Silk VSS Provider installer at $SilkVSSPath"
        } else {
            InfoMessage "Silk VSS Provider installer found at $SilkVSSPath"
        }

        if ($IsDryRun) {
            # stop execution if dry run is enabled
            InfoMessage "Dry run mode enabled. Skipping actual installation."
            return $null
        }

        $AgentToken = RegisterHostAtFlex -FlexIP $FlexIP -FlexToken $FlexToken
        if (-not $AgentToken) {
            return "Failed to register host $HostID with Flex and obtain agent token"
        }

        # Install Silk VSS Provider
        $vssResult = InstallSilkVSSProvider -InstallerFilePath $SilkVSSPath -SDPID $SDPID -SDPHost $SDPHost -SDPPort $SDPPort -Credential $SDPCredential
        if (-not $vssResult.Success) {
            ErrorMessage "Failed to install Silk VSS Provider: $($vssResult.Reason)"
            return $vssResult.Message
        }

        InfoMessage "Temporary directory: $SilkVSSDirectory"
        if ($IsDryRun) {
            InfoMessage "Validation completed successfully. No actual installation was performed."
        } else {
            InfoMessage "Silk Node Agent and VSS Provider installation completed successfully."
        }

        $installResult = InstallSilkNodeAgent -InstallerFilePath $SilkAgentPath `
                                          -SQLConnectionString $ConnectionString `
                                          -FlexIP $FlexIP `
                                          -AgentToken $AgentToken `
                                          -MountPointsDirectory $MountPointsDirectory
        if (-not $installResult.Success) {
            ErrorMessage "Failed to install Silk Node Agent: $($installResult.Reason)"
            return $installResult.Message
        }

        # Return $null to indicate success
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}
#endregion setup

#region SetupHost
function SetupHost {
    InfoMessage "Starting Silk Node Agent and VSS Provider installation script..."

    try {
        $error = setup
    } catch {
        $error = $_
    }

    PrintAgentInstallationLog
    PrintSVSSInstallationLog

    if ($error) {
        ErrorMessage "Process log files located at:"
        ErrorMessage " - Silk Node Agent installation log: $AgentInstallationLogPath"
        ErrorMessage " - Silk VSS Provider installation log: $SVSSInstallationLogPath"
        ErrorMessage "Setup completed with errors. Please check the logs for details: $($error)"
        throw "Setup failed on Host[$env:COMPUTERNAME]. $($error)"
    } else {
        CleanupInstallerFiles
        InfoMessage "Setup completed successfully."
    }
}

SetupHost
#endregion SetupHost
