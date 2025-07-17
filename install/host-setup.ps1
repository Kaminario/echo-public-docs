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

.PARAMETER SilkAgentURL
    The URL to download the Silk Node Agent installer.

.PARAMETER SilkVSSURL
    The URL to download the Silk VSS Provider installer.

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
    .\host-setup.ps1 -FlexIP "10.0.0.1" -FlexToken "abc123" -DBConnectionString "server=localhost;..." -SilkAgentURL "https://..." -SilkVSSURL "https://..." -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password"
    
    Installs Silk Echo components with the specified parameters.

.EXAMPLE
    .\host-setup.ps1 -FlexIP "10.0.0.1" -FlexToken "abc123" -DBConnectionString "server=localhost;..." -SilkAgentURL "https://..." -SilkVSSURL "https://..." -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password" -DryRun
    
    Performs validation and connectivity tests without installing the components.

.NOTES
    File Name      : host-setup.ps1
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
    [string]$FlexIP,
    [string]$FlexToken,
    [string]$DBConnectionString,
    [string]$SilkAgentURL,
    [string]$SilkVSSURL,
    [string]$SDPId,
    [string]$SDPUsername,
    [string]$SDPPassword,
    [string]$MountPointsDirectory,
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

# make DryRun global variable
Set-Variable -Name IsDryRun -Value $DryRun.IsPresent -Scope Global

# suppress progress bar
$ProgressPreference = 'SilentlyContinue'
# init if running in PowerShell 7 or later
$IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
# Create SDP credential from passed parameters
$SDPCredential = New-Object System.Management.Automation.PSCredential($SDPUsername, (ConvertTo-SecureString $SDPPassword -AsPlainText -Force))
# Store original SDPPassword for logging redaction before clearing it
$OriginalSDPPassword = $SDPPassword
# clear the SDPPassword
$SDPPassword = $null

# global variables
Set-Variable -Name AgentInstallationLogPath -Scope Global
Set-Variable -Name SVSSInstallationLogPath -Scope Global
Set-Variable -Name HostID -Value "$(hostname)" -Scope Global
#Create global variable $TmpDir that can be accessable from every where in script
Set-Variable -Name TmpDir -Value "" -Scope Global
Set-Variable -Name MessageCurrentObject -Value "Host[$(hostname)]" -Scope Global
Set-Variable -Name FlexToken -Value $FlexToken -Scope Global
Set-Variable -Name SDPPassword -Value $OriginalSDPPassword -Scope Global


#region Logging
Function LogTimeStamp {
    # returns formatted timestamp
	return Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
}

function Sanitize {
    param (
        [string]$Text
    )
   
    # Reduct password from text, sometimes text contains connection string with password
    $ReductedText = $Text -replace '(?i)(?<=Password=)[^;]+', '********'
    
    # Replace the value of the $FlexToken variable with '********' only if it exists and is not empty
    if ($Global:FlexToken -and $Global:FlexToken.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:FlexToken), '********'
    }
    
    # Replace the value of the $SDPPassword variable with '********' only if it exists and is not empty  
    if ($Global:SDPPassword -and $Global:SDPPassword.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:SDPPassword), '********'
    }
    
    return $ReductedText
}

Function ArgsToSanitizedString {
    $sanitizedArgs = @()
    foreach ($arg in $args) {
        if ($arg -is [System.Management.Automation.ErrorRecord]) {
            $sanitizedArgs += Sanitize -Text $arg.Exception.Message
        } else {
            $sanitizedArgs += Sanitize -Text $arg.ToString()
        }
    }
    return [string]::Join(' ', $sanitizedArgs)
}

# Functions to print colored messages
Function ErrorMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [ERROR] - $msg"
    Write-Error "$(LogTimeStamp) - $($MessageCurrentObject) - [ERROR] - $msg"
}

Function InfoMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [INFO] - $msg"
}

Function DebugMessage {
    if ($DebugPreference -ne 'Continue') {
        return
    }
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [DEBUG] - $msg"
}

Function WarningMessage {
    $msg = ArgsToSanitizedString @args

	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [WARN] - $msg"
}
#endregion Logging


#region SkipCertificateCheck
function SkipCertificateCheck {
    if ($IsPowerShell7) {
        # if Powershell version is 7 or higher, set SkipCertificateCheck
        return
    }
    
    # set policy only once per powershell sessions
    $currentPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    if ($currentPolicy -eq $null -or ($currentPolicy.GetType().FullName -ne "TrustAllCertsPolicy")) {
        add-type @"
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
    } else {
        InfoMessage "Certificate policy already set to $([System.Net.ServicePointManager]::CertificatePolicy). skipping."
    }
}
#endregion SkipCertificateCheck


#region MakeTempDirectory
function MakeTempDirectory {
    # Create temp directory in user's temp folder with unique name
    $TmpDir = Join-Path $env:TEMP "echo-installer-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    # Create directory if it doesn't exist
    New-Item -Path $TmpDir -ItemType Directory -Force | Out-Null
    # move install.log if it exists to name with timestamp
    Set-Variable -Name AgentInstallationLogPath -Value "$TmpDir\install.log" -Scope Global
    Set-Variable -Name SVSSInstallationLogPath -Value "$TmpDir\SilkVSSProviderInstall.log" -Scope Global
    Set-Variable -Name TmpDir -Value "$TmpDir" -Scope Global
    DebugMessage "Temporary directory created at $TmpDir"
    DebugMessage "Agent installation log path: $AgentInstallationLogPath"
    DebugMessage "SVSS installation log path: $SVSSInstallationLogPath"
}
#endregion MakeTempDirectory


#region NETWORK

#region CallSelfCertEndpoint
function CallSelfCertEndpoint {
    param (
        [string]$URL,
        [string]$HttpMethod,
        [object]$RequestBody,
        [hashtable]$Headers
    )

    DebugMessage "Calling [$HttpMethod]$URL"
    # capitalize the first letter of HttpMethod
    $HttpMethod = $HttpMethod.Substring(0,1).ToUpper() + $HttpMethod.Substring(1).ToLower()

    if ($IsPowerShell7) {
        if ( $HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
    } else {
        if ($HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            # If no request body is provided
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -ErrorAction Stop
        }
    }
    return $response
}
#endregion CallSelfCertEndpoint

#region CallSDPApi
function CallSDPApi {
    param (
        [string]$SDPFloatingIP,
        [string]$SDPHttpsPort,
        [string]$ApiEndpoint,
        [System.Management.Automation.PSCredential]$Credential
    )

    $url = "https://${SDPFloatingIP}:${SDPHttpsPort}/api/v2/$ApiEndpoint"

    DebugMessage "==== CallSDPApi USERNAME: $($Credential.UserName) ===="
    $BasicAuthString = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    
    $BasicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($BasicAuthString))
    $_headers = @{
        "Authorization" = "Basic $BasicAuth"
    }

    try {
        $response = CallSelfCertEndpoint -URL $url -HttpMethod "GET" -RequestBody $null -Headers $_headers
        if ($response.StatusCode -ne 200) {
            ErrorMessage "Failed to call SDP API at $url. Status code: $($response.StatusCode)"
            return $null
        }
        DebugMessage "Response from SDP API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling SDP API: $_"
        return $null
    }
}
#endregion CallSDPApi

#region CallFlexApi
function CallFlexApi {
        param (
        [string]$FlexIP,
        [string]$FlexToken,
        [string]$ApiEndpoint,
        [string]$HttpMethod,
        [string]$RequestBody
    )

    $flexApiUrl = "https://$FlexIP$ApiEndpoint"
    $headers = @{ "Authorization" = "Bearer $FlexToken" }

    DebugMessage "Calling Flex API at $flexApiUrl with method $HttpMethod"
    try {
        $response = CallSelfCertEndpoint -URL $flexApiUrl -HttpMethod $HttpMethod -RequestBody $RequestBody -Headers $headers
        DebugMessage "Response from Flex API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling Flex API: $_"
        return $null
    }
    
}
    #endregion CallFlexApi

#endregion NETWORK


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
        return $null
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


#region DownloadArtifact
function DownloadArtifact {
    param (
        [string]$ArtifacURL
    )
    $Name = [System.IO.Path]::GetFileName($ArtifacURL)
    $fileLoc = "$TmpDir\$Name"

    # Check if the installer already exists
    if (Test-Path -Path $fileLoc) {
        DebugMessage "$Name already exists at $fileLoc. Skipping download."
        return $fileLoc
    }

    DebugMessage "Downloading Silk Node Agent from $ArtifacURL to $fileLoc"
    if ( $DryRun ) {
        InfoMessage "Try to access of Silk Node Agent from $ArtifacURL"
        # We will do HEAD to see if we can get the file
        try {
            $response = Invoke-WebRequest -Uri $ArtifacURL -Method Head -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                InfoMessage "Silk Node Agent is accessible at $ArtifacURL"
                return $fileLoc
            }
        } catch {
            ErrorMessage "Error accessing Silk Node Agent at $ArtifacURL : $_"
        }
        return ""
    }

    try {
        Invoke-WebRequest -Uri $ArtifacURL -OutFile $fileLoc -UseBasicParsing
        DebugMessage "Downloaded Silk Node Agent to $fileLoc"
        return $fileLoc
    } catch {
        ErrorMessage "Error downloading or installing Silk Node Agent: $_"
        return ""
    }
}
#endregion DownloadArtifact


#region DiscovertMSSQLHostPort
function DiscovertMSSQLHostPort {
    $listener = Get-NetTCPConnection -State Listen | Where-Object {
        (Get-Process -Id $_.OwningProcess).ProcessName -eq "sqlservr" -and
        $_.LocalAddress -match '^\d{1,3}(\.\d{1,3}){3}$'
    }

    if (-not $listener) {
        DebugMessage "No SQL Server listener found. Please ensure SQL Server is running."
        return $null
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

    # Check if SQL Server is listening on hostname IP or 0.0.0.0 - prefer hostname
    if ($hostnameIP) {
        $hostnameListener = $listener | Where-Object { $_.LocalAddress -eq $hostnameIP }
        if ($hostnameListener) {
            $sqlPort = $hostnameListener[0].LocalPort
            InfoMessage "SQL Server is listening on hostname IP ($hostnameIP) using hostname: ${hostname},${sqlPort}"
            return "${hostname},${sqlPort}"
        }

        $hostnameListener = $listener | Where-Object { $_.LocalAddress -eq "0.0.0.0" }
        if ($hostnameListener) {
            $sqlPort = $hostnameListener[0].LocalPort
            InfoMessage "SQL Server is listening on 0.0.0.0, using hostname: ${hostname},${sqlPort}"
            return "${hostname},${sqlPort}"
        }
    }

    # Priority 1: Take specific IP (different from hostname and loopback)
    $specificIPListener = $listener | Where-Object { 
        $_.LocalAddress -ne "0.0.0.0" -and 
        $_.LocalAddress -notlike "127.*" -and 
        ($hostnameIP -eq $null -or $_.LocalAddress -ne $hostnameIP)
    }
    if ($specificIPListener) {
        $sqlIP = $specificIPListener[0].LocalAddress
        $sqlPort = $specificIPListener[0].LocalPort
        InfoMessage "Found SQL Server listener on specific IP: ${sqlIP},${sqlPort}"
        return "${sqlIP},${sqlPort}"
    }

    # Priority 2: Take loopback address that SQL Server listens to
    $loopbackListener = $listener | Where-Object { $_.LocalAddress -like "127.*" }
    if ($loopbackListener) {
        $sqlIP = $loopbackListener[0].LocalAddress
        $sqlPort = $loopbackListener[0].LocalPort
        InfoMessage "Found SQL Server listener on loopback: ${sqlIP},${sqlPort}"
        return "${sqlIP},${sqlPort}"
    }

    # Fallback: Use first available listener
    if ($listener.Count -gt 0) {
        $sqlIP = if ($listener[0].LocalAddress -eq "0.0.0.0") { "localhost" } else { $listener[0].LocalAddress }
        $sqlPort = $listener[0].LocalPort
        InfoMessage "Using fallback SQL Server listener: ${sqlIP},${sqlPort}"
        return "${sqlIP},${sqlPort}"
    }

    InfoMessage "No suitable SQL Server listener found."
    return $null
}
#endregion DiscovertMSSQLHostPort


#region createConnectionString
function createConnectionString {
    param (
        [string]$DBConnectionString
    )
    
    # always set application name to SilkAgent
    $params = @{}
    $DBConnectionString = $DBConnectionString.Trim()
    $parts = $DBConnectionString -split ';'
    foreach ($part in $parts) {
        $key, $value = $part -split '=', 2
        $params[$key.Trim()] = $value.Trim()
    }

    # if Server not in connection string, add it by finding a IP and port it is listening on or fail
    if (-not $params.ContainsKey('Server') -or $params['Server'] -eq '') {
        $HostPort = DiscovertMSSQLHostPort
        if ($HostPort) {
            InfoMessage "Discovered SQL Server running at: $HostPort"
            $params['Server'] = $HostPort
        } else {
            ErrorMessage "Failed to discover SQL Server host and port. Exiting script."
            return $null
        }
    }

    # set application name to SilkAgent
    if (-not $params.ContainsKey('Application Name')) {
        $params['Application Name'] = 'SilkAgent'
    }

    # join the parameters back to a connection string
    $connectionStringParts = $params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
    $connectionString = [string]::Join(';', $connectionStringParts)

    return $connectionString
}
#endregion createConnectionString


#region ValidateSQLConnection
function ValidateSQLConnection {
    param (
        [string]$ConnectionString
    )
    try {
        InfoMessage "Validating SQL Server connection with connection string: $ConnectionString"
        $sqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        $sqlConnection.Open()
        InfoMessage "Successfully connected to SQL Server."
        $sqlConnection.Close()
        return $true
    } catch {
        # remove password from error message
        ErrorMessage "Failed to connect to SQL Server:" $_.Exception.Message
        return $false
    }
}
#endregion ValidateSQLConnection


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


#region CleanupTempDirectory
function CleanupTempDirectory {
    if (Test-Path -Path $TmpDir) {
        try {
            Remove-Item -Path $TmpDir -Recurse -Force
            DebugMessage "Cleaned up temporary directory: $TmpDir"
        } catch {
            WarningMessage "Failed to cleanup temporary directory $TmpDir`: $_"
        }
    }
}
#endregion CleanupTempDirectory

function EscapePowershellParameter {
    param (
        [string]$Parameter
    )
    # Spaces and special characters should be handled by PowerShell automatically, but we can ensure they are escaped
    $escapedParameter = $Parameter -replace '([;,])', '`$1'
    return $escapedParameter
}


#region InstallSilkNodeAgent
function InstallSilkNodeAgent {
    param (
        [string]$InstallerFilePath,
        [string]$SQLConnectionString,
        [string]$FlexIP,
        [string]$AgentToken
    )
    InfoMessage "Installing Silk Node Agent from $InstallerFilePath"
    # execute InstallerFilePath
    if (-not (Test-Path -Path $InstallerFilePath)) {
        InfoMessage "Installer file not found at $InstallerFilePath. Exiting script."
        return $false
    }

    # pass argumnets as /DbConnStr='"$sqlConn"'
    $arguments = @(
        '/S', # Silent installation
        "/DbConnStr='$SQLConnectionString'",
        "/FlexHost='$FlexIP'",
        "/Token='$AgentToken'",
        "/MountPointsDirectory='$MountPointsDirectory'"
    )

    try {
        Start-Process -FilePath $InstallerFilePath -ArgumentList $arguments -Wait -NoNewWindow
        if ($LASTEXITCODE -ne 0) {
            ErrorMessage "Silk Node Agent installation failed with exit code $LASTEXITCODE"
            return $false
        }
    } catch {
        InfoMessage "Error installing Silk Node Agent: $_"
        return $false
    }

    # error handling
    
    InfoMessage "Silk Node Agent installation completed. Checking installation log at $AgentInstallationLogPath"

    # test log file do not contain "error"
    if (Test-Path -Path $AgentInstallationLogPath) {
        $logContent = Get-Content -Path $AgentInstallationLogPath
        if ($logContent -match "error") {
            ErrorMessage "Installation log contains errors. Please check the log file at $AgentInstallationLogPath"
            return $false
        } else {
            DebugMessage "Silk Node Agent installed successfully."
            return $true
        }
    } else {
        ErrorMessage "Installation log file not found at $AgentInstallationLogPath. Installation may have failed."
        return $false
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
        [string]$SDPFloatingIP,
        [string]$SDPHttpsPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ApiEndpoint = 'system/state'

    InfoMessage "==== ValidateSDPConnection USERNAME: $($Credential.UserName) ===="
    $response = CallSDPApi -SDPFloatingIP $SDPFloatingIP -SDPHttpsPort $SDPHttpsPort -ApiEndpoint $ApiEndpoint -Credential $Credential
    if (-not $response) {
        ErrorMessage "Failed to call SDP API at https://${SDPFloatingIP}:${SDPHttpsPort}/api/v2/$ApiEndpoint"
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
        [string]$SDPFloatingIP,
        [string]$SDPHttpsPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    InfoMessage "Installing Silk VSS Provider from $InstallerFilePath"
    # execute InstallerFilePath
    if (-not (Test-Path -Path $InstallerFilePath)) {
        InfoMessage "Installer file not found at $InstallerFilePath. Exiting script."
        return $false
    }

$ArgumentList = @(
        '/silent',
        "/external_ip=$SDPFloatingIP",
        "/host_name=$(hostname)",
        "/password=$($Credential.GetNetworkCredential().Password)",
        "/log_level_provider=info",
        "/log_level_json=info",
        "/log_level_configurator=info",
        '/check_vg_full=false',
        '/snap_prefix=snap',
        '/retention_policy=Best_Effort_Retention',
        "/log=$TmpDir\SilkVSSProviderInstall.log"
    )

    try {
        $processArgs = @{
            FilePath     = $InstallerFilePath
            Wait         = $true
            ArgumentList = $ArgumentList
            NoNewWindow  = $true
        }
        Start-Process @processArgs

    } catch {
        InfoMessage "Error installing Silk VSS Provider: $_"
        return $false
    }

    # error handling
    DebugMessage "Silk VSS Provider installed successfully."
    return $true
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
        $SDPFloatingIP = $SDPInfo["mc_floating_ip"] 
        $SDPHttpsPort = $SDPInfo["mc_https_port"]
        InfoMessage "Successfully retrieved SDP info from Flex $SDPID ($SDPVersion) at ${SDPFloatingIP}:$SDPHttpsPort"

        $SdpConnectionValid = ValidateSDPConnection -SDPFloatingIP $SDPFloatingIP -SDPHttpsPort $SDPHttpsPort -Credential $SDPCredential
        if (-not $SdpConnectionValid) {
            ErrorMessage "Failed to validate SDP connection"
            return "Unable to establish connection with SDP at ${SDPFloatingIP}:${SDPHttpsPort}"
        }

        $ConnectionString = createConnectionString -DBConnectionString $DBConnectionString

        if (-not $ConnectionString) {
            ErrorMessage "Failed to create connection string"
            return "Unable to create SQL Server connection string. Check SQL Server availability and credentials"
        }

        if (-not (ValidateSQLConnection -ConnectionString $ConnectionString)) {
            ErrorMessage "Failed to connect to SQL Server"
            return "Unable to establish connection with SQL Server using the provided connection string"
        }

        DebugMessage "Downloading Silk VSS Provider from $SilkVSSURL"
        $vssFileLoc = DownloadArtifact -ArtifacURL $SilkVSSURL

        if ($vssFileLoc) {
            InfoMessage "Silk VSS Provider downloaded to $vssFileLoc"
        } else {
            InfoMessage "Failed to download Silk VSS Provider"
            return "Unable to download Silk VSS Provider from $SilkVSSURL"
        }

        $agentFileLoc = DownloadArtifact -ArtifacURL $SilkAgentURL

        if ($agentFileLoc) {
            InfoMessage "Silk Node Agent downloaded to $agentFileLoc"
        } else {
            ErrorMessage "Failed to download Silk Node Agent"
            return "Unable to download Silk Node Agent from $SilkAgentURL"
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

        if (-not (InstallSilkNodeAgent -InstallerFilePath $agentFileLoc -SQLConnectionString $ConnectionString -FlexIP $FlexIP -AgentToken $AgentToken)) {
            ErrorMessage "Failed to install Silk Node Agent"
            return "Installation of Silk Node Agent failed. Check the installation log at $AgentInstallationLogPath"
        }

        # Install Silk VSS Provider
        $installed = InstallSilkVSSProvider -InstallerFilePath $vssFileLoc -SDPID $SDPID -SDPFloatingIP $SDPFloatingIP -SDPHttpsPort $SDPHttpsPort -Credential $SDPCredential
        if (-not $installed) {
            ErrorMessage "Failed to install Silk VSS Provider"
            return "Installation of Silk VSS Provider failed. Check the installation log at $TmpDir\SilkVSSProviderInstall.log"
        }

        InfoMessage "Temporary directory: $TmpDir"
        if ($IsDryRun) {
            InfoMessage "Validation completed successfully. No actual installation was performed."
        } else {
            InfoMessage "Silk Node Agent and VSS Provider installation completed successfully."
        }
        # Return $null to indicate success
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}
#endregion setup

#region Main
function Main {
    InfoMessage "Starting Silk Node Agent and VSS Provider installation script..."
    
    MakeTempDirectory

    try {
        $error = setup
    } catch {
        $error = $_
    }
    
    PrintAgentInstallationLog
    PrintSVSSInstallationLog
    CleanupTempDirectory

    if ($error) {
        ErrorMessage "Setup completed with errors. Please check the logs for details: $($error)"
        throw "Setup failed. $($error)"
    }
}

Main
#endregion Main
