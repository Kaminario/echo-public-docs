<#
.SYNOPSIS
    Silk Echo Installer PowerShell Script - Install Silk Echo on multiple remote hosts using PowerShell.

.DESCRIPTION
    This script installs Silk Echo on multiple remote Windows hosts using PowerShell remoting.
    It reads configuration from a JSON file and performs remote installation on specified hosts.

    The script requires PowerShell version 5 or higher and must be run with administrator privileges.
    It uses an external script 'setup-one-host.ps1' to perform the actual installation on each host.

.PARAMETER ConfigPath
    Full or relative path to the configuration file in JSON format.
    The configuration file must contain hosts, flex_host_ip, and sdpid fields.

.PARAMETER MaxConcurrency
    Number of hosts to install in parallel. Default value is 10.
    This helps manage resource usage and provides better progress tracking for large deployments.

.PARAMETER DryRun
    Perform validation of connectivity before running actual installation.
    It will validate connectivity from this host to the hosts defined in configuration file.
    After we have all the hosts validated, it will validate connectivity from each host to flex_host_ip and SDP.
    Default value is false.

.EXAMPLE
    .\bulk-setup.ps1 -ConfigPath "bulk-setup-config.json"

    Installs Silk Echo on hosts specified in the configuration file using default MaxConcurrency of 10.

.EXAMPLE
    .\bulk-setup.ps1 -ConfigPath "config.json" -MaxConcurrency 5

    Installs Silk Echo on hosts in batches of 5 at a time.

.EXAMPLE
    .\bulk-setup.ps1 -ConfigPath "config.json" -MaxConcurrency 5 -DryRun

    Performs a dry run validation on hosts in batches of 5 at a time without making any changes.

.EXAMPLE
    .\bulk-setup.ps1 -ConfigPath "config.json" -Debug

    Runs the installation with debug output enabled.

.EXAMPLE
    Get-Help .\bulk-setup.ps1 -Detailed

    Shows detailed help information for this script.

.INPUTS
    JSON configuration file with the following structure:
    {
        "agent": "https://storage.googleapis.com/silk-public-files/silk-agent-installer-latest.exe",
        "svss": "https://storage.googleapis.com/silk-public-files/svss-install.exe",
        "hosts": [
            "host-fgy01",
            "host-fgy02",
            "10.178.24.11"
        ],
        "flex_host_ip": "10.155.0.18",
        "sqlconnection": "",
        "sdpid": "d9b601"
    }

.OUTPUTS
    Installation logs and status messages.
    Detailed logs are saved to installation_logs_<timestamp>.json file.

.NOTES
    File Name      : bulk-setup.ps1
    Author         : Ilya.Levin@Silk.US
    Organization   : Silk.us, Inc.
    Version        : 0.0.1
    Copyright      : (c) 2024 Silk.us, Inc.
    Host Types     : Valid for Windows environments

    Prerequisites:
    - PowerShell version 5 or higher
    - Administrator privileges
    - Network access to target hosts
    - setup-one-host.ps1 script in the same directory

    The WinRemoting feature must be enabled on the target hosts.
    Ensure that the WinRM service is running and properly configured on each host.

    You can use the following command to check the WinRM service status:
    ```powershell
    Get-Service WinRM
    Enable-PSRemoting
    ```

    The WinRm is listening by default to 5985(http) and 5986(https) ports.
    Run to confirm on your target host:
    ```powershell
    WinRM enumerate winrm/config/listener
    ```

.LINK
    https://github.com/silk-us/echo-public-docs

.FUNCTIONALITY
    Remote installation, System administration, Silk Echo deployment
#>

#region Script Definitions
param (
    [Parameter(Mandatory=$true, HelpMessage="Full or relative path to the configuration file in JSON format")]
    [string]$ConfigPath,

    [Parameter(Mandatory=$false, HelpMessage="Number of hosts to install in parallel")]
    [int]$MaxConcurrency = 10,

    [Parameter(Mandatory=$false, HelpMessage="Perform dry run to validate connectivity before actual installation")]
    [switch]$DryRun
)

# Make MaxConcurrency a global variable accessible from any function
Set-Variable -Name MaxConcurrency -Value $MaxConcurrency -Option AllScope -Scope Script
Set-Variable -Name DryRun -Value $DryRun -Option AllScope -Scope Script

if ($DebugPreference -eq 'Continue' -or $VerbosePreference -eq 'Continue') {
    $DebugPreference = 'Continue'
    $VerbosePreference = 'Continue'
} else {
    $DebugPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
}

# Ensure the minimum version of the PowerShell Validator is 5 and above
#Requires -Version 5

$IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7

# Global parameter for messages

Set-Variable -Name InstallerProduct -Value "0.0.1" -Option AllScope -Scope Script
Set-Variable -Name MessageCurrentObject -Value "Silk Echo Installer" -Option AllScope -Scope Script


$InstallScriptName = "host-setup.ps1"
$InstallScriptPath = Join-Path -Path $PSScriptRoot -ChildPath $InstallScriptName

$SilkAgentURL = 'https://storage.googleapis.com/silk-public-files/silk-agent-installer-latest.exe'
$SilkVSSURL = 'https://storage.googleapis.com/silk-public-files/svss-install.exe'


#endregion

#region Logging
Function LogTimeStamp {
    # # returns formatted timestamp
	return Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
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
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [ERROR] - $args" -ForegroundColor Red
}

Function InfoMessage {
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [INFO] - $args"
}

Function ImportantMessage {
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [INFO] - $args" -ForegroundColor Green
}

Function DebugMessage {
    if ($DebugPreference -ne 'Continue') {
        return
    }
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [DEBUG] - $args"
}

Function WarningMessage {
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [WARN] - $args" -ForegroundColor Yellow
}
#endregion Logging

#region CheckAdminUserCrossPlatform
function CheckAdminUserCrossPlatform {
    # CheckAdminUserCrossPlatform Function - Checking the current user in Windows and Linux environment. You must run as administrator (Windows)
    if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))	{
        return $false
    } else {
        DebugMessage "Running as an Administrator, on Windows OS version - $((Get-CimInstance Win32_OperatingSystem).version)"
	    return $true
    }
}
#endregion

#region ReadConfigFile
function ReadConfigFile {
    # read the configuration file passed as parameter to this scipt "-Config"
    # ConfigFile can be a full or relative path to the JSON file
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConfigFile
    )
    if (-Not (Test-Path -Path $ConfigFile)) {
        Write-Error -Message "Configuration file not found: $ConfigFile"
        Exit 1
    }
    try {
        $config = Get-Content -Path $ConfigFile | ConvertFrom-Json
    } catch {
        return $null
    }

    # Validate expected JSON structure
    if (-not ($config.hosts -and
              $config.flex_host_ip)) {
        ErrorMessage "Configuration file must contain 'hosts', 'flex_host_ip' fields"
        return $null
    }

    # Validate hosts array is not empty
    if ($config.hosts.Count -eq 0) {
        ErrorMessage "Configuration file must contain at least one host"
        return $null
    }

    # Validate flex_host_ip is a valid IP address
    if (-not ($config.flex_host_ip -as [IPAddress])) {
        ErrorMessage "flex_host_ip must be a valid IP address"
        return $null
    }

    if (-not $config.sdpid) {
        ErrorMessage "Configuration file must contain 'sdpid' field"
        return $null
    }

    if (-not $config.mount_points_directory -or $config.mount_points_directory -eq "") {
        ErrorMessage "Configuration file must contain 'mount_points_directory' field and it cannot be empty"
        return $null
    }

    # the sql connection script is optional.

    return $config
}
#endregion

#region EnsureRequirements
# EnsureRequirements Function - Checking the PowerShell version and edition
function EnsureRequirements {
    $PSVersion = $PSVersionTable.PSVersion.Major
    $ShellEdition = $PSVersionTable.PSEdition
    $passedPreReqs = $True
    if ($PSVersion -lt 5) {
        Write-Warning -Message "PowerShell version is $PSVersion, but version 5 or higher is required."
        $passedPreReqs = $False
    }
    if ($ShellEdition -ne "Core" -and $ShellEdition -ne "Desktop") {
        Write-Warning -Message "PowerShell edition is $ShellEdition, but only Core or Desktop editions are supported."
        $passedPreReqs = $False
    }
    if (-Not (Test-Path -Path $InstallScriptPath)) {
        Write-Warning -Message "Installation script '$InstallScriptName' not found in the current directory."
        $passedPreReqs = $False
    }
    return $passedPreReqs
}
#endregion


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
        Write-Host "Certificate policy already set to $([System.Net.ServicePointManager]::CertificatePolicy). skipping."
    }
}
#endregion SkipCertificateCheck

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

    DebugMessage "Call SDPApi USERNAME: $($Credential.UserName)"
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

#region GetCredSDP
function GetSDPCredentials {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SDPFloatingIP,
        [Parameter(Mandatory=$true)]
        [int]$SDPHttpsPort
    )
    $SdpConnectionValid = $false
    while (-not $SdpConnectionValid) {
        InfoMessage "Please provide SDP (Silk Data Platform) credentials for the installation"
        $SDPCredential = Get-Credential -Message "Enter your SDP credentials"
        if (-not $SDPCredential) {
            InfoMessage "Please provide valid credentials to continue."
            Continue
        }

        $SdpConnectionValid = ValidateSDPConnection -SDPFloatingIP $SDPFloatingIP -SDPHttpsPort $SDPHttpsPort -Credential $SDPCredential
        if ($SdpConnectionValid) {
            InfoMessage "SDP connection validated successfully."
            return $SDPCredential
        }
        InfoMessage "Failed to validate SDP connection. Please check your credentials and try again."
    }


}
#endregion GetCredSDP

#region LoginToFlex

#region GetCredFlex
function _GetFlexCredentials {
    $cred = Get-Credential -Message "Enter your Silk Flex credentials"
    if (-not $cred) {
        ErrorMessage "No credentials provided. Exiting."
        Exit 1
    }
    return $cred
}
#endregion GetCredFlex

#region _LoginToFlex
function _LoginToFlex {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexIP
    )

    <#
        curl 'https://52.151.194.250/api/v1/auth/local/login' \
        -X POST \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-raw 'password=*****&username=kaminario'
        response = {"access_token":"******","expiresIn":604800,"expiresOn":"2025-07-08 14:32:43"}
    #>

    # read credentials from the user
    $cred = _GetFlexCredentials
    $body = @{
        username = $cred.UserName
        password = $cred.GetNetworkCredential().Password
    }

    $url = "https://$FlexIP/api/v1/auth/local/login"
    $headers = @{
        'Accept' = 'application/json'
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    try {
        $response = CallSelfCertEndpoint -URL $url -HttpMethod 'POST' -RequestBody $body -Headers $headers
        if ($response.StatusCode -eq 200) {
            InfoMessage "Successfully logged in to Silk Flex at $FlexIP"
            # Parse the response content to extract the access token
            $JsonResponse = $response.Content | ConvertFrom-Json
            # return token

            return $JsonResponse.access_token
        } else {
            ErrorMessage "Failed to log in to Silk Flex: $($response.StatusDescription)"
            return ""
        }
    } catch {
        ErrorMessage "Error during login to Silk Flex: $_"
        return ""
    }

}
#endregion _LoginToFlex

function LoginToFlex {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexIP
    )
    $flexToken = ""
    while (-not $flexToken) {
        $flexToken = _LoginToFlex -FlexIP $FlexIP
    }
    return $flexToken
}

#endregion LoginToFlex

#region SDP

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

        InfoMessage "Found k2x with ID $($sdpInfo.id) and version $($sdpInfo.version)"
        return $sdpInfo
    } catch {
        ErrorMessage "Error getting SDP info from Flex: $_"
        return $null
    }
}
#endregion GetSDPInfo

#region ValidateSDPConn
function ValidateSDPConnection {
    param (
        [string]$SDPFloatingIP,
        [string]$SDPHttpsPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ApiEndpoint = 'system/state'

    DebugMessage "ValidateSDPConnection USERNAME: $($Credential.UserName)"
    $response = CallSDPApi -SDPFloatingIP $SDPFloatingIP -SDPHttpsPort $SDPHttpsPort -ApiEndpoint $ApiEndpoint -Credential $Credential
    if (-not $response) {
        ErrorMessage "Failed to call SDP API at https://${SDPFloatingIP}:${SDPHttpsPort}/api/v2/$ApiEndpoint"
        return $false
    }
    return $true
}
#endregion ValidateSDPConn

#endregion SDP

#region SQL

#region GetCredSQL
function GetSqlCredentials {
    param (
        [string]$Username,
        [string]$Password
    )
    # Check if user id is set, and ask for credentials if not
    while (-not $Username -or -not $Password) {
        InfoMessage "Please provide SQL credentials for the connection string."
        $cred = Get-Credential -Message "Enter your SQL Server credentials"
        if ($cred) {
            return $cred
        } else {
            ErrorMessage "No credentials provided. Cannot proceed without valid SQL Server credentials."
        }
    }
}
#endregion GetCredSQL

#region PrepSQLStr
function PrepareSqlConnectionString {
    param (
        [string]$SqlConnectionString
    )

    $connectionString = $SqlConnectionString.Trim()
    # Split the connection string into key-value pairs
    $pairs = $connectionString -split ';' | Where-Object { $_ -ne "" }
    $params = @{}
    foreach ($pair in $pairs) {
        $key, $value = $pair -split '=', 2
        if ($key -and $value) {
            $params[$key.Trim()] = $value.Trim()
            Write-Debug "Parsed parameter: $($key.Trim()) = $($value.Trim())"
        }
    }

    # validate server or data source parameter
    # not together
    if ($params.ContainsKey('server') -and $params.ContainsKey('data source')) {
        ErrorMessage "SQL connection string cannot contain both 'server' and 'data source' parameters."
        Exit 1
    }

    if ($params.ContainsKey('data source') -or $params.ContainsKey('server')) {
        if ($params.ContainsKey('server')){
            $KeyName = 'server'
        }
        if ($params.ContainsKey('data source')) {
            $KeyName = 'data source'
        }
        ImportantMessage @"
SQL connection string contains '$KeyName=$($params[$KeyName])'.
All servers will use the same Server for SQL connection.

This configuration is typical for a SQL Server cluster,
where all nodes connect to a single virtual network name (VNN).
"@
        # It must be a VNN AND not IP
        if ($params[$KeyName] -match '^\d{1,3}(\.\d{1,3}){3}$') {
            ErrorMessage "SQL Server cluster configuration cannot use IP address in '$KeyName' parameter: '$($params[$KeyName])'."
            Exit 1
        }

        $confirmation = Read-Host "Do you want to continue with this SQL connection string? (y/N)"
        if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
            ErrorMessage "User declined to continue with the SQL connection string. Exiting."
            Exit 1
        }
    }

    $credSQL = GetSqlCredentials -Username $params['user id'] -Password $params['password']
    # update params with credentials
    $params['user id'] = $credSQL.UserName
    $params['password'] = $credSQL.GetNetworkCredential().Password

    # set Application Name if not set
    if (-not $params.ContainsKey('Application Name')) {
        $params['Application Name'] = 'SilkAgent'
        DebugMessage "Application Name is not set, adding 'SilkAgent' to the connection string"
    }

    # Rebuild the connection string
    $connectionStringParts = $params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
    $connectionString = [string]::Join(';', $connectionStringParts)
    $LogSqlConnectionString = $connectionString -replace '(?i)password=[^;]+', 'password=***'
    InfoMessage "Prepared SQL connection string: $LogSqlConnectionString"

    return $connectionString
}
#endregion PrepSQLStr

#endregion SQL


#region TrustHosts
function AddHostsToTrustedHosts {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Hosts,
        [Parameter(Mandatory=$false)]
        [hashtable]$AuthMethod
    )

    # Skip TrustedHosts configuration when using Kerberos authentication
    if ($AuthMethod -and $AuthMethod.UseKerberos) {
        DebugMessage "Using Kerberos authentication - TrustedHosts configuration not required"
        return $true
    }

    $currentTrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts
    $newHosts = $Hosts | Where-Object { $_ -notin $currentTrustedHosts.Value.Split(',') }

    if ($newHosts.Count -eq 0) {
        DebugMessage "All hosts are already in TrustedHosts list"
        return $true
    }

    # ask user if they want to add hosts to TrustedHosts or process without it
    $confirmation = Read-Host "Do you want to add these hosts to TrustedHosts? (y/N)"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        InfoMessage "User declined to add hosts to TrustedHosts. Proceeding without adding to TrustedHosts may cause issues with remote communication."
        return $true
    }

    $hostsToAdd = $newHosts -join ','
    InfoMessage "The following hosts need to be added to TrustedHosts:"
    InfoMessage $hostsToAdd

    try {
        if ($currentTrustedHosts.Value) {
            $newValue = "$($currentTrustedHosts.Value),$hostsToAdd"
        } else {
            $newValue = $hostsToAdd
        }
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newValue -Force
        InfoMessage "Successfully added hosts to TrustedHosts"
        return $true
    } catch {
        ErrorMessage "Failed to add hosts to TrustedHosts: $_"
        return $false
    }

}
#endregion TrustHosts


#region GetHostAuth
function GetAuthenticationPreference {
    InfoMessage "Please select the authentication method for the hosts:"
    InfoMessage "1. Kerberos (Windows Authentication)"
    InfoMessage "2. Single Username and Password for all the hosts"
    InfoMessage "3. Each host has its own Username and Password"

    do {
        $choice = Read-Host "Enter your choice (1, 2, or 3)"
        if ($choice -eq "1" -or $choice -eq "2" -or $choice -eq "3") {
            break
        }
        WarningMessage "Invalid choice. Please enter 1 for Kerberos, 2 for One Username and Password, or 3 for Each host has its own Username and Password."
    } while ($true)

    $useKerberos = $choice -eq "1"
    if ($useKerberos) {
        # look if ips in conf.hosts
        $ipsInConfig = $Config.hosts | Where-Object { $_ -match    '^\d{1,3}(\.\d{1,3}){3}$' }
        if ($ipsInConfig.Count -gt 0) {
            ErrorMessage "Kerberos authentication requires hostnames, IP addresses found."
            InfoMessage "You have IP addresses in the configuration file: $($ipsInConfig -join ', ')"
            InfoMessage "Please use hostnames for the destination hosts instead of IP addresses in the configuration file."
            Exit 1
        }
    }
    $useSingleCredential = $choice -eq "2"

    if ($useKerberos) {
        return @{
            UseKerberos = $true
            Credential = $null
        }
    } elseif ($useSingleCredential) {
        InfoMessage "Using username and password authentication..."
        $cred = Get-Credential -Message "Enter credentials for remote hosts"
        if (-not $cred) {
            throw "No credentials provided. Cannot proceed without valid credentials."
        }
        return @{
            UseKerberos = $false
            Credential = $cred
        }
    } else {
        InfoMessage "Using individual credentials for each host..."
        return @{
            UseKerberos = $false
            Credential = $null
        }
    }
}
#endregion GetHostAuth

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
        [string]$computerName,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$jobResult,
        [string]$JobState
    )
    # Initialize arrays for different output types
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
                ComputerName = $computerName
                JobState = $JState
                Info = $outputLines
                Error = $errorLines
            }
    return $result
}
#endregion FetchJobResult

#region Install-SingleHost
function Install-SingleHost {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [string]$FlexToken,
        [Parameter(Mandatory=$true)]
        [string]$SqlConnectionString,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$SdpCredentials,
        [Parameter(Mandatory=$true)]
        [hashtable]$AuthMethod
    )

    InfoMessage "Starting installation on $ComputerName..."

    $IsDebug = $DebugPreference -eq 'Continue'
    $IsDryRun = $DryRun.IsPresent
    $ArgumentList = @(
        $Config.flex_host_ip,
        $FlexToken,
        $SqlConnectionString,
        $Config.agent,
        $Config.svss,
        $Config.sdpid,
        $SdpCredentials.UserName,
        $SdpCredentials.GetNetworkCredential().Password,
        $IsDebug,
        $IsDryRun,
        $Config.mount_points_directory
    )

    DebugMessage "Preparing to run installation script on $ComputerName"
    DebugMessage "Using Flex IP: $($Config.flex_host_ip)"
    DebugMessage "Using Flex Token: [REDACTED]"
    DebugMessage "Using SQL Connection String: [REDACTED]"
    DebugMessage "Using agent URL: $($Config.agent)"
    DebugMessage "Using VSS URL: $($Config.svss)"
    DebugMessage "Using SDP ID: $($Config.sdpid)"
    DebugMessage "Using SDP Username: $($SdpCredentials.UserName)"
    DebugMessage "Using SDP Password: [REDACTED]"
    DebugMessage "Debug Mode: $($IsDebug)"
    DebugMessage "Dry Run Mode: $($IsDryRun)"
    DebugMessage "Mount Points Directory: $($Config.mount_points_directory)"


    # Read the script content and convert it to a scriptblock
    $installScript = [ScriptBlock]::Create((Get-Content -Path $InstallScriptPath -Raw))

    # Create the remote scriptblock
    $scriptBlock = {
        param($FlexIP, $FlexToken, $DBConnectionString, $SilkAgentURL, $SilkVSSURL, $SDPId, $SDPUsername, $SDPPassword, $DebugMode, $DryRunMode, $MountPointsDirectory, $Script)

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
            SilkAgentURL = $SilkAgentURL
            SilkVSSURL = $SilkVSSURL
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
            Write-Error "Failed to execute setup-one-host.ps1: $_"
            throw
        }
    }

    # Add the script content to the argument list
    $ArgumentList += @($installScript.ToString())

    # Prepare invoke command parameters
    $invokeParams = @{
        ComputerName = $ComputerName
        AsJob = $true
        ScriptBlock = $scriptBlock
        ArgumentList = $ArgumentList
    }

    # Add credential parameter only if not using Kerberos
    if (-not $AuthMethod.UseKerberos) {
        if ($AuthMethod.Credential) {
            InfoMessage "Using provided credentials for remote connection to $ComputerName"
            $credential = $AuthMethod.Credential
        } else {
            $credential = $null
            InfoMessage "No credentials provided, will prompt for credentials on each host"
            while (-not $credential) {
                InfoMessage "Please enter credentials for remote host $ComputerName"
                $credential = Get-Credential -Message "Enter credentials for remote host $ComputerName"
            }
        }
        $invokeParams['Credential'] = $credential
    }

    $job = Invoke-Command @invokeParams
    return [PSCustomObject]@{
        ComputerName = $ComputerName
        Job = $job
    }
}
#endregion Install-SingleHost

#region main
function main {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$config
    )

    # Skip certificate check for Invoke-WebRequest,
    # this is needed for self-signed certificates of the Flex server
    SkipCertificateCheck

    # Get authentication preference and credentials if needed
    $AuthMethod = GetAuthenticationPreference

    # make SQL server authentication string
    $SqlConnectionString = PrepareSqlConnectionString -SqlConnectionString $config.sqlconnection
    if (-not $SqlConnectionString) {
        ErrorMessage "Failed to prepare SQL connection string. Cannot proceed with installation."
        return
    }

    # Login to Silk Flex and get the token
    $flexToken = LoginToFlex -FlexIP $config.flex_host_ip

    # get SDP floating IP and port from Flex

    $SDPInfo = GetSDPInfo -FlexIP $config.flex_host_ip -FlexToken $flexToken -SDPID $config.sdpid

    if (-not $SDPInfo) {
        ErrorMessage "Failed to get SDP info from Flex"
        return "Unable to retrieve SDP information from Flex server"
    }

    InfoMessage "SDP ID: $($SDPInfo.id), Version: $($SDPInfo.version), Floating IP: $($SDPInfo.mc_floating_ip), HTTPS Port: $($SDPInfo.mc_https_port)"

    # Get SDP credentials from user input
    $sdpCredentials = GetSDPCredentials -SDPFloatingIP $SDPInfo.mc_floating_ip -SDPHttpsPort $SDPInfo.mc_https_port
    if (-not $sdpCredentials) {
        ErrorMessage "No SDP credentials provided. Cannot proceed with installation."
        return
    }

    # Add hosts to TrustedHosts if needed
    $remoteComputers = $config.hosts

    $trustResult = AddHostsToTrustedHosts -Hosts $remoteComputers -AuthMethod $AuthMethod
    if (-not $trustResult) {
        ErrorMessage "Cannot proceed without adding hosts to TrustedHosts"
        return
    }

    InfoMessage "The following hosts will be configured:"
    for ($i = 0; $i -lt $remoteComputers.Count; $i++) {
        $remoteComputers[$i] = $remoteComputers[$i].Trim()
        InfoMessage "$($remoteComputers[$i])"
    }

    InfoMessage "Starting remote installation on $($remoteComputers.Count) hosts in batches of $MaxConcurrency..."
    try {
        $results = @()
        $totalHosts = $remoteComputers.Count
        $processedHosts = 0

        # Process hosts in chunks
        for ($batchStart = 0; $batchStart -lt $totalHosts; $batchStart += $MaxConcurrency) {
            $batchEnd = [Math]::Min($batchStart + $MaxConcurrency - 1, $totalHosts - 1)
            $currentBatch = $remoteComputers[$batchStart..$batchEnd]
            $batchNumber = [Math]::Floor($batchStart / $MaxConcurrency) + 1
            $totalBatches = [Math]::Ceiling($totalHosts / $MaxConcurrency)

            InfoMessage "Processing batch $batchNumber of $totalBatches (hosts $($batchStart + 1)-$($batchEnd + 1) of $totalHosts)..."

            # Start jobs for current batch
            $jobs = @()
            foreach ($computer in $currentBatch) {
                $jobInfo = Install-SingleHost -ComputerName $computer -Config $config -FlexToken $flexToken -SqlConnectionString $SqlConnectionString -SdpCredentials $sdpCredentials -Auth $AuthMethod
                $jobs += $jobInfo
            }

            InfoMessage "Installation jobs started for batch $batchNumber. Waiting for completion..."

            # Process each job in the current batch
            foreach ($jobInfo in $jobs) {
                $computerName = $jobInfo.ComputerName

                $job = $jobInfo.Job


                InfoMessage "Waiting for job completion on $computerName..."
                $job | Wait-Job | Out-Null

                # read job errors if any
                $jobErrors = $null
                Receive-Job -Job $job -Keep -ErrorVariable jobErrors


                $jobResult = $job.ChildJobs[0]

                # Fetch logs from the job result
                $result = FetchJobResult -ComputerName $computerName -jobResult $jobResult -JobState $job.State

                # add jobErrors to the result if any
                if ($jobErrors) {
                    $result.Error += $jobErrors | ForEach-Object { $_.ToString().Trim() }
                }

                $results += $result

                if ($result.JobState -eq 'Success') {
                    $script:NumOfSucessHosts++
                } else {
                    $script:NumOfFailedHosts++
                }
                # Clean up the job
                $job | Remove-Job
                $processedHosts++
            }

            InfoMessage "Batch $batchNumber completed. Progress: $processedHosts/$totalHosts hosts processed."
        }

        # Save detailed logs to a file
        $logPath = Join-Path $PSScriptRoot "installation_logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $logPath
        InfoMessage "Detailed logs saved to: $logPath"

        # Display summary
        InfoMessage "*************************************************"
        InfoMessage "Installation Summary:"
        InfoMessage "Total Hosts: $($remoteComputers.Count)"
        InfoMessage "Successful: $script:NumOfSucessHosts"

        if ($script:NumOfFailedHosts -gt 0) {
            ErrorMessage "Failed: $script:NumOfFailedHosts"
            foreach ($result in $results | Where-Object { $_.JobState -eq 'Failed' }) {
                ErrorMessage "    $($result.ComputerName)"
            }
            ErrorMessage "Installation failed on $script:NumOfFailedHosts host(s). Check the logs for details. $logPath"
        } else {
            InfoMessage "Installation completed successfully on all hosts."
        }
        InfoMessage "*************************************************"
    }
    catch {
        ErrorMessage "Error during remote installation: $_"
        return
    }
}

#region Start of the Execution

# get the configuration file path from the command line argument -ConfigPath
if (-Not $ConfigPath) {
    ErrorMessage "Configuration file path is required. Please provide it as an argument to the script using -ConfigPath parameter."
    InfoMessage "Usage: .\bulk-setup.ps1 -ConfigPath <path_to_config_file>"
    Exit 1
}

$config = ReadConfigFile -ConfigFile $ConfigPath
if (-Not $config) {
    ErrorMessage "Failed to read the configuration file. Please ensure it is a valid JSON file."
    Exit 1
}

$passedPreReqs = EnsureRequirements

if(!$passedPreReqs) {
	InfoMessage "PSVersion is - $($PSVersionTable.PSVersion.Major)"
	InfoMessage "PSEdition is - $($PSVersionTable.PSEdition)"
	WarningMessage "PowerShell version failed in the prerequisites,`nPlease read pre-requisites section in Silk guide.`nGood Bye!"
	ErrorMessage "`n`tPress any key to continue...";
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	return
} else {
    # clear the console
    #clear-host
}

# Local Variables for Summary
[string]$script:HostList      = ""
[int]$script:NumOfHosts       = 0
[int]$script:NumOfSucessHosts = 0
[int]$script:NumOfFailedHosts = 0

# Check if the user is running as administrator
$MessageCurrentObject = "Echo Installer"


InfoMessage "Silk Installer for Echo - v$($InstallerProduct)"
InfoMessage "PowerShell Version is - $($PSVersionTable.PSVersion.Major)"
InfoMessage "PowerShell Edition is - $($PSVersionTable.PSEdition)"

InfoMessage "Checking if the script is running with elevated privileges..."
if (-not (CheckAdminUserCrossPlatform)) {
    Write-Warning -Message "You must run this script as an administrator. Please re-run the script with elevated privileges."
    WarningMessage "The script is not running as administrator - switching to run as administrator and run again"
    Exit 1
}

if ($DryRun) {
    ImportantMessage "************************************************"
    ImportantMessage "DryRun mode is enabled. No changes will be made."

    Write-Debug "DryRun mode is enabled. No changes will be made."
    Write-Verbose "Verbose output is enabled."
    ImportantMessage "************************************************"

}

if ( $DebugPreference -eq 'Continue' ) {
    $safeConfig = @{
        agent = $config.agent
        svss = $config.svss
        hosts = $config.hosts
        flex_host_ip = $config.flex_host_ip
        sqlconnection = $config.sqlconnection -replace '(?<=password=)[^;]+', '***'
        sdpid = $config.sdpid
        }

    InfoMessage @"
Configuration is:
$($safeConfig | ConvertTo-Json -Depth 4)
"@
}
main $config

if ($DryRun) {
    ImportantMessage "DryRun mode is enabled. No changes were made."
}
