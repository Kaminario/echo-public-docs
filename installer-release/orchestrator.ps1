<#
.SYNOPSIS
    Silk Echo Installer PowerShell Script - Install Silk Echo on multiple remote hosts using PowerShell.

.DESCRIPTION
    This script installs Silk Echo on multiple remote Windows hosts using PowerShell remoting.
    It reads configuration from a JSON file and performs remote installation on specified hosts.

    The script requires PowerShell version 5 or higher and must be run with administrator privileges.
    It uses an external script 'orc_host_installer.ps1' to perform the actual installation on each host.

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

.PARAMETER CreateConfigTemplate
    Generate a config.json template file based on config-example.json structure.
    When this parameter is used, the script will only create the template file and exit.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath ".\config.json"

    Installs Silk Echo on hosts specified in the configuration file using default MaxConcurrency of 10.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 5

    Installs Silk Echo on hosts in batches of 5 at a time.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 5 -DryRun

    Performs a dry run validation on hosts in batches of 5 at a time without making any changes.

.EXAMPLE
    .\orchestrator.ps1 -ConfigPath "config.json" -Debug

    Runs the installation with debug output enabled.

.EXAMPLE
    Get-Help .\orchestrator.ps1 -Detailed

    Shows detailed help information for this script.

.EXAMPLE
    .\orchestrator.ps1 -CreateConfigTemplate

    Generates a config.json template file based on config-example.json structure.

.INPUTS
    JSON configuration file with the following structure like generated with parameter -CreateConfigTemplate

.OUTPUTS
    Installation logs and status messages.
    Detailed logs are saved to installation_logs_<timestamp>.json file.

.NOTES
    File Name      : orchestrator.ps1
    Author         : Ilya.Levin@Silk.US
    Organization   : Silk.us, Inc.
    Version        : 0.1.3
    Copyright      : (c) 2024 Silk.us, Inc.
    Host Types     : Valid for Windows environments

    Prerequisites:
    - PowerShell version 5 or higher
    - Administrator privileges
    - Network access to target hosts

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
    [Parameter(Mandatory=$false, HelpMessage="Full or relative path to the configuration file in JSON format")]
    [string]$ConfigPath,

    [Parameter(Mandatory=$false, HelpMessage="Number of hosts to install in parallel")]
    [int]$MaxConcurrency = 10,

    [Parameter(Mandatory=$false, HelpMessage="Perform dry run to validate connectivity before actual installation")]
    [switch]$DryRun,

    [Parameter(Mandatory=$false, HelpMessage="Generate a config.json template file and exit")]
    [switch]$CreateConfigTemplate
)

# Set error action preference to stop on any error
$ErrorActionPreference = "Stop"

# ConvertTo-SecureString should be available by default in PowerShell

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
#endregion

###########################################################################
# Load external scripts first
###########################################################################
# Constants
#region orc_constants.ps1
#region Constants
Set-Variable -Name InstallerProduct -Value "0.1.3" -Option AllScope -Scope Script
Set-Variable -Name MessageCurrentObject -Value "Silk Echo Installer" -Option AllScope -Scope Script

Set-Variable -Name ENUM_ACTIVE_DIRECTORY -Value "active_directory" -Option AllScope -Scope Script
Set-Variable -Name ENUM_CREDENTIALS -Value "credentials" -Option AllScope -Scope Script

# Installer URLs
Set-Variable -Name SilkAgentURL -Value 'https://storage.googleapis.com/silk-public-files/silk-agent-installer-latest.exe' -Option AllScope -Scope Script
Set-Variable -Name SilkVSSURL -Value 'https://storage.googleapis.com/silk-public-files/svss-install.exe' -Option AllScope -Scope Script

# Installer Script Artifacts Directory
$cacheDir = Join-Path $PSScriptRoot "SilkEchoInstallerArtifacts"
Set-Variable -Name SilkEchoInstallerCacheDir -Value $cacheDir -Option AllScope -Scope Script
# Marker
Set-Variable -Name HOSTSETUP_START_MARKER -Value ("MARKER: " + "HOST_INSTALLER_STARTS_HERE") -Option AllScope -Scope Script

# Development mode detection - true if orchestrator contains imports (. ./orc_*.ps1)
$orchestratorContent = Get-Content -Path $PSCommandPath -Raw -ErrorAction SilentlyContinue
$isDevelopmentMode = $orchestratorContent -match '\. \./orc_.*\.ps1'
Set-Variable -Name IsDevelopmentMode -Value $isDevelopmentMode -Option AllScope -Scope Script

Set-Variable -Name IsDomainUser -Value $false -Option AllScope -Scope Script
#endregion Constants

#endregion orc_constants.ps1

# ConvertSecureStringToPlainText
#region orc_common.ps1
#region Common Utility Functions


#region ensureCacheDir
function ensureCacheDir {
    param (
        [string]$CacheDir = $null
    )
    # Ensure the cache directory exists
    if (-not (Test-Path $CacheDir)) {
        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
        InfoMessage "Created installer cache directory: $CacheDir"
    }
}
#endregion ensureCacheDir


#region ConvertSecureStringToPlainText
function ConvertSecureStringToPlainText {
    param (
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$SecureString
    )

    if (-not $SecureString) {
        return $null
    }

    try {
        # Create a temporary PSCredential to extract the plain text password
        $tempCred = New-Object System.Management.Automation.PSCredential("temp", $SecureString)
        return $tempCred.GetNetworkCredential().Password
    } catch {
        Write-Error "Failed to convert SecureString to plain text: $_"
        return $null
    }
}
#endregion ConvertSecureStringToPlainText

#endregion Common Utility Functions

#endregion orc_common.ps1

# ErrorMessage, InfoMessage, ImportantMessage, DebugMessage, WarningMessage
#region orc_logging.ps1

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
    $ReductedText = $Text -replace '(?i)(?<=Password=)[^;]+', '[reducted]'

    # Replace the value of the $FlexToken variable with '[reducted]' only if it exists and is not empty
    if ($Global:FlexToken -and $Global:FlexToken.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:FlexToken), '[reducted]'
    }

    # Replace the value of the $SDPPassword variable with '[reducted]' only if it exists and is not empty
    if ($Global:SDPPassword -and $Global:SDPPassword.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:SDPPassword), '[reducted]'
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

Function ErrorMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [ERROR] - $msg" -ForegroundColor Red
    Write-Error "$(LogTimeStamp) - $($MessageCurrentObject) - [ERROR] - $msg" -ErrorAction Continue
}

Function ImportantMessage {
    $msg = ArgsToSanitizedString @args
    Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [INFO] - $msg" -ForegroundColor Green
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
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [WARN] - $msg" -ForegroundColor Yellow
}
#endregion Logging

#endregion orc_logging.ps1

# CallSelfCertEndpoint, CallSDPApi, CallFlexApi
#region orc_web_client.ps1
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
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
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
        [string]$SDPHost,
        [string]$SDPPort,
        [string]$ApiEndpoint,
        [System.Management.Automation.PSCredential]$Credential
    )

    $url = "https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"

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

#endregion orc_web_client.ps1

# UpdateFlexAuthToken
#region orc_flex_login.ps1
#region FlexLogin

#region getFlexCredentials
function getFlexCredentials {
    WarningMessage "Please provide Silk Flex credentials."
    $cred = Get-Credential -Message "Enter your Silk Flex credentials"
    if (-not $cred) {
        ErrorMessage "No credentials provided. Exiting."
        Exit 1
    }
    return $cred
}
#endregion getFlexCredentials

#region loginToFlex
function loginToFlex {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexIP,
        [string]$FlexUser,
        [string]$FlexPass
    )

    <#
        curl 'https://52.151.194.250/api/v1/auth/local/login' \
        -X POST \
        -H 'Accept: application/json' \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-raw 'password=*****&username=kaminario'
        response = {"access_token":"******","expiresIn":604800,"expiresOn":"2025-07-08 14:32:43"}
    #>

    # Use provided credentials or ask user for them
    if ($FlexUser -and $FlexPass) {
        $username = $FlexUser
        $password = $FlexPass
    } else {
        $cred = getFlexCredentials
        $username = $cred.UserName
        $password = $cred.GetNetworkCredential().Password
    }

    $body = @{
        username = $username
        password = $password
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
#endregion UpdateFlexAuthToken
function UpdateFlexAuthToken {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )

    # Use flex credentials from common section or prompt user

    $flexIP = $Config.common.flex_host_ip
    $flexUser = $Config.common.flex_user
    $flexPass = if ($Config.common.flex_pass) {
        ConvertSecureStringToPlainText -SecureString $Config.common.flex_pass
    } else {
        $null
    }

    # Get access token from Flex
    $flexToken = $null
    while (-not $flexToken) {
        $flexToken = loginToFlex -FlexIP $flexIP -FlexUser $flexUser -FlexPass $flexPass
        if (-not $flexToken) {
            InfoMessage "Please re-enter credentials."
            $flexUser = $null
            $flexPass = $null
        }
    }

    # Apply the access token to all hosts
    foreach ($hostInfo in $Config.hosts) {
        $hostInfo | Add-Member -MemberType NoteProperty -Name "flex_access_token" -Value $flexToken -Force
    }

    InfoMessage "Successfully obtained and assigned Flex token for $flexIP to $($Config.hosts.Count) host(s)"
    return $flexToken
}
#endregion UpdateFlexAuthToken

#endregion orc_flex_login.ps1

# SkipCertificateCheck
#region orc_no_verify_cert.ps1
#region SkipCertificateCheck
function SkipCertificateCheck {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
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

#endregion orc_no_verify_cert.ps1

# ReadConfigFile, GenerateConfigTemplate
#region orc_config.ps1
#region ConfigFile

function GenerateConfigTemplate {

    $useKerberos = Read-Host "Would you like to use Active Directory authentication for the hosts? (Y/n)"
    if ($useKerberos -eq 'Y' -or $useKerberos -eq 'y' -or $useKerberos -eq '') {
        $UseKerberos = $true
    } else {
        $UseKerberos = $false
    }

    $templateConfigJson = '{"installers":{"agent":{"path": "local_path"},"vss": {"path": "local_path"}},"common":{"sdp_id":"sdp_id","sdp_user":"sdp_user","sdp_pass":"sdp_pass","sql_user":"sql_user","sql_pass":"sql_pass","flex_host_ip":"flex-ip","flex_user":"flex_user","flex_pass":"flex_pass","host_user":"host_user","host_pass":"host_pass", "host_auth": "unset", "mount_points_directory":"E:\\MountPoints"},"hosts":[{"host_addr":"host_ip","sql_user":"sql_user_1","sql_pass":"sql_pass_1","mount_points_directory":"F:\\MountPoints"},"host_ip","host_ip"]}'

    # load template as json, make chages, and dump in a pretty way
    $ConfObj = $templateConfigJson | ConvertFrom-Json

    if ($UseKerberos) {
        $ConfObj.common.host_auth = $ENUM_ACTIVE_DIRECTORY
        if ($ConfObj.common.PSObject.Properties['host_user']) {
            $ConfObj.common.PSObject.Properties.Remove('host_pass')
        }
        if ($ConfObj.common.PSObject.Properties['host_user']) {
            $ConfObj.common.PSObject.Properties.Remove('host_user')
        }
        # update hosts with <hostname> instead of <host_ip>
        for ($i = 0; $i -lt $ConfObj.hosts.Count; $i++) {
            $hostEntry = $ConfObj.hosts[$i]
            if ($hostEntry -is [string]) {
                # Replace string with hostname
                $ConfObj.hosts[$i] = "hostname"
            } else {
                # It's an object, remove host_user and host_pass properties and update host
                if ($hostEntry.PSObject.Properties['host_user']) {
                    $hostEntry.PSObject.Properties.Remove('host_user')
                }
                if ($hostEntry.PSObject.Properties['host_pass']) {
                    $hostEntry.PSObject.Properties.Remove('host_pass')
                }

                $hostEntry.host_addr = "hostname"
            }
        }
    } else {
        $ConfObj.common.host_auth = $ENUM_CREDENTIALS
    }

    $configPath = Join-Path $PSScriptRoot "config.json"

    # Check if config.json already exists and ask for confirmation
    if (Test-Path -Path $configPath) {
        WarningMessage "Configuration file already exists: $configPath"
        $overwrite = Read-Host "Do you want to overwrite the existing config.json file? (y/N)"
        if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
            InfoMessage "Configuration template creation cancelled."
            Exit 0
        }
    }

    try {
        $formattedJson = $ConfObj | ConvertTo-Json -Depth 4

        $formattedJson | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "Configuration template created successfully: $configPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "Please edit the config.json file with your specific values." -ForegroundColor Yellow
        Write-Host "- Update SQL credentials and mount point directories as needed"
        Write-Host "- Add or remove hosts as required"
        Write-Host ""
    } catch {
        Write-Error "Failed to create configuration template: $_"
        Exit 1
    }
    Exit 0
}

function constructHosts {
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$CommonConfig,

        [Parameter(Mandatory=$true)]
        [Array]$HostEntries
    )

    # for each host in a list create an object that contains all common properties
    $processedHosts = @()
    foreach ($hostEntry in $HostEntries) {
        $hostObject = New-Object -TypeName PSObject

        # Add all common properties to the new object
        foreach ($property in $CommonConfig.PSObject.Properties) {
            Add-Member -InputObject $hostObject -MemberType NoteProperty -Name $property.Name -Value $property.Value
        }

        if ($hostEntry -is [string]) {
            # If the host is just a string (IP or hostname)
            Add-Member -InputObject $hostObject -MemberType NoteProperty -Name "host_addr" -Value $hostEntry -Force
        } elseif ($hostEntry -is [psobject]) {
            # If the host is an object with specific properties
            foreach ($property in $hostEntry.PSObject.Properties) {
                Add-Member -InputObject $hostObject -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force
            }
        }

        # convert host_pass to secure string
        if ($hostObject.host_pass) {
            $hostObject.host_pass = ConvertTo-SecureString $hostObject.host_pass -AsPlainText -Force
        }
        if ($hostObject.sql_pass) {
            $hostObject.sql_pass = ConvertTo-SecureString $hostObject.sql_pass -AsPlainText -Force
        }
        if ($hostObject.sdp_pass) {
            $hostObject.sdp_pass = ConvertTo-SecureString $hostObject.sdp_pass -AsPlainText -Force
        }
        if ($hostObject.flex_pass) {
            $hostObject.flex_pass = ConvertTo-SecureString $hostObject.flex_pass -AsPlainText -Force
        }

        $processedHosts += $hostObject
    }
    return $processedHosts
}

function ReadConfigFile {
    # read the configuration file passed as parameter to this scipt "-Config"
    # ConfigFile can be a full or relative path to the JSON file
    # {
    # "installers": {
    #     "agent": {
    #         "url": "<remote_url>",
    #         "path": "<local_path>"
    #     },
    #     "vss": {
    #         "url": "<remote_url>",
    #         "path": "<local_path>"
    #     }
    # },
    # "common": {
    #     "sdp_id": "<sdp_id>",
    #     "sdp_user": "<sdp_user>",
    #     "sdp_pass": "<sdp_pass>",
    #     "sql_user": "<sql_user>",
    #     "sql_pass": "<sql_pass>",
    #     "flex_host_ip": "10.8.71.100",
    #     "flex_user": "<flex_user>",
    #     "flex_pass": "<flex_pass>",
    #     "host_user": "<host_user>",
    #     "host_pass": "<host_pass>",
    #     "host_auth": "credentials",  // or "active_directory"
    #     "mount_points_directory": "E:\\MountPoints"
    # },
    # "hosts": [
    #     {
    #     "host_addr": "10.30.40.50",
    #     "sql_user": "<sql_user_1>",
    #     "sql_pass": "<sql_pass_1>",
    #     "mount_points_directory": "F:\\MountPoints"
    #     },
    #     "10.30.40.51",
    #     "10.30.40.52"
    #     ]
    # }

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

    # Get the common configuration
    $commonConfig = $config.common
    if (-not ($config.hosts -and
          $commonConfig.flex_host_ip -and
          $commonConfig.sdp_id -and
          $commonConfig.mount_points_directory -and
          $commonConfig.mount_points_directory -ne "")) {

        ErrorMessage "Configuration file must contain 'hosts', 'flex_host_ip', 'sdp_id', and 'mount_points_directory' fields"
        return $null
    }

    # Validate hosts array is not empty
    if ($config.hosts.Count -eq 0) {
        ErrorMessage "Configuration file must contain at least one host"
        return $null
    }

    # Validate flex_host_ip is a valid IP address
    if (-not ($commonConfig.flex_host_ip -as [IPAddress])) {
        ErrorMessage "flex_host_ip must be a valid IP address"
        return $null
    }

    $config.hosts = constructHosts -CommonConfig $commonConfig -HostEntries $config.hosts

    # convert all common.pass to ConvertTo-SecureString
    if ($commonConfig.sdp_pass) {
        $commonConfig.sdp_pass = ConvertTo-SecureString -String $commonConfig.sdp_pass -AsPlainText -Force
    }
    if ($commonConfig.sql_pass) {
        $commonConfig.sql_pass = ConvertTo-SecureString -String $commonConfig.sql_pass -AsPlainText -Force
    }
    if ($commonConfig.flex_pass) {
        $commonConfig.flex_pass = ConvertTo-SecureString -String $commonConfig.flex_pass -AsPlainText -Force
    }
    if ($commonConfig.host_pass) {
        $commonConfig.host_pass = ConvertTo-SecureString -String $commonConfig.host_pass -AsPlainText -Force
    }

    # Ensure installer configuration has default values
    ensureInstallerDefault -Config $config -InstallerName "agent" -DefaultUrl $SilkAgentURL
    ensureInstallerDefault -Config $config -InstallerName "vss" -DefaultUrl $SilkVSSURL

    # the sql connection script is optional.

    # Validate that all hosts have unique addresses
    $hostAddresses = @()
    foreach ($hostInfo in $config.hosts) {
        if ($hostAddresses -contains $hostInfo.host_addr) {
            ErrorMessage "Duplicate host address found: '$($hostInfo.host_addr)'. All hosts must have unique IP addresses or hostnames."
            return $null
        }
        $hostAddresses += $hostInfo.host_addr
    }

    # all host must have "host_auth" and "flex_host_ip"
    foreach ($hostInfo in $config.hosts) {
        if (-not $hostInfo.host_auth) {
            ErrorMessage "Host '$($hostInfo.host_addr)' is missing 'host_auth' property. Update the host or a common section."
            return $null
        }
        if (-not $hostInfo.flex_host_ip) {
            ErrorMessage "Host '$($hostInfo.host_addr)' is missing 'flex_host_ip' property. Update the host or a common section."
            return $null
        }
        # Validate flex_host_ip is a valid IP address
        if (-not ($hostInfo.flex_host_ip -as [IPAddress])) {
            ErrorMessage "Host '$($hostInfo.host_addr)' has invalid flex_host_ip '$($hostInfo.flex_host_ip)'. Must be a valid IP address."
            return $null
        }
    }

    return $config
}

#region ensureInstallerDefault
function ensureInstallerDefault {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [string]$InstallerName,
        [Parameter(Mandatory=$true)]
        [string]$DefaultUrl
    )

    try {
        $url = $Config.installers.$InstallerName.url
        if (-not $url) { throw }
    } catch {
        InfoMessage "$InstallerName installer URL missing. Using default: $DefaultUrl"
        if (-not $Config.installers) { $Config | Add-Member -NotePropertyName "installers" -NotePropertyValue @{} -Force }
        if (-not $Config.installers.$InstallerName) { $Config.installers | Add-Member -NotePropertyName $InstallerName -NotePropertyValue @{} -Force }
        $Config.installers.$InstallerName | Add-Member -NotePropertyName "url" -NotePropertyValue $DefaultUrl -Force
    }
}

#endregion ensureInstallerDefault

#endregion ConfigFile

#endregion orc_config.ps1

# EnsureRequirements
#region orc_requirements.ps1

#region checkAdminPrivileges
function checkAdminPrivileges {
    # CheckAdminPrivileges Function - Checking the current user in Windows and Linux environment. You must run as administrator (Windows)
    if(!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))	{
        return $false
    } else {
        DebugMessage "Running as an Administrator, on Windows OS version - $((Get-CimInstance Win32_OperatingSystem).version)"
	    return $true
    }
}
#endregion checkAdminPrivileges

#region EnsureRequirements
function EnsureRequirements {
    $PSVersion = $PSVersionTable.PSVersion.Major
    $ShellEdition = $PSVersionTable.PSEdition
    $passedPreReqs = $true

    # Check if running on Linux platform - not supported for this Windows-based installation
    if ($PSVersionTable.Platform -eq "Unix") {
        ErrorMessage "This installer is designed for Windows environments only."
        ErrorMessage "PowerShell remoting to Windows hosts from Linux is not supported by this script."
        ErrorMessage "Please run this script from a Windows machine with PowerShell 5.1 or 7.x."
        passedPreReqs = $false
    }

    if ($PSVersion -lt 5) {
        WarningMessage "PowerShell version is $PSVersion, but version 5 or higher is required."
        $passedPreReqs = $false
    }
    if ($ShellEdition -ne "Core" -and $ShellEdition -ne "Desktop") {
        WarningMessage "PowerShell edition is $ShellEdition, but only Core or Desktop editions are supported."
        $passedPreReqs = $false
    }

    InfoMessage "Checking if the script is running with elevated privileges..."
    if (-not (CheckAdminPrivileges)) {
        WarningMessage "The script is not running with elevated privileges. Please run the script as an administrator."
        $passedPreReqs = $false
    }

    # Host installer script is now extracted dynamically by GetHostInstallScript function
    DebugMessage "Host installer will be extracted dynamically from orchestrator content."

    return $passedPreReqs
}
#endregion

#endregion orc_requirements.ps1

# UpdateHostSqlConnectionString
#region orc_mssql.ps1
#region SQL

#region getSqlCredentials
function getSqlCredentials {
    param (
        [string]$Username,
        [string]$Password
    )
    # Check if user id is set, and ask for credentials if not
    while (-not $Username -or -not $Password) {
        WarningMessage "Please provide SQL credentials for the connection string."
        $cred = Get-Credential -Message "Enter your SQL Server credentials"
        if ($cred) {
            return $cred
        } else {
            ErrorMessage "No credentials provided. Cannot proceed without valid SQL Server credentials."
        }
    }
}
#endregion getSqlCredentials

#region PrepSQLStr
function UpdateHostSqlConnectionString {
    param (
        [PSCustomObject]$Config
    )

    # each host in $config.hosts can contain "sql_user", and "sql_pass"
    # if missing ask for credentials and use it for all hosts without credentials
    # create a connectrion string for each host and update $config.hosts with "sql_connection_string"
    DebugMessage "Checking SQL credentials for each host..."

    $defaultSqlUser = $null
    $defaultSqlPass = $null
    $commonCredentialsNeeded = $false

    # Check if any hosts are missing SQL credentials
    foreach ($hostInfo in $Config.hosts) {
        if (-not $hostInfo.sql_user -or -not $hostInfo.sql_pass) {
            $commonCredentialsNeeded = $true
            break
        }
    }

    DebugMessage "Common SQL credentials needed: $commonCredentialsNeeded"
    # If any hosts are missing credentials, ask for default credentials to use
    if ($commonCredentialsNeeded) {
        $commonSqlPass = if ($Config.common.sql_pass) {
            ConvertSecureStringToPlainText -SecureString $Config.common.sql_pass
        } else {
            $null
        }
        $credSQL = getSqlCredentials -Username $Config.common.sql_user -Password $commonSqlPass
        if ($credSQL) {
            $defaultSqlUser = $credSQL.UserName
            $defaultSqlPass = $credSQL.GetNetworkCredential().Password
        } else {
            ErrorMessage "Failed to get SQL credentials"
            return $false
        }
         # Create connection string for each host
        foreach ($hostInfo in $Config.hosts) {
            # Use host-specific credentials if available, otherwise use default
            if (-not $hostInfo.sql_user) {
                Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "sql_user" -Value $defaultSqlUser -Force
            }
            if (-not $hostInfo.sql_pass) {
                Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "sql_pass" -Value $defaultSqlPass -Force
            }
        }
    }

    foreach ($hostInfo in $Config.hosts) {
        # Build connection string parameters
        $hostSqlPass = if ($hostInfo.sql_pass -is [System.Security.SecureString]) {
            DebugMessage "Retrieving SQL password for host $($hostInfo.host_addr)"
            ConvertSecureStringToPlainText -SecureString $hostInfo.sql_pass
        } else {
            $hostInfo.sql_pass
        }
        $connectionParams = @{
            'User ID' = $hostInfo.sql_user
            'Password' = $hostSqlPass
            'Application Name' = 'SilkAgent'
        }

        # Build the connection string
        $connectionStringParts = $connectionParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)

        # Add connection string to host object
        $hostInfo | Add-Member -MemberType NoteProperty -Name "sql_connection_string" -Value $connectionString -Force

        # Log the connection string (with masked password)
        $LogSqlConnectionString = Sanitize $connectionString
        DebugMessage "Prepared SQL connection string for host $($hostInfo.host_addr): $LogSqlConnectionString"
    }

    ImportantMessage "Successfully prepared SQL connection strings for all hosts"
    return $true
}
#endregion PrepSQLStr

#endregion SQL

#endregion orc_mssql.ps1

# UpdateSDPCredentials, GetSDPInfo
#region orc_sdp.ps1
#region SDP

#region validateSDPConnection
function validateSDPConnection {
    param (
        [string]$SDPHost,
        [string]$SDPPort,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ApiEndpoint = 'system/state'

    DebugMessage "validateSDPConnection USERNAME: $($Credential.UserName)"
    $response = CallSDPApi -SDPHost $SDPHost -SDPPort $SDPPort -ApiEndpoint $ApiEndpoint -Credential $Credential
    if (-not $response) {
        ErrorMessage "Failed to call SDP API at https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"
        return $false
    }
    return $true
}
#endregion validateSDPConnection

#region getSDPCredentials
function getSDPCredentials {
    param (
        [PSCustomObject]$HostInfo,
        [string]$SDPHost,
        [string]$SDPPort
    )

    # Use SDP credentials from common section or prompt user
    $sdp_id = $HostInfo.sdp_id
    $sdpUser = if ($HostInfo.sdp_user) { $HostInfo.sdp_user } else { $null }
    $sdpPass = if ($HostInfo.sdp_pass) { $HostInfo.sdp_pass } else { $null }

    # Get validated SDP credentials
    $SDPCredential = $null
    $SdpConnectionValid = $false

    while (-not $SdpConnectionValid) {
        # Try with provided credentials first, then prompt if needed
        if ($sdpUser -and $sdpPass) {
            $SDPCredential = New-Object System.Management.Automation.PSCredential($sdpUser, $sdpPass)
        } else {
            WarningMessage "Please provide SDP (Silk Data Platform) credentials for the installation"
            $SDPCredential = Get-Credential -Message "Enter your SDP credentials"
            if (-not $SDPCredential) {
                Continue
            }
        }
        $SdpConnectionValid = validateSDPConnection -SDPHost $SDPHost -SDPPort $SDPPort -Credential $SDPCredential
        if (-not $SdpConnectionValid) {
            ErrorMessage "Failed to validate SDP connection. Please check your credentials and try again."
            # Reset credentials to force prompt on next iteration
            $sdpUser = $null
            $sdpPass = $null
        }
    }

    InfoMessage "SDP credentials retrieved successfully."
    return $SDPCredential

}
#endregion getSDPCredentials

#region UpdateSDPCredentials
function UpdateSDPCredentials {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        [Parameter(Mandatory=$true)]
        [string]$flexToken
    )

    # get all different SDPId from hosts
    $SDPIDs = $Config.hosts | ForEach-Object { $_.sdp_id } | Sort-Object -Unique

    # get sdpInfo for each SDPId (floating IP and port from Flex)
    $SDPInfo = @{}
    foreach ($SDPID in $SDPIDs) {
        $sdp = GetSDPInfo -FlexIP $config.common.flex_host_ip -FlexToken $flexToken -SDPID $SDPID
        if (-not $sdp) {
            ErrorMessage "Failed to get SDP info for SDP ID $SDPID from Flex. Unable to continue."
            Exit 1
        }
        $SDPInfo[$SDPID] = $sdp
        InfoMessage "SDP ID: $($sdp.id), Version: $($sdp.version), Floating IP: $($sdp.mc_floating_ip), HTTPS Port: $($sdp.mc_https_port)"
    }

    foreach ($hostInfo in $Config.hosts) {
        $hostInfo | Add-Member -MemberType NoteProperty -Name "sdp_credential" -Value $null -Force
        if ($SDPInfo[$hostInfo.sdp_id].credentials -eq $null) {
            # we already veryfied user and pass for that sdp
            $SDPCredential = getSDPCredentials -HostInfo $hostInfo -SDPHost $SDPInfo[$hostInfo.sdp_id].mc_floating_ip -SDPPort $SDPInfo[$hostInfo.sdp_id].mc_https_port
            if (-not $SDPCredential) {
                ErrorMessage "Failed to get SDP credentials for host $($hostInfo.name)."
                Exit 1
            }
            $SDPInfo[$hostInfo.sdp_id].credentials = $SDPCredential
        }
        Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "sdp_credential" -Value $SDPInfo[$hostInfo.sdp_id].credentials -Force
    }

}
#endregion UpdateSDPCredentials

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

#endregion SDP

#endregion orc_sdp.ps1

# EnsureLocalInstallers, UploadInstallersToHosts
#region orc_uploader.ps1
#region InstallerUploader

#region EnsureLocalInstallers
function EnsureLocalInstallers {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    # Ensure installers present in local directory

    $localPaths = @{}
    $requiredInstallers = @('agent', 'vss')

    # Process all required installers
    foreach ($installerType in $requiredInstallers) {
        $installerConfig = $Config.installers.$installerType
        if (-not $installerConfig) {
            ErrorMessage "Missing required $installerType installer configuration in config.installers"
            return $null
        }

        # If path is provided and file exists, use it directly
        if ($InstallerConfig.path) {
            if (Test-Path $InstallerConfig.path) {
                InfoMessage "Using existing $InstallerType installer at: $($InstallerConfig.path)"
                $installerPath = $InstallerConfig.path
            } else {
                # If path is provided but doesn't exist
                ErrorMessage "$InstallerType installer path specified but file not found: $($InstallerConfig.path)"
                return $null
            }
        } else {
            if (-not $InstallerConfig.url) {
                ErrorMessage "No URL specified for $InstallerType installer in configuration"
                return $null
            }
            $installerPath = downloadInstaller -InstallerURL $InstallerConfig.url -CacheDir $SilkEchoInstallerCacheDir -InstallerType $installerType
        }

        if ($installerPath) {
            $localPaths[$installerType] = $installerPath
        } else {
            ErrorMessage "Failed to ensure $installerType installer is available locally"
            return $null
        }
    }

    InfoMessage "All installers are available locally"
    return $localPaths
}
#endregion EnsureLocalInstallers

#region downloadInstaller
function downloadInstaller {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InstallerURL,
        [Parameter(Mandatory=$true)]
        [string]$CacheDir,
        [Parameter(Mandatory=$true)]
        [string]$InstallerType
    )


    if (-not $InstallerURL) {
        ErrorMessage "No URL specified for $InstallerType installer in configuration"
        return $null
    }

    # If URL is provided, download to cache

    $fileName = "$InstallerType-installer.exe"
    $localPath = Join-Path $CacheDir $fileName

    # Check if already cached
    if (Test-Path $localPath) {
        InfoMessage "$InstallerType installer already cached at: $localPath"
        return $localPath
    }

    InfoMessage "Downloading $InstallerType installer from: $($InstallerURL)"
    try {
        ensureCacheDir $CacheDir
        # Use Invoke-WebRequest to download the file
        Invoke-WebRequest -Uri $InstallerURL -OutFile $localPath -UseBasicParsing

        if (Test-Path $localPath) {
            $fileSize = (Get-Item $localPath).Length
            InfoMessage "Downloaded $InstallerType installer ($fileSize bytes) to: $localPath"
            return $localPath
        } else {
            ErrorMessage "Download completed but file not found at: $localPath"
        }
    } catch {
        ErrorMessage "Failed to download $InstallerType installer: $_"
    }
    return $null
}
#endregion downloadInstaller

#region UploadInstallersToHosts
function UploadInstallersToHosts {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$HostInfos,
        [Parameter(Mandatory=$true)]
        [hashtable]$LocalPaths,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )

    InfoMessage "Starting parallel upload of installers to $($HostInfos.Count) host(s) with max concurrency: $MaxConcurrency..."

    # Start upload jobs for all hosts
    $jobs = @()
    $batchCount = 0

    foreach ($hostInfo in $HostInfos) {
        # Wait if we've reached max concurrency
        while ($jobs.Count -ge $MaxConcurrency) {
            $completedJob = $jobs | Where-Object { $_.Job.State -ne 'Running' } | Select-Object -First 1
            if ($completedJob) {
                $processJobResult = processUploadJobResult -JobInfo $completedJob
                $jobs = @($jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id })
                if (-not $processJobResult) {
                    # Clean up remaining jobs and return failure
                    $jobs | ForEach-Object { Remove-Job $_.Job -Force }
                    return $false
                }
            } else {
                Start-Sleep -Milliseconds 100
            }
        }

        # Start new job
        InfoMessage "Starting upload job for host: $($HostInfo.host_addr)"
        $job = Start-Job -ScriptBlock {
            param($HostInfo, $LocalPaths, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS)

            function DebugMessage { param($message) Write-Host "[DEBUG] $message" -ForegroundColor Gray }
            function InfoMessage { param($message) Write-Host "[INFO] $message" -ForegroundColor Green }
            function ErrorMessage { param($message) Write-Host "[ERROR] $message" -ForegroundColor Red }

            # Simplified inline version of copyInstallersToHost
            $remoteRelDir = "Temp\silk-echo-install-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $remoteDir = "C:\$remoteRelDir"
            $remotePaths = @{}

            try {
                # Create remote directory
                $scriptBlock = {
                    param($RemoteDir)
                    if (-not (Test-Path $RemoteDir)) {
                        New-Item -ItemType Directory -Path $RemoteDir -Force | Out-Null
                        Write-Output "Created remote directory: $RemoteDir"
                    }
                    return $RemoteDir
                }

                if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                    $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ArgumentList $remoteDir -ErrorAction Stop
                } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                    $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ArgumentList $remoteDir -ErrorAction Stop
                }

                DebugMessage "Remote directory prepared on $($HostInfo.host_addr): $remoteDir"

                # Copy each installer file
                foreach ($installerType in $LocalPaths.Keys) {
                    $localPath = $LocalPaths[$installerType]
                    $fileName = Split-Path $localPath -Leaf



                    DebugMessage "Copying $installerType installer to $($HostInfo.host_addr)..."
                    $remotePath = "$remoteDir\$fileName"

                    if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                        $remotePathUnc = "\\$($HostInfo.host_addr)\C$\$remoteRelDir\$fileName"
                        Copy-Item -Path $localPath -Destination $remotePathUnc -Force -ErrorAction Stop
                    } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {

                        $session = New-PSSession -ComputerName $HostInfo.host_addr -Credential $credential -SessionOption $sessionOption -ErrorAction Stop
                        Copy-Item -Path $localPath -Destination $remotePath -ToSession $session -Force -ErrorAction Stop
                        Remove-PSSession $session -ErrorAction SilentlyContinue
                    }
                    $remotePaths[$installerType] = $remotePath
                    DebugMessage "Copied $installerType installer to: $remotePath"
                }

                InfoMessage "All installers uploaded to $($HostInfo.host_addr)"
                return $remotePaths

            } catch {
                ErrorMessage "Failed to upload installers to $($HostInfo.host_addr): $_"
                return $null
            }
        } -ArgumentList $hostInfo, $LocalPaths, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS

        $jobs += @{
            Job = $job
            HostInfo = $hostInfo
        }

        $batchCount++
        if ($batchCount % $MaxConcurrency -eq 0) {
            InfoMessage "Started upload jobs for $batchCount hosts..."
        }
    }

    # Wait for remaining jobs to complete
    InfoMessage "Waiting for remaining upload jobs to complete..."
    while ($jobs.Count -gt 0) {
        $completedJob = $jobs | Where-Object { $_.Job.State -ne 'Running' } | Select-Object -First 1
        if ($completedJob) {
            $processJobResult = processUploadJobResult -JobInfo $completedJob
            $jobs = @($jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id })
            if (-not $processJobResult) {
                # Clean up remaining jobs and return failure
                $jobs | ForEach-Object { Remove-Job $_.Job -Force }
                return $false
            }
        } else {
            Start-Sleep -Milliseconds 100
        }
    }

    InfoMessage "Completed uploading installers to all hosts successfully"
    return $true
}

function processUploadJobResult {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$JobInfo
    )

    $job = $JobInfo.Job
    $hostInfo = $JobInfo.HostInfo

    if ($job.State -eq 'Completed') {
        $remoteInstallerPaths = Receive-Job -Job $job
        if ($remoteInstallerPaths) {
            # Store remote paths in host object for use by InstallSingleHost
            $hostInfo | Add-Member -MemberType NoteProperty -Name "remote_installer_paths" -Value $remoteInstallerPaths -Force
            InfoMessage "Successfully uploaded installers to $($hostInfo.host_addr)"
            Remove-Job -Job $job -Force
            return $true
        } else {
            ErrorMessage "Failed to upload installers to $($hostInfo.host_addr)"
            Remove-Job -Job $job -Force
            return $false
        }
    } else {
        $errorMsg = if ($job.State -eq 'Failed') {
            Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
        } else {
            "Job timed out or failed"
        }
        ErrorMessage "Upload job failed for $($hostInfo.host_addr): $errorMsg"
        Remove-Job -Job $job -Force
        return $false
    }
}
#endregion UploadInstallersToHosts


#endregion InstallerUploader

#endregion orc_uploader.ps1

# InstallSingleHost, FetchJobResult, ProcessSingleJobResult
#region orc_invoke_remote_install.ps1
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
        [string]$computerName,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$jobResult,
        [string]$JobState
    )
    # Initialize arrays for different output types
    InfoMessage "Fetching job result for $computerName with state $JobState"
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
                ComputerName = $computerName
                JobState = $JState
                Info = $outputLines
                Error = $errorLines
            }
    InfoMessage "Job result for $computerName`: $($result.JobState)"
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

    $ComputerName = $HostInfo.host_addr
    InfoMessage "Starting installation on $ComputerName..."

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

    DebugMessage "Preparing to run installation script on $ComputerName"
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
        ComputerName = $ComputerName
        AsJob = $true
        ScriptBlock = $scriptBlock
        ArgumentList = $ArgumentList
    }

    # Add credential parameter only if not using Kerberos
    if ($HostInfo.host_auth -ne $ENUM_ACTIVE_DIRECTORY) {
        $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
        $invokeParams['Credential'] = $credential
    }
    InfoMessage "Invoking installation script on $ComputerName..."
    $job = Invoke-Command @invokeParams
    InfoMessage "Installation script invoked on $ComputerName, job ID: $($job.Id)"
    return [PSCustomObject]@{
        ComputerName = $ComputerName
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

    $computerName = $JobInfo.ComputerName
    $job = $JobInfo.Job

    InfoMessage "Waiting for job completion on $computerName..."
    try {
        $job | Wait-Job | Out-Null
        InfoMessage "Job completed on $computerName."
    } catch {
        WarningMessage "Error while waiting for job completion on $computerName`: $_"
    }

    # read job errors if any - wrap in try-catch to prevent script termination
    $jobErrors = $null
    try {
        Receive-Job -Job $job -Keep -ErrorVariable jobErrors -ErrorAction SilentlyContinue
        DebugMessage "Job state for $computerName`: $($job.State)"
    } catch {
        WarningMessage "Error while receiving job output from $computerName`: $_"
        $jobErrors = @($_.Exception.Message)
    }

    $jobResult = $null
    try {
        $jobResult = $job.ChildJobs[0]
    } catch {
        WarningMessage "Error accessing child job for $computerName`: $_"
    }

    # Fetch logs from the job result - wrap in try-catch
    try {
        $result = FetchJobResult -ComputerName $computerName -jobResult $jobResult -JobState $job.State
    } catch {
        WarningMessage "Error fetching job result for $computerName`: $_"
        # Create a fallback result object
        $result = [PSCustomObject]@{
            ComputerName = $computerName
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
        DebugMessage "Cleaned up job for $computerName"
    } catch {
        WarningMessage "Error cleaning up job for $computerName`: $_"
    }

    return $result
}
#endregion ProcessSingleJobResult

#endregion orc_invoke_remote_install.ps1

# EnsureHostsConnectivity
#region orc_host_communication.ps1
#region addHostsToTrustedHosts
function addHostsToTrustedHosts {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )

    $hostsToAdd = @()
    foreach ($hostInfo in $hostEntries){
        $hostsToAdd += $hostInfo.host_addr
    }

    if($hostsToAdd.Count -eq 0){
        DebugMessage "No hosts to add to TrustedHosts list."
        return
    }

    $currentTrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts
    $newHosts = @($hostsToAdd | Where-Object { $_ -notin $currentTrustedHosts.Value.Split(',') })

    if ($newHosts.Count -eq 0) {
        InfoMessage "All hosts are already in TrustedHosts list"
        return
    } else {
        InfoMessage "Not all hosts are in TrustedHosts list."
        InfoMessage "The following hosts will be added to TrustedHosts:"
        foreach ($hostAddr in $newHosts) {
            InfoMessage "$hostAddr"
        }
    }

    # ask user if they want to add hosts to TrustedHosts or process without it
    $confirmation = Read-Host "Do you want to add these hosts to TrustedHosts? (Y/n)"
    if ($confirmation -eq 'N' -or $confirmation -eq 'n') {
        InfoMessage "User declined to add hosts to TrustedHosts. Unable to proceed with installation."
        Exit 1
    }

    $hostsToAddString = $newHosts -join ','
    InfoMessage "The following hosts need to be added to TrustedHosts:"
    InfoMessage $hostsToAddString

    if ($currentTrustedHosts.Value) {
        $newValue = "$($currentTrustedHosts.Value),$hostsToAddString"
    } else {
        $newValue = $hostsToAddString
    }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newValue -Force
    InfoMessage "Successfully added hosts to TrustedHosts"
}
#endregion addHostsToTrustedHosts

#region ensureHostCredentials
function ensureHostCredentials {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )

    # Check if any hosts with credentials auth are missing username or password
    $missingCredHosts = @($hostEntries | Where-Object {
        $_.host_auth -eq $ENUM_CREDENTIALS -and (-not $_.host_user -or -not $_.host_pass)
    })

    # return if no missing
    if ($missingCredHosts.Count -eq 0) {
        return
    }

    ImportantMessage "Missing credentials detected for some hosts with credentials authentication."
    ImportantMessage "The provided username and password will be used for all hosts with missing credentials:"

    foreach ($hostInfo in $missingCredHosts) {
        ImportantMessage "$($hostInfo.host_addr)"
    }

    $cred = Get-Credential -Message "Enter Host's username and password"
    if (-not $cred) {
        ErrorMessage "No credentials provided. Cannot proceed without valid credentials for all hosts."
        Exit 1
    }

    foreach ($hostInfo in $missingCredHosts) {
        if (-not $hostInfo.host_user) {
            Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "host_user" -Value $cred.UserName -Force
        }
        if (-not $hostInfo.host_pass) {
            Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "host_pass" -Value $cred.GetNetworkCredential().Password -Force
        }
    }

    # convert all hosts with auth credentials to secured credentials
    foreach ($hostInfo in $hostEntries) {
        if ($hostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Only convert if it's not already a SecureString
            if ($hostInfo.host_pass -is [string]) {
                $hostInfo.host_pass = ConvertTo-SecureString $hostInfo.host_pass -AsPlainText -Force
            }
        }
    }
}
#endregion ensureHostCredentials

#region resolveIPToHostname
function resolveIPToHostname {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    try {
        $hostname = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        if ($hostname -and $hostname -ne $IPAddress) {
            InfoMessage "Resolved IP $IPAddress to hostname: $hostname"
            return $hostname
        }
    } catch {
        DebugMessage "Failed to resolve IP $IPAddress to hostname: $_"
    }
    
    return $null
}
#endregion resolveIPToHostname

#region isActiveDirectoryUser
function isActiveDirectoryUser {
    # Check if the current user is logged in to Active Directory
    try {
        # Try multiple methods for cross-version compatibility
        $isDomainUser = $false

        # Method 1: Check environment variables (works in both PS 5.1 and 7)
        $userDomain = $env:USERDOMAIN
        $computerName = $env:COMPUTERNAME
        if ($userDomain -and $userDomain -ne $computerName) {
            $isDomainUser = $true
        }

        # Method 2: Try .NET method
        if (-not $isDomainUser) {
            try {
                $adUser = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                if ($adUser) {
                    $isDomainUser = $true
                }
            } catch {
                # Ignore errors, continue with other methods
            }
        }

        # Method 3: Check using WMI/CIM
        if (-not $isDomainUser) {
            try {
                if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                } else {
                    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
                }
                if ($computerSystem -and $computerSystem.PartOfDomain) {
                    $isDomainUser = $true
                }
            } catch {
                # Ignore errors
            }
        }

        if ($isDomainUser) {
            InfoMessage "Current user is logged in to Active Directory domain: $userDomain"
            return $true
        } else {
            InfoMessage "Current user is not logged in to Active Directory."
            return $false
        }
    } catch {
        DebugMessage "Failed to check Active Directory login status: $_"
        return $false
    }
}
#endregion isActiveDirectoryUser

#region isHostConnectivityValid
function isHostConnectivityValid {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$HostInfo
    )
    # Execute simple command on the host using defined authentication
    try {
        $scriptBlock = {
            try {
                Get-Date
            } catch {
                "ERROR: $($_.Exception.Message)"
            }
        }

        if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
            # Use current credentials for Active Directory authentication
            InfoMessage "Testing connectivity to $($HostInfo.host_addr) using $ENUM_ACTIVE_DIRECTORY authentication..."
            $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ErrorAction Stop
        } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Create credential object for explicit authentication
            $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)

            # Use session options for better compatibility
            $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            InfoMessage "Testing connectivity to $($HostInfo.host_addr) using $ENUM_CREDENTIALS authentication..."
            $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ErrorAction Stop
        } else {
            return $false
        }
        InfoMessage "Successfully connected to $($HostInfo.host_addr) with result: $result"
        # Check if result indicates an error
        if ($result -and $result.ToString().StartsWith("ERROR:")) {
            return $false
        }

        return $true
    } catch {
        return $false
    }
}
#endregion isHostConnectivityValid

#region EnsureHostsConnectivity
function EnsureHostsConnectivity {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )

    # Reset host_connectivity_issue to "not validated" before start processing
    foreach ($hostInfo in $hostEntries) {
        $hostInfo | Add-Member -NotePropertyName "host_connectivity_issue" -NotePropertyValue "not validated" -Force
    }

    # Fulfill credentials for hosts
    ensureHostCredentials -hostEntries $hostEntries

    # Check that all hosts have proper host_auth values
    foreach ($hostInfo in $hostEntries) {
        if ($hostInfo.host_auth -ne $ENUM_ACTIVE_DIRECTORY -and $hostInfo.host_auth -ne $ENUM_CREDENTIALS) {
            $hostInfo.host_connectivity_issue = "Invalid host_auth value. Must be '$ENUM_ACTIVE_DIRECTORY' or '$ENUM_CREDENTIALS'"
            continue
        }
    }

    # Handle active_directory authentication
    $adHosts = @($hostEntries | Where-Object { $_.host_auth -eq $ENUM_ACTIVE_DIRECTORY })
    if ($adHosts.Count -gt 0) {
        # Ensure current user is domain user
        if (-not (isActiveDirectoryUser)) {
            foreach ($hostInfo in $adHosts) {
                $hostInfo.host_connectivity_issue = "Current user is not logged in to Active Directory"
            }
        } else {
            foreach ($hostInfo in $adHosts) {
                # Check if host is IP address and try to resolve to hostname
                if ($hostInfo.host_addr -as [IPAddress]) {
                    $resolvedHostname = resolveIPToHostname -IPAddress $hostInfo.host_addr
                    if ($resolvedHostname) {
                        # Update host_addr to use the resolved hostname
                        $hostInfo.host_addr = $resolvedHostname
                        InfoMessage "Using resolved hostname $resolvedHostname for Active Directory authentication"
                    } else {
                        $hostInfo.host_connectivity_issue = "Could not resolve IP $($hostInfo.host_addr) to hostname for $ENUM_ACTIVE_DIRECTORY auth"
                        continue
                    }
                }
                # Test connectivity
                if (isHostConnectivityValid -HostInfo $hostInfo) {
                    $hostInfo.host_connectivity_issue = ""
                } else {
                    $hostInfo.host_connectivity_issue = "Failed to connect to host using $ENUM_ACTIVE_DIRECTORY authentication"
                }
            }
        }
    }

    # Handle credentials authentication
    $credHosts = @($hostEntries | Where-Object { $_.host_auth -eq $ENUM_CREDENTIALS })
    if ($credHosts.Count -gt 0) {

        # validate all host entries has an IP addresses
        $isError = $false
        foreach ($hostInfo in $credHosts) {
            if (-not ($hostInfo.host_addr -as [IPAddress])) {
                $hostInfo.host_connectivity_issue = "Invalid host address '$($hostInfo.host_addr)'. Must be an IP address for $ENUM_CREDENTIALS authentication."
                $isError = $true
            }
        }
        if ($isError) {
            return $hostEntries | Where-Object { $_.host_connectivity_issue -ne ""  -and $_.host_connectivity_issue -ne "not validated" }
        }

        try{
            addHostsToTrustedHosts -hostEntries $credHosts
        } catch {
            # print exception mesage
            ErrorMessage "$_"
            ErrorMessage "Failed to add hosts to TrustedHosts. Cannot proceed with $ENUM_CREDENTIALS authentication."
            Exit 1
        }

        foreach ($hostInfo in $credHosts) {
            # Test connectivity
            if (isHostConnectivityValid -HostInfo $hostInfo) {
                $hostInfo.host_connectivity_issue = ""
            } else {
                $hostInfo.host_connectivity_issue = "Failed to connect to host using $ENUM_CREDENTIALS authentication"
            }
        }
    }

    $badHosts = @($hostEntries | Where-Object { $_.host_connectivity_issue -ne ""  -and $_.host_connectivity_issue -ne "not validated" })

    return $badHosts
}
#endregion EnsureHostsConnectivity

#endregion orc_host_communication.ps1

# GetHostInstallScript
#region orc_host_setup_extractor.ps1
#region GetHostInstallScript
function GetHostInstallScript {
    <#
    .SYNOPSIS
        Extracts the host installation script from the orchestrator.

    .DESCRIPTION
        This function reads the orchestrator script content and extracts the host installer
        portion after the HOSTSETUP_START_MARKER.

    .PARAMETER OrchestratorPath
        Path to the orchestrator script. If not specified, uses the script that called this function.

    .OUTPUTS
        String containing the host installation script content
    #>

    param (
        [Parameter(Mandatory=$true)]
        [string]$OrchestratorPath
    )

    try {
        DebugMessage "Extracting host installation script from orchestrator..."

        # Read the orchestrator script content
        $orchestratorContent = Get-Content -Path $OrchestratorPath -Raw

        # Extract content after the HOSTSETUP_START_MARKER
        $hostScriptContent = $orchestratorContent -split $HOSTSETUP_START_MARKER | Select-Object -Last 1
        $hostScriptContent = $hostScriptContent.Trim()

        if ([string]::IsNullOrWhiteSpace($hostScriptContent)) {
            ErrorMessage "Failed to extract host installer script content from orchestrator."
            return $null
        }

        DebugMessage "Host installation script extracted successfully."
        return $hostScriptContent
    }
    catch {
        ErrorMessage "Failed to extract host installation script: $_"
        return $null
    }
}
#endregion GetHostInstallScript

#endregion orc_host_setup_extractor.ps1

# ExpandImportsInline
#region orc_import_expander.ps1
#region ExpandImportsInline
function ExpandImportsInline {
    <#
    .SYNOPSIS
        Expands dot-sourced imports by replacing them with actual file content.

    .DESCRIPTION
        This function replaces dot-sourced imports (. ./orc_*.ps1) with actual file content.
        It processes imports up to 3 times to handle nested dependencies.
        This creates a self-contained script with all dependencies embedded inline.

    .PARAMETER ScriptContent
        The script content containing imports to process

    .OUTPUTS
        String containing the processed script content with imports replaced
    #>

    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptContent
    )

    try {
        DebugMessage "Expanding imports inline..."

        $processedContent = $ScriptContent

        # Process imports up to 3 times to handle nested dependencies
        for ($iteration = 1; $iteration -le 3; $iteration++) {
            DebugMessage "Expanding imports - iteration $iteration"

            # Find all orc_* files and replace the dot-sourcing lines with their content
            $orcFiles = Get-ChildItem -Path $PSScriptRoot -Filter "orc_*.ps1"
            $importsProcessed = 0

            foreach ($orcFile in $orcFiles) {
                $importPattern = ". ./$($orcFile.Name)"

                if ($processedContent.Contains($importPattern)) {
                    try {
                        $orcContent = Get-Content -Path $orcFile.FullName -Raw
                        $replacementContent = "#region $($orcFile.Name)`n$orcContent`n#endregion $($orcFile.Name)`n"

                        $processedContent = $processedContent.Replace($importPattern, $replacementContent)
                        $importsProcessed++

                        DebugMessage "Replaced import for $($orcFile.Name)"
                    }
                    catch {
                        WarningMessage "Failed to process import for $($orcFile.Name): $_"
                    }
                }
            }

            DebugMessage "Iteration $iteration completed. Processed $importsProcessed imports."

            # If no imports were processed in this iteration, we can break early
            if ($importsProcessed -eq 0) {
                DebugMessage "No more imports to process. Breaking early."
                break
            }
        }

        DebugMessage "Import expansion completed successfully."
        return $processedContent
    }
    catch {
        ErrorMessage "Failed to expand imports inline: $_"
        return $ScriptContent
    }
}
#endregion ExpandImportsInline

#endregion orc_import_expander.ps1


#region MainOrchestrator
function MainOrchestrator {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$config
    )

    # Skip certificate check for Invoke-WebRequest,
    # this is needed for self-signed certificates of the Flex server
    SkipCertificateCheck

    # Save detailed logs to a file in $SilkEchoInstallerCacheDir
    ensureCacheDir $SilkEchoInstallerCacheDir

    # Download and cache installer files locally (before asking for any credentials)
    InfoMessage "Ensuring installer files are available locally..."
    $localInstallerPaths = EnsureLocalInstallers -Config $config
    if (-not $localInstallerPaths) {
        ErrorMessage "Failed to ensure installer files are available. Cannot proceed with installation."
        return
    }

    $failedHosts = EnsureHostsConnectivity -hostEntries $config.hosts

    if ($failedHosts.Count -eq 0) {
        ImportantMessage "Hosts connectivity check succeeded."
    } else {
        # Log errors to stderr but continue execution
        Write-Error "Hosts connectivity check failed:" -ErrorAction Continue
        foreach ($hostInfo in $failedHosts) {
            Write-Error " - $($hostInfo.host_addr): $($hostInfo.host_connectivity_issue)" -ErrorAction Continue
        }
        return
    }

    # make SQL server authentication string
    $ok = UpdateHostSqlConnectionString -Config $config
    if (-not $ok) {
        ErrorMessage "Failed to prepare SQL connection string. Cannot proceed with installation."
        return
    }

    # Login to Silk Flex and get the token
    $flexToken = UpdateFlexAuthToken -Config $config

    # Get and validate SDP credentials
    UpdateSDPCredentials -Config $config -flexToken $flexToken

    # Add hosts to TrustedHosts if needed
    $remoteComputers = @($config.hosts)

    InfoMessage "The following hosts will be configured:"
    foreach ($hostInfo in $remoteComputers) {
        InfoMessage "    $($hostInfo.host_addr)"
    }

    # Upload installer files to all hosts
    InfoMessage "Uploading installer files to target hosts..."
    $uploadSuccess = UploadInstallersToHosts -HostInfos $remoteComputers -LocalPaths $localInstallerPaths -MaxConcurrency $MaxConcurrency
    if (-not $uploadSuccess) {
        ErrorMessage "Failed to upload installers to some hosts. Cannot proceed with installation."
        return
    }

    $HostSetupScript = GetHostInstallScript -OrchestratorPath $PSCommandPath

    # Process imports in development mode
    if ($IsDevelopmentMode) {
        InfoMessage "Development mode detected - expanding imports in host script..."
        $HostSetupScript = ExpandImportsInline -ScriptContent $HostSetupScript
        if ($HostSetupScript -eq $null) {
            ErrorMessage "Failed to expand imports in host script."
            return
        }
    }

    InfoMessage "Starting remote installation on $($remoteComputers.Count) hosts in batches of $MaxConcurrency..."
    try {
        $results = @()
        $totalHosts = $remoteComputers.Count
        $processedHosts = 0

        # Process hosts in chunks
        for ($batchStart = 0; $batchStart -lt $totalHosts; $batchStart += $MaxConcurrency) {
            $batchEnd = [Math]::Min($batchStart + $MaxConcurrency - 1, $totalHosts - 1)
            if ($batchStart -eq $batchEnd) {
                $currentBatch = @($remoteComputers[$batchStart])
            } else {
                $currentBatch = $remoteComputers[$batchStart..$batchEnd]
            }
            $batchNumber = [Math]::Floor($batchStart / $MaxConcurrency) + 1
            $totalBatches = [Math]::Ceiling($totalHosts / $MaxConcurrency)

            InfoMessage "Processing batch $batchNumber of $totalBatches (hosts $($batchStart + 1)-$($batchEnd + 1) of $totalHosts)..."

            # Start jobs for current batch
            $jobs = @()
            foreach ($hostInfo in $currentBatch) {
                $jobInfo = InstallSingleHost -HostInfo $hostInfo -Config $config -FlexToken $hostInfo.flex_access_token -SqlConnectionString $hostInfo.sql_connection_string -SdpCredentials $hostInfo.sdp_credential -HostSetupScript $HostSetupScript
                $jobs += $jobInfo
            }

            InfoMessage "Installation jobs started for batch $batchNumber. Waiting for completion..."

            # Process each job in the current batch
            foreach ($jobInfo in $jobs) {
                $result = ProcessSingleJobResult -JobInfo $jobInfo
                $results += $result

                if ($result.JobState -eq 'Success') {
                    $script:NumOfSuccessHosts++
                } else {
                    $script:NumOfFailedHosts++
                }
                $processedHosts++
            }

            InfoMessage "Batch $batchNumber completed. Progress: $processedHosts/$totalHosts hosts processed."
        }

        $logPath = Join-Path $SilkEchoInstallerCacheDir "installation_logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $logPath
        InfoMessage "Detailed logs saved to: $logPath"

        # Display summary
        InfoMessage "*************************************************"
        InfoMessage "Installation Summary:"
        InfoMessage "Total Hosts: $($remoteComputers.Count)"
        InfoMessage "Successful: $script:NumOfSuccessHosts"

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

# Local Variables for Summary
[string]$script:HostList      = ""
[int]$script:NumOfHosts       = 0
[int]$script:NumOfSuccessHosts = 0
[int]$script:NumOfFailedHosts = 0

# Check if the user is running as administrator
$MessageCurrentObject = "Echo Installer"

# Header intro with common information
ImportantMessage "=================================================="
ImportantMessage "       Silk Echo Installer - v$($InstallerProduct)"
ImportantMessage "=================================================="

InfoMessage "PowerShell Version is - $($PSVersionTable.PSVersion.Major)"
InfoMessage "PowerShell Edition is - $($PSVersionTable.PSEdition)"

# Get current user information

if ($PSVersionTable.Platform -eq "Unix") {
    $userName = $env:USER
    InfoMessage "Current User: $userName"
    InfoMessage "Authentication Type: Local User Account"
    InfoMessage "Computer Name: $env:HOSTNAME"
    InfoMessage "Operating System: $(uname -a)"
    $userName = "$env:USER"
    $isDomainUser = $false
} else {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $currentUser.Name
    $isDomainUser = isActiveDirectoryUser

    InfoMessage "Current User: $userName"
    if ($isDomainUser) {
        InfoMessage "Authentication Type: Active Directory Domain User"
    } else {
        InfoMessage "Authentication Type: Local User Account"
    }
    InfoMessage "Computer Name: $env:COMPUTERNAME"
    InfoMessage "Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption)"
}

# Handle CreateConfigTemplate parameter
if ($CreateConfigTemplate) {
    GenerateConfigTemplate
    exit 0
}

# get the configuration file path from the command line argument -ConfigPath
if (-Not $ConfigPath) {
    ErrorMessage "Configuration file path is required. Please provide it as an argument to the script using -ConfigPath parameter."
    InfoMessage "Usage: .\orchestrator.ps1 -ConfigPath <path_to_config_file>"
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
	WarningMessage "Requirements are not met,`nPlease fix the Requirements.`nGood Bye!"
	ErrorMessage "`n`tPress any key to continue...";
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
	return
} else {
    # clear the console
    #clear-host
}

InfoMessage "Script Location: $PSScriptRoot"
InfoMessage "Configuration File: $ConfigPath"
InfoMessage "Max Concurrency: $MaxConcurrency hosts"

if ($DryRun) {
    ImportantMessage "Mode: DRY RUN (Validation Only - No Changes)"
} else {
    ImportantMessage "Mode: LIVE INSTALLATION"
}

if ( $DebugPreference -eq 'Continue' ) {
    Write-Verbose "Verbose/Debug output is enabled."
    $safeConfig = @{
        installers = $config.installers
        hosts = $config.hosts
    }

    InfoMessage @"
Configuration is:
$($safeConfig | ConvertTo-Json -Depth 4)
"@
}
MainOrchestrator -config $config

if ($DryRun) {
    ImportantMessage "DryRun mode is enabled. No changes were made."
}

exit 0

# MARKER: HOST_INSTALLER_STARTS_HERE

#region orc_host_installer.ps1
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
#region orc_logging_on_host.ps1

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
    $ReductedText = $Text -replace '(?i)(?<=Password=)[^;]+', '[reducted]'

    # Replace the value of the $FlexToken variable with '[reducted]' only if it exists and is not empty
    if ($Global:FlexToken -and $Global:FlexToken.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:FlexToken), '[reducted]'
    }

    # Replace the value of the $SDPPassword variable with '[reducted]' only if it exists and is not empty
    if ($Global:SDPPassword -and $Global:SDPPassword.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:SDPPassword), '[reducted]'
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

#endregion orc_logging_on_host.ps1

# SkipCertificateCheck
#region orc_no_verify_cert.ps1
#region SkipCertificateCheck
function SkipCertificateCheck {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
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

#endregion orc_no_verify_cert.ps1

# CallSelfCertEndpoint, CallSDPApi, CallFlexApi
#region orc_web_client.ps1
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
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
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
        [string]$SDPHost,
        [string]$SDPPort,
        [string]$ApiEndpoint,
        [System.Management.Automation.PSCredential]$Credential
    )

    $url = "https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"

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

#endregion orc_web_client.ps1


# global variables
# ============================================================================

# Create SDP credential from passed parameters
$SDPCredential = New-Object System.Management.Automation.PSCredential($SDPUsername, (ConvertTo-SecureString $SDPPassword -AsPlainText -Force))

Set-Variable -Name SDPCredential -Value $SDPCredential -Scope Global
Set-Variable -Name IsDryRun -Value $DryRun.IsPresent -Scope Global
Set-Variable -Name AgentInstallationLogPath -Scope Global
Set-Variable -Name SVSSInstallationLogPath -Scope Global
Set-Variable -Name HostID -Value "$(hostname)" -Scope Global
Set-Variable -Name MessageCurrentObject -Value "Host[$(hostname)]" -Scope Global
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

    # Phase 1: Filter listeners - prioritize standard ports 1433, 1434
    $standardPortListeners = $listener | Where-Object { $_.LocalPort -eq 1433 -or $_.LocalPort -eq 1434 }
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

    InfoMessage "==== ValidateSDPConnection USERNAME: $($Credential.UserName) ===="
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

$ArgumentList = @(
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

        InfoMessage "Successfully established SQL Server connection"

        # Use local installer files that were uploaded by orchestrator
        DebugMessage "Using Silk VSS Provider installer at $SilkVSSPath"

        if (-not (Test-Path $SilkVSSPath)) {
            ErrorMessage "Silk VSS Provider installer not found at $SilkVSSPath"
            return "Unable to find Silk VSS Provider installer at $SilkVSSPath"
        } else {
            InfoMessage "Silk VSS Provider installer found at $SilkVSSPath"
        }

        DebugMessage "Using Silk Node Agent installer at $SilkAgentPath"

        if (-not (Test-Path $SilkAgentPath)) {
            ErrorMessage "Silk Node Agent installer not found at $SilkAgentPath"
            return "Unable to find Silk Node Agent installer at $SilkAgentPath"
        } else {
            InfoMessage "Silk Node Agent installer found at $SilkAgentPath"
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

        if (-not (InstallSilkNodeAgent -InstallerFilePath $SilkAgentPath -SQLConnectionString $ConnectionString -FlexIP $FlexIP -AgentToken $AgentToken)) {
            ErrorMessage "Failed to install Silk Node Agent"
            return "Installation of Silk Node Agent failed. Check the installation log at $AgentInstallationLogPath"
        }

        # Install Silk VSS Provider
        $installed = InstallSilkVSSProvider -InstallerFilePath $SilkVSSPath -SDPID $SDPID -SDPHost $SDPHost -SDPPort $SDPPort -Credential $SDPCredential
        if (-not $installed) {
            ErrorMessage "Failed to install Silk VSS Provider"
            return "Installation of Silk VSS Provider failed. Check the installation log at $SVSSInstallationLogPath"
        }

        InfoMessage "Temporary directory: $SilkVSSDirectory"
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
        throw "Setup failed. $($error)"
    } else {
        CleanupInstallerFiles
        InfoMessage "Setup completed successfully."
    }
}

SetupHost
#endregion SetupHost

#endregion orc_host_installer.ps1


