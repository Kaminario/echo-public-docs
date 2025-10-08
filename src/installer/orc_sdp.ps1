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

    $goodHost = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })

    # Check if any hosts need VSS installation
    $hostsNeedingVSS = @($goodHost | Where-Object { $_.install_vss -eq $true })

    if ($hostsNeedingVSS.Count -eq 0) {
        InfoMessage "No hosts require VSS installation - skipping SDP credential collection"
        return
    }

    # get all different SDPId from hosts that need VSS
    $SDPIDs = $hostsNeedingVSS | ForEach-Object { $_.sdp_id } | Sort-Object -Unique

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
        if ($SDPInfo[$hostInfo.sdp_id].credentials -eq $null) {
            # we already veryfied user and pass for that sdp
            $SDPCredential = getSDPCredentials -HostInfo $hostInfo -SDPHost $SDPInfo[$hostInfo.sdp_id].mc_floating_ip -SDPPort $SDPInfo[$hostInfo.sdp_id].mc_https_port
            if (-not $SDPCredential) {
                ErrorMessage "Failed to get SDP credentials for host $($hostInfo.name)."
                Exit 1
            }
            $SDPInfo[$hostInfo.sdp_id].credentials = $SDPCredential
        }
        $hostInfo.sdp_credential = $SDPInfo[$hostInfo.sdp_id].credentials
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
