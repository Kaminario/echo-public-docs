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
