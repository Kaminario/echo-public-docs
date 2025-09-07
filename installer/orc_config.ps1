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
