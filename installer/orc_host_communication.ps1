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
