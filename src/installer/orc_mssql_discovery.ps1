#region SQL Server Discovery

#region GetMSSQLHostPorts
function GetMSSQLHostPorts {
    <#
    .SYNOPSIS
        Discovers SQL Server endpoints on the local host.

    .DESCRIPTION
        Scans for SQL Server listeners on the local machine and returns prioritized
        list of endpoints to try. Prioritizes localhost, then hostname, then IPs.
        Filters by sqlservr.exe process to exclude Browser service (port 1434).

    .OUTPUTS
        Returns array of server endpoints in "host,port" format, prioritized:
        1. localhost (loopback addresses)
        2. hostname (wildcard and hostname IP listeners)
        3. Specific IPs

    .NOTES
        Requires SQL Server to be running on the local machine.
        Standard port 1433 is prioritized when available.
    #>
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

#endregion SQL Server Discovery
