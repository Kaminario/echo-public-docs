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

#region UpdateHostSqlConnectionString
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

    $goodHost = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })

    # Check if any hosts need Agent installation
    $hostsNeedingAgent = @($goodHost | Where-Object { $_.install_agent -eq $true })

    if ($hostsNeedingAgent.Count -eq 0) {
        InfoMessage "No hosts require Agent installation - skipping SQL credential collection"
        return $true
    }

    # Check if any hosts requiring Agent are missing SQL credentials
    foreach ($hostInfo in $hostsNeedingAgent) {
        if (-not $hostInfo.sql_user -or -not $hostInfo.sql_pass) {
            $commonCredentialsNeeded = $true
            break
        }
    }

    InfoMessage "Common SQL credentials needed: $commonCredentialsNeeded"
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
            # the sql_user/pass fields is always exist but may be null
            if (-not $hostInfo.sql_user) {
                $hostInfo.sql_user = $defaultSqlUser
            }
            if (-not $hostInfo.sql_pass) {
                $hostInfo.sql_pass = $defaultSqlPass
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

        # Add SQL Server parameter if specified (bypasses endpoint discovery)
        if ($hostInfo.sql_server) {
            $connectionParams['Server'] = $hostInfo.sql_server
            InfoMessage "Using specified SQL Server for host $($hostInfo.host_addr): $($hostInfo.sql_server)"
        } else {
            InfoMessage "No SQL Server specified for host $($hostInfo.host_addr), endpoint discovery will be performed during installation"
        }

        # Build the connection string
        $connectionStringParts = $connectionParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)

        # Add connection string to host object
        $hostInfo.sql_connection_string = $connectionString

        # Log the connection string (with masked password)
        $LogSqlConnectionString = Sanitize $connectionString
        DebugMessage "Prepared SQL connection string for host $($hostInfo.host_addr): $LogSqlConnectionString"
    }

    ImportantMessage "Successfully prepared SQL connection strings for all hosts"
    return $true
}
#endregion UpdateHostSqlConnectionString

#endregion SQL
