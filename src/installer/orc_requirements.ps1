
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
