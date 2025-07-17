# Echo Installation Scripts

This directory contains PowerShell scripts for installing Echo on Windows systems, supporting both single-host and multi-host deployments.

## Files Overview

| File | Purpose |
|------|---------|
| `bulk-setup.ps1` | Interactive multi-host installation orchestrator |
| `host-setup.ps1` | Standalone single-host installation script |
| `bulk-setup-config.json` | Multi-host configuration file |

## Quick Start

### Single Host Setup
```powershell
# Run with required parameters
.\host-setup.ps1 -FlexIP "10.0.0.1" -FlexToken "your-token" -DBConnectionString "server=localhost;..." -SilkAgentURL "https://..." -SilkVSSURL "https://..." -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password"

# Validation mode (dry run)
.\host-setup.ps1 -FlexIP "10.0.0.1" -FlexToken "your-token" -DBConnectionString "server=localhost;..." -SilkAgentURL "https://..." -SilkVSSURL "https://..." -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password" -DryRun
```

### Multi-Host Setup
```powershell
# Install across multiple hosts using config file
.\bulk-setup.ps1 -ConfigPath "bulk-setup-config.json"

# Use custom configuration with different MaxConcurrency
.\bulk-setup.ps1 -ConfigPath "custom-config.json" -MaxConcurrency 5

# Validation mode (dry run)
.\bulk-setup.ps1 -ConfigPath "bulk-setup-config.json" -DryRun

# Combined options
.\bulk-setup.ps1 -ConfigPath "config.json" -MaxConcurrency 3 -DryRun
```

## Configuration

Edit `bulk-setup-config.json` for multi-host deployments:

```json
{
  "agent": "https://storage.googleapis.com/silk-public-files/silk-agent-installer-latest.exe",
  "svss": "https://storage.googleapis.com/silk-public-files/svss-install.exe",
  "hosts": ["host-server01", "host-server02", "host-server03"],
  "flex_host_ip": "192.168.1.10",
  "sqlconnection": "",
  "sdpid": "d9b601",
  "mount_points_directory": "c:\\MountPoints"
}
```


### Configuration Notes

- **Kerberos Authentication**: When using Kerberos authentication, the `hosts` array MUST contain hostnames (not IP addresses). IP addresses will cause authentication failures.
- **Mixed Authentication**: You can use IP addresses in the `hosts` array only when using username/password authentication methods.
- **Example with IP addresses** (username/password auth only):
  ```json
  "hosts": ["10.209.137.4", "10.209.137.5", "10.209.137.6"]
  ```
- **Example with hostnames** (required for Kerberos):
  ```json
  "hosts": ["server01", "server02", "server03"]
  ```

## PowerShell Features

Both `bulk-setup.ps1` and `host-setup.ps1` scripts support standard PowerShell features:

- **Get-Help**: Use `Get-Help .\bulk-setup.ps1` or `Get-Help .\host-setup.ps1` to view detailed parameter information and examples
- **Verbose and Debug**: Add `-Verbose` or `-Debug` parameters to enable debug level output for detailed execution information

Examples:
```powershell
# Get help for single-host script
Get-Help .\host-setup.ps1 -Full

# Run with debug level output
.\bulk-setup.ps1 -ConfigPath "config.json" -Verbose

# Run with debug level output
.\host-setup.ps1 -FlexIP "10.0.0.1" -FlexToken "token" -DBConnectionString "..." -SilkAgentURL "..." -SilkVSSURL "..." -SDPId "d9b601" -SDPUsername "admin" -SDPPassword "password" -Debug
```

## Requirements

- Windows OS with PowerShell 5.1+
- Administrator privileges
- Network connectivity to target hosts
- Valid SQL Server connection
- Flex server access credentials
- SDP (Silk Data Platform) credentials
- Download URLs for Silk Agent and VSS Provider installers
- PowerShell remoting enabled on target hosts (for multi-host setup)
- WinRM service running on target hosts (for multi-host setup)

## Parameters

### host-setup.ps1 Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `FlexIP` | IP address of the Silk Flex server | Yes |
| `FlexToken` | Authentication token for Flex API | Yes |
| `DBConnectionString` | SQL Server connection string | Yes |
| `SilkAgentURL` | Download URL for Silk Node Agent installer | Yes |
| `SilkVSSURL` | Download URL for Silk VSS Provider installer | Yes |
| `SDPId` | SDP (Silk Data Platform) identifier | Yes |
| `SDPUsername` | Username for SDP authentication | Yes |
| `SDPPassword` | Password for SDP authentication | Yes |
| `MountPointsDirectory` | Directory for mount points | Yes |
| `DryRun` | Validation mode without actual installation | No |
| `Debug/Verbose` | Enable debug output | No |

### bulk-setup.ps1 Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `ConfigPath` | Path to configuration JSON file | Yes | - |
| `MaxConcurrency` | Number of hosts to install in parallel | No | 10 |
| `DryRun` | Validation mode without actual installation | No | false |
| `Debug/Verbose` | Enable debug output | No | false |
