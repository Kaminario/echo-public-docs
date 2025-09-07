# Silk Echo Installer

A PowerShell-based installer for deploying Silk Echo components (Node Agent and VSS Provider) across Windows environments.

## Overview

The Silk Echo installer automates the deployment of Silk's data acceleration components:

- **Silk Node Agent**: Performs Database manipulation on Windows hosts
- **Silk VSS Provider**: Enables Volume Shadow Copy Service integration with Silk Data Platform (SDP)
- **Host Registration**: Registers hosts with Silk Flex management server
- **SQL Server Integration**: Configures database connectivity for the Node Agent

The installer supports parallel execution across multiple hosts with comprehensive validation, logging, and error handling.

## Quick Start

### 1. Download the Installer
Download `orchestrator.ps1` from the latest release or directly from this repository
`https://github.com/Kaminario/echo-public-docs/tree/main/installer-release`

### 2. Generate Configuration Template
```powershell
.\orchestrator.ps1 -CreateConfigTemplate
```

This creates a `config.json` file with the appropriate structure based on your chosen authentication method.

### 3. Edit Configuration
Edit the generated `config.json` file with your environment-specific values:
- Update credentials for Flex server, SDP, and SQL Server
- Specify target hosts (IP addresses or hostnames)
- Configure mount point directories

### 4. Validate Configuration (Optional)
```powershell
.\orchestrator.ps1 -ConfigPath "config.json" -DryRun
```

### 5. Run Installation
```powershell
.\orchestrator.ps1 -ConfigPath "config.json"
```

## Prerequisites

- **Windows OS** with PowerShell 5.1 or higher
- **Administrator privileges** on the machine running the installer
- **Network connectivity** to target hosts
- **PowerShell remoting enabled** on target hosts (WinRM service running)
- Valid credentials for:
  - Silk Flex management server
  - SDP (Silk Data Platform) 
  - SQL Server instances
  - Target Windows hosts (if using credential-based authentication)

## Parameters Reference

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `ConfigPath` | Path to the JSON configuration file | Yes* | - |
| `CreateConfigTemplate` | Generate a config.json template interactively | No | - |
| `MaxConcurrency` | Number of hosts to process in parallel | No | 10 |
| `DryRun` | Validation mode - checks connectivity without making changes | No | false |
| `Verbose/Debug` | Enable verbose output for detailed logging | No | false |

*Required unless using `-CreateConfigTemplate`

### Usage Examples

```powershell
# Generate configuration template
.\orchestrator.ps1 -CreateConfigTemplate

# Install on hosts with default concurrency (10)
.\orchestrator.ps1 -ConfigPath "config.json"

# Install with custom concurrency
.\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 5

# Validate configuration without installing
.\orchestrator.ps1 -ConfigPath "config.json" -DryRun

# Run with verbose logging
.\orchestrator.ps1 -ConfigPath "config.json" -Verbose

# Get detailed help
Get-Help .\orchestrator.ps1 -Full
```

## Configuration Guide

The configuration file (`config.json`) has three main sections:

### installers Section
Defines how to obtain the Silk Agent and VSS Provider installers.

```json
{
  "installers": {
    "agent": {
      "url": "https://custom-server.com/silk-agent.exe",
      "path": "C:\\Installers\\silk-agent.exe"
    },
    "vss": {
      "url": "https://custom-server.com/svss-install.exe", 
      "path": "C:\\Installers\\svss-install.exe"
    }
  }
}
```

**Installer Source Priority:**
1. **Local Path**: If `path` is specified and the file exists, it will be used
2. **Download URL**: If `url` is specified, the installer will be downloaded
3. **Default URLs**: If neither is specified, built-in default URLs are used:
   - Agent: `https://storage.googleapis.com/silk-public-files/silk-agent-installer-latest.exe`
   - VSS: `https://storage.googleapis.com/silk-public-files/svss-install.exe`

### common Section
Contains shared configuration inherited by all hosts unless overridden.

```json
{
  "common": {
    "sdp_id": "your-sdp-identifier",
    "sdp_user": "sdp-username",
    "sdp_pass": "sdp-password",
    "sql_user": "sql-username", 
    "sql_pass": "sql-password",
    "flex_host_ip": "192.168.1.100",
    "flex_user": "flex-username",
    "flex_pass": "flex-password",
    "host_user": "local-admin-user",
    "host_pass": "local-admin-password",
    "host_auth": "credentials",
    "mount_points_directory": "E:\\MountPoints"
  }
}
```

**Required Fields:**
- `sdp_id`: SDP platform identifier
- `flex_host_ip`: IP address of Silk Flex server (must be valid IP)
- `mount_points_directory`: Directory for mount points (must not be empty)

**Authentication Fields:**
- `host_auth`: Either `"active_directory"` or `"credentials"`
- `host_user`/`host_pass`: Required for credential-based authentication
- Not needed for Active Directory authentication

### Credential Handling

The installer supports flexible credential management for all
authentication requirements:

**Configuration File Credentials:**
All credential fields in the config file are optional. You can
provide credentials in the configuration file or leave them empty.
When credentials are missing or invalid, the installer will prompt
you interactively.

**Example with Mixed Credential Sources:**
```json
{
  "common": {
    "sdp_id": "prod-sdp-01",
    "flex_host_ip": "192.168.1.100",
    "flex_user": "flex-admin",
    // flex_pass omitted - will be prompted
    // sdp_user/sdp_pass omitted - will be prompted
    "sql_user": "silk-agent",
    "sql_pass": "sql-password",
    "host_auth": "credentials"
    // host_user/host_pass omitted - will be prompted
  }
}
```

This approach allows you to:
- Store non-sensitive configuration in files
- Keep sensitive credentials out of configuration files
- Handle credential rotation without editing config files
- Provide different credentials per service as needed

### hosts Section
Defines target hosts for installation. Supports two formats:

#### Simple Format (String)
Hosts inherit all settings from the `common` section:
```json
{
  "hosts": [
    "192.168.1.10",
    "192.168.1.11", 
    "server03.domain.com"
  ]
}
```

#### Object Format

Allows per-host overrides of common settings:
```json
{
  "hosts": [
    {
      "host_addr": "192.168.1.10",
      "sql_user": "custom-sql-user",
      "sql_pass": "custom-sql-password",
      "mount_points_directory": "F:\\CustomMountPoints"
    },
    "192.168.1.11"
  ]
}
```

## Authentication Methods

### Active Directory Authentication
Uses the current domain user's credentials via Kerberos authentication.

**Requirements:**
- Current PowerShell user must be logged into an Active Directory domain
- User must have administrator privileges
- Target hosts must be domain-joined

**Host Address Handling:**
- **IP Addresses**: Automatically resolved to hostnames via reverse DNS lookup
- **Hostnames**: Used directly  
- **Resolution Failure**: Host is skipped with error message

**Configuration:**
```json
{
  "common": {
    "host_auth": "active_directory"
  },
  "hosts": [
    "192.168.1.10",  // Auto-resolved to hostname
    "server01.domain.com"  // Used directly
  ]
}
```

### Credentials Authentication  
Uses explicit username/password for each target host.

**Requirements:**
- Valid local administrator credentials for each target host
- Target hosts will be added to TrustedHosts list (with user confirmation)

**Host Address Handling:**
- **Must use IP addresses only**
- **Hostnames not supported** for credential authentication

**Configuration:**
```json
{
  "common": {
    "host_auth": "credentials",
    "host_user": "Administrator", 
    "host_pass": "Password123"
  },
  "hosts": [
    "192.168.1.10",  // Valid
    "192.168.1.11"   // Valid
  ]
}
```

## Host Configuration Options

### Property Inheritance
All hosts inherit properties from the `common` section. Object-format hosts can override specific properties:

```json
{
  "common": {
    "sql_user": "default-sql-user",
    "sql_pass": "default-sql-password",
    "mount_points_directory": "E:\\MountPoints"
  },
  "hosts": [
    // Inherits all common properties
    "192.168.1.10",
    
    // Overrides SQL credentials, inherits mount_points_directory
    {
      "host_addr": "192.168.1.11",
      "sql_user": "special-sql-user",
      "sql_pass": "special-sql-password" 
    },
    
    // Overrides mount point directory
    {
      "host_addr": "192.168.1.12", 
      "mount_points_directory": "F:\\AlternateMountPoints"
    }
  ]
}
```

### Per-Host Authentication
While not recommended, you can specify different authentication methods per host:

```json
{
  "hosts": [
    {
      "host_addr": "192.168.1.10",
      "host_auth": "credentials",
      "host_user": "admin",
      "host_pass": "password"
    },
    {
      "host_addr": "server02.domain.com",
      "host_auth": "active_directory"
    }
  ]
}
```

### Complete Configuration Example

#### Active Directory Authentication

Here's a full example configuration file for Active Directory authentication with local installer files:

```json
{
  "installers": {
    "agent": {
      "path": "C:\\tmp\\installers\\silk-agent-installer.exe"
    },
    "vss": {
      "path": "C:\\tmp\\installers\\svss-install.exe"
    }
  },
  "common": {
    "sdp_id": "12506",
    "sdp_user": "admin",
    "sdp_pass": "SdpAdminPassword123!",
    "sql_user": "silk-agent",
    "sql_pass": "SqlServicePassword456!",
    "flex_host_ip": "10.10.1.100",
    "flex_user": "flex", 
    "flex_pass": "FlexAdminPassword789!",
    "host_auth": "active_directory",
    "mount_points_directory": "C:\\SilkMountPoints"
  },
  "hosts": [
    "sql-server-01",
    "sql-server-02",
    "sql-server-03"
  ]
}
```

This configuration:
- Uses local installer files from `C:\tmp\installers\`
- Configures Active Directory authentication
- Includes all required passwords in the configuration
- Uses simple string format for all hosts (inherits all common settings)
- Sets consistent mount points directory for all hosts

#### Credentials Authentication

Here's a full example configuration file for credential-based authentication with interactive password prompting:

```json
{
  "installers": {
    "agent": {
      "path": "C:\\tmp\\installers\\silk-agent-installer.exe"
    },
    "vss": {
      "path": "C:\\tmp\\installers\\svss-install.exe"
    }
  },
  "common": {
    "sdp_id": "12506",
    "flex_host_ip": "10.10.1.100",
    "host_auth": "credentials",
    "mount_points_directory": "C:\\SilkMountPoints"
  },
  "hosts": [
    "192.168.1.10",
    "192.168.1.11", 
    "192.168.1.12"
  ]
}
```

This configuration:
- Uses local installer files from `C:\tmp\installers\`
- Configures credential-based authentication
- **Omits all passwords** - the installer will prompt interactively for:
  - SDP password (`sdp_pass`)
  - SQL Server password (`sql_pass`) 
  - Flex server password (`flex_pass`)
  - Host administrator password (`host_pass`)
- Uses IP addresses (required for credential authentication)
- Uses simple string format for all hosts (inherits all common settings)
- Sets consistent mount points directory for all hosts

## Installation Process

The installer follows this workflow:

1. **Prerequisites Check**: Validates PowerShell version, admin privileges, and platform
2. **Configuration Validation**: Parses and validates the config.json file
3. **Installer Preparation**: Downloads or locates required installer files locally
   - Downloads from URLs if specified, or uses default URLs
   - Uses local paths if files exist at specified locations
   - Caches downloaded files in `SilkEchoInstallerArtifacts` directory
4. **Connectivity Testing**: Validates PowerShell remoting to all target hosts
5. **Authentication Setup**: 
   - Logs into Silk Flex server and obtains access token
   - Validates SDP credentials
   - Prepares SQL connection strings
6. **File Distribution**: Uploads installer files to target hosts in parallel
   - Creates temporary directory on each target host (`C:\Temp\silk-echo-install-<timestamp>`)
   - Copies both agent and VSS installer files to each host
   - Uses PowerShell remoting for file transfer
   - Processes hosts with configured concurrency (default: 10)
   - **Only proceeds to installation if ALL uploads succeed**
7. **Installation Execution**: Runs installations across hosts with configured concurrency
   - Uses the uploaded installer files from each host's temporary directory
   - Executes installations in parallel batches
8. **Results Collection**: Gathers logs and provides installation summary

## Troubleshooting

### Common Issues

**"Failed to connect to host using active_directory authentication"**
- Verify current user is logged into Active Directory domain
- Check that target hosts are domain-joined
- Ensure PowerShell remoting is enabled on target hosts
```powershell
# Check if current user is domain user
$env:USERDOMAIN -ne $env:COMPUTERNAME

# Test Active Directory connectivity to host
Invoke-Command -ComputerName "server01.domain.com" -ScriptBlock { Get-Date }

# Check if host is domain-joined
Get-WmiObject -Class Win32_ComputerSystem -ComputerName "server01.domain.com" | Select PartOfDomain, Domain
```

**"Could not resolve IP to hostname for active_directory auth"**  
- The script couldn't perform reverse DNS lookup for the IP address
- Either use hostnames directly or switch to credential authentication
- Verify DNS configuration
```powershell
# Test reverse DNS resolution
[System.Net.Dns]::GetHostEntry("192.168.1.10")

# Test forward DNS resolution
Resolve-DnsName "server01.domain.com"
```

**"Failed to connect to host using credentials authentication"** 
- Verify username/password are correct for target host
- Check that target host allows the user account to log in
- Ensure WinRM service is running on target host
```powershell
# Test WinRM service on target host
Test-WSMan -ComputerName "192.168.1.10"

# Test credential-based PowerShell remoting
$cred = Get-Credential
Invoke-Command -ComputerName "192.168.1.10" -Credential $cred -ScriptBlock { Get-Date }

# Check WinRM service status
Get-Service -Name WinRM -ComputerName "192.168.1.10"
```

**"Failed to add hosts to TrustedHosts"**
- The script needs to add target IPs to PowerShell's TrustedHosts list
- Run PowerShell as Administrator
- Confirm the prompt to add hosts to TrustedHosts
```powershell
# Check current TrustedHosts list
Get-Item WSMan:\localhost\Client\TrustedHosts

# Check if running as Administrator
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Display hosts in TrustedHosts
(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
```

### Validation Commands
```powershell
# Validate Admin privileges
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Test WinRM connectivity manually
Test-WSMan -ComputerName "192.168.1.10"

# Check TrustedHosts list  
Get-Item WSMan:\localhost\Client\TrustedHosts

# Test PowerShell remoting
Invoke-Command -ComputerName "192.168.1.10" -ScriptBlock { Get-Date } -Credential (Get-Credential)

# Test PowerShell remoting active_directory
Invoke-Command -ComputerName "server01.domain.com" -ScriptBlock { Get-Date }
```

### Debug Mode
Run with `-Debug` or `-Verbose` for detailed troubleshooting information:

```powershell
.\orchestrator.ps1 -ConfigPath "config.json" -Debug -DryRun
```

## Security Considerations

- **Credential Storage**: All passwords in config.json are stored as plain text. Secure the configuration file appropriately
- **TrustedHosts**: For credential authentication, target IPs are added to PowerShell's TrustedHosts list
- **Network Security**: Ensure proper firewall rules for PowerShell remoting (typically ports 5985/5986)

## Logging and Output

The installer provides comprehensive logging:

- **Console Output**: Real-time progress and status messages
- **Detailed Logs**: Saved to `SilkEchoInstallerArtifacts\installation_logs_<timestamp>.json`
- **Credential Sanitization**: Passwords are automatically redacted from all log output
- **Installation Summary**: Final report showing success/failure count per host

The installer creates a cache directory `SilkEchoInstallerArtifacts` in the script location for temporary files and logs.