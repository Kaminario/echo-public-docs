Copyright (c) 2025 Silk Technologies, Inc.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.

# Silk Echo Installer

A PowerShell-based installer for deploying Silk Echo components (Node Agent and VSS Provider) across Windows environments.

## Overview

The Silk Echo installer automates the deployment of Silk's data acceleration components:

- **Silk Node Agent**: Performs Database manipulation on Windows hosts
- **Silk VSS Provider**: Enables Volume Shadow Copy Service integration with Silk Data Platform (SDP)
- **Host Registration**: Registers hosts with Silk Flex management server
- **SQL Server Integration**: Configures database connectivity for the Node Agent

## Key Features

### 🎯 **Flexible Component Installation**
- **Selective Installation**: Install Agent only, VSS only, or both components
- **Independent Components**: Agent and VSS can be installed separately without dependencies
- **Configuration Control**: Per-host control over which components to install
- **Optimized Workflow**: Skip unnecessary prerequisites when installing single components

### 🛡️ **Enterprise-Grade Reliability**
- **Fault Tolerance**: Continues with valid hosts when some fail validation, upload, or installation
- **State Persistence**: Resume capability via automatic progress tracking in `processing.json`
- **Timeout Protection**: Two-tier timeout system (110s internal, 120s orchestrator) prevents hanging jobs
- **Comprehensive Logging**: Detailed timestamped logs with credential sanitization

### 📊 **Advanced Monitoring**
- **Progress Monitoring**: Status updates during upload, connectivity testing, and installation
- **Host-by-Host Status**: Detailed progress reports and final installation summaries
- **Immediate Result Collection**: Job results processed and logged as soon as they complete

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
| `Force` | Force reprocessing all hosts, ignore completed tracking | No | false |
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

# Force reprocessing all hosts (ignore completed tracking)
.\orchestrator.ps1 -ConfigPath "config.json" -Force

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
    "mount_points_directory": "C:\\MountPoints"
  }
}
```

**Required Fields:**
- `sdp_id`: SDP platform identifier
- `flex_host_ip`: IP address of Silk Flex server (must be valid IP)
- `mount_points_directory`: Directory for mount points (must not be empty)

**Optional Fields:**
- `sql_server`: SQL Server instance to use for all host connections. If
  set, this server will be used in all host connection strings unless
  overridden in the host section itself. If not set, the installer will
  auto-discover SQL Server instances by scanning for listening SQL
  servers on each host. Port 1433 will be prioritized, and the hostname
  will be used instead of IP address or localhost if the server is
  listening on 0.0.0.0.
- `install_to_directory`: Target directory for component installations. If
  empty or not specified, system default installation paths are used. If
  set to a custom path (e.g., `"C:\\CustomPath"`), both Silk Node Agent
  and VSS Provider will be installed to that directory. The directory must
  exist on the target host before installation begins, or the installation
  will fail with a validation error. This setting is primarily configured
  in the `common` section for all hosts but can be overridden at the host
  level for specific deployment scenarios.

  **Version Requirements**: Custom installation directory is supported only
  from Agent version 1.0.28 and VSS version 2.0.17. Earlier versions will
  ignore this parameter and install to default system paths.

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

## Selective Component Installation

You can control which components to install using the `install_agent` and `install_vss` configuration options. These are **primarily configured in the `common` section** to apply to all hosts, with optional host-level overrides for specific deployment scenarios.

### Configuration Options

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `install_agent` | Boolean | Install Silk Node Agent component | `true` |
| `install_vss` | Boolean | Install Silk VSS Provider component | `true` |

### Common Section Configuration (Primary Method)

The recommended approach is to set component installation options in the `common` section, which applies to all hosts.

#### Install Both Components (Default)
If neither `install_agent` nor `install_vss` is specified in the common section, both components will be installed on all hosts:

```json
{
  "common": {
    "flex_host_ip": "192.168.1.100",
    "mount_points_directory": "C:\\MountPoints"
  },
  "hosts": [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12"
  ]
}
```

#### Install Agent Only on All Hosts
Useful when you need database manipulation capabilities without VSS integration across your entire environment:

```json
{
  "common": {
    "install_agent": true,
    "install_vss": false,
    "flex_host_ip": "192.168.1.100",
    "sql_user": "sa",
    "sql_pass": "password",
    "mount_points_directory": "C:\\MountPoints"
  },
  "hosts": [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12"
  ]
}
```

**Prerequisites skipped when VSS is disabled:**
- SDP information retrieval
- SDP connection validation
- VSS installer download/upload

#### Install VSS Only on All Hosts
Useful when you only need Volume Shadow Copy Service integration across your entire environment:

```json
{
  "common": {
    "install_agent": false,
    "install_vss": true,
    "flex_host_ip": "192.168.1.100",
    "sdp_id": "12506",
    "sdp_user": "admin",
    "sdp_pass": "password",
    "mount_points_directory": "C:\\MountPoints"
  },
  "hosts": [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12"
  ]
}
```

**Prerequisites skipped when Agent is disabled:**
- SQL Server connection validation
- Host registration at Flex
- Agent installer download/upload

### Host-Level Overrides (Advanced)

For specific hosts that need different component configurations, you can override the common section settings at the host level.

#### Override for Specific Hosts
Common section sets defaults, individual hosts override as needed:

```json
{
  "common": {
    "install_agent": true,
    "install_vss": false,
    "flex_host_ip": "192.168.1.100",
    "mount_points_directory": "C:\\MountPoints"
  },
  "hosts": [
    "192.168.1.10",  // Installs only Agent (inherits from common)
    "192.168.1.11",  // Installs only Agent (inherits from common)
    {
      "host_addr": "192.168.1.12",
      "install_vss": true  // Override: installs both Agent and VSS
    }
  ]
}
```

### Validation Rules

- At least one component (`install_agent` or `install_vss`) must be enabled for each host
- Setting both to `false` will result in a validation error
- Installers are only downloaded/uploaded for enabled components
- Credential validation is skipped for disabled components (e.g., no SQL validation if Agent is disabled)

## Host Configuration Options

### Property Inheritance
All hosts inherit properties from the `common` section. Object-format hosts can override specific properties:

```json
{
  "common": {
    "sql_user": "default-sql-user",
    "sql_pass": "default-sql-password",
    "mount_points_directory": "C:\\MountPoints",
    "install_to_directory": "C:\\SilkComponents"
  },
  "hosts": [
    // Inherits all common properties
    "192.168.1.10",

    // Overrides SQL credentials, inherits mount_points_directory and install_to_directory
    {
      "host_addr": "192.168.1.11",
      "sql_user": "special-sql-user",
      "sql_pass": "special-sql-password"
    },

    // Overrides mount point directory
    {
      "host_addr": "192.168.1.12",
      "mount_points_directory": "F:\\AlternateMountPoints"
    },

    // Overrides installation directory (uses system defaults)
    {
      "host_addr": "192.168.1.13",
      "install_to_directory": ""
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
    "mount_points_directory": "C:\\SilkMountPoints",
    "install_to_directory": ""
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
- Uses system default installation paths (empty install_to_directory)

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
    "mount_points_directory": "C:\\SilkMountPoints",
    "install_to_directory": ""
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
- Uses system default installation paths (empty install_to_directory)

## Installation Process

The installer follows this enhanced workflow with advanced batch orchestration:

1. **Prerequisites Check**: Validates PowerShell version, admin privileges, and platform
2. **Output Directory Setup**: Creates and validates write permissions for `SilkEchoInstallerArtifacts` directory
3. **State Recovery**: Loads `processing.json` to identify previously completed hosts (skipped automatically unless `-Force` used)
4. **Configuration Validation**: Parses and validates the config.json file with enhanced error reporting
5. **Installer Preparation**: Downloads or locates required installer files locally
   - Downloads from URLs if specified, or uses default URLs
   - Uses local paths if files exist at specified locations
   - Caches downloaded files in `SilkEchoInstallerArtifacts` directory
6. **Parallel Connectivity Testing**: Validates PowerShell remoting to all target hosts using dynamic batch processing
   - **Progress Updates**: Shows connectivity test status and completion
   - **Fault-tolerant**: Failed hosts are logged but script continues with valid hosts
   - **Dynamic Scheduling**: New tests start immediately as slots become available
   - Only terminates if no valid hosts remain
7. **Authentication Setup** (for valid hosts only):
   - Logs into Silk Flex server and obtains access token
   - Validates SDP credentials
   - Prepares SQL connection strings with automatic endpoint discovery
8. **Parallel File Distribution**: Uploads installer files to target hosts using dynamic batch processing
   - **Progress Updates**: Shows upload status and completion
   - Creates temporary directory on each target host (`C:\Temp\silk-echo-install-<timestamp>`)
   - Copies both agent and VSS installer files to each host
   - Uses PowerShell remoting for file transfer
   - **Dynamic Scheduling**: New uploads start immediately as slots become available
   - **Fault-tolerant**: Failed uploads are logged but script continues with successful hosts
9. **Parallel Installation Execution**: Runs installations across hosts using dynamic batch processing
   - **Progress Updates**: Shows installation status and completion
   - Uses the uploaded installer files from each host's temporary directory
   - **Multi-tier Timeout Protection**: 110s internal timeout, 120s orchestrator timeout
   - **Dynamic Scheduling**: New installations start immediately as slots become available
   - **Immediate State Persistence**: Successful installations tracked immediately in `processing.json`
10. **Results Collection and Reporting**:
    - **Real-time Result Processing**: Job results processed immediately upon completion
    - **Comprehensive Logging**: All output saved to transcript and report files
    - **Final Summary**: Console display with success/failure counts and log file locations

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
# Debug mode with dry run (recommended for troubleshooting)
.\orchestrator.ps1 -ConfigPath "config.json" -Debug -DryRun

# Verbose mode shows additional execution details
.\orchestrator.ps1 -ConfigPath "config.json" -Verbose

# Check the full transcript log after execution
Get-Content "SilkEchoInstallerArtifacts\orchestrator_full_log_<timestamp>.txt" | Select-Object -Last 50
```

## Security Considerations

- **Credential Storage**: All passwords in config.json are stored as plain text. Secure the configuration file appropriately
- **TrustedHosts**: For credential authentication, target IPs are added to PowerShell's TrustedHosts list
- **Network Security**: Ensure proper firewall rules for PowerShell remoting (typically ports 5985/5986)

## Logging and Output

The installer provides comprehensive logging and state tracking:

### **Console Output**
- **Progress Updates**: Status messages during all operations
- **Timestamped Messages**: All output includes timestamps for tracking execution timeline
- **Color-coded Messages**: ImportantMessage (Green), ERROR (Red), WARNING (Yellow), INFO/DEBUG (Default white)
- **Credential Sanitization**: Passwords are automatically redacted from all log output

### **File Logging**
- **Full Execution Transcript**: Complete session log saved to `SilkEchoInstallerArtifacts\orchestrator_full_log_<timestamp>.txt`
- **Installation Report**: Detailed per-host results saved to `SilkEchoInstallerArtifacts\installation_report_<timestamp>.txt`
- **Processing State**: Progress tracking saved to `SilkEchoInstallerArtifacts\processing.json`
- **Remote Host Logs**: All remote execution output is captured and echoed to the orchestrator console

### **Log Locations**
The installer creates a cache directory `SilkEchoInstallerArtifacts` in the script location containing:
- `orchestrator_full_log_<timestamp>.txt` - Complete execution transcript
- `installation_report_<timestamp>.txt` - Final installation results per host
- `processing.json` - Completed hosts tracking for resume capability
- Downloaded installer files (cached for reuse)

### **After Installation**
Once installation completes, you can find:
1. **Console Summary**: Final count of successful/failed installations
2. **Full Transcript**: Complete log file with all execution details
3. **Installation Report**: Per-host status with error details if any failures occurred
4. **Resume State**: Completed hosts list for potential re-runs

## Installation State Tracking

The installer automatically tracks installation progress to prevent duplicate installations and enable safe resumption:

### **Processing State File**
- **Location**: `SilkEchoInstallerArtifacts\processing.json`
- **Purpose**: Tracks which hosts have been successfully processed
- **Format**: Simple JSON file with completed host addresses and completion timestamps

### **Simple Tracking**
- Only successfully completed hosts are tracked
- Each completed host has a timestamp of when it was completed
- Failed hosts are NOT tracked (they will be retried on next run)
- Simple format: `{"host_addr": "completion_timestamp"}`

### **Resume Capability**
- If the script is interrupted, rerun with the same configuration
- Already completed hosts will be automatically skipped
- Only remaining hosts will be processed
- To reprocess all hosts, use `-Force` parameter or delete `processing.json` file

### **Recovery After Failures**

#### **If Installation Fails or Gets Interrupted:**
1. **Check the logs**: Review the full transcript and installation report files
2. **Identify failed hosts**: Look for ERROR messages in the console output or log files
3. **Fix underlying issues**: Address connectivity, credential, or configuration problems
4. **Resume installation**: Simply rerun the same command - completed hosts will be skipped automatically

#### **Common Recovery Scenarios:**
```powershell
# View current processing state
Get-Content "SilkEchoInstallerArtifacts\processing.json" | ConvertFrom-Json

# Resume after interruption (skips completed hosts)
.\orchestrator.ps1 -ConfigPath "config.json"

# Force reprocessing all hosts (ignore completed tracking)
.\orchestrator.ps1 -ConfigPath "config.json" -Force

# Reset processing state manually (alternative to -Force)
Remove-Item "SilkEchoInstallerArtifacts\processing.json"

# Check recent logs for failure analysis
Get-Content "SilkEchoInstallerArtifacts\orchestrator_full_log_*.txt" | Select-Object -Last 100 | Where-Object { $_ -like "*ERROR*" }
```

#### **Failure Analysis Steps:**
1. **Check Console Output**: Look for final summary showing success/failure counts
2. **Review Full Transcript**: Open `orchestrator_full_log_<timestamp>.txt` and search for "ERROR"
3. **Check Installation Report**: Open `installation_report_<timestamp>.txt` for per-host results
4. **Verify Prerequisites**: Ensure failed hosts meet all requirements (WinRM, credentials, etc.)
5. **Test Individual Host**: Use troubleshooting commands to verify connectivity to failed hosts
