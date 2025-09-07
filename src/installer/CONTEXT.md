# Silk Echo Installer Directory Analysis

## Overview
The Silk Echo Installer is a PowerShell-based orchestration system for installing Silk Echo components (Node Agent and VSS Provider) on Windows hosts. This analysis covers only git-tracked files.

## Git-Tracked Files & Functions

### Main Scripts
| File | Function | Key Features |
|------|----------|--------------|
| **orchestrator.ps1** | Multi-host installation orchestrator | • Parallel installation (configurable concurrency)<br>• Host connectivity validation<br>• Authentication (AD/credentials)<br>• Installer download/upload<br>• Batch processing with summary reporting |
| **orc_host_installer.ps1** | Single-host installation script | • Silk Node Agent installation<br>• VSS Provider installation<br>• Flex server registration<br>• SQL Server configuration<br>• SDP connectivity validation |

### Build & Release
| File | Function | Key Features |
|------|----------|--------------|
| **make-release.ps1** | Production build script | • Combines all scripts into single file<br>• Expands imports inline<br>• Creates self-contained deployment package |

### Core Modules (orc_*.ps1)
| File | Function | Key Features |
|------|----------|--------------|
| **orc_constants.ps1** | Global constants and variables | • Version info (v0.1.1)<br>• Authentication enums (AD/credentials)<br>• Default installer URLs<br>• Development mode detection |
| **orc_common.ps1** | Common utility functions | • SecureString conversion<br>• Active Directory user detection<br>• Cache directory management |
| **orc_logging.ps1** | Centralized logging system | • Timestamp formatting<br>• Credential sanitization<br>• Multi-level logging (ERROR/INFO/WARN/DEBUG)<br>• Token/password redaction |
| **orc_logging_on_host.ps1** | Host-specific logging | • Remote host logging functions<br>• Context-aware messages |
| **orc_config.ps1** | Configuration management | • JSON config parsing<br>• Template generation<br>• Host inheritance (common → host-specific)<br>• Interactive config creation |
| **orc_requirements.ps1** | System validation | • PowerShell version check (≥5.0)<br>• Edition validation (Core/Desktop)<br>• Administrator privilege check |

### Authentication & Security
| File | Function | Key Features |
|------|----------|--------------|
| **orc_flex_login.ps1** | Silk Flex authentication | • API token management<br>• Login endpoint handling<br>• Token refresh logic |
| **orc_no_verify_cert.ps1** | Certificate handling | • Self-signed cert bypass<br>• PowerShell version compatibility<br>• HTTPS security override |

### Network & Communication
| File | Function | Key Features |
|------|----------|--------------|
| **orc_web_client.ps1** | HTTP/API client | • Flex API calls<br>• SDP API calls<br>• Self-signed certificate handling<br>• REST endpoint management |
| **orc_host_communication.ps1** | Host connectivity | • PowerShell remoting validation<br>• WinRM connectivity tests<br>• Network reachability checks |

### Integration Modules
| File | Function | Key Features |
|------|----------|--------------|
| **orc_mssql.ps1** | SQL Server integration | • Connection string generation<br>• Credential validation<br>• Named instance support<br>• Custom port handling |
| **orc_sdp.ps1** | Silk Data Platform integration | • SDP API connectivity<br>• Credential validation<br>• System state checks |

### Installation Management
| File | Function | Key Features |
|------|----------|--------------|
| **orc_uploader.ps1** | File management | • Installer download/caching<br>• Remote file upload<br>• Multi-host distribution<br>• Parallel transfers |
| **orc_invoke_remote_install.ps1** | Remote execution | • PowerShell job management<br>• Parallel execution<br>• Result collection<br>• Error aggregation |
| **orc_host_setup_extractor.ps1** | Script extraction | • Dynamic script generation<br>• Marker-based separation<br>• Import expansion |
| **orc_import_expander.ps1** | Import processing | • Inline script expansion<br>• Dependency resolution<br>• Development/production modes |

### Configuration Files
| File | Function | Description |
|------|----------|-------------|
| **config-example.json** | Configuration template | Example configuration with placeholders for SDP, SQL, Flex, and host settings |
| **readme.md** | Documentation | Usage instructions and parameter reference |

## Configuration Structure

### JSON Configuration Format
```json
{
  "installers": {
    "agent": {
      "url": "https://storage.googleapis.com/silk-public-files/silk-agent-installer-latest.exe",
      "path": "C:\\Installers\\agent_installer.exe"
    },
    "vss": {
      "url": "https://storage.googleapis.com/silk-public-files/svss-install.exe",
      "path": "C:\\Installers\\vss_installer.exe"
    }
  },
  "common": {
    "sdp_id": "<sdp_id>",
    "sdp_user": "<sdp_user>",
    "sdp_pass": "<sdp_pass>",
    "sql_user": "<sql_user>",
    "sql_pass": "<sql_pass>",
    "flex_host_ip": "10.8.71.100",
    "flex_user": "<flex_user>",
    "flex_pass": "<flex_pass>",
    "host_user": "<host_user>",
    "host_pass": "<host_pass>",
    "host_auth": "credentials|active_directory",
    "mount_points_directory": "E:\\MountPoints"
  },
  "hosts": [
    {
      "host_addr": "10.30.40.50",
      "sql_user": "<sql_user_1>",
      "sql_pass": "<sql_pass_1>",
      "mount_points_directory": "F:\\MountPoints"
    },
    "10.30.40.51",
    "10.30.40.52"
  ]
}
```

### Configuration Inheritance
- Common properties are inherited by all hosts
- Host-specific properties override common values
- Mixed format supports both string hostnames and detailed host objects

## Key Processes

### 1. Authentication Flow
1. **Host Authentication**: Either Active Directory (Kerberos) or username/password credentials
2. **Flex Authentication**: Login to Silk Flex management server to obtain API token
3. **SDP Authentication**: Validate credentials against Silk Data Platform

### 2. Connectivity Validation
- PowerShell remoting connectivity to each host
- HTTP/HTTPS connectivity to Flex management server
- API connectivity to SDP management interface
- SQL Server connectivity validation

### 3. Installation Process
1. **Preparation Phase**:
   - Download installer files to local orchestrator machine
   - Upload installers to all target hosts
   - Prepare connection strings and credentials

2. **Registration Phase**:
   - Register each host with Silk Flex
   - Obtain host-specific authentication tokens

3. **Installation Phase**:
   - Install Silk Node Agent with SQL and Flex configuration
   - Install VSS Provider with SDP configuration
   - Validate successful installation through log analysis

### 4. Error Handling & Logging
- Comprehensive error tracking with sanitized credentials
- Timestamped logging at multiple levels (DEBUG, INFO, WARN, ERROR)
- Detailed installation logs saved to files
- Summary reports with success/failure counts

## Security Features

### Credential Management
- Secure string conversion for passwords
- Automatic credential sanitization in logs
- Support for both interactive prompts and configuration file credentials

### Certificate Handling
- Automatic bypass of certificate validation for self-signed certificates
- PowerShell version compatibility (5.x and 7.x)

### Network Security
- HTTPS communication with all management endpoints
- PowerShell remoting with credential or Kerberos authentication
- Trusted hosts management for secure remote connections

## System Requirements

### Orchestrator Host (Control Machine)
- PowerShell 5.1 or 7.x (Core or Desktop edition)
- Administrator privileges
- Network access to all target hosts
- Internet access for downloading installers

### Target Hosts (Installation Targets)
- Windows operating system
- PowerShell remoting enabled (WinRM service)
- SQL Server installed and accessible
- Administrator privileges for installation
- Network access to Flex and SDP management servers

## Usage Examples

### Basic Installation
```powershell
.\orchestrator.ps1 -ConfigPath "config.json"
```

### Parallel Installation with Custom Concurrency
```powershell
.\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 5
```

### Validation Only (Dry Run)
```powershell
.\orchestrator.ps1 -ConfigPath "config.json" -DryRun
```

### Generate Configuration Template
```powershell
.\orchestrator.ps1 -CreateConfigTemplate
```

## File Organization

```
install/
├── orchestrator.ps1              # Main orchestrator script
├── orc_host_installer.ps1                # Per-host installation script
├── config-example.json           # Configuration template
├── orc_constants.ps1             # Authentication constants
├── orc_logging.ps1               # Centralized logging functions
├── orc_logging_on_host.ps1       # Host-specific logging
├── orc_config.ps1                # Configuration management
├── orc_requirements.ps1          # System requirements validation
├── orc_web_client.ps1            # HTTP/HTTPS API client
├── orc_flex_login.ps1            # Flex authentication
├── orc_sdp.ps1                   # SDP integration
├── orc_mssql.ps1                 # SQL Server integration
├── orc_invoke_remote_install.ps1 # Remote execution management
├── orc_uploader.ps1              # File upload functionality
├── orc_host_communication.ps1    # Host connectivity
├── orc_no_verify_cert.ps1        # Certificate bypass
└── orc_trust_hosts.ps1           # Trusted hosts management
```

## Integration Points

### Silk Flex API
- Authentication: `/api/v1/auth/local/login`
- System Info: `/api/v2/flex/info`
- Dashboard: `/api/v1/pages/dashboard`
- Host Registration: `/api/hostess/v1/hosts/{hostId}`

### SDP API
- System State: `/api/v2/system/state`
- Basic Authentication with username/password

### SQL Server
- Connection string validation
- Automatic discovery of SQL Server listeners
- Support for named instances and custom ports

This documentation provides a comprehensive overview of the Silk Echo Installer system architecture, configuration, and operational procedures.