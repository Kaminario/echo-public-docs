# Silk Echo Public Documentation

## Project Overview

**Silk Echo** is a comprehensive database snapshot and cloning solution that enables application-consistent or crash-consistent snapshots of databases. The project provides both API documentation and practical tools for database replication, backup, and disaster recovery scenarios.

### Key Capabilities

- **Database Snapshotting**: Create application-consistent or crash-consistent snapshots of MSSQL databases
- **Database Cloning**: Clone databases from snapshots to different hosts with precision and reliability
- **Automated Workflows**: Support for both manual operations and automated integration into existing workflows
- **Multi-Host Management**: Orchestrate database operations across multiple Windows hosts
- **Flex Integration**: Seamless integration with Silk Flex management server and SDP (Silk Data Platform)

## Project Structure

```
echo-public-docs/
├── README.md                    # Main API documentation and usage guide
├── LICENSE                      # MIT license file
├── Makefile                     # PDF generation from README.md
├── AGENT.md                     # This file - project overview and structure
│
├── src/installer/               # PowerShell installer source code
│   ├── orchestrator.ps1         # Main multi-host installation orchestrator
│   ├── orc_host_installer.ps1   # Single-host installation script
│   ├── orc_*.ps1               # Modular PowerShell components (20+ files)
│   ├── config-example.json     # Configuration template
│   ├── make-release.ps1        # Production build script
│   └── readme.md               # Detailed installer documentation
│
├── installer-release/           # Production-ready installer package
│   ├── orchestrator.ps1         # Self-contained deployment script
│   ├── readme.md               # Quick start guide
│   └── version                 # Version information
│
├── example/python/              # Python API examples and utilities
│   ├── db_clone.py             # Database cloning automation script
│   ├── delete_echo_db.py       # Database deletion utility
│   ├── list_snapshots.py       # Snapshot listing utility
│   ├── make_echo_db.py         # Database creation utility
│   ├── make_snapshot.py        # Snapshot creation utility
│   ├── refresh.py              # Database refresh utility
│   ├── snapshot_daily.py       # Daily snapshot automation
│   ├── run.sh                  # Execution script
│   ├── requirements.txt        # Python dependencies
│   └── README.md               # Python examples documentation
```

## Context Files and Documentation

### Primary Documentation

1. **`README.md`** - Main project documentation
   - Complete API reference for all endpoints
   - Authentication and operation tracking details
   - Host management, snapshot, and clone operations
   - Task state monitoring and error handling

2. **`src/installer/readme.md`** - Comprehensive installer documentation
   - Detailed architecture overview
   - Configuration system and authentication methods
   - Development workflow and troubleshooting
   - Selective component installation guide

3. **`installer-release/readme.md`** - Quick start guide
   - Simplified installation instructions
   - Configuration examples
   - Common usage patterns

### Configuration Files

1. **`src/installer/config-example.json`** - Configuration template
   - Complete example with all available options
   - Host authentication methods (AD vs credentials)
   - Installer source configuration
   - Component selection options

2. **`example/python/requirements.txt`** - Python dependencies
   - `requests==2.32.3` - HTTP client for API calls
   - `fire==0.7.0` - Command-line interface framework

### Source Code Organization

#### PowerShell Installer (`src/installer/`)

**Core Scripts:**
- `orchestrator.ps1` - Multi-host installation orchestrator with parallel processing
- `orc_host_installer.ps1` - Single-host installation logic
- `make-release.ps1` - Production build system

**Modular Components (`orc_*.ps1`):**
- **Constants**: `orc_constants.ps1`, `orc_constants_installer.ps1`
- **Utilities**: `orc_common.ps1`, `orc_logging.ps1`, `orc_logging_on_host.ps1`, `orc_config.ps1`, `orc_requirements.ps1`, `orc_import_expander.ps1`
- **Authentication**: `orc_flex_login.ps1`, `orc_security.ps1`
- **Network**: `orc_web_client.ps1`, `orc_host_communication.ps1`
- **Database**: `orc_mssql.ps1`, `orc_mssql_discovery.ps1`
- **Storage**: `orc_sdp.ps1`, `orc_uploader.ps1`
- **Installation**: `orc_batch_installer.ps1`, `orc_invoke_remote_install.ps1`, `orc_host_setup_extractor.ps1`, `silent-agent-installer.ps1`
- **State Management**: `orc_tracking.ps1`, `orc_generic_batch_processor.ps1`

**Entry Points:**
- `orchestrator.ps1` → `MainOrchestrator` (line ~282) - Multi-host installation orchestrator
- `orc_host_installer.ps1` → `SetupHost` (line ~1078) - Single host entry point
  - `setup` (line ~989) - Full installation (agent + VSS)
  - `setup_agent` (line ~747) - Agent-only installation
  - `setup_vss` (line ~815) - VSS-only installation
  - `upgrade_only` (line ~889) - Upgrade existing installation

#### Python Examples (`example/python/`)

**Core Utilities:**
- `db_clone.py` - Automated database cloning from snapshots
- `make_snapshot.py` - Snapshot creation automation
- `list_snapshots.py` - Snapshot discovery and listing
- `refresh.py` - Database refresh operations
- `snapshot_daily.py` - Automated daily snapshot scheduling

**Supporting Scripts:**
- `delete_echo_db.py` - Database cleanup utilities
- `make_echo_db.py` - Database creation helpers
- `run.sh` - Execution wrapper script

## Key Features by Component

### API Documentation (`README.md`)
- **Topology API**: Retrieve host > database > snapshot relationships
- **Host APIs**: Register, unregister, and manage hosts
- **Clone APIs**: Create snapshots and clone databases
- **Snapshot APIs**: Manage database snapshots
- **Task APIs**: Monitor long-running operations
- **Refresh APIs**: Replace database volumes from snapshots

### PowerShell Installer (`src/installer/`)
- **Selective Installation**: Install Agent only, VSS only, or both components
- **Parallel Processing**: Dynamic batch orchestration with configurable concurrency
- **Fault Tolerance**: Continue with valid hosts when some fail
- **State Persistence**: Resume capability via progress tracking
- **Authentication**: Support for both Active Directory and credential-based auth
- **Validation**: Early SQL credential testing before file uploads

### Python Examples (`example/python/`)
- **API Integration**: Complete Python client for all Echo APIs
- **Automation**: Scripts for common database operations
- **Error Handling**: Robust error handling and user confirmation
- **Tracking**: Request tracking with unique identifiers
- **Flexibility**: Command-line interface with Fire framework

## Development and Deployment

### Development Workflow
1. **Source Development**: Work in `src/installer/` with modular components
2. **Testing**: Use `orchestrator.ps1` for development and testing
3. **Production Build**: Run `make-release.ps1` to create self-contained installer
4. **Deployment**: Use `installer-release/orchestrator.ps1` for production

### Release Build Process

The release process combines ~25 modular PowerShell files into a single self-contained script.

**How it works (`make-release.ps1`):**
1. Reads `orchestrator.ps1` which contains dot-source imports (`. ./orc_*.ps1`)
2. Uses `ExpandImportsInline` function from `orc_import_expander.ps1`
3. For each import line matching `. ./orc_*.ps1`:
   - Reads the referenced file content
   - Replaces the import line with actual content
   - Wraps in `#region`/`#endregion` tags for organization
4. Processes up to 3 iterations to handle nested dependencies
5. Replaces `{{VERSION_PLACEHOLDER}}` with new version number
6. Outputs single file to `installer-release/orchestrator.ps1`

**Version management:**
- Version stored in `installer-release/version` (semver format)
- `make-release.ps1 -Part patch|minor|major` increments version

**Result:** A ~4000+ line self-contained script that can be deployed without dependencies.

### Configuration Management
- **Template Generation**: `orchestrator.ps1 -CreateConfigTemplate`
- **Validation**: `orchestrator.ps1 -ConfigPath config.json -DryRun`
- **Flexible Credentials**: Support for config file or interactive prompting

### Documentation Generation
- **PDF Output**: `make pdf` generates `readme.pdf` from `README.md`
- **Markdown Processing**: Uses Pandoc with custom formatting

## Target Environments

- **Source Hosts**: Windows Server with MSSQL and original databases
- **Destination Hosts**: Windows Server with MSSQL for cloned databases
- **Management**: Silk Flex server and SDP integration
- **Authentication**: Active Directory or credential-based authentication
- **Network**: PowerShell remoting (WinRM) enabled hosts

This project provides a complete solution for enterprise database replication and backup scenarios, with both comprehensive API documentation and practical implementation tools.
