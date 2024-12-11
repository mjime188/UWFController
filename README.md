# Created by Mark Jimenez, Bryan Arango Cruz, Francisco Cuello
# CIS5370 Group 8 Final Project UWF Controller
# UWF Controller

A graphical user interface for managing Windows Unified Write Filter (UWF) settings. This application simplifies the process of configuring and monitoring UWF on Windows systems.

## Overview

The UWF Controller provides a user-friendly interface for:
- Enabling/disabling UWF protection
- Managing protected volumes
- Configuring overlay settings
- Managing file and registry exclusions
- Monitoring UWF status

## Requirements

- Windows 10/11 Education or Enterprise with UWF capability enabled
- Python 3.8 or higher
- Administrator privileges
- Required Python packages:
  - tkinter (usually comes with Python)

## Recommended
- Virtual Machine

## Installation

1. Enable UWF in Windows:
   ```
   Turn Windows Features on or off > Device Lockdown > Unified Write Filter
   ```
   Note: System restart required after enabling UWF

2. Clone or download the repository

3. Ensure all files are in the correct structure:
   ```
   UWF-Controller/
   ├── main.py
   ├── computer_config.py
   ├── script_protection.py
   ├── batch_scripts/
   │   ├── uwf_batch_scripts.bat
   │   └── script.hash
   └── README.md
   ```

## Usage

1. Run the application with administrator privileges:
   ```
   python main.py or main.exe
   ```

2. The interface consists of three main sections:
   - Dashboard: Quick overview and basic controls
   - Status: Detailed UWF configuration status
   - Settings: Complete configuration options

### Key Features

- **Dashboard**
  - Current UWF status display
  - Quick enable/disable controls
  - Protected volumes overview

- **Status Panel**
  - Detailed configuration display
  - Current protection status
  - Overlay usage statistics
  - List of protected volumes
  - File and registry exclusions

- **Settings Panel**
  - Volume protection management
  - Overlay configuration
    - Type (RAM/DISK)
    - Maximum size
    - Warning threshold
    - Critical threshold
  - Exclusion management
    - File/folder exclusions
    - Registry exclusions

## Security Features

- Script integrity verification
- Command sanitization
- Administrator privileges requirement
- Configuration backup

## Known Limitations

- UWF must be enabled through DISM before using the application
- Requires administrator privileges
- Some settings require system restart to take effect

## Troubleshooting

1. **"Security Error" Message**
   - Delete script.hash in batch_scripts folder
   - Restart application to regenerate hash

2. **"Access Denied" Error**
   - Ensure running with administrator privileges
   - Check UWF is properly enabled in Windows

3. **Settings Not Applying**
   - Some changes require system restart
   - Check system messages panel for specific errors