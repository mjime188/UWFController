# UWF Remote Management Tool - Setup Guide

## Prerequisites
- Windows Edu or Enterprise OS
- (For testing) Two Windows VMs (one controller, one target)
- Python 3.11.7 installed on controller VM
- Administrator access on both VMs

## Installation Steps

### 1. Python Setup (Controller VM)
1. Download Python 3.11.7 from [python.org](https://www.python.org/downloads/)
2. During installation:
   - Check "Add Python to PATH"
   - Check "Install for all users"
   - Choose "Customize installation"

3. Install required Python packages:
```cmd
pip install wmi
pip install pywin32
```

### 2. PSExec Setup (Both VMs)
1. Download PsTools from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
2. Extract the zip file
3. Copy psexec.exe to `C:\Windows\System32`
4. Run in Command Prompt as Administrator:
```cmd
psexec -accepteula
```

### 3. Network Configuration (Both VMs)

#### Workgroup Setup
1. Open System Properties (Right-click Computer -> Properties)
2. Click "Change settings" next to Computer name
3. Click "Change"
4. Set workgroup name to "WORKGROUP" on both machines
5. Restart both VMs

#### Network Settings
1. Assign unique static IP addresses to each VM


### 4. Windows Services & Firewall (Both VMs)

Run these commands in PowerShell as Administrator:

```powershell
# Enable WMI
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"

# Enable File and Printer Sharing
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"

# Enable Network Discovery
Enable-NetFirewallRule -DisplayGroup "Network Discovery"

# Enable Remote Administration
New-NetFirewallRule -Name "PSExec" -DisplayName "PSExec" -Direction Inbound -Program "C:\Windows\System32\psexec.exe" -Action Allow

# Enable Required Services
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
Set-Service RemoteRegistry -StartupType Automatic
Start-Service RemoteRegistry
```

### 5. User Permissions (Target VM)

1. Open Local Security Policy (`secpol.msc`)
2. Navigate to Security Settings > Local Policies > User Rights Assignment
3. Configure these policies for your user account:
   - Allow log on through Remote Desktop Services
   - Log on as a batch job
   - Log on as a service
   - Access this computer from the network

### 6. UWF Setup (Target VM)
1. Open PowerShell as Administrator
2. Check if UWF is installed:
```powershell
uwfmgr.exe
```
3. If not installed, install UWF:
	- Nagviage to Turn Windows Features On or Off > Device Lockdown > Unified Write Filter

## Testing the Setup

1. Test basic connectivity:
```cmd
ping [target-ip]
```

2. Test network share access:
```cmd
dir \\[target-ip]\C$
```

## Troubleshooting

### Connection Issues
- Verify both VMs are in the same workgroup
- Ensure firewall rules are properly configured
- Check if services are running (WMI, Remote Registry)
- Verify network connectivity between VMs

### Permission Issues
- Verify user accounts have administrator privileges
- Check security policy settings
- Ensure proper network logon rights

### PSExec Errors
- Verify PSExec is in System32 directory
- Run PSExec with -accepteula flag first
- Check if the target machine allows remote execution

## Common Error Messages

1. "Network resource type is not correct":
   - Check network share accessibility
   - Verify workgroup configuration

2. "Access is denied":
   - Verify user permissions
   - Check administrator privileges

3. "WMI service is unavailable":
   - Check WMI service status
   - Verify firewall rules

4. "Command timed out":
   - Check network connectivity
   - Verify PSExec installation
   - Check service status on target machine
