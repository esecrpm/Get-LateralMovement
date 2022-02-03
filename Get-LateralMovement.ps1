<#
.SYNOPSIS
	This script will accept the mounted drive or full path to an evidence source
	and process relevant forensic artifacts for evidence of lateral movement.
.DESCRIPTION
	The Get-LateralMovement.ps1 script is based on the SANS Hunt Evil ("blue")
	poster and was created to process relevant event log, registry, and file system
	artifacts for evidence of lateral movement.
	
	The script accepts a mounted drive or full path to an evidence source.  This
	source can be a drive image mounted with Arsenal Image Mounter, a mounted VHDX
	file created by KAPE, or the local C: drive of the running system.
	
	The output path must be supplied on the command line and the script uses Eric
	Zimmerman's Tools to create CSV output that can be parsed or reviewed for
	evidence of lateral movement.  The path to the tools directory is specified by
	the $Tools variable in the script and must be changed to match the specific path
	on your analysis machine or USB device.
.PARAMETER SrcPath
	Full path to the folder or mounted drive containing evidence to process
.PARAMETER DstPath
	Full path to the folder where output of evidence processing will be placed
.EXAMPLE
	Get-LateralMovement.ps1 -SrcPath G: -DstPath N:\Network\Case\Folder
	Using a mounted drive letter, write the output to a network folder
.EXAMPLE
	Get-LateralMovement.ps1 -SrcPath C:\ -DstPath E:\USB\Case\Folder
	Using the live system drive, write the output to a USB drive
.EXAMPLE
	Get-LateralMovement.ps1 -SrcPath O:\C -DstPath D:\LocalDrive\Case\Folder
	Using a mounted KAPE image, write the output to a local drive
.LINK
	https://ericzimmerman.github.io/
.LINK
	https://www.sans.org/posters/hunt-evil/
.LINK
	https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape
.NOTES
	Author: esecrpm
	
	Revision History
	2022-02-02	0.1	Initial build
	2022-02-03	0.2	Added test for live system
	2022-02-03	0.3 Output progress to console
	
#>


#Requires -RunAsAdministrator


param (
	[Parameter(Mandatory=$True)][string]$SrcPath = (Resolve-Path "."),
	[Parameter(Mandatory=$True)][string]$DstPath
)

# Variable assignment
$Tools = "C:\ForensicTools\ZimmermanTools"
$Source = $SrcPath+"\Users"
if ($SrcPath -eq $Env:SystemDrive) {
	$Live = $True
	$SrcPath = $SrcPath+"\"
}

# Create destination path for output
New-Item -Path $DstPath -ItemType Directory | Out-Null



# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# Lateral Movement/Remote Access (Source)
# ///////////////////////////////////////


# Remote Desktop
# **************
# Event Logs
#  Security.evtx
#   4648 - Logon specifying alternate credentials (if NLA enabled on destination)
#   - Current logged-on User Name
#   - Alternate User Name
#   - Destination Host Name/IP 
#   - Process Name
#  Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx
#   1024 - Destination Host Name
#   1102 - Destination IP Address

# Registry
#  NTUSER.DAT
#   Software\Microsoft\Terminal Server Client\Servers
#   - Remote desktop destinations are tracked per-user
# mstsc.exe in any of the following
#   Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
#   Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   CurrentControlSet\Services\bam\State\UserSettings\{SID}
#   CurrentControlSet\Services\dam\State\UserSettings\{SID}
#  Amcache.hve
#

# File System
#  Jumplists
#  – C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\{MSTSC-APPID}.automaticDestinations-ms
#  - Tracks remote desktop connection destination and times
#  Prefetch
#  – mstsc.exe
#  Bitmap Cache – C:\USERS\<USERNAME>\AppData\Local\Microsoft\Terminal Server Client\Cache
#  - bcache##.bmc
#  - cache####.bin


# Map Network Shares (net.exe) to C$ or Admin$
# ********************************************
# Event Logs
#  Security.evtx
#   4648 - Logon specifying alternate credentials (if NLA enabled on destination)
#   - Current logged-on User Name
#   - Alternate User Name
#   - Destination Host Name/IP 
#   - Process Name
#  Microsoft-Windows-SmbClient%4Security.evtx
#   31001 - Failed logon to destination
#   - Destination Host Name
#   - User Name for failed logon
#   - Reason code for failed destination logon (e.g. bad password)
#   31010 - Failed to connect to the share
#   - Error: (Access Denied)
#   - UNC Path

# Registry
#  NTUSER.DAT
#   Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
#   - Remotely mapped shares
#  UsrClass.dat
#   ShellBags
#   - Remote folders accessed inside an interactive session via Explorer by attackers
# net.exe/net1.exe in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   CurrentControlSet\Services\bam\State\UserSettings\{SID}
#   CurrentControlSet\Services\dam\State\UserSettings\{SID}
#  Amcache.hve

# File System
#  Prefetch
#  - net.exe
#  - net1.exe
#  Shortcuts and Jumplists
#  - Review shortcut files and jumplists for remote files accessed by attackers, if they had interactive access (RDP)




# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# Lateral Movement/Remote Execution (Source)
# //////////////////////////////////////////


# PsExec
# ******
# Event Logs
#  Security.evtx
#   4648 - Logon specifying alternate credentials (if NLA enabled on destination)
#   - Current logged-on User Name
#   - Alternate User Name
#   - Destination Host Name/IP 
#   - Process Name

# Registry
#  NTUSER.DAT
#   Software\SysInternals\PsExec\EulaAccepted
# psexec.exe in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   CurrentControlSet\Services\bam\State\UserSettings\{SID}
#   CurrentControlSet\Services\dam\State\UserSettings\{SID}
#  Amcache.hve

# File System
#  Prefetch
#  - psexec.exe
#  - Possible references to other files accessed by psexec.exe, such as executables copied to target system with the “-c” option
#  File Creation
#  - psexec.exe file downloaded and created on local host as the file is not native to Windows


# Scheduled Tasks
# ***************
# Event Logs
#  Security.evtx
#   4648 - Logon specifying alternate credentials (if NLA enabled on destination)
#   - Current logged-on User Name
#   - Alternate User Name
#   - Destination Host Name/IP 
#   - Process Name

# Registry
# at.exe/schtasks.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   CurrentControlSet\Services\bam\State\UserSettings\{SID}
#   CurrentControlSet\Services\dam\State\UserSettings\{SID}
#  Amcache.hve

# File System
#  Prefetch
#  - at.exe
#  - schtasks.exe


# Services
# ********
# Event Logs
#  N/A

# Registry
# sc.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   CurrentControlSet\Services\bam\State\UserSettings\{SID}
#   CurrentControlSet\Services\dam\State\UserSettings\{SID}
#  Amcache.hve

# File System
#  Prefetch - sc.exe


# WMI/WMIC
# ********
# Event Logs
#  Security.evtx
#   4648 - Logon specifying alternate credentials (if NLA enabled on destination)
#   - Current logged-on User Name
#   - Alternate User Name
#   - Destination Host Name/IP 
#   - Process Name

# Registry
# wmic.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   CurrentControlSet\Services\bam\State\UserSettings\{SID}
#   CurrentControlSet\Services\dam\State\UserSettings\{SID}
#  Amcache.hve

# File System
#  Prefetch - wmic.exe


# PowerShell Remoting
# *******************
# Event Logs
#  Security.evtx
#   4648 - Logon specifying alternate credentials (if NLA enabled on destination)
#   - Current logged-on User Name
#   - Alternate User Name
#   - Destination Host Name/IP 
#   - Process Name
#  Microsoft-Windows-WinRM%4Operational.evtx
#   6 – WSMan Session initialize
#   - Session created
#   - Destination Host Name or IP
#   - Current logged-on User Name
#   8, 15, 16, 33 – WSMan Session deinitialization
#   - Closing of WSMan session
#   - Current logged-on User Name
#  Microsoft-Windows-PowerShell%4Operational.evtx
#   40961, 40962 - Records the local initiation of powershell.exe and associated user account
#   8193 & 8194 - Session created
#   8197 - Connect (Session closed)

# Registry
# powershell.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   CurrentControlSet\Services\bam\State\UserSettings\{SID}
#   CurrentControlSet\Services\dam\State\UserSettings\{SID}
#  Amcache.hve

# File System
#  Prefetch
#  - powershell.exe
#  - PowerShell scripts (.ps1 files) found in powershell.exe prefetch file
#  Command history
#  - C:\USERS\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
#  - With PS v5+, a history file with previous 4096 commands is maintained per user




# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# Lateral Movement/Remote Access (Destination)
# ////////////////////////////////////////////

# Remote Desktop
# **************
# Event Logs
#  Security.evtx
#   4624 Logon Type 10 - Source IP/Logon User Name
#   4778/4779 - IP Address of Source/Source System Name, Logon User Name
#  Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx
#   131 – Connection Attempts, Source IP
#   98 – Successful Connections
#  Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
#   1149 - Source IP/Logon User Name, Blank user name may indicate use of Sticky Keys
#  Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
#   21, 22, 25 - Source IP/Logon User Name
#   41 - Logon User Name

# Registry
# rdpclip.exe/tstheme.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#  Amcache.hve

# File System
#  Prefetch
#  - rdpclip.exe
#  - tstheme.exe


# Map Network Shares (net.exe) to C$ or Admin$
# ********************************************
# Event Logs
#  Security.evtx
#   4624 Logon Type 3 - Source IP/Logon User Name 
#   4672 - Logon User Name
#   - Logon by user with administrative rights
#   - Requirement for accessing default shares such as C$ and ADMIN$
#   4776 – NTLM if authenticating to Local System Source Host Name/Logon User Name
#   4768 – TGT Granted
#   - Source Host Name/Logon User Name
#   - Available only on domain controller
#   4769 – Service Ticket Granted if authenticating to Domain Controller
#   - Destination Host Name/Logon User Name
#   - Source IP
#   - Available only on domain controller
#   5140 - Share Access
#   5145 - Auditing of shared files – NOISY!

# Registry
#  N/A

# File System
#  File Creation
#  - Attacker's files (malware) copied to destination system
#  - Look for Modified Time before Creation Time
#  - Creation Time is time of file copy


# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# Lateral Movement/Remote Execution (Destination)
# ///////////////////////////////////////////////


# PsExec
# ******
# Event Logs
#  Security.evtx
#   4648 - Logon specifying alternate credentials
#   - Connecting User Name
#   - Process Name 
#   4624 Logon Type 3 (and Type 2 if “-u” Alternate Credentials are used)
#   - Source IP/Logon User Name 
#   4672 - Logon User Name
#   - Logon by a user with administrative rights
#   - Requirement for access default shares such as C$ and ADMIN$
#   5140 – Share Access
#   - ADMIN$ share used by PsExec
#  System.evtx
#   7045 - Service Install

# Registry
# psexesvc.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Services\PSEXESVC
#   - “-r” option can allow attacker to rename service
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#  Amcache.hve

# File System
#  Prefetch
#  - psexesvc.exe
#  - evil.exe
#  File Creation
#  - User profile directory structure created unless “-e” option used
#  - psexesvc.exe will be placed in ADMIN$ (\Windows) by default, as well as other executables (evil.exe) pushed by PsExec


# Scheduled Tasks
# ***************
# Event Logs
#  Security.evtx
#   4624 Logon Type 3 - Source IP/Logon User Name 
#   4672 - Logon User Name
#   - Logon by a user with administrative rights
#   - Requirement for accessing default shares such as C$ and ADMIN$
#   4698 – Scheduled task created
#   4702 – Scheduled task updated
#   4699 – Scheduled task deleted
#   4700/4701 – Scheduled task enabled/disabled
#  Microsoft-Windows-TaskScheduler%4Operational.evtx
#   106 – Scheduled task created
#   140 – Scheduled task updated
#   141 – Scheduled task deleted
#   200/201 – Scheduled task executed/completed

# Registry
#  SOFTWARE
#   Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
#   Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
# evil.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#  Amcache.hve

# File System
#  File Creation
#  - evil.exe
#  - Job files created in C:\Windows\Tasks
#  - XML task files created in C:\Windows\System32\Tasks
#    - Author tag under "RegistrationInfo" can identify:
#      - Source system name
#      - Creator username
#  Prefetch - evil.exe


# Services
# ********
# Event Logs
#  Security.evtx
#   4624 Logon Type 3 - Source IP/Logon User Name 
#   4697 - Security records service install, if enabled
#   - Enabling non-default Security events such as ID 4697 are particularly useful if only the Security logs are forwarded to a centralized log server
#  System.evtx
#   7034 – Service crashed unexpectedly
#   7035 – Service sent a Start/Stop control
#   7036 – Service started or stopped
#   7040 – Start type changed (Boot | On Request | Disabled)
#   7045 – A service was installed on the system

# Registry
# evil.exe in any of the following
#  SYSTEM
#   CurrentControlSet\Services - New service creation
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#   - ShimCache records existence of malicious service executable, unless implemented as a service DLL
#  Amcache.hve

# File System
#  File Creation
#  - evil.exe or evil.dll malicious service executable or service DLL
#  Prefetch – evil.exe


# WMI/WMIC
# ********
# Event Logs
#  Security.evtx
#   4624 Logon Type 3 - Source IP/Logon User Name 
#   4672 - Logon User Name
#   - Logon by an a user with administrative rights
#  Microsoft-Windows-WMI-Activity%4Operational.evtx
#   5857 - Indicates time of wmiprvse execution and path to provider DLL
#   – attackers sometimes install malicious WMI provider DLLs 
#   5860, 5861 - Registration of Temporary (5860) and Permanent (5861) Event Consumers
#   - Typically used for persistence, but can be used for remote execution. 

# Registry
# scrcons.exe/mofcomp.exe/wmiprvse.exe/evil.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#  Amcache.hve

# File System
#  File Creation
#   evil.exe
#   evil.mof – .mof files can be used to manage the WMI Repository
#  Prefetch
#   - scrcons.exe
#   - mofcomp.exe
#   - wmiprvse.exe
#   - evil.exe
#  Unauthorized changes to the WMI Repository in C:\Windows\System32\wbem\Repository


# PowerShell Remoting
# *******************
# Event Logs
#  Security.evtx
#   4624 Logon Type 3 - Source IP/Logon User Name 
#   4672 - Logon User Name
#   - Logon by an a user with administrative rights
#  Microsoft-Windows-PowerShell%4Operational.evtx
#   4103, 4104 - Script Block logging
#   - Logs suspicious scripts by default in PS v5
#   - Logs all scripts if configured
#   53504 - Records the authenticating user
#  Windows PowerShell.evtx
#   400/403 - "ServerRemoteHost" indicates start/end of Remoting session
#   800 - Includes partial script code
#  Microsoft-Windows-WinRM%4Operational.evtx 
#   91 - Session creation
#   168 - Records the authenticating user

# Registry
# SOFTWARE
#  Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell
#   ExecutionPolicy - Attacker may change execution policy to a less restrictive setting, such as "bypass"
# wsmprovhost.exe/evil.exe found in any of the following
#  SYSTEM
#   CurrentControlSet\Control\Session Manager\AppCompatCache
#  Amcache.hve

# File System
#  File Creation
#  - evil.exe
#    - With Enter-PSSession, a user profile directory may be created
#  Prefetch
#  – evil.exe
#  - wsmprovhost.exe


# Registry
# NTUSER.DAT
# - UserAssist, RecentApps
# UsrClass.dat
# - ShellBags
# SOFTWARE
# SYSTEM
# AppCompatCache
# AmCache


# File System
# $MFT
# Prefetch
# PowerShell Console History
# WMI Repository
# Jumplists
# SRUM




# \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
# Process Forensic Artifacts for Evidence of Lateral Movement
# ///////////////////////////////////////////////////////////


# Event Logs
Write-Host "Processing Event Logs..."
& $Tools\EvtxECmd\EvtxECmd.exe -d $SrcPath\Windows\System32\winevt\Logs --inc 6,8,15,16,21,22,25,33,41,91,98,106,131,140,141,168,200,201,400,403,800,1024,1102,1149,4103,4104,4624,4648,4672,4688,4697,4698,4699,4700,4701,4702,4768,4769,4776,4778,4779,5140,5145,5857,5860,5861,7034,7035,7036,7040,7045,8193,8194,8197,31001,31010,40961,40962,53504 --csv $DstPath --csvf LatMvmt_Events.csv | Out-File -Encoding ASCII -FilePath $DstPath\!EvtxECmd_Messages.txt

# Registry
Write-Host "Processing Registry Hives..."
& $Tools\RECmd\RECmd.exe -d $SrcPath --bn $Tools\RECmd\BatchExamples\Kroll_Batch.reb --csv $DstPath --csvf LatMvmt_Registry.csv | Out-File -Encoding ASCII -FilePath $DstPath\!RECmd_Messages.txt
Write-Host "- ShellBags"
If ($Live) {
	& $Tools\SBECmd.exe -l --dedupe --csv $DstPath --csvf LatMvmt_ShellBags.csv | Out-File -Encoding ASCII -FilePath $DstPath\!SBECmd_Messages.txt
} else {
	& $Tools\SBECmd.exe -d $SrcPath\Users --dedupe --csv $DstPath --csvf LatMvmt_ShellBags.csv | Out-File -Encoding ASCII -FilePath $DstPath\!SBECmd_Messages.txt
}
Write-Host "- ShimCache"
& $Tools\AppCompatCacheParser.exe -f $SrcPath\Windows\System32\config\SYSTEM --csv $DstPath --csvf LatMvmt_ShimCache.csv | Out-File -Encoding ASCII -FilePath $DstPath\!AppCompatCache_Messages.txt
Write-Host "- Amcache"
& $Tools\AmcacheParser.exe -f $SrcPath\Windows\appcompat\Programs\Amcache.hve --csv $DstPath --csvf LatMvmt_Amcache.csv | Out-File -Encoding ASCII -FilePath $DstPath\!Amcache_Source_Messages.txt

# File System
Write-Host "Processing File System Artifacts..."
Write-Host "- MFT"
& $Tools\MFTECmd.exe -f $SrcPath'\$MFT' --csv $DstPath --csvf LatMvmt_mft.csv | Out-File -Encoding ASCII -FilePath $DstPath\!MFTECmd_Messages.txt
Write-Host "- Prefetch"
& $Tools\PECmd.exe -d $SrcPath\Windows\Prefetch -q --csv $DstPath --csvf LatMvmt_Prefetch.csv | Out-File -Encoding ASCII -FilePath $DstPath\!PECmd_Messages.txt
Write-Host "- JumpLists"
& $Tools\JLECmd.exe -d $SrcPath\Users -q --csv $DstPath --csvf LatMvmt_JumpLists.csv | Out-File -Encoding ASCII -FilePath $DstPath\!JLECmd_Messages.txt
Write-Host "- Shortcut Files"
& $Tools\LECmd.exe -d $SrcPath\Users -q --neb --csv $DstPath --csvf LatMvmt_Shortcuts.csv | Out-File -Encoding ASCII -FilePath $DstPath\!LECmd_Messages.txt
Write-Host "- PowerShell Console History"
Get-ChildItem $Source -Filter ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue -Force | foreach {
	$Path = ($_.DirectoryName + "\") -replace [Regex]::Escape($Source), $DstPath
	If (!(Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
	Copy-Item $_.FullName -Destination $Path -Force
}
