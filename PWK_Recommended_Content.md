PWK_Recommended_Content

# Offensive Security Recommended Content

-[The Journey to Try Harder: TJnull’s Preparation Guide for PEN-200 PWK/OSCP 2.0](https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html)
	- https://docs.google.com/spreadsheets/d/12bT8APhWsL-P8mBtWCYu4MLftwG1cPmIL25AEBtXDno/edit#gid=2048224779
-[Scund00r Passing OSCP](https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#overview)
-[A Detailed Guide on OSCP Preparation – From Newbie to OSCP](http://niiconsulting.com/checkmate/2017/06/a-detail-guide-on-oscp-preparation-from-newbie-to-oscp/)
-[John J OSCP Preparation GuideAdditional Resources](https://johnjhacking.com/blog/the-oscp-preperation-guide-2020/)

- PWK Labs Learning Path: https://help.offensive-security.com/hc/en-us/articles/360050473812

# Books
- Hacking: The Art of Exploitation, 2nd Edition - Rented it!
- The Web Application Hacker’s Handbook - Have request for library
- Black Hat Python - Own it! Mac Kindle
- CCNA Cisco Certified Network Associate Study Guide, 7th Edition - O'Rielly

# Tips
## Scnd00r (OLD)
- Do the exercises
- SSH Tunneling/ Pivoting use `sshuttle` #sshtunneling #pivoting #tunneling
- Passwords are guessable or cracked within minutes, if spending >20 min brute forcing, or dictionary attacking, try another way. Use [SecList](https://github.com/danielmiessler/SecLists)
- Get organized, KEEP NOTES
- Lab machines have loot to refer to later
- [Nebula](https://exploit-exercises.com/) on ExploitExercises was useful (PWK 1.0)
- `IppSec` Youtube channel
- Create table with summary info on systems
- Upload [standalone nmap binary](https://github.com/ZephrFish/static-tools/blob/master/nmap/nmap) to run scans #nmap
- Script your #enumeration - [codingo]() & [Reconnoitre](https://github.com/codingo/Reconnoitre)
- "PrivEsc Bibles" - #privesc 
    - [g0tmi1k for Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
    - [fuzzysecurity for Windows](http://www.fuzzysecurity.com/tutorials/16.html)
    - Use searchsploit everything, with or without a version number - actually read and understand how they work
- Scripts: [LinuxPrivChecker](https://github.com/sleventyeleven/linuxprivchecker), [LinEnum](https://github.com/rebootuser/LinEnum), and [PowerUp](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerUp)
    - **These DON'T always find everything, manual search required**
- Kernel Exploits - [abatchy17 Windows Exploits](https://github.com/abatchy17/WindowsExploits) & [lucyoa Kernel Exploits](https://github.com/lucyoa/kernel-exploits) #kernel #exploits #kernelexploits
### Exam
- Run [Open Broadaster Software](https://obsproject.com/) to record screen in case you miss screenshots
- Separate terminal window for each target
- Exam not difficult, vulnerabilities are well hidden (1.0 VERSION!)

## TJNull 2.0
### Windows Privilege Escalation Guides:
#privesc
- Fuzzysecurity Windows Privilege Escalation Fundamentals: Shout out to fuzzysec for taking the time to write this because this is an amazing guide that will help you understand Privilege escalation techniques in Windows. http://www.fuzzysecurity.com/tutorials/16.html
- Pwnwiki Windows Privilege Escalation Commands: http://pwnwiki.io/#!privesc/windows/index.md
- Absolomb’s Security Blog: Windows Privilege Escalation Guide https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
- Pentest.blog: Windows Privilege Escalation Methods for Pentesters https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
- PayloadAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- SharpAllTheThings: https://github.com/N7WEra/SharpAllTheThings
- LOLBAS (Created by Oddvar Moe): https://lolbas-project.github.io/

### Windows Privilege Escalation Tools:

- JAWS (Created by 411Hall): A cool windows enumeration script written in PowerShell. https://github.com/411Hall/JAWS/commits?author=411Hall
- Windows Exploit Suggester Next Generation: https://github.com/bitsadmin/wesng
- Sherlock (Created by RastaMouse): Another cool PowerShell script that finds missing software patches for local privilege escalation techniques in Windows. https://github.com/rasta-mouse/Sherlock
- WinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
- Watson: https://github.com/rasta-mouse/Watson
- Seatbelt: https://github.com/GhostPack/Seatbelt
- Powerless: https://github.com/M4ximuss/Powerless
- Powerview: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon

Other Resources for Windows Privilege Escalation Techniques: https://medium.com/@rahmatnurfauzi/windows-privilege-escalation-scripts-techniques-30fa37bd194

GTFOBins (I have to thank Ippsec for sharing this with me): Contains a curated list of Unix binaries that that have the ability to be exploited by an attacker to bypass local security restrictions on a Linux system. https://gtfobins.github.io/

PayloadsAllTheThings Linux Priv Esc Guide: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
### Linux Privilege Escalation Tools:
- LinEnum: A great Linux privilege escalation checker that is still maintained by the guys at rebootuser.com. You can find there tool here: https://github.com/rebootuser/LinEnum
- Linux Exploit Suggester 2: https://github.com/jondonas/linux-exploit-suggester-2
- LinPEAS: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS]

### Wordlist generators:
#passwordcracking #passwords #wordlist #wordlistgenerator
Cewl: https://digi.ninja/projects/cewl.php
Crunch: https://tools.kali.org/password-attacks/crunch
Cupp (In Kali Linux): https://github.com/Mebus/cupp

### Metasploit/`msfvenom`
#metasploit #msfvenom #cheatsheets
Msfvenom Cheat Sheets:
- http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/
- https://netsec.ws/?p=331
- https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom


## Newbie to OSCP
2. Assembly language primer by Vivek Ramachandran. http://www.securitytube.net/groups?operation=view&groupId=5

Don’t get bored after seeing Assembly language. Just go through the first 2 videos in this video series. That is enough for understanding the memory layout.

3. Buffer Overflow Megaprimer by Vivek Ramachandran. http://www.securitytube.net/groups?operation=view&groupId=4.

In-depth video of buffer overflow where its explained in a very detailed way.

4. Exploit Research Megaprimer by Vivek Ramachandran. http://www.securitytube.net/groups?operation=view&groupId=7

Real-time Exploitation of buffer overflow which will be very interesting, where exploitation is explained in stepwise clearly. You can even try it yourself as mentioned in the video for your practice. It’s enough to go through first 5 videos. SEH Based buffer overflow is not required for OSCP.

If you follow the above steps, you will be able to do exploitation with buffer overflow by yourself 100%.

Many people shy away from preparing for buffer overflows because it helps to exploit only one machine in the exam. But still, it’s a very important and interesting concept. I have seen many people failing because of improper preparation on buffer overflows. Moreover, OSCP is not the target. All the things you learn here is for the real world.

# Enumeration
#enumeration
http://www.0daysecurity.com/penetration-testing/enumeration.html

https://nmap.org/nsedoc/

https://www.youtube.com/watch?v=Hk-21p2m8YY

# Shell Exploitation
#shellexploitation #exploitation #shells
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/          

https://netsec.ws/?p=331

# Windows Privilege Escalation
#privesc #winprivesc
http://www.fuzzysecurity.com/tutorials/16.html

https://www.youtube.com/watch?v=kMG8IsCohHA

https://www.youtube.com/watch?v=PC_iMqiuIRQ

https://github.com/GDSSecurity/Windows-Exploit-Suggester     

# Linux Privilege Escalation
#linuxprivesc #privesc
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

https://www.youtube.com/watch?v=dk2wsyFiosg

# Privilege escalation recon scripts:
#privescrecon #script #privescscript
http://www.securitysift.com/download/linuxprivchecker.py

http://pentestmonkey.net/tools/audit/unix-privesc-check

# John J Hacking
- I recommend immediately utilizing nmapAutomator or Autorecon to get in the habit of scanning systems quickly, and avoiding the possibility of overlooking enumeration that you should be doing.
- Do not utilize automation until you are confident that you know how to operate and understand all of the commands that the scripts execute. nmapAutomator provides a ridiculous amount of tool integration and scanning functionality, therefore let this be my warning not become too reliant on it.