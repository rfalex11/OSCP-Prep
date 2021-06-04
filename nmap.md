# `nmap` Book
https://nmap.org/book/toc.html

## Chapter 9 - NSE
LUA Manual:
- http://www.lua.org/manual/5.3/
- Free: http://www.lua.org/pil/
- Programming in Lua - 4th Edition: http://www.amazon.com/dp/8590379868?tag=secbks-20

## Chapter 10 - IDS
### Subverting IDS
- IPv4 offers obscure option called record route for gathering traceroute info
    - `nmap --ip-options R --packet-trace`
    - or most OS' offer `ping -R` which is easier to use than `nmap`
- Use `hping -t 5 --traceroute -p ## -S IP_Addr` to do a deep dive for if a port is actually closed, or if an IDS is sending RST packets
- Use `nmap --badsum` to prove a response was sent from a firewall, rather than prove that a filtered probe was dropped by the end host