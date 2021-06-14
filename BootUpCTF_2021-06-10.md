# BootUp CTF 2021-06-10 - 2021-06-12
Notes about the CTF as I go along.  Mainly high level things to remember and takeaways.

- `readelf` to read an ELF header
- ELF header is 64 bytes
- Can compare ELF header to existing/working file
- `binwalk` - never used before
  - can use to extract files from a pcap file
  - puts files in a new directory
- Use `ltrace` to intercept and record dynamic library calls (binary analysis)