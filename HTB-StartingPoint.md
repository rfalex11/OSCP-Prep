Intended to capture observations during the walkthroughs for processes to apply or things to  remember when coming across certain steps during information gathering.

#Archetype
- If you see SMB, see if anonymous access is granted
    - `smbclient -N -L \\\\IP_ADDR\\`
    - If any are interesting, try to connect with `smbclient -N \\\IP_ADDR\shared_drive_name`

