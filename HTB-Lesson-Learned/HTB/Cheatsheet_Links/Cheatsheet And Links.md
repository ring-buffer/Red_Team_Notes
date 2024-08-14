### Index
1.  CheatSheet Links 
2. Some of the Useful Commands

### CheatSheets Links

LZone Cheat Sheet - https://lzone.de/#/LZone%20Cheat%20Sheets

CyberKhalid Cheat Sheet - https://cyberkhalid.github.io/categories/


### Some of the Useful Commands

#### Samba

Trying to List smb share using Guest account \
`netexec smb 10.10.10.111 -u Guest -p "" --shares` \
`netexec --verbose smb 10.10.10.111 -u Guest -p "" --shares` \

Dumbing Password Policy through SMB Share
`netexec --verbose smb 10.10.10.111 -u Guest -p "" --pass-pol`

Spidering SMB shares
`netexec --verbose smb 10.10.10.111 -u Guest -p "" --spider IPC$`

#### nmap

Always run the nmap command in the following manner.
```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV <IP>
```

If you put the -sC or -sV parameters before --min-rate than your results might not have the Ports/Service versions.


Ongoing notes...Will add things later as I found during HTB machines