### Index
1.  Initial Nmap Enumeration
2.  SMB Enumeration - Port 139,445
3. RPC Enumeration - Port 135 -  `593 as well but that port is not open`

### Initial Nmap Enumeration

```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV 10.10.10.134             
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-08-14T06:55:06
|_  start_date: 2024-08-14T04:39:12
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-08-14T08:55:07+02:00
|_clock-skew: mean: -39m59s, deviation: 1h09m14s, median: -1s
```

### SMB Enumeration - Port 139,445

Listing the SMB Share without password. We got one unusual share name "Backup". Let's try to dig up more. **--no-pass** Argument always goes first in the following command.
```
$ smbclient --no-pass -L 10.10.10.134
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

Let us first find our if we have any permission to Read/Write on Backup Share.
```
$ smbmap -u "guest" -p "" -H 10.10.10.134
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
[!] Unable to remove test file at \\10.10.10.134\Backups\MCGQIDRANG.txt, please remove manually                              
[+] IP: 10.10.10.134:445        Name: bastion.htb               Status: Authenticated
	Disk                                                    Permissions     Comment
	----                                                    -----------     -------
	ADMIN$                                                  NO ACCESS       Remote Admin
	Backups                                                 READ, WRITE
	C$                                                      NO ACCESS       Default share
	IPC$                                                    READ ONLY       Remote IPC
[*] Closed 1 connections                                   
```

Okay so we can READ + Write on Backups share. Connecting the `Backups` share. I check the IPC$ share and it;s empty.
```
$ smbclient -U guest //10.10.10.134/Backups                         
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Aug 14 03:04:51 2024
  ..                                  D        0  Wed Aug 14 03:04:51 2024
  MCGQIDRANG.txt                      A        0  Wed Aug 14 03:04:51 2024
  note.txt                           AR      116  Tue Apr 16 06:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 07:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 07:44:02 2019

5638911 blocks of size 4096. 1175141 blocks available
```

Running All the SMB script through Nmap

```
$ nmap -p139,445 --script=smb-* --min-rate=1000 -sC -sV 10.10.10.134
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-14 14:07 EDT
Nmap scan report for bastion.htb (10.10.10.134)
Host is up (0.059s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-system-info: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-mbenum: 
|_  ERROR: Call to Browser Service failed with status = 2184
|_smb-vuln-ms10-054: false
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1
| smb-brute: 
|_  guest:<blank> => Valid credentials
|_smb-flood: ERROR: Script execution failed (use -d to debug)
| smb-ls: Volume \\10.10.10.134\Backups
| SIZE   TIME                 FILENAME
| <DIR>  2019-02-22T11:39:42  .
| <DIR>  2019-02-22T11:39:42  ..
| 0      2024-08-14T07:04:51  MCGQIDRANG.txt
| 260    2024-08-14T18:12:23  nmap-test-file
| 116    2019-04-16T10:02:05  note.txt
| 0      2019-02-22T12:43:08  SDT65CB.tmp
| <DIR>  2019-02-22T12:44:02  WindowsImageBackup
| <DIR>  2019-02-22T12:44:02  WindowsImageBackup\L4mpje-PC
|_
| smb-enum-sessions: 
|_  <nobody>
|_smb-print-text: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.10.134\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.134\Backups: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
|   \\10.10.10.134\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.134\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-08-14T20:11:52+02:00

```

Nothing Interesting other than just a Share Names. Let's try out enum4linux
```
$ enum4linux -a 10.10.10.134                                                                                        
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Aug 14 14:32:43 2024

 =========================================( Target Information )=========================================

Target ........... 10.10.10.134
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.10.134 )============================


[E] Can't find workgroup/domain



 ================================( Nbtstat Information for 10.10.10.134 )================================

Looking up status of 10.10.10.134
No reply from 10.10.10.134

 ===================================( Session Check on 10.10.10.134 )===================================


[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.

```

Again Nothing Interesting. Running `enum4linux-ng`. NG Stands for Next Generation.
```
$ enum4linux-ng -A 10.10.10.134
ENUM4LINUX - next generation (v1.3.3)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.10.134
[*] Username ......... ''
[*] Random Username .. 'jdcquqmx'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.10.10.134    |
 =====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ===========================================================
|    NetBIOS Names and Workgroup/Domain for 10.10.10.134    |
 ===========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 =========================================
|    SMB Dialect Check on 10.10.10.134    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                                                     
  SMB 1.0: true                 
  SMB 2.02: true                                                                                                                                     
  SMB 2.1: true                    
  SMB 3.0: true  
  SMB 3.1.1: true                                                                                                                                                       
Preferred dialect: SMB 3.0                                                                                                                                              
SMB1 only: false                                                                                                                                                        
SMB signing required: false                                                                                                                                             

 ===========================================================
|    Domain Information via SMB session for 10.10.10.134    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: BASTION                                                                                                                                          
NetBIOS domain name: ''
DNS domain: Bastion                                                                                                                                  
FQDN: Bastion                                                                                                                                        
Derived membership: workgroup member                                                                                                                 
Derived domain: unknown     

 =========================================
|    RPC Session Check on 10.10.10.134    |
 =========================================
[*] Check for null session
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for random user
[+] Server allows session using username 'jdcquqmx', password ''
[H] Rerunning enumeration with user 'jdcquqmx' might give more results

 ===============================================
|    OS Information via RPC for 10.10.10.134    |
 ===============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: Windows Server 2016 Standard 14393                                                                                                                                  
OS version: '10.0'                                                                                                                                   
OS release: '1607'                                                                                                                                   
OS build: '14393'                                                                                                                                    
Native OS: Windows Server 2016 Standard 14393                                                                                                        
Native LAN manager: Windows Server 2016 Standard 6.3                                                                                                 
Platform id: null                                                                                                                                    
Server type: null                                                                                                                                    
Server type string: null                                                                                                                             

[!] Aborting remainder of tests, sessions are possible, but not with the provided credentials (see session check results)

Completed after 8.39 seconds
```

Again nothing Interesting. 



### RPC Enumeration - Port 135
