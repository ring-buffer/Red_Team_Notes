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
	4.2  

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

> [!Why we are able to request the ticket for the user svc-alfresco?] 
> The Service user has Kerberos Pre-Authentication Disabled. Which means in some cases, there will be users who don’t have the Kerberos Pre-Authentication Attribute Enabled. This means that anyone can send a KRB_AS_REQ request to the DC on behalf of any of those users and receive the KRB_AS_REP from the KDC. In a real-world scenario, not all applications will support Kerberos pre-authentication, making it common to find users in the DC for whom Kerberos Pre-Authentication is disabled. This allows attackers to request TGTs for these users and crack their session key offline using tools like John or hashcat. This is known as AS-REPRoasting.

> The Service user has Kerberos Pre-Authentication Disabled. Which means in some cases, there will be users who don’t have the Kerberos Pre-Authentication Attribute Enabled. This means that anyone can send a KRB_AS_REQ request to the DC on behalf of any of those users and receive the KRB_AS_REP from the KDC. In a real-world scenario, not all applications will support Kerberos pre-authentication, making it common to find users in the DC for whom Kerberos Pre-Authentication is disabled. This allows attackers to request TGTs for these users and crack their session key offline using tools like John or hashcat. This is known as AS-REPRoasting.