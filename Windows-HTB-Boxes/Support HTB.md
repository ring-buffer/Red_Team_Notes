Box: Windows 

Level: Easy

### Index
1. Box Info 
2. Initial Nmap Enumeration

### Box Info
```
Support is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication. After connecting to the share, an executable file is discovered that is used to query the machine&amp;amp;amp;amp;#039;s LDAP server for available users. Through reverse engineering, network analysis or emulation, the password that the binary uses to bind the LDAP server is identified and can be used to make further LDAP queries. A user called `support` is identified in the users list, and the `info` field is found to contain his password, thus allowing for a WinRM connection to the machine. Once on the machine, domain information can be gathered through `SharpHound`, and `BloodHound` reveals that the `Shared Support Accounts` group that the `support` user is a member of, has `GenericAll` privileges on the Domain Controller. A Resource Based Constrained Delegation attack is performed, and a shell as `NT Authority\System` is received.
```

### Initial Nmap Enum

```
# nmap -p- --min-rate=10000 -Pn 10.10.11.174
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-27 02:11 EDT
Nmap scan report for support.htb (10.10.11.174)
Host is up (0.080s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49674/tcp open  unknown
49691/tcp open  unknown
49713/tcp open  unknown

```

Further Enumeration using nmap
```
# nmap -p 53,88 --min-rate=3000 -Pn -T2 -sC -sV 10.10.11.174
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-27 02:20 EDT
Nmap scan report for support.htb (10.10.11.174)
Host is up (0.038s latency).

PORT   STATE SERVICE      VERSION
53/tcp open  domain       Simple DNS Plus
88/tcp open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-08-27 06:20:25Z)


PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Microsoft Windows netbios-ssn
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

PORT    STATE    SERVICE VERSION
389/tcp filtered ldap

PORT    STATE    SERVICE      VERSION
445/tcp filtered microsoft-ds

PORT    STATE SERVICE   VERSION
464/tcp open  kpasswd5?

PORT    STATE    SERVICE        VERSION
593/tcp filtered http-rpc-epmap

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

Notice that the `Domain: support.htb0`. 