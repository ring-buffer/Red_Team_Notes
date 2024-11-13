`Box: Medium Windows`
### `Index`
1. [Box-Info](#Box-Info)


dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdafdsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
v
v
v
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf



dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf



dsjfnakdsfnjksdaf






dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf












dsjfnakdsfnjksdaf
dsjfnakdsfnjksdafdsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf
v
dsjfnakdsfnjksdafvdsjfnakdsfnjksdafv





dsjfnakdsfnjksdafdsjfnakdsfnjksdafdsjfnakdsfnjksdaf














dsjfnakdsfnjksdafdsjfnakdsfnjksdafdsjfnakdsfnjksdaf
dsjfnakdsfnjksdaf




dsjfnakdsfnjksdafdsjfnakdsfnjksdafdsjfnakdsfnjksdaf















dsjfnakdsfnjksdafdsjfnakdsfnjksdafdsjfnakdsfnjksdaf















dsjfnakdsfnjksdafdsjfnakdsfnjksdafdsjfnakdsfnjksdaf











dsdfsd
### `Box-Info`
```
Flight is a hard Windows machine that starts with a website with two different virtual hosts. One of them is vulnerable to LFI and allows an attacker to retrieve an NTLM hash. Once cracked, the obtained clear text password will be sprayed across a list of valid usernames to discover a password re-use scenario. Once the attacker has SMB access as the user `s.moon` he is able to write to a share that gets accessed by other users. Certain files can be used to steal the NTLMv2 hash of the users that access the share. Once the second hash is cracked the attacker will be able to write a reverse shell in a share that hosts the web files and gain a shell on the box as low privileged user. Having credentials for the user `c.bum`, it will be possible to gain a shell as this user, which will allow the attacker to write an `aspx` web shell on a web site that&amp;amp;amp;#039;s configured to listen only on localhost. Once the attacker has command execution as the Microsoft Virtual Account he is able to run Rubeus to get a ticket for the machine account that can be used to perform a DCSync attack ultimately obtaining the hashes for the Administrator user.
```
### `Initial Nmap`