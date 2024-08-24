This is an unofficial checklist that I am preparing while solving Labs and HTB Machines. The checklist is not yet sorted but will eventually sort out this as I progress.

### Index
1.  Initial Enumeration Checklist
2.  Privilege Escalation Checklist
3.  CURL
4.  Ways to Get the Shell Worked 

### Initial Enumeration

- [ ] Run the Nmap command in this order: `nmap -p- --min-rate=1000 -Pn -T4 -sC -sV <IP>`
- [ ] If there's a Web Application Involved, Use Burp and Wappalyzer to identify framework. Find Relative vulnerabilities on Exploit-DB, GitHub Poc.
### Privilege Escalation

- [ ] Run winPEAS.bat on CMD and if you can access the PowerShell, run winPEAS.ps1. The PowerShell one has a color output with little extra details. Prefer ps1 over bat.
- [ ] Some of the Important Paths to check during Privilege Escalation
	- [ ] Check C:\\Users\\[UserName]\\**AppData Local** and **AppData Roaming** Directory.
	- [ ] Another Import Path to check C:\\ProgramData and C:\\Users\\Public

