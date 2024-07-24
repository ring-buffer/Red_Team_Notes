### AdmirerToo HTB Box

While Solving this box, I did a directory enumeration and realized that there was a link for any not found page. Something like this:

![](Pasted%20image%2020240722020632.png)

But when I mouseover on it, i notice the following in the browsere.

![](Pasted%20image%2020240722022039.png)
Note that the domain here is "admirer-gallery.htb". I added this into my host file and ran the wfuzz again to enumerate the subdomain.
![](Pasted%20image%2020240722022149.png)

##### Server Side Request Forgery (SSRF)
This box present the Adminer CVE-2021-21311 SSRF Challenge. 

Identify the Hash Type: hashid 8CE6ACD7FC9ABDE377FF1CE332CE1D790E167086

Once I got the ssh session, I can replicate the SSH session of the user using the following command: (I have installed sshpass on kali.)
```
sshpass -p 'bQ3u7^AxzcB7qAsxE3' ssh jennifer@10.10.11.137
```