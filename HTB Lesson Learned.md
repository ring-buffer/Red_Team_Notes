### AdmirerToo.HTB 

While Solving this box, I did a directory enumeration and realized that there was a link for any not found page. Something like this:
![](Pasted%20image%2020240722020318.png)
But when I mouseover on it, i notice the following in the browsere.
![[Pasted image 20240722014550.png]]
> Notice that the domain is admirer-gallery.htb

So I added "admirer-gallery.htb" into my host file and ran the subdomain enumeration again and got the following results.
![[Pasted image 20240722014745.png]]

so there was a db.admirer-gallery.htb subdomain present. I added that into the host file as well and than tried to access it. Afterwards, I got the login screen for the db.admirer-gallery.htb page.

So that's how it works