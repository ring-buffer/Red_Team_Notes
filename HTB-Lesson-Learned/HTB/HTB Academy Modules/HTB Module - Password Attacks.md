## Credentials Storage 

1. How Rockyou.txt was created?
	This list includes about 14 million unique passwords, and it was created after a data breach of the company RockYou, which contained a total of 32 million user accounts. The RockYou company stored all the credentials in plain text in their database, which the attackers could view. after a successful SQL injection attack.

#### Linux

Passwords are stored in an encrypted file. This is called Shadow file located in /etc/shadow. Here's the format of the shadow file.
```
$>cat /etc/shadow
root:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::

start with username root and than :
encrypted password and than :
Day of last change and than :
minimum age of the password and than :
maximum age of the password and than :
warning period and than :
inactivity period and than :
expiration date and than :
```

The encryption of the password in the /etc/shadow file formatted as follows
```
$<id>$<salt>$<hashed>
$y$j9T$3Q...hashed
```

The id $y is the cryptographic hash used to encrypt the password. Following are some of the examples.
```
$y$  --> YesCrypt
$1$  --> MD5
$2a$ --> Bolwfish
..... The list is long ... But the initial value right after the first $ sign up until the second $ sign represent the cryptographic hash used to encrypt the password.
```

The /etc/shadow file can only be read by the root user. On the other hand, there's another file /etc/passwd and /etc/group. 

```
$> cat /etc/passwd
root:x:1000:1000:,,,:/home/root:/bin/bash
root   --> username
x      --> password  
1000   --> uid
1000   --> gid
,,,    --> comment
/home/root --> Home Directory
/bin/bash  --> Shell access 
```

The 'x' in the password indicate that the password are stored in the /etc/shadow file. Group information is stored in /etc/group. The format is similar to that of /etc/passwd, with the entries containing fields for the group name, password, numerical id (gid), and a comma−separated list of group members. An entry in /etc/group looks like this:
```
$> cat /etc/gshadow
pasta:x:103:spagetti,fettucini,linguine,vermicelli
```

#### Windows
