# DC416-Baffle
[Link to vulnhub](https://www.vulnhub.com/entry/dc416-2016,168/)

## Reconnaissance
I start with reconnaissance to find the target because it has been set to receive DHCP
```
nmap -sS -O 192.168.159.0/24
```
I found the target at **192.168.159.133**. Now I start enumerate services running on that host.

## Enumeration
```
root@BOEING# nmap -A -T4 -p- 192.168.159.133

Starting Nmap 7.25BETA1 ( https://nmap.org ) at 2017-03-04 09:18 PST
Nmap scan report for 192.168.159.133
Host is up (0.00057s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 34:b3:3e:f7:50:91:51:6f:0b:e2:35:7b:d1:34:a1:eb (DSA)
|   2048 b9:a9:a8:bc:db:7d:77:e4:ae:31:1c:16:4f:3b:8b:de (RSA)
|_  256 88:3f:60:bb:9e:49:53:e3:f7:bb:30:84:7f:a8:f0:17 (ECDSA)
80/tcp   open  http     nginx 1.6.2
| http-git: 
|   192.168.159.133:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Trashed my code, but deployed the product anyway. 
|_http-server-header: nginx/1.6.2
|_http-title: baffle
6969/tcp open  acmsoda?
MAC Address: 00:0C:29:3A:D1:1A (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.4
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.57 ms 192.168.159.133

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.14 seconds
```

From the result of Nmap, I found that the target was running 3 services
* SSH running on TCP port 22
* HTTP running on TCP port 80
* acmsoda (what is this service?) running on TCP port 6969

### Engagement Rules
First of all, I checked for a simple page /index.html on 192.168.159.133 then I found the instruction of this machine.
```
DC416 : baffle
Engagement Rules:

* No username/password bruteforcing is necessary
* This box has 5 flags
* Flags are in FLAG{} format
* The goal is not to get root. Get the flags and move on
* Have fun
```

I found git repository was stored on **/.git/**, I checked for this first. But even /.git existed I still could not clone this repository.
```
root@BOEING# git clone http://192.168.159.133/.git
Cloning into '192.168.159.133'...
fatal: repository 'http://192.168.159.133/.git/' not found
```

I used **wget -r http://<i></i>192.168.159.133/.git/** to recursive download all page on /.git
```
root@BOEING# ls -al
total 56
drwxr-xr-x  8 root root 4096 Mar  4 09:26 .
drwxr-xr-x  3 root root 4096 Mar  4 09:26 ..
drwxr-xr-x  2 root root 4096 Mar  4 09:26 branches
-rw-r--r--  1 root root   50 Oct 17 11:58 COMMIT_EDITMSG
-rw-r--r--  1 root root   92 Oct 17 11:12 config
-rw-r--r--  1 root root   73 Oct 17 11:12 description
-rw-r--r--  1 root root   23 Oct 17 11:12 HEAD
drwxr-xr-x  2 root root 4096 Mar  4 09:26 hooks
-rw-r--r--  1 root root  112 Oct 17 11:57 index
-rw-r--r--  1 root root 1394 Mar  4 09:26 index.html
drwxr-xr-x  2 root root 4096 Mar  4 09:26 info
drwxr-xr-x  3 root root 4096 Mar  4 09:26 logs
drwxr-xr-x 22 root root 4096 Mar  4 09:26 objects
drwxr-xr-x  4 root root 4096 Mar  4 09:26 refs
```

Checked for git's log by using command **git log** on dowloaded /.git directory.
```
root@BOEING# git log
commit 8bde72465957415c12ab6f89ff679f8f9e7c5c7a
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:58:02 2016 -0400

    Trashed my code, but deployed the product anyway.

commit d38ce2e28e32aa7787d5e8a2cb83d3f75c988eca
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:55:07 2016 -0400

    Some assembly required

commit 9b5c226d15d611d6957f3fda7c993186270a6cc4
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:52:40 2016 -0400

    Made it into a write-type-thing instead

commit 06483346fab91b2b17471074a887ac7dffd9ceda
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:44:25 2016 -0400

    My cat danced on the keyboard

commit 7edc47a1c3e4dc880a7191915bdbf1565c6b7441
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:37:14 2016 -0400

    This coder turned coffee into code. You won't believe how she did it!

commit d7a1f067a2f4ac469bc4cf77c689a34e2286b665
Author: alice <alice@baffle.me>
Date:   Mon Oct 17 14:30:20 2016 -0400

    Hello, friend...
```

I clone git from local downloaded page.
```
root@BOEING# pwd
/kapi/vulnhub/dc416-baffle/192.168.159.133/.git
root@BOEING# cd ..
root@BOEING# ls -al
total 64
drwxr-xr-x 3 root root  4096 Mar  4 09:26 .
drwxr-xr-x 3 root root  4096 Mar  4 09:26 ..
drwxr-xr-x 8 root root  4096 Mar  4 09:26 .git
-rw-r--r-- 1 root root   570 Oct 20 14:33 index.html
-rw-r--r-- 1 root root 44867 Mar 21  2015 logo.png
-rw-r--r-- 1 root root   256 Oct 20 14:36 styles.css
root@BOEING# git clone .git baffle_git
Cloning into 'baffle_git'...
done.
```

Now I saw hellofriend.c
```
root@BOEING# cd baffle_git/
root@BOEING# ls -al
total 16
drwxr-xr-x 3 root root 4096 Mar  4 09:33 .
drwxr-xr-x 4 root root 4096 Mar  4 09:33 ..
drwxr-xr-x 8 root root 4096 Mar  4 09:33 .git
-rw-r--r-- 1 root root  616 Mar  4 09:33 hellofriend.c
```

Check it out.
```
root@BOEING# cat hellofriend.c 
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char to_write[500]; 

int parse_request(char *req, int n) {
    char data[500]; 
    char file[500]; 
    char file_content[500]; 
    int file_len; 
    int req_type; 
    char mode[10];
    char *ptr = req; 
    FILE *fp;

    if (req_type == 0x01) {
        /* todo */
    }
    if (req_type == 0x2) {
        /* todo */
    }
    return 0; 
}

int main(int argc, char *argv[]) {
    char buf[2000];
    int n; 

    setbuf(stdout, 0); 

    memset(buf, 0, sizeof(buf)); 
    n = read(0, buf, sizeof(buf)); 
    parse_request(buf, n);

    return 0; 
}
```

To see complete git log of each commit use: **git log -p**

When I checked for all commits I found the commit **06483346fab91b2b17471074a887ac7dffd9ceda** has abnormal character case.
Including of the comment of commit **My cat danced on the keyboard**.

I checked out commit 06483346fab91b2b17471074a887ac7dffd9ceda
```
root@BOEING# git checkout 06483346fab91b2b17471074a887ac7dffd9ceda
root@BOEING# cat hellofriend.c 
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int parse_request(char *req, int n) {
    char file[500]; 
    char file_content[500]; 
    int file_len; 
    char *ptr = req; 
    FILE *fp;
    
    memset(file, 0, sizeof(file)); 

    ptr = (char *)ptr + 2;
    FiLe_len = n - 2 - 5 - 2; 
    memcpy(file, ptr, file_len); 

    fp = fopen(file, "r"); 
    if (fp) {
        memset(file_content, 0, sizeof(file_content)); 
        fgets(file_content, sizeof(file_content), fp); 
        printf("%s", file_content); 
    }
    return 0; 
}

int mAin(int arGc, char *argv[]) {
    char buf[2000];
    int n; 

    setbuf(stdout, 0); 

    memset(buf, 0, sizeof(buf)); 
    n = read(0, buf, sizeof(buf)); 
    p{ARSE_REQUEST}(buf, n);

    return 0; 
}
```

I check for only upper case of the file hellofriend.c
```
root@BOEING# grep -Eo "[A-Z]" hellofriend.c
FILEFLAGARSEREQUEST
```

I look like flag. I extracted it manually.
### 1st FLAG.
```
FLAG{ARSE_REQUEST}
```

## Exploitation
###  Shellshock PoC
## Escalation
## Another way to get root
## Find the flag
### For other information