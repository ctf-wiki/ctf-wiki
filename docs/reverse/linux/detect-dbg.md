检测调试器的方法很多, 比如检测进程名之类. 这里我们介绍一种方法, 就是通过检测一些函数的调用情况来分析程序当前是否处于被调试状态

```c 
int main()
{
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
		printf("DEBUGGING... Bye\n");
		return 1;
	}
	printf("Hello\n");
	return 0;
}
```

一个进程只能被一个进程ptrace, 如果你自己调用ptrace, 那么其它程序就无法通过ptrace调试或向你的程序注入代码. 

如果程序当前被gdb调试, 那么ptrace函数就会返回错误, 也就侧面表明了检测到了调试器的存在.

## 绕过方法1

显然ptrace只能作用于使用ptrace的调试器, 我们可以用不使用ptrace的调试器.

我们也可以通过打补丁的方式将ptrace函数擦除, 更简单就是将ptrace的调用代码或是之后的校验给擦除了.

如果可执行文件(实际情况下不太可能)在编译时并没有启用-s选项(-s 选项能移除所有的符号表信息和重定位信息), 那么情况会变得简单很多. 我们从这个简单的情况来分析

```
# objdump -t test_debug | grep ptrace
080482c0 	F *UND* 	00000075 	ptrace@@GLIBC_2.0
```

ptrace在`0x080482c0`位置被调用

```
# objdump -d -M intel test_debug |grep 80482c0
80482c0: 	ff 25 04 96 04 08 	jmp ds:0x8049604
80483d4: 	e8 e7 fe ff ff 	call 80482c0 <_init+0x28>
```

那要是有启用-s选项, 该怎么处理呢? 这时我们需要使用gdb

```
# gdb test_debug
gdb> bp ptrace
Breakpoint 1 at 0x80482c0
gdb> run
Breakpoint 1 at 0x400e02f0
......
0x400e02f0 <ptrace>: push %ebp
0x400e02f1 <ptrace+1>: mov %esp,%ebp
0x400e02f3 <ptrace+3>: sub $0x10,%esp
0x400e02f6 <ptrace+6>: mov %edi,0xfffffffc(%ebp)
0x400e02f9 <ptrace+9>: mov 0x8(%ebp),%edi
0x400e02fc <ptrace+12>: mov 0xc(%ebp),%ecx
------------------------------------------------------------------------------
Breakpoint 1, 0x400e02f0 in ptrace () from /lib/tls/libc.so.6
```

我们简单地断在了ptrace处, 现在输入finish执行到当前函数返回, 回到main函数里

```
# gdb test_debug
gdb> finish
00x80483d9 <main+29>: 	add $0x10,%esp
0x80483dc   <main+32>: 	test %eax,%eax
0x80483de   <main+34>: 	jns 0x80483fa <main+62>
0x80483e0   <main+36>: 	sub $0xc,%esp
0x80483e3   <main+39>: 	push $0x80484e8
0x80483e8   <main+44>: 	call 0x80482e0
------------------------------------------------------------------------------
0x080483d9 in main ()
```

将函数返回结果eax修改为正确的返回结果, 就可以了

```
gdb> set $eax=0
gdb> c
everything ok
Program exited with code 016.
_______________________________________________________________________________
No registers.
gdb>
```

## 绕过方法2

方法2就是编写自己的ptrace函数

如前几篇所述, `LD_PRELOAD`环境变量可以将可执行文件指向我们自己的ptrace函数.

我们写一个ptrace函数并生成目标文件

``` c
// -- ptrace.c --
// gcc -shared ptrace.c -o ptrace.so
int ptrace(int i, int j, int k, int l)
{
	printf(" PTRACE CALLED!\n");
}
```

我们接下来就可以通过设置环境变量LD_PRELOAD来使用我们自己的ptrace函数, 当然这里是可以在gdb中进行设置

```
gdb> set environment LD_PRELOAD ./ptrace.so
gdb> run
PTRACE CALLED!
Hello World!
Program exited with code 015.
gdb>
```

可以看到程序无法检测到调试器了. 



> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)



