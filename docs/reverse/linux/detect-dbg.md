[EN](./detect-dbg.md) | [ZH](./detect-dbg-zh.md)
There are many ways to detect the debugger, such as detecting the process name. Here we introduce a method to detect whether the program is currently being debugged by detecting the call of some functions.


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



A process can only be ptrace by a process. If you call ptrace yourself, other programs cannot debug through ptrace or inject code into your program.


If the program is currently being debugged by gdb, the ptrace function will return an error, which indicates that the debugger is detected.


## Bypass Method 1


Obviously ptrace can only be used with debuggers that use ptrace, we can use debuggers that don&#39;t use ptrace.


We can also erase the ptrace function by patching. The simpler is to erase the ptrace call code or the subsequent checksum.


If the executable (which is unlikely in the real world) does not have the -s option enabled at compile time (the -s option removes all symbol table information and relocation information), then the situation becomes much simpler. We are from this Simple situation to analyze


```

# objdump -t test_debug | grep ptrace

080482c0 	F *UND* 	00000075 	ptrace@@GLIBC_2.0

```



Ptrace is called at `0x080482c0`


```

# objdump -d -M intel test_debug |grep 80482c0

80482c0: 	ff 25 04 96 04 08 	jmp ds:0x8049604

80483d4: 	e8 e7 fe ff ff 	call 80482c0 <_init+0x28>

```



If there is the -s option enabled, what should I do? At this point we need to use gdb


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

0x400e02fc <ptrace+12> : move 0xc (% ebp),% ecx
------------------------------------------------------------------------------

Breakpoint 1, 0x400e02f0 in ptrace () from /lib/tls/libc.so.6

```



We simply broke at ptrace, now enter finish to return to the current function, back to the main function


```

# gdb test_debug

gdb> finish

00x80483d9 <main+29>: 	add $0x10,%esp

0x80483dc   <main+32>: 	test %eax,%eax

0x80483de <main+34> : Jus 0x80483fa <main+62>
0x80483e0   <main+36>: 	sub $0xc,%esp

0x80483e3   <main+39>: 	push $0x80484e8

0x80483e8   <main+44>: 	call 0x80482e0

------------------------------------------------------------------------------

0x080483d9 in main ()

```



Modify the function return result eax to the correct return result, you can


```

gdb> set $eax=0

gdb&gt; c
everything ok

Program exited with code 016.

_______________________________________________________________________________

No registers.

gdb>

```



## Bypass Method 2


Method 2 is to write your own ptrace function


As mentioned in the previous sections, the `LD_PRELOAD` environment variable can point the executable to our own ptrace function.


We write a ptrace function and generate the target file


``` c

// -- ptrace.c --

// gcc -shared ptrace.c -o ptrace.so

int ptrace(int i, int j, int k, int l)

{

	printf(" PTRACE CALLED!\n");

}

```



We can then use our own ptrace function by setting the environment variable LD_PRELOAD, which can be set in gdb.


```

gdb> set environment LD_PRELOAD ./ptrace.so

gdb> run

PTRACE CALLED!

Hello World!

Program exited with code 015.

gdb>

```



You can see that the program can&#39;t detect the debugger.






> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)






