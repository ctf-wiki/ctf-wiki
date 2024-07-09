# Detecting debugging

檢測調試器的方法很多, 比如檢測進程名之類. 這裏我們介紹一種方法, 就是通過檢測一些函數的調用情況來分析程序當前是否處於被調試狀態

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

一個進程只能被一個進程ptrace, 如果你自己調用ptrace, 那麼其它程序就無法通過ptrace調試或向你的程序注入代碼. 

如果程序當前被gdb調試, 那麼ptrace函數就會返回錯誤, 也就側面表明了檢測到了調試器的存在.

## 繞過方法1

顯然ptrace只能作用於使用ptrace的調試器, 我們可以用不使用ptrace的調試器.

我們也可以通過打補丁的方式將ptrace函數擦除, 更簡單就是將ptrace的調用代碼或是之後的校驗給擦除了.

如果可執行文件(實際情況下不太可能)在編譯時並沒有啓用-s選項(-s 選項能移除所有的符號表信息和重定位信息), 那麼情況會變得簡單很多. 我們從這個簡單的情況來分析

```
# objdump -t test_debug | grep ptrace
080482c0 	F *UND* 	00000075 	ptrace@@GLIBC_2.0
```

ptrace在`0x080482c0`位置被調用

```
# objdump -d -M intel test_debug |grep 80482c0
80482c0: 	ff 25 04 96 04 08 	jmp ds:0x8049604
80483d4: 	e8 e7 fe ff ff 	call 80482c0 <_init+0x28>
```

那要是有啓用-s選項, 該怎麼處理呢? 這時我們需要使用gdb

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

我們簡單地斷在了ptrace處, 現在輸入finish執行到當前函數返回, 回到main函數裏

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

將函數返回結果eax修改爲正確的返回結果, 就可以了

```
gdb> set $eax=0
gdb> c
everything ok
Program exited with code 016.
_______________________________________________________________________________
No registers.
gdb>
```

## 繞過方法2

方法2就是編寫自己的ptrace函數

如前幾篇所述, `LD_PRELOAD`環境變量可以將可執行文件指向我們自己的ptrace函數.

我們寫一個ptrace函數並生成目標文件

``` c
// -- ptrace.c --
// gcc -shared ptrace.c -o ptrace.so
int ptrace(int i, int j, int k, int l)
{
	printf(" PTRACE CALLED!\n");
}
```

我們接下來就可以通過設置環境變量LD_PRELOAD來使用我們自己的ptrace函數, 當然這裏是可以在gdb中進行設置

```
gdb> set environment LD_PRELOAD ./ptrace.so
gdb> run
PTRACE CALLED!
Hello World!
Program exited with code 015.
gdb>
```

可以看到程序無法檢測到調試器了. 



> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)



