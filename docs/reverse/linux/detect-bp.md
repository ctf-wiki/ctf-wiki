gdb通过替换目标地址的字节为`0xcc`来实现断点, 这里给出一个简单的检测`int 3`断点的示例:

``` c
void foo() {
    printf("Hello\n");
}
int main() {
    if ((*(volatile unsigned *)((unsigned)foo) & 0xff) == 0xcc) {
        printf("BREAKPOINT\n");
        exit(1);
    }
    foo();
}
```

正常运行程序会输出Hello, 但是如果之前有在`foo`函数这里设置`cc`断点并运行, gdb则无法断下, 并会输出`BREAKPOINT`. 

```
# gdb ./x
gdb> bp foo
Breakpoint 1 at 0x804838c
gdb> run
BREAKPOINT
Program exited with code 01.
```

这个要绕过也很简单, 那就是需要阅读汇编代码并注意设置断点不要在`foo`函数入口处. 实际情况就要看检测断点的位置是哪里.

这种监视断点的反调试技术, 关键不在于如何绕过它, 而是在于如何检测它. 在这个示例中可以很轻松的发现, 程序也有打印出相应的信息. 在实际情况中, 程序不会输出任何信息, 断点也无法轻易地断下. 我们可以使用`perl`脚本过滤反汇编代码中有关`0xcc`的代码出来进行检查.

我们可以使用perl脚本过滤反汇编代码中有关0xcc的代码出来进行检查


``` perl
#!/usr/bin/perl
while(<>)
{
    if($_ =~ m/([0-9a-f][4]:\s*[0-9a-f \t]*.*0xcc)/ ){ print; }
}
```

显示结果

```
# objdump -M intel -d xxx | ./antibp.pl
      80483be: 3d cc 00 00 00 cmp eax,0xcc
```

检测到后, 既可以将0xcc修改成0x00或0x90, 也可以做任何你想做的操作.

改变0xcc也同样可能带来问题, 就如上篇介绍一样, 程序如果有进行文件校验, 那么我们的改变是会被检测到的. 可能的情况下, 程序也不只是对函数入口点进行检测, 也会在一个循环里对整个函数进行检测.

因此你也可以用十六进制编辑器手动放置一个`ICEBP(0xF1)`字节到需要断下的位置(而非`int 3`). 因为`ICEBP`也一样能让gdb断下来.



> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)