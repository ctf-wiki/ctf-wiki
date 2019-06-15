[EN](./detect-bp.md) | [ZH](./detect-bp-zh.md)
Gdb implements a breakpoint by replacing the byte of the destination address with `0xcc`. Here is a simple example of detecting the `int 3` breakpoint:


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



The normal running program will output Hello, but if you set the `cc` breakpoint and run it in the `foo` function, gdb will not be able to break, and will output `BREAKPOINT`.


```

# gdb ./x

gdb> bp foo

Breakpoint 1 at 0x804838c

gdb> run

BREAKPOINT

Program exited with code 01.

```



This is also very simple to bypass, that is, you need to read the assembly code and pay attention to set the breakpoint not at the entrance of the `foo` function. The actual situation depends on where the detection breakpoint is.


The key to this anti-debugging technique for monitoring breakpoints is not how to bypass it, but how to detect it. In this example, it is easy to find that the program also prints out the corresponding information. In actual situations, the program does not Any information will be output, and the breakpoint will not be easily broken. We can use the `perl` script to filter the code for the `0xcc` in the disassembly code for checking.


We can use the perl script to filter the 0xcc code in the disassembly code for checking.




``` perl

#!/usr/bin/perl

while(<>)

{

    if($_ =~ m/([0-9a-f][4]:\s*[0-9a-f \t]*.*0xcc)/ ){ print; }

}

```



show result


```

# objdump -M intel -d xxx | ./antibp.pl

      80483be: 3d cc 00 00 00 cmp eax,0xcc

```



After detection, you can either change 0xcc to 0x00 or 0x90, or do whatever you want.


Changing 0xcc can also cause problems. As mentioned in the previous article, if the program has file verification, then our changes will be detected. If possible, the program does not only detect the function entry point. The entire function is also tested in a loop.


So you can also manually place an `ICEBP(0xF1)` byte into the location you want to break (not `int 3`) with a hex editor. Because `ICEBP` also breaks gdb.






> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)