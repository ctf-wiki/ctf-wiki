[EN](./intof.md) | [ZH](./intof-zh.md)
---
typora-root-url: ../../../docs
---

# 整数溢出

## 介绍

在C语言中，整数的基本数据类型分为短整型(short)，整型(int)，长整型(long)，这三个数据类型还分为有符号和无符号，每种数据类型都有各自的大小范围，(因为数据类型的大小范围是编译器决定的，所以之后所述都默认是 64 位下使用 gcc-5.4)，如下所示:


| 类型 | 字节 | 范围 |
| :-: | :-: | :-: |
| short int | 2byte(word) | 0\~32767(0\~0x7fff) <br> -32768\~-1(0x8000\~0xffff)  |
| unsigned short int | 2byte(word) | 0\~65535(0\~0xffff) |
| int | 4byte(dword) | 0\~2147483647(0\~0x7fffffff) <br> -2147483648\~-1(0x80000000\~0xffffffff) |
| unsigned int | 4byte(dword) | 0\~4294967295(0\~0xffffffff) |
| long int | 8byte(qword) | 正: 0\~0x7fffffffffffffff <br> 负:0x8000000000000000\~0xffffffffffffffff |
| unsigned long int | 8byte(qword) | 0\~0xffffffffffffffff |

当程序中的数据超过其数据类型的范围，则会造成溢出，整数类型的溢出被称为整数溢出。

## 原理

接下来简单阐述下整数溢出的原理

### 上界溢出

```
# 伪代码
short int a;

a = a + 1;
# 对应的汇编
movzx  eax, word ptr [rbp - 0x1c]
add    eax, 1
mov    word ptr [rbp - 0x1c], ax

unsigned short int b;

b = b + 1;
# assembly code
add    word ptr [rbp - 0x1a], 1
``` 

上界溢出有两种情况，一种是 `0x7fff + 1`， 另一种是 `0xffff + 1`。

因为计算机底层指令是不区分有符号和无符号的，数据都是以二进制形式存在(编译器的层面才对有符号和无符号进行区分，产生不同的汇编指令)。

所以 `add 0x7fff, 1 == 0x8000`，这种上界溢出对无符号整型就没有影响，但是在有符号短整型中，`0x7fff` 表示的是 `32767`，但是 `0x8000` 表示的是 `-32768`，用数学表达式来表示就是在有符号短整型中 `32767+1 == -32768`。

第二种情况是 `add 0xffff, 1`，这种情况需要考虑的是第一个操作数。

比如上面的有符号型加法的汇编代码是 `add eax, 1`，因为 `eax=0xffff`，所以 `add eax, 1 == 0x10000`，但是无符号的汇编代码是对内存进行加法运算 `add word ptr [rbp - 0x1a], 1 == 0x0000`。

在有符号的加法中，虽然 `eax` 的结果为 0x10000，但是只把 `ax=0x0000` 的值储存到了内存中，从结果看和无符号是一样的。

再从数字层面看看这种溢出的结果，在有符号短整型中，`0xffff==-1，-1 + 1 == 0`，从有符号看这种计算没问题。

但是在无符号短整型中，`0xffff == 65535, 65535 + 1 == 0`。

### 下界溢出

下届溢出的道理和上界溢出一样，在汇编代码中，只是把 `add` 替换成了 `sub`。

一样也是有两种情况：

第一种是 `sub 0x0000, 1 == 0xffff`，对于有符号来说 `0 - 1 == -1` 没问题，但是对于无符号来说就成了 `0 - 1 == 65535`。

第二种是 `sub 0x8000, 1 == 0x7fff`，对于无符号来说是 `32768 - 1 == 32767` 是正确的，但是对于有符号来说就变成了 `-32768 - 1 = 32767`。

## 例子

在我见过的整数溢出的漏洞中，我认为可以总结为两种情况。

### 未限制范围

这种情况很好理解，比如有一个固定大小的桶，往里面倒水，如果你没有限制倒入多少水，那么水则会从桶中溢出来。

一个有固定大小的东西，你没有对其进行约束，就会造成不可预期的后果。

简单的写一个示例:

```c
$ cat test.c
#include<stddef.h>
int main(void)
{
    int len;
    int data_len;
    int header_len;
    char *buf;
    
    header_len = 0x10;
    scanf("%uld", &data_len);
    
    len = data_len+header_len
    buf = malloc(len);
    read(0, buf, data_len);
    return 0;
}
$ gcc test.c
$ ./a.out
-1
asdfasfasdfasdfafasfasfasdfasdf
# gdb a.out
► 0x40066d <main+71>    call   malloc@plt <0x400500>
        size: 0xf
```

只申请 `0x20` 大小的堆，但是却能输入 `0xffffffff` 长度的数据，从整型溢出到堆溢出

### 错误的类型转换

即使正确的对变量进行约束，也仍然有可能出现整数溢出漏洞，我认为可以概括为错误的类型转换，如果继续细分下去，可以分为：

1. 范围大的变量赋值给范围小的变量

```c
$ cat test2.c
void check(int n)
{
    if (!n)
        printf("vuln");
    else
        printf("OK");
}

int main(void)
{
    long int a;
    
    scanf("%ld", &a);
    if (a == 0)
        printf("Bad");
    else
        check(a);
    return 0;
}
$ gcc test2.c
$ ./a.out
4294967296
vuln
```

上述代码就是一个范围大的变量(长整型a)，传入 check 函数后变为范围小的变量(整型变量n)，造成整数溢出的例子。

已经长整型的占有 8 byte 的内存空间，而整型只有 4 byte 的内存空间，所以当 long -> int，将会造成截断，只把长整型的低 4byte 的值传给整型变量。

在上述例子中，就是把 `long: 0x100000000 -> int: 0x00000000`。

但是当范围更小的变量就能完全的把值传递给范围更大的变量，而不会造成数据丢失。

2. 只做了单边限制

这种情况只针对有符号类型

```c
$ cat test3.c
int main(void)
{
    int len, l;
    char buf[11];

    scanf("%d", &len);
    if (len < 10) {
        l = read(0, buf, len);
        *(buf+l) = 0;
        puts(buf);
    } else
        printf("Please len < 10");        
}
$ gcc test3.c
$ ./a.out
-1
aaaaaaaaaaaa
aaaaaaaaaaaa
```

从表面上看，我们对变量 len 进行了限制，但是仔细思考可以发现，len 是有符号整型，所以 len 的长度可以为负数，但是在 read 函数中，第三个参数的类型是 `size_t`，该类型相当于 `unsigned long int`，属于无符号长整型

上面举例的两种情况都有一个共性，就是函数的形参和实参的类型不同，所以我认为可以总结为错误的类型转换

## CTF例题

题目：[Pwnhub 故事的开始 calc](http://atum.li/2016/12/05/calc/)


