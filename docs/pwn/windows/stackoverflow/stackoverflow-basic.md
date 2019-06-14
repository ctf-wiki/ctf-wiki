# 栈溢出原理 

## 介绍 

关于栈的介绍，可以阅读 [Linux Pwn](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stack_intro/) 中的介绍。



## 基本示例 

下面给出一个典型例子，在这个例子中由于变量声明的顺序和 buffer 声明的大小导致存在最后一字节的溢出。

```c
#include <stdio.h>
#define PASSWORD "666666"
int verify_password(char *password)
{
	int authenticated;
	char buffer[8];
	authenticated = strcmp(password,PASSWORD);
	strcpy(buffer,password); 
	return authenticated;
}
void main()
{
	int valid_flag =0;
	char password[128];
	while(1)
	{
		printf("please input password:  ");
		scanf("%s",password);
		valid_flag = verify_password(password);
		if (valid_flag !=0)
		{
			printf("incorrect password!\n");
		}
		else
		{
			printf("Congratulation! You have passed the verification!\n");
			break;
		}
	}
}
```

这是一个简单的密码校验程序，会判断输入的字符串是否和666666相等。使用 vc6.0 来编译这个程序，成功后使用 winchecksec 查看所开的防护。可以看到 GS 是开启的，但这并不妨碍我们的溢出。

```
C:\Users\CarlStar\Desktop>winchecksec.exe demo1.exe
Dynamic Base    : false
ASLR            : true
High Entropy VA : false
Force Integrity : false
Isolation       : true
NX              : true
SEH             : true
CFG             : false
RFG             : false
SafeSEH         : true
GS              : true
Authenticode    : false
.NET            : true
```

使用 OllyDbg 动态调试这个程序，输入 aaaaaa 看一下程序正常的执行流程。为了方便理解整个过程，在 **strcmp** 函数和 **strcpy** 执行完后下一个断点。

![demo1](./figure/demo1-1.png)

现在可以让程序运行，输入 aaaaaa 后程序会执行到我们下的第一个断点。进入 **strcmp** 这个函数，观察它的返回值。因为 a 的 ascii 码值大于 6 的 ascii 码值，不出意外函数会返回 **1** ，x86 下返回值保存在 EAX 寄存器中，函数正常返回后，由于程序完成它的其余功能还会使用这些寄存器，所以这个返回值会保存在栈上，也就是 **ss:[0012FEA0]** 这个地方。

![demo2](./figure/demo1-2.png)

![demo3](./figure/demo1-3.png)

当执行到第二个断点时，看一下栈结构。其中 61 是我们输入 a 的 ascii 码形式，**00** 是字符串结束符。那么 **buffer** 的大小是 8 字节，如果我们输入 8 个 a 的话，最后的字符串结束符会溢出到 **0012FEA0** 这个位置把原来的值覆盖为 0，这样我们就可以改变程序的执行流程，输出 Congratulation! You have passed the verification!

```
0012FE90   CCCCCCCC
0012FE94   CCCCCCCC
0012FE98   61616161
0012FE9C   CC006161
0012FEA0   00000001
```

好，我们先让程序正常运行下去。

![demo4](./figure/demo1-4.png)

这次我们输入 8 个 a 验证一下是否如我们想的一样：**字符串的结束符会溢出到 strcmp 的返回值**。可以看到 strcmp 的返回值还是 1。

![demo5](./figure/demo1-5.png)

继续运行到第二个断点处，查看一下当前栈的值。**strcmp的返回值已经成功由 1 溢出为 0 **。

```
0012FE90   CCCCCCCC
0012FE94   CCCCCCCC
0012FE98   61616161
0012FE9C   61616161
0012FEA0   00000000
```

这时候让程序继续运行，成功的输出了预想的字符串。

![demo6](./figure/demo1-6.png)



## 参考阅读 

[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow)

[0day安全：软件漏洞分析技术]()

[Winchecksec](https://github.com/trailofbits/winchecksec)

