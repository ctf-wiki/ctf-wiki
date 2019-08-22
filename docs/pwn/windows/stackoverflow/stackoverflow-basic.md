[EN](./stackoverflow-basic.md) | [ZH](./stackoverflow-basic-zh.md)
#Stack overflow principle


## Introduction


For an introduction to the stack, read the introduction in [Linux Pwn] (https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stack-intro/).






## Basic example


A typical example is given below, in which the last byte overflow occurs due to the order of the variable declarations and the size of the buffer declaration.


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

char password [128];
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



This is a simple password verification program that will determine if the input string is equal to 666666. Use vc6.0 to compile this program. After successful, use winchecksec to view the protection that was opened. It can be seen that GS is turned on, but this does not hinder our overflow.


```

C:\Users\CarlStar\Desktop>winchecksec.exe demo1.exe

Dynamic Base    : false

ASLR            : true

High Entropy VA : false

Force Integrity : false

Isolation       : true

NX              : true

SEH: true
CFG             : false

RFG             : false

SafeSEH         : true

GS              : true

Authenticode    : false

.NET            : true

```



Use OllyDbg to dynamically debug this program, enter aaaaaa and see the normal execution flow of the program. To make it easier to understand the whole process, the next breakpoint is executed after the **strcmp** function and **strcpy** are executed.


![demo1](./figure/demo1-1.png)



Now let the program run, after entering aaaaaa, the program will execute to the first breakpoint under us. Go to the **strcmp** function and observe its return value. Because the ascii code value of a is greater than the ascii code value of 6, no unexpected function will return **1**, the return value under x86 is saved in the EAX register, after the function returns normally, the rest of the function will be used because the program completes it. These registers, so this return value will be stored on the stack, which is **ss:[0012FEA0]**.


![demo2](./figure/demo1-2.png)



! [demo3] (./ figure / demo1-3.png)


When executing to the second breakpoint, look at the stack structure. Where 61 is the ascii code form we entered a, and **00** is the string terminator. Then the size of **buffer** is 8 bytes. If we enter 8 a, the last string terminator will overflow to **0012FEA0**. This position overwrites the original value to 0, so we can change The execution flow of the program, output Congratulation! You have passed the verification!


```

0012FE90   CCCCCCCC

0012FE94   CCCCCCCC

0012FE98   61616161

0012FE9C   CC006161

0012FEA0   00000001

```



Ok, let&#39;s let the program run normally.


![demo4](./figure/demo1-4.png)



This time we enter 8 a to verify if we think the same: ** The end of the string will overflow to the return value of strcmp**. You can see that the return value of strcmp is still 1.


![demo5](./figure/demo1-5.png)



Continue to the second breakpoint and look at the current stack value. The return value of **strcmp has been successfully overflowed from 1 to 0 **.


```

0012FE90   CCCCCCCC

0012FE94   CCCCCCCC

0012FE98   61616161

0012FE9C   61616161

0012FEA0   00000000

```



At this time, let the program continue to run, and successfully output the expected string.


![demo6](./figure/demo1-6.png)







## Reference reading


[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow)



[0day security: software vulnerability analysis technology] ()


[Winchecksec](https://github.com/trailofbits/winchecksec)


