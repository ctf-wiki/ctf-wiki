[EN](./intof.md) | [ZH](./intof-zh.md)
---

typora-root-url: ../../../docs

---



# integer overflow


## Introduction


In C language, the basic data types of integers are divided into short (short), integer (int), and long (long). These three data types are also divided into signed and unsigned, each data type. They all have their own size ranges (because the size range of the data type is determined by the compiler, so the default is to use gcc-5.4 under 64 bits), as shown below:




| Type | Byte | Range |
| :-: | :-: | :-: |

| short int | 2byte(word) | 0\~32767(0\~0x7fff) <br> -32768\~-1(0x8000\~0xffff)  |

| unsigned short int | 2byte(word) | 0\~65535(0\~0xffff) |

| int | 4byte(dword) | 0\~2147483647(0\~0x7fffffff) <br> -2147483648\~-1(0x80000000\~0xffffffff) |

| unsigned int | 4byte(dword) | 0\~4294967295(0\~0xffffffff) |

| long int | 8byte(qword) | 正: 0\~0x7fffffffffffffff <br> Negative: 0x8000000000000000\~0xffffffffffffffff |
| unsigned long int | 8byte(qword) | 0\~0xffffffffffffffff |



When the data in the program exceeds the range of its data type, it will cause an overflow, and the overflow of the integer type is called integer overflow.


## Principle


Next, the principle of integer overflow is briefly explained.


### Upper bound overflow


```

# Fake code
short int a;



a = a + 1;

# corresponding assembly
movzx eax, word ptr [rbp - 0x1c]
add    eax, 1

mov word ptr [rbp - 0x1c], ax


unsigned short int b;



b = b + 1;

# assembly code

add    word ptr [rbp - 0x1a], 1

``` 



There are two cases of upper bound overflow, one is `0x7fff + 1` and the other is `0xffff + 1`.


Because the underlying instructions of the computer are not distinguishable between signed and unsigned, the data exists in binary form (the compiler level distinguishes between signed and unsigned, resulting in different assembly instructions).


So `add 0x7fff, 1 == 0x8000`, this upper bound overflow has no effect on unsigned integers, but in signed short integers, `0x7fff` means `32767`, but `0x8000` It is `-32768`, which is represented by a mathematical expression in the signed short integer `32767+1 == -32768`.


The second case is `add 0xffff, 1`. In this case, the first operand is considered.


For example, the assembly code for the signed addition above is `add eax, 1`, because `eax=0xffff`, so `add eax, 1 == 0x10000`, but the unsigned assembly code is to add the memory `add Word ptr [rbp - 0x1a], 1 == 0x0000`.


In the signed addition, although the result of `eax` is 0x10000, only the value of `ax=0x0000` is stored in the memory, and the result is the same as the unsigned.


Look at the result of this overflow from the digital level. In the signed short integer, `0xffff==-1, -1 + 1 == 0`, this calculation is no problem from a signed one.


But in an unsigned short, `0xffff == 65535, 65535 + 1 == 0`.


### 下界溢


The next overflow is the same as the upper bound overflow. In the assembly code, just replace `add` with `sub`.


There are two cases as well:


The first is `sub 0x0000, 1 == 0xffff`, which is ok for signed `0 - 1 == -1`, but for unsigned it becomes `0 - 1 == 65535`.


The second is `sub 0x8000, 1 == 0x7fff`, for unsigned it is `32768 - 1 == 32767` is correct, but for signed it becomes `-32768 - 1 = 32767` .


## example


In the vulnerability of the integer overflow I have seen, I think it can be summarized in two cases.


### Unrestricted range


This situation is well understood. For example, if you have a fixed-size bucket, pour water into it. If you don&#39;t limit how much water is poured, the water will overflow from the bucket.


A thing of a fixed size, you do not constrain it, can have unpredictable consequences.


Simply write an example:


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
scanf (&quot;% wool&quot;, &amp; data_len);
    

len = data_len + header_len
buf = malloc (read);
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



Only apply `0x20` size heap, but can input `0xffffffff` length data, from integer overflow to heap overflow


### Wrong type conversion


Even if the correct constraints on the variables, there is still the possibility of integer overflow vulnerabilities, I think can be summarized as the wrong type conversion, if you continue to subdivide, you can be divided into:


1. A large range of variables is assigned to a small range of variables


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



The above code is a large variable (long integer a), which is a variable with a small range (integer variable n) after passing the check function, causing an integer overflow.


The long integer has 8 bytes of memory space, while the integer has only 4 bytes of memory space, so when long -&gt; int, it will cause truncation, and only the low 4 bytes of the long integer will be passed to the integer variable.


In the above example, put `long: 0x100000000 -&gt; int: 0x00000000`.


But when a smaller variable can completely pass the value to a larger variable without causing data loss.


2. Only unilateral restrictions


This case is only for signed types


```c

$ cat test3.c

int main(void)

{

int len, l;
    char buf[11];



scanf (&quot;% d&quot;, &amp; len);
if (len &lt;10) {
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



On the surface, we have limited the variable len, but if you think about it, you can see that len is a signed integer, so the length of len can be negative, but in the read function, the type of the third parameter is `size_t` , the type is equivalent to `unsigned long int`, which is an unsigned long integer


The two cases in the above example have a commonality, that is, the formal parameters of the function and the types of the actual parameters are different, so I think it can be summarized as the wrong type conversion.


## CTF example


Title: [Pwnhub Story&#39;s Beginning Cal] (http://atum.li/2016/12/05/calc/)



