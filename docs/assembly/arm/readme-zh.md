[EN](./readme.md) | [ZH](./readme-zh.md)
介绍 arm 基础内容。



## 1. arm汇编基础

### 1. LDMIA R0 , {R1,R2,R3,R4}

LDM为: 多寄存器”内存取”指令
IA表示每次LDM指令结束之后R0增加1个字
最终结果为R1 = [R0], R1 = [R0+#4], R1 = [R0+#8], R1 = [R0+#0xC]

### 2. 堆栈寻址 (FA、EA、FD、ED)

STMFD SP! , {R1-R7,LR} @ 将R1~R7以及LR入栈
LDMFD SP! , {R1-R7,LR} @ 将R1~R7以及LR出栈

### 3. 块拷贝寻址

LDM和STM为指令前缀，表示多寄存器寻址，指令后缀(IA、DA、IB、DB)。
LDMIA R0!, {R1-R3} @从R0所指向的内存地址依次取出3个字到R1、R2、R3寄存器
STMIA R0!, {R1-R3} @将R1、R2、R3所存储的内容依次存放在R0所指向的内存。

### 4. 相对寻址

```
以当前程序计数器PC的当前值为基地址，将标号标记位置为偏移量，两者相加得
到有效地址。


BL NEXT
    ...        
NEXT:
    ...
```

## 2. 指令集

### 1. 由于arm芯片更新很快，所以指令集很多，使用较为普遍的就是arm指令集以及Thumb指令集。



### 2.跳转指令

arm实现了两种跳转类型，一种是直接使用跳转指令，另外一种则是给PC寄存器直接赋值。

#### 1. B跳转指令

```
结构 B{cond} label    
直接跳走，如`BNE LABEL`
```

#### 2. BL跳转指令

```
结构 BL{cond} label    
执行BL指令时，若条件满足，则首先将当前指令的下一条指令的地址赋值给R14寄存器(LR)，然
后跳转到label标记的地址处继续执行。一般用在过程调用中，过程结束之后通过`MOV PC, LR`返回
```

#### 3. BX带状态切换的跳转指令

```
结构 BX{cond}Rm   
当执行BX指令时，如果条件满足，会判断Rm寄存器的位[0]是否为1，如果是1则会在跳转时自动将CPSR寄存器的T标志位置为1,并将目标位置处的指令解析为Thumb指令，相反，若Rm寄存器的位[0]为0，则将CPSR寄存器的T标志位复位，同时将目标位置的指令解析为arm指令。
```

如下:

```
ADR R0, thumbcode + 1
BX R0       @跳转到thumbcode。并且处理器运行为thumb模式
thumbcode:
.code 16
```



#### 4.BLX带链接和状态切换的跳转指令

```
结构 BLX{cond}Rm
BLX指令集合了BL和BX的功能，在BX的功能上同时保存返回地址到R14(LR)
```

### 3.寄存器访问指令

存储器访问指令操作包括从存储区加载数据，存储数据到存储器，寄存器与存储器之间的数据交换等。

#### `LDR`

将内存中的数据放入到寄存器中

指令示例：

```
LDRH R0，[R1]         ；将存储器地址为R1的半字数据读入寄存器R0，并将R0的高16位清零。
LDRH R0，[R1，＃8]    ；将存储器地址为R1＋8的半字数据读入寄存器R0，并将R0的高16位清零。
LDRH R0，[R1，R2]    ；将存储器地址为R1＋R2的半字数据读入寄存器R0，并将R0的高16位清零。
```


#### `STR`

STR用于存储数据到制定地址。格式如下：
STR{type}{cond}Rd,label
STRD{cond}Rd,Rd2,label
用法如下:
`STR R0,[R2,#04]` 将R0的值存储到R2+4的地址处

#### `LDM`

```
LDM{addr_mode}{cond}Rn{!}reglist
```

该指令是将内存中堆栈内的数据，批量的赋值给寄存器，即是出栈操作。

> 特别注意, ! 为可选后缀。如果有 ! 则最终地址会写回到Rn寄存器

#### `STM`

STM将一个寄存器列表的数据存储到指定的地址单元中。格式如下

```
STM{addr_mod}{cond}Rn{!}reglist
```

#### `PUSH&&POP`

格式如下：
PUSH{cond}reglist
POP{cond}reglist
栈操作指令

```
PUSH {r0,r4-r7}
POP {r0,r4-r7}
```



#### `SWP`

### 寄存器之间的数据交换。

格式为`SWP{B}{cond}Rd,Rm,[Rn]`
B是可选的字节，若有B，则交换字节，否则交换字
Rd为临时存放的寄存器，Rm是`要替换`的值
Rn是`要被替换`的数据地址

### 参考链接

[arm 指令学习](https://ring3.xyz/2017/03/05/[%E9%80%86%E5%90%91%E7%AF%87]arm%E6%8C%87%E4%BB%A4%E5%AD%A6%E4%B9%A0/)

[常用arm指令](http://www.51-arm.com/upload/ARM_%E6%8C%87%E4%BB%A4.pdf)

[arm-opcode-map](http://imrannazar.com/ARM-Opcode-Map)

