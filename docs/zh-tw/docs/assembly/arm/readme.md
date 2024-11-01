# ARM

介紹 arm 基礎內容。



## 1. arm彙編基礎

### 1. LDMIA R0 , {R1,R2,R3,R4}

LDM爲: 多寄存器“內存取”指令
IA表示每次LDM指令結束之後R0增加1個字
最終結果爲R1 = [R0], R1 = [R0+#4], R1 = [R0+#8], R1 = [R0+#0xC]

### 2. 堆棧尋址 (FA、EA、FD、ED)

STMFD SP! , {R1-R7,LR} @ 將R1~R7以及LR入棧
LDMFD SP! , {R1-R7,LR} @ 將R1~R7以及LR出棧

### 3. 塊拷貝尋址

LDM和STM爲指令前綴，表示多寄存器尋址，指令後綴(IA、DA、IB、DB)。
LDMIA R0!, {R1-R3} @從R0所指向的內存地址依次取出3個字到R1、R2、R3寄存器
STMIA R0!, {R1-R3} @將R1、R2、R3所存儲的內容依次存放在R0所指向的內存。

### 4. 相對尋址

```
以當前程序計數器PC的當前值爲基地址，將標號標記位置爲偏移量，兩者相加得
到有效地址。


BL NEXT
    ...        
NEXT:
    ...
```

## 2. 指令集

### 1. 由於arm芯片更新很快，所以指令集很多，使用較爲普遍的就是arm指令集以及Thumb指令集。



### 2.跳轉指令

arm實現了兩種跳轉類型，一種是直接使用跳轉指令，另外一種則是給PC寄存器直接賦值。

#### 1. B跳轉指令

```
結構 B{cond} label    
直接跳走，如`BNE LABEL`
```

#### 2. BL跳轉指令

```
結構 BL{cond} label    
執行BL指令時，若條件滿足，則首先將當前指令的下一條指令的地址賦值給R14寄存器(LR)，然
後跳轉到label標記的地址處繼續執行。一般用在過程調用中，過程結束之後通過`MOV PC, LR`返回
```

#### 3. BX帶狀態切換的跳轉指令

```
結構 BX{cond}Rm   
當執行BX指令時，如果條件滿足，會判斷Rm寄存器的位[0]是否爲1，如果是1則會在跳轉時自動將CPSR寄存器的T標誌位置爲1,並將目標位置處的指令解析爲Thumb指令，相反，若Rm寄存器的位[0]爲0，則將CPSR寄存器的T標誌位復位，同時將目標位置的指令解析爲arm指令。
```

如下:

```
ADR R0, thumbcode + 1
BX R0       @跳轉到thumbcode。並且處理器運行爲thumb模式
thumbcode:
.code 16
```



#### 4.BLX帶鏈接和狀態切換的跳轉指令

```
結構 BLX{cond}Rm
BLX指令集合了BL和BX的功能，在BX的功能上同時保存返回地址到R14(LR)
```

### 3.寄存器訪問指令

存儲器訪問指令操作包括從存儲區加載數據，存儲數據到存儲器，寄存器與存儲器之間的數據交換等。

#### `LDR`

將內存中的數據放入到寄存器中

指令示例：

```
LDRH R0，[R1]         ；將存儲器地址爲R1的半字數據讀入寄存器R0，並將R0的高16位清零。
LDRH R0，[R1，＃8]    ；將存儲器地址爲R1＋8的半字數據讀入寄存器R0，並將R0的高16位清零。
LDRH R0，[R1，R2]    ；將存儲器地址爲R1＋R2的半字數據讀入寄存器R0，並將R0的高16位清零。
```


#### `STR`

STR用於存儲數據到制定地址。格式如下：
STR{type}{cond}Rd,label
STRD{cond}Rd,Rd2,label
用法如下:
`STR R0,[R2,#04]` 將R0的值存儲到R2+4的地址處

#### `LDM`

```
LDM{addr_mode}{cond}Rn{!}reglist
```

該指令是將內存中堆棧內的數據，批量的賦值給寄存器，即是出棧操作。

> 特別注意, ! 爲可選後綴。如果有 ! 則最終地址會寫回到Rn寄存器

#### `STM`

STM將一個寄存器列表的數據存儲到指定的地址單元中。格式如下

```
STM{addr_mod}{cond}Rn{!}reglist
```

#### `PUSH&&POP`

格式如下：
PUSH{cond}reglist
POP{cond}reglist
棧操作指令

```
PUSH {r0,r4-r7}
POP {r0,r4-r7}
```



#### `SWP`

### 寄存器之間的數據交換。

格式爲`SWP{B}{cond}Rd,Rm,[Rn]`
B是可選的字節，若有B，則交換字節，否則交換字
Rd爲臨時存放的寄存器，Rm是`要替換`的值
Rn是`要被替換`的數據地址

### 參考鏈接

[arm 指令學習](https://ring3.xyz/2017/03/05/[%E9%80%86%E5%90%91%E7%AF%87]arm%E6%8C%87%E4%BB%A4%E5%AD%A6%E4%B9%A0/)

[常用arm指令](http://www.51-arm.com/upload/ARM_%E6%8C%87%E4%BB%A4.pdf)

[arm-opcode-map](http://imrannazar.com/ARM-Opcode-Map)

