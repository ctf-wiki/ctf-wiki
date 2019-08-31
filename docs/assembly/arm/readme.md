[EN](./readme.md) | [ZH](./readme-zh.md)
Introduce the basic content of arm.






## 1. arm assembly basis


### 1. LDMIA R0 , {R1,R2,R3,R4}



LDM is: Multi-register &quot;internal access&quot; instruction
IA indicates that R0 is incremented by 1 word after each LDM instruction ends.
The final result is R1 = [R0], R1 = [R0+#4], R1 = [R0+#8], R1 = [R0+#0xC]


### 2. Stack addressing (FA, EA, FD, ED)


STMFD SP! , {R1-R7, LR} @ Push R1~R7 and LR onto the stack
LDMFD SP! , {R1-R7, LR} @ Pop R1~R7 and LR


### 3. Block copy addressing


LDM and STM are instruction prefixes, indicating multi-register addressing, instruction suffixes (IA, DA, IB, DB).
LDMIA R0!, {R1-R3} @Retrieve 3 words from the memory address pointed to by R0 to the R1, R2, R3 registers
STMIA R0!, {R1-R3} @ Stores the contents stored by R1, R2, and R3 in the memory pointed to by R0.


### 4. Relative addressing


```

With the current value of the current program counter PC as the base address, the label mark position is offset, and the two are added together.
To a valid address.




BL NEXT

    ...        

NEXT:

    ...

```



## 2. Instruction set


### 1. Since the arm chip is updated very quickly, there are many instruction sets. The most common ones are the arm instruction set and the Thumb instruction set.






### 2. Jump instruction


Arm implements two types of jumps, one is to use jump instructions directly, and the other is to directly assign values to PC registers.


#### 1. B jump instruction


```

Structure B{cond} label
Jump directly, such as `BNE LABEL`
```



#### 2. BL jump instruction


```

Structure BL{cond} label
When the BL instruction is executed, if the condition is satisfied, the address of the next instruction of the current instruction is first assigned to the R14 register (LR).
Then jump to the address marked by the label to continue execution. Generally used in process calls, after the process is over, return via `MOV PC, LR`
```



#### 3. BX jump instruction with state switching


```

Structure BX{cond}Rm
When the BX instruction is executed, if the condition is satisfied, it will judge whether the bit [0] of the Rm register is 1, and if it is 1, the T flag of the CPSR register is automatically set to 1 at the time of the jump, and the instruction at the target position is Resolved as a Thumb instruction. Conversely, if bit [0] of the Rm register is 0, the T flag of the CPSR register is reset and the instruction at the target position is interpreted as an arm instruction.
```



as follows:


```

ADR R0, thumbcode + 1

BX R0 @ Jump to thumbcode. And the processor runs in thumb mode
thumbcode:

.code 16

```







#### 4.BLX jump instruction with link and state switch


```

Structure BLX{cond}Rm
The BLX instruction aggregates the functions of BL and BX, and simultaneously saves the return address to R14 (LR) on the function of BX.
```



### 3. Register access instruction


Memory access instruction operations include loading data from a memory area, storing data to a memory, exchanging data between registers and memory, and the like.


#### `LDR`


Put the data in memory into the register


Example of instruction:


```

LDRH R0, [R1] ; Read halfword data with memory address R1 into register R0 and clear the upper 16 bits of R0.
LDRH R0, [R1, #8] ; Read halfword data with memory address R1+8 into register R0 and clear the upper 16 bits of R0.
LDRH R0, [R1, R2] ; Read halfword data with memory address R1+R2 into register R0 and clear the upper 16 bits of R0.
```





#### `STR`


The STR is used to store data to an address. The format is as follows:
STR{type}{cond}Rd,label

Harden {cond} Rd, Rd2, label
The usage is as follows:
`STR R0,[R2,#04]` Store the value of R0 at the address of R2+4


#### `LDM`



```

LDM{addr_mode}{cond}Rn{!}reglist

```



This instruction is to allocate the data in the stack in memory to the register in batches, that is, the pop operation.


&gt; Special note, ! is an optional suffix. If there is! Then the final address will be written back to the Rn register.


#### `STM`


The STM stores the data of a register list into a specified address location. Format is as follows


```

STM{addr_mod}{cond}Rn{!}reglist
```



#### `PUSH&&POP`



The format is as follows:
PUSH {cond} reglist
POP {cond}
Stack operation instruction


```

PUSH {r0,r4-r7}

POP {r0,r4-r7}

```







#### `SWP`


### Data exchange between registers.


The format is `SWP{B}{cond}Rd,Rm,[Rn]`
B is an optional byte. If there is B, the byte is exchanged. Otherwise, the word is exchanged.
Rd is a temporarily stored register, and Rm is the value to be replaced.
Rn is the data address of `to be replaced&#39;


### Reference link


[arm instruction learning] (https://ring3.xyz/2017/03/05/[%E9%80%86%E5%90%91%E7%AF%87]arm%E6%8C%87%E4% BB%A4%E5%AD%A6%E4%B9%A0/)


[Common arm command] (http://www.51-arm.com/upload/ARM_%E6%8C%87%E4%BB%A4.pdf)


[arm-opcode-map](http://imrannazar.com/ARM-Opcode-Map)


