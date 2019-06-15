[EN](./false-disasm.md) | [ZH](./false-disasm-zh.md)
对于一些常用的反汇编器, 如`objdump`, 或是基于`objdump`的反汇编器项目. 都存在一些反汇编的缺陷. 有一些方式可以让`objdump`反汇编出的代码, 并没有那么的准确.

##  跳到一条指令中间

最简单的方法就是利用`jmp`跳转到某一条指令中间执行, 也就是说真实的代码是从某条指令"之中"开始的, 但在反汇编时由于是针对整条指令而不能列出真正被运行的汇编指令代码. 

说起来好像很拗口, 很难懂, 我们来看一个示例吧, 给出以下的汇编代码.

```
start:
	jmp label+1
label: 	
	DB 0x90
	mov eax, 0xf001
```

这段代码`label`所在的第一条指令是`DB 0x90`. 我们来看看`objdump`对这段代码反汇编的结果:

```
08048080 <start>:
  8048080: 	e9 01 00 00 00 	jmp 8048086 <label+0x1>
08048085 <label>:
  8048085: 	90 		nop
  8048086: 	b8 01 f0 00 00 	mov eax,0xf001
```

看起来也没什么问题, `DB 0x90`被准确地反汇编成`90 nop`. 

但是如果我们将`nop`指令修改为1字节以上的指令, 那么objdump就不会跟随我们的jump并正确的反汇编, 而是线性地从上往下继续汇编(线性扫描算法). 比如我将`DB 0x90`改成了`DB 0xE9`, 来看看objdump再次反汇编的结果:

```
08048080 <start>:
  8048080: 	e9 01 00 00 00 	jmp 8048086 <label+0x1>
08048085 <label>:
  8048085: 	e9 b8 01 f0 00 	jmp 8f48242 <__bss_start+0xeff1b6>
```

对比之前的反汇编结果, 你很明显地看出来是什么情况了吧. `DB 0xE9`单纯只是一个数据, 也不会被执行, 而反汇编出的结果, 却将其视作一个指令, 之后的结果也因此而改变了.

objdump`忽略了jmp的目的地址处的代码`并直接汇编jmp后的指令, 这样我们真正的代码也就被很好地"隐藏"了起来

## 解决方法

该如何解决这个问题呢? 看起来最直接的方法就是将这个无用的`0xE9`用十六进制编辑器手动替换成`0x90`. 但是如果程序有进行文件校验, 计算checksum值, 那么这个方法就行不通了. 

所以更好的解决办法是使用如IDA或类似有做控制流分析的反汇编器, 对于同样有问题的程序. 反汇编结果可能如下: 

```
  ---- section .text ----:
08048080 	E9 01 00 00 00 	jmp Label_08048086
			                                    ; (08048086)
			                                    ; (near + 0x1)
08048085 	DB E9

Label_08048086:
08048086	B8 01 F0 00 00	mov eax, 0xF001
			                                    ; xref ( 08048080 ) 
```

反汇编结果看上去还行

## 运行时计算跳转地址

这种方法, 甚至可以对抗分析控制流的反汇编器. 我们可以看一个示例代码, 更好地理解:

```
; ----------------------------------------------------------------------------
    call earth+1
Return:
                    ; x instructions or random bytes here               x byte(s)
earth:              ; earth = Return + x
    xor eax, eax    ; align disassembly, using single byte opcode       1 byte
    pop eax         ; start of function: get return address ( Return )  1 byte
                    ; y instructions or random bytes here               y byte(s)
    add eax, x+2+y+2+1+1+z ; x+y+z+6                                    2 bytes
    push eax        ;                                                   1 byte
    ret             ;                                                   1 byte
                    ; z instructions or random bytes here               z byte(s)
; Code:
                    ; !! Code Continues Here !!
; ----------------------------------------------------------------------------
```

程序通过`call+pop`来获取调用函数当时保存到栈上的返回地址, 其实就是调用函数前的`EIP`. 然后在函数返回处塞入垃圾数据. 但实际上在函数运行时已经将返回地址修改到了Code处. 因此`earth`函数返回会跳转到`Code`处继续运行，而不是`Return`处继续运行.

来看一个简易的demo

```
; ----------------------------------------------------------------------------
	call earth+1
earth: 	
    DB 0xE9 	        ; 1 <--- pushed return address,
		                ; E9 is opcode for jmp to disalign disas-
	; sembly
	pop eax 	        ; 1 hidden
	nop 	            ; 1
	add eax, 9 	        ; 2 hidden
	push eax 	        ; 1 hidden
	ret 	            ; 1 hidden
	DB 0xE9 	        ; 1 opcode for jmp to misalign disassembly
Code: 	                ; code continues here <--- pushed return address + 9
	nop
	nop
	nop
	ret
; ----------------------------------------------------------------------------
```

如果是使用objdump进行反汇编, 光是`call earth+1`就会出现问题, 如下:

```
00000000 <earth-0x5>:
  0: 	e8 01 00 00 00 	call 6 <earth+0x1>
00000005 <earth>:
  5: 	e9 58 90 05 09 	jmp 9059062 <earth+0x905905d>
  a: 	00 00 		    add %al,(%eax)
  c: 	00 50 c3 		add %dl,0xffffffc3(%eax)
  f: 	e9 90 90 90 c3 	jmp c39090a4 <earth+0xc390909f>
```

来看一下`ida`的情况

```
text:08000000 	; Segment permissions: Read/Execute
.text:08000000	 _text 	segment para public 'CODE' use32
.text:08000000 		assume cs:_text
.text:08000000 		;org 8000000h
.text:08000000 		assume 	es:nothing, ss:nothing, ds:_text,
.text:08000000 			fs:nothing, gs:nothing
.text:08000000 		dd 1E8h
.text:08000004 ; -------------------------------------------------------------
.text:08000004 		add cl, ch
.text:08000006 		pop eax
.text:08000007 		nop
.text:08000008 		add eax, 9
.text:0800000D 		push eax
.text:0800000E 		retn
.text:0800000E ; -------------------------------------------------------------
.text:0800000F 		dd 909090E9h
.text:08000013 ; -------------------------------------------------------------
.text:08000013 		retn
.text:08000013 _text 		ends
.text:08000013
.text:08000013
.text:08000013 		end
```

我们在最后的3个`nop`, 都被很好的隐藏起来. 不仅如此, 我们计算`EIP`的过程也被完美的隐藏了起来. 实际上整个反汇编的代码已经跟实际代码完全不同.

如何解决这项问题? 实际上并没有能够保证`100%`准确反汇编的工具, 当反汇编器做到代码模拟执行的时候也许能做到完全正确的汇编.

在现实情况, 这并不是特别大的问题. 因为针对交互性反汇编器. 你是可以指定代码起始的位置. 而且当调试的时候, 也能很好的看明白程序实际跳转的地址.

所以此时我们除开需要静态分析, 也需要动态调试.




> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)


