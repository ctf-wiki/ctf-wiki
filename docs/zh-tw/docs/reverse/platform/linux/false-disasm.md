# False Disassembly

對於一些常用的反彙編器, 如`objdump`, 或是基於`objdump`的反彙編器項目. 都存在一些反彙編的缺陷. 有一些方式可以讓`objdump`反彙編出的代碼, 並沒有那麼的準確.

##  跳到一條指令中間

最簡單的方法就是利用`jmp`跳轉到某一條指令中間執行, 也就是說真實的代碼是從某條指令"之中"開始的, 但在反彙編時由於是針對整條指令而不能列出真正被運行的彙編指令代碼. 

說起來好像很拗口, 很難懂, 我們來看一個示例吧, 給出以下的彙編代碼.

```
start:
	jmp label+1
label: 	
	DB 0x90
	mov eax, 0xf001
```

這段代碼`label`所在的第一條指令是`DB 0x90`. 我們來看看`objdump`對這段代碼反彙編的結果:

```
08048080 <start>:
  8048080: 	e9 01 00 00 00 	jmp 8048086 <label+0x1>
08048085 <label>:
  8048085: 	90 		nop
  8048086: 	b8 01 f0 00 00 	mov eax,0xf001
```

看起來也沒什麼問題, `DB 0x90`被準確地反彙編成`90 nop`. 

但是如果我們將`nop`指令修改爲1字節以上的指令, 那麼objdump就不會跟隨我們的jump並正確的反彙編, 而是線性地從上往下繼續彙編(線性掃描算法). 比如我將`DB 0x90`改成了`DB 0xE9`, 來看看objdump再次反彙編的結果:

```
08048080 <start>:
  8048080: 	e9 01 00 00 00 	jmp 8048086 <label+0x1>
08048085 <label>:
  8048085: 	e9 b8 01 f0 00 	jmp 8f48242 <__bss_start+0xeff1b6>
```

對比之前的反彙編結果, 你很明顯地看出來是什麼情況了吧. `DB 0xE9`單純只是一個數據, 也不會被執行, 而反彙編出的結果, 卻將其視作一個指令, 之後的結果也因此而改變了.

objdump`忽略了jmp的目的地址處的代碼`並直接彙編jmp後的指令, 這樣我們真正的代碼也就被很好地"隱藏"了起來

## 解決方法

該如何解決這個問題呢? 看起來最直接的方法就是將這個無用的`0xE9`用十六進制編輯器手動替換成`0x90`. 但是如果程序有進行文件校驗, 計算checksum值, 那麼這個方法就行不通了. 

所以更好的解決辦法是使用如IDA或類似有做控制流分析的反彙編器, 對於同樣有問題的程序. 反彙編結果可能如下: 

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

反彙編結果看上去還行

## 運行時計算跳轉地址

這種方法, 甚至可以對抗分析控制流的反彙編器. 我們可以看一個示例代碼, 更好地理解:

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

程序通過`call+pop`來獲取調用函數當時保存到棧上的返回地址, 其實就是調用函數前的`EIP`. 然後在函數返回處塞入垃圾數據. 但實際上在函數運行時已經將返回地址修改到了Code處. 因此`earth`函數返回會跳轉到`Code`處繼續運行，而不是`Return`處繼續運行.

來看一個簡易的demo

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

如果是使用objdump進行反彙編, 光是`call earth+1`就會出現問題, 如下:

```
00000000 <earth-0x5>:
  0: 	e8 01 00 00 00 	call 6 <earth+0x1>
00000005 <earth>:
  5: 	e9 58 90 05 09 	jmp 9059062 <earth+0x905905d>
  a: 	00 00 		    add %al,(%eax)
  c: 	00 50 c3 		add %dl,0xffffffc3(%eax)
  f: 	e9 90 90 90 c3 	jmp c39090a4 <earth+0xc390909f>
```

來看一下`ida`的情況

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

我們在最後的3個`nop`, 都被很好的隱藏起來. 不僅如此, 我們計算`EIP`的過程也被完美的隱藏了起來. 實際上整個反彙編的代碼已經跟實際代碼完全不同.

如何解決這項問題? 實際上並沒有能夠保證`100%`準確反彙編的工具, 當反彙編器做到代碼模擬執行的時候也許能做到完全正確的彙編.

在現實情況, 這並不是特別大的問題. 因爲針對交互性反彙編器. 你是可以指定代碼起始的位置. 而且當調試的時候, 也能很好的看明白程序實際跳轉的地址.

所以此時我們除開需要靜態分析, 也需要動態調試.




> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)


