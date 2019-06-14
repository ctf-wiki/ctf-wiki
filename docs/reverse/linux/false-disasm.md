[EN](./false-disasm.md) | [ZH](./false-disasm-zh.md)
For some common disassemblers, such as `objdump`, or disassembler projects based on `objdump`, there are some disassembly flaws. There are ways to make `objdump` disassemble the code, not so Accurate.


## Jump to the middle of an instruction


The easiest way is to use `jmp` to jump to the middle of an instruction, that is, the real code starts from &quot;inside&quot; an instruction, but in disassembly it cannot be listed for the entire instruction. The actual assembly instruction code that is being run.


It sounds like a mouthful, it&#39;s hard to understand, let&#39;s look at an example, give the following assembly code.


```

start:

	jmp label+1

label: 	

	DB 0x90

	mov eax, 0xf001

```



The first instruction in the code `label` is `DB 0x90`. Let&#39;s take a look at the result of disassembly of this code by `objdump`:


```

08048080 <start>:

8048080: e9 01 00 00 00 jmp 8048086 <label+0x1>
08048085 <label>:

8048085: 90 nop
  8048086: 	b8 01 f0 00 00 	mov eax,0xf001

```



It seems that there is no problem, `DB 0x90` is accurately disassembled into `90 nop`.


But if we change the `nop` instruction to a command of more than 1 byte, then objdump will not follow our jump and correctly disassemble, but linearly continue to assemble from top to bottom (linear scan algorithm). For example, I Change `DB 0x90` to `DB 0xE9` to see the result of objdump disassembling again:


```

08048080 <start>:

8048080: e9 01 00 00 00 jmp 8048086 <label+0x1>
08048085 <label>:

  8048085: 	e9 b8 01 f0 00 	jmp 8f48242 <__bss_start+0xeff1b6>

```



Compared with the previous disassembly results, you can clearly see what is going on. `DB 0xE9` is just a piece of data, it will not be executed, but the result of disassembly will be treated as an instruction. The result has also changed.


Objdump` ignores the code at the destination address of jmp and directly assembles the instructions after jmp, so that our real code is well &quot;hidden&quot;


## Solution


How to solve this problem? The most straightforward way is to manually replace this useless `0xE9` with a hex editor with `0x90`. But if the program has file checksum, calculate the checksum value, then this The method will not work.


So a better solution is to use a disassembler such as IDA or similar control flow analysis, for programs that are also problematic. The disassembly results might look like this:


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



Disassembly results look okay


## Run time calculation jump address


This method can even counter the disassembler of the analysis control flow. We can look at a sample code to better understand:


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

right ; 1 byte
                    ; z instructions or random bytes here               z byte(s)

; Code:

                    ; !! Code Continues Here !!

; ----------------------------------------------------------------------------

```



The program uses `call+pop` to get the return address that the calling function saved to the stack at the time. It is actually the `EIP` before the function is called. Then the garbage data is stuffed at the function return. But it will actually return when the function is running. The address is modified to Code. So the `earth` function returns to jump to `Code` and continues to run, instead of `Return`.


Look at a simple demo


```

; ----------------------------------------------------------------------------

	call earth+1

earth: 	

    DB 0xE9 	        ; 1 <--- pushed return address,

		                ; E9 is opcode for jmp to disalign disas-

	; sembly

	pop eax 	        ; 1 hidden

NOP ; first
	add eax, 9 	        ; 2 hidden

	push eax 	        ; 1 hidden

right ; 1 hidden
	DB 0xE9 	        ; 1 opcode for jmp to misalign disassembly

Code: 	                ; code continues here <--- pushed return address + 9

NOP
NOP
NOP
right
; ----------------------------------------------------------------------------

```



If you use objdump for disassembly, there will be problems with `call earth+1`, as follows:


```

00000000 <earth-0x5>:

  0: 	e8 01 00 00 00 	call 6 <earth+0x1>

00000005 <earth>:

5: e9 58 90 05 09 jmp 9059062 <earth+0x905905d>
a: 00 00 add% al, (% eax)
  c: 	00 50 c3 		add %dl,0xffffffc3(%eax)

  f: 	e9 90 90 90 c3 	jmp c39090a4 <earth+0xc390909f>

```



Let&#39;s take a look at the case of `ida`


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

.text: 08000007 nop
.text:08000008 		add eax, 9

.text:0800000D 		push eax

.text: 0800000E retn
.text:0800000E ; -------------------------------------------------------------

.text:0800000F 		dd 909090E9h

.text:08000013 ; -------------------------------------------------------------

.text: 08000013 retn
.text:08000013 _text 		ends

.text:08000013

.text:08000013

.text:08000013 		end

```



We are very well hidden in the last three `nop`. Not only that, but our process of calculating `EIP` is also perfectly hidden. In fact, the entire disassembled code is completely different from the actual code.


How to solve this problem? There is actually no tool that can guarantee &#39;100%&#39; accurate disassembly. When the disassembler does code simulation, it may be able to do the correct assembly.


In reality, this is not a particularly big problem. Because it is for the interactive disassembler. You can specify the starting position of the code. And when debugging, you can also see the address of the actual jump of the program.


So at this point we need static analysis, but also need dynamic debugging.








> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)




