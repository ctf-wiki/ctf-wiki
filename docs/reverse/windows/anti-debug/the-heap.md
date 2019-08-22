[EN](./the-heap.md) | [ZH](./the-heap-zh.md)
When the heap is initialized, it will check `heap flags` and make additional changes to the environment depending on the presence or absence of some flags. Like `Themida`, this method is used to detect the debugger.


such as:


* If the `HEAP_TAIL_CHECKING_ENABLED` flag is set (see the `Heap Flags` section), then in the 32-bit windows, 2 `0xABABABAB` will be appended to the end of the allocated heap block (the 64-bit environment is 4).
* If the `HEAP_FREE_CHECKING_ENABLED` (see the `Heap Flags` section) flag is set, then when extra bytes are needed to fill the end of the heap block, it will be filled with `0xFEEEFEEE` (or part)


So, a new way to detect the debugger is to check these values.


## heap pointer is known


If a heap pointer is known, then we can directly check the data in the heap. However, in Windows Vista and later, the heap protection mechanism (both 32-bit/64-bit) is used, using an XOR. The key is used to encrypt the heap size. Although you can choose whether to use the key, but the default is used. And the location of the heap header, in `Windows NT/2000/XP` and `Windows Vista and higher. `There is also a difference between them. So we also need to take the `Windows version` into account.


The following 32-bit code can be used to detect a 32-bit environment:


`` `asm
    xor ebx, ebx

    call GetVersion

cmp al, 6
    sbb ebp, ebp

    jb l1

    ;Process Environment Block

    mov eax, fs:[ebx+30h]

    mov eax, [eax+18h] ;get process heap base

    mov ecx, [eax+24h] ;check for protected heap

    jecxz l1

mov ecx, [ecx]
    test [eax+4ch], ecx

    cmovne ebx, [eax+50h] ;conditionally get heap key

l1: mov eax, <heap ptr>

    movzx edx, w [eax-8] ;size

    xor dx, bx

    movzx ecx, b [eax+ebp-1] ;overhead

under it, ecx
    lea edi, [edx*8+eax]

mov al, 0abh
    mov cl, 8

Repe scasb
    je being_debugged

```



Or use the following 64-bit code to detect a 64-bit environment:


```

    xor ebx, ebx

    call GetVersion

cmp al, 6
sbb rbp, rbp
    jb l1

    ;Process Environment Block

    mov rax, gs:[rbx+60h]

    mov eax, [rax+30h] ;get process heap base

    mov ecx, [rax+40h] ;check for protected heap

jrcxz l1
mov ecx, [RCX + 8]
test [rax + 7ch], ecx
    cmovne ebx, [rax+88h] ;conditionally get heap key

l1: mov eax, <heap ptr>

    movzx edx, w [rax-8] ;size

    xor dx, bx

    add edx, edx

    movzx ecx, b [rax+rbp-1] ;overhead

under it, ecx
Lea, [rdx * 8 + rax]
mov al, 0abh
    mov cl, 10h

Repe scasb
    je being_debugged

```



There is no example of using a 32-bit code to detect a 64-bit environment, since a 64-bit heap cannot be parsed by a 32-bit heap function.




## heap pointer unknown


If we don&#39;t know the heap pointer, we can use the `HenelWalk()` function of `kernel32` or the `RtlWalkHeap()` function of `ntdll` (or even the `GetCommandLine()` function of `kernel32`). The returned heap The size value will be automatically decrypted, so you don&#39;t need to care about the version of windows anymore.


The following 32-bit code can be used to detect a 32-bit environment:


`` `asm
    mov ebx, offset l2

    ;get a pointer to a heap block

l1: push ebx

    mov eax, fs:[30h] ;Process Environment Block

    push d [eax+18h] ;save process heap base

    call HeapWalk

    cmp w [ebx+0ah], 4 ;find allocated block

jne l1
    mov edi, [ebx] ;data pointer

    add edi, [ebx+4] ;data size

mov al, 0abh
    push 8

pop ecx
Repe scasb
    je being_debugged

    ...

l2: db 1ch dup (0) ;sizeof(PROCESS_HEAP_ENTRY)

```



Or use the following 64-bit code to detect a 64-bit environment:


`` `asm
mov rbx, offset l2
    ;get a pointer to a heap block

l1: push rbx

    pop rdx

    push 60h

pop rsi
    gs:lodsq ;Process Environment Block

    ;get a pointer to process heap base

mov ecx, [rax + 30h]
    call HeapWalk

    cmp w [rbx+0eh], 4 ;find allocated block

jne l1
    mov edi, [rbx] ;data pointer

    add edi, [rbx+8] ;data size

mov al, 0abh
    push 10h

    pop rcx

Repe scasb
    je being_debugged

    ...

l2: db 28h dup (0) ;sizeof(PROCESS_HEAP_ENTRY)

```



There is no example of using a 32-bit code to detect a 64-bit environment, since a 64-bit heap cannot be parsed by a 32-bit heap function.

