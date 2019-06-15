[EN](./the-heap.md) | [ZH](./the-heap-zh.md)
堆在初始化时, 会检查`heap flags`, 并视一些标志位的有无设置而对环境作出额外的改变. 像`Themida`就有采用这种方法来检测调试器.

比如:

* 如果设置了`HEAP_TAIL_CHECKING_ENABLED`标志(见`Heap Flags`节), 那么在32位windows中就会在分配的堆块尾部附加2个`0xABABABAB`(64位环境就是4个).
* 如果设置了`HEAP_FREE_CHECKING_ENABLED`(见`Heap Flags`节)标志, 那么当需要额外的字节来填充堆块尾部时, 就会使用`0xFEEEFEEE`(或一部分)来填充

那么, 一种新的检测调试器的方法就是来检查这些值. 

## 堆指针已知

如果已知一个堆指针, 那么我们可以直接检查堆块里的数据. 然而在`Windows Vista`及更高版本中采用了堆保护机制(32位/64位都有), 使用了一个异或密钥来对堆块大小进行了加密. 虽然你可以选择是否使用密钥, 但是默认是使用的. 而且就堆块首部的位置, 在`Windows NT/2000/XP`和`Windows Vista及更高版本`之间也是不相同的. 因此我们还需要将`Windows版本`也考虑在内. 

可以使用以下32位代码来检测32位环境:

``` asm
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
    sub eax, ecx
    lea edi, [edx*8+eax]
    mov al, 0abh
    mov cl, 8
    repe scasb
    je being_debugged
```

或使用以下64位代码检测64位环境:

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
    mov ecx, [rcx+8]
    test [rax+7ch], ecx
    cmovne ebx, [rax+88h] ;conditionally get heap key
l1: mov eax, <heap ptr>
    movzx edx, w [rax-8] ;size
    xor dx, bx
    add edx, edx
    movzx ecx, b [rax+rbp-1] ;overhead
    sub eax, ecx
    lea edi, [rdx*8+rax]
    mov al, 0abh
    mov cl, 10h
    repe scasb
    je being_debugged
```

这里没有使用32位代码检测64位环境的样例, 因为64位的堆无法由32位的堆函数解析.


## 堆指针未知

如果无法得知堆指针, 我们可以使用`kernel32`的`HeapWalk()`函数或`ntdll`的`RtlWalkHeap()`函数(或甚至是`kernel32`的`GetCommandLine()`函数). 返回的堆大小的值会被自动解密, 因此就不需要再关心windows的版本

可以使用以下32位代码来检测32位环境:

``` asm
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
    repe scasb
    je being_debugged
    ...
l2: db 1ch dup (0) ;sizeof(PROCESS_HEAP_ENTRY)
```

或使用以下64位代码检测64位环境:

``` asm
    mov rbx, offset l2
    ;get a pointer to a heap block
l1: push rbx
    pop rdx
    push 60h
    pop rsi
    gs:lodsq ;Process Environment Block
    ;get a pointer to process heap base
    mov ecx, [rax+30h]
    call HeapWalk
    cmp w [rbx+0eh], 4 ;find allocated block
    jne l1
    mov edi, [rbx] ;data pointer
    add edi, [rbx+8] ;data size
    mov al, 0abh
    push 10h
    pop rcx
    repe scasb
    je being_debugged
    ...
l2: db 28h dup (0) ;sizeof(PROCESS_HEAP_ENTRY)
```

这里没有使用32位代码检测64位环境的样例, 因为64位的堆无法由32位的堆函数解析.

