# The Heap

堆在初始化時, 會檢查`heap flags`, 並視一些標誌位的有無設置而對環境作出額外的改變. 像`Themida`就有采用這種方法來檢測調試器.

比如:

* 如果設置了`HEAP_TAIL_CHECKING_ENABLED`標誌(見`Heap Flags`節), 那麼在32位windows中就會在分配的堆塊尾部附加2個`0xABABABAB`(64位環境就是4個).
* 如果設置了`HEAP_FREE_CHECKING_ENABLED`(見`Heap Flags`節)標誌, 那麼當需要額外的字節來填充堆塊尾部時, 就會使用`0xFEEEFEEE`(或一部分)來填充

那麼, 一種新的檢測調試器的方法就是來檢查這些值. 

## 堆指針已知

如果已知一個堆指針, 那麼我們可以直接檢查堆塊裏的數據. 然而在`Windows Vista`及更高版本中採用了堆保護機制(32位/64位都有), 使用了一個異或密鑰來對堆塊大小進行了加密. 雖然你可以選擇是否使用密鑰, 但是默認是使用的. 而且就堆塊首部的位置, 在`Windows NT/2000/XP`和`Windows Vista及更高版本`之間也是不相同的. 因此我們還需要將`Windows版本`也考慮在內. 

可以使用以下32位代碼來檢測32位環境:

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

或使用以下64位代碼檢測64位環境:

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

這裏沒有使用32位代碼檢測64位環境的樣例, 因爲64位的堆無法由32位的堆函數解析.


## 堆指針未知

如果無法得知堆指針, 我們可以使用`kernel32`的`HeapWalk()`函數或`ntdll`的`RtlWalkHeap()`函數(或甚至是`kernel32`的`GetCommandLine()`函數). 返回的堆大小的值會被自動解密, 因此就不需要再關心windows的版本

可以使用以下32位代碼來檢測32位環境:

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

或使用以下64位代碼檢測64位環境:

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

這裏沒有使用32位代碼檢測64位環境的樣例, 因爲64位的堆無法由32位的堆函數解析.

