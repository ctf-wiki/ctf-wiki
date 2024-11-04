# shell 獲取小結

## overview

我們獲取到的 shell 一般有兩種形式

- 直接可交互的 shell
- 將 shell 綁定到指定 ip 的指定端口

下面總結幾種常見的獲取 shell 的方式。

## shellcode

在利用 shellcode 獲取 shell 時，基本要求就是我們能夠將 shellcode 佈置在**可寫可執行的內存區域**中。因此，在沒有可寫可執行的內存區域的時候，我們需要利用`mprotect` 等函數設置相關內存的權限。

此外，有時候可能 shellcode 中的字符必須滿足某些要求，比如可打印字符，字母，數字等等。

## system

我們這裏一般是執行 system("/bin/sh")，system('sh') 等函數。

這裏我們主要需要找到一些地址，可以參考獲取地址的小節。

- system 的地址
- "/bin/sh"， “sh” 地址
    - binary 裏面是否字符串
    - 考慮個人讀取對應字符串
    - libc 中其實是有 /bin/sh 的

在 system 獲取 shell 時，一個非常好的優點在於我們只需要佈置一個參數就可以了，缺點就是我們在佈置參數時，可能因爲破壞了環境變量而無法執行。

## execve

執行 execve("/bin/sh",NULL,NULL)。

在利用 `execve` 獲取 shell 時，前幾條同 system 一致。但它具有一個優點就是幾乎不受環境變量的影響。但是缺點在於我們需要佈置三個參數。

此外，glibc 中我們還可以使用 one_gadget 來獲取 shell。

## syscall

系統調用號 `__NR_execve` 在 IA-32 中爲 11，x86-64 爲 59。

它的優點在於幾乎不受環境變量的影響。然而我們需要找到 `syscall` 之類的系統調用命令。