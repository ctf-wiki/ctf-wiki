# ret2VDSO

## VDSO介紹

什麼是VDSO(Virtual Dynamically-linked Shared Object)呢？聽其名字，大概是虛擬動態鏈接共享對象，所以說它應該是虛擬的，與虛擬內存一致，在計算機中本身並不存在。具體來說，它是將內核態的調用映射到用戶地址空間的庫。那麼它爲什麼會存在呢？這是因爲有些系統調用經常被用戶使用，這就會出現大量的用戶態與內核態切換的開銷。通過vdso，我們可以大量減少這樣的開銷，同時也可以使得我們的路徑更好。這裏路徑更好指的是，我們不需要使用傳統的int 0x80來進行系統調用，不同的處理器實現了不同的快速系統調用指令

- intel實現了sysenter，sysexit
- amd實現了syscall，sysret

當不同的處理器架構實現了不同的指令時，自然就會出現兼容性問題，所以linux實現了vsyscall接口，在底層會根據具體的結構來進行具體操作。而vsyscall就實現在vdso中。

這裏，我們順便來看一下vdso，在Linux(kernel 2.6 or upper)中執行ldd /bin/sh, 會發現有個名字叫linux-vdso.so.1(老點的版本是linux-gate.so.1)的動態文件, 而系統中卻找不到它, 它就是VDSO。 例如:

```shell
➜  ~ ldd /bin/sh
	linux-vdso.so.1 =>  (0x00007ffd8ebf2000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f84ff2f9000)
	/lib64/ld-linux-x86-64.so.2 (0x0000560cae6eb000)
```

除了快速系統調用，glibc也提供了VDSO的支持, open(), read(), write(), gettimeofday()都可以直接使用VDSO中的實現。使得這些調用速度更快。 內核新特性在不影響glibc的情況下也可以更快的部署。

這裏我們以intel的處理器爲例，進行簡單說明。

其中sysenter的參數傳遞方式與int 0x80一致，但是我們可能需要自己佈置好 function prolog（32位爲例）

```asm
push ebp
mov ebp,esp
```

此外，如果我們沒有提供functtion prolog的話，我們還需要一個可以進行棧遷移的gadgets，以便於可以改變棧的位置。

## 原理

待補充。

## 題目

- **Defcon 2015 Qualifier fuckup**

## 參考

- http://man7.org/linux/man-pages/man7/vdso.7.html
- http://adam8157.info/blog/2011/10/linux-vdso/

