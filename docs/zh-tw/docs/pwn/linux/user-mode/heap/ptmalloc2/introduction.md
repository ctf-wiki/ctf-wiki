# 堆利用

在該章節中，我們會按照如下的步驟進行介紹

1. 介紹我們所熟知的動態內存分配的堆的宏觀操作
2. 介紹爲了達到這些操作所使用的數據結構
3. 介紹利用這些數據結構實現堆的分配與回收的具體操作
4. 由淺入深地介紹堆的各種利用技巧。

對於不同的應用來說，由於內存的需求各不相同等特性，因此目前堆的實現有很多種，具體如下

```text
dlmalloc  – General purpose allocator
ptmalloc2 – glibc
jemalloc  – FreeBSD and Firefox
tcmalloc  – Google
libumem   – Solaris
```

這裏我們主要以 glibc 中堆的實現爲主進行介紹。如果後續有時間，會繼續介紹其它堆的實現及其利用。

該部分主要參考的資料如下，文中有很多內容會和參考資料中一致，以後就不一一說明瞭。

- [black hat heap exploitation](https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf)
- [github heap exploition](https://heap-exploitation.dhavalkapil.com/)
- [sploitfun](https://sploitfun.wordpress.com/archives/)
- glibc 源碼
- 更多的參考文獻請看ref目錄下的文件

