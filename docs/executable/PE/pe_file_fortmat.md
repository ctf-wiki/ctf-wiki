---
typora-root-url: ../../../docs
---

# PE 文件



### 简介

PE 文件的全称是 Portable Executable ，意为可移植的可执行的文件，常见的EXE、DLL、OCX、SYS、COM都是PE 文件，PE 文件是微软Windows操作系统上的程序文件，可能是间接被执行，如DLL）。

![](https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg)

上图是32位下 PE 文件的结构。PE 文件通常包括 DOS 头 、PE 文件头 、块表、text 段、rdata 段、data 段和其他节区。

### DOS Header

每个 PE 文件的开始都是以一个 DOS 程序开始的。



### 