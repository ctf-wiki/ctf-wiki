[EN](./pe-relocation-table.md) | [ZH](./pe-relocation-table-zh.md)

# 基址重定位表

链接器在生成 PE 文件时，它假设执行时 PE 文件会被装载到默认的基地址处，于是将代码和数据的绝对地址都写入到 PE 文件中。如果装载时 PE 文件确实装载到了默认基地址处，就不需要进行重定位；但是，如果转载时 PE 文件装载到了别处，此时文件中的绝对地址就都失效了，因为装载基地址已经改变，代码和数据的实际地址也相应的改变了，这时就需要通过重定位修复绝对地址，使其都能指向正确的位置。

对于 EXE 文件，每个文件在执行时都会使用独立的虚拟地址空间，即总是能装载到在默认基地址处，也就不需要重定位信息；但是，同一个虚拟地址空间中可能存在多个 DLL，可能有的 DLL 就会面临默认基地址已经被占用的情况，所以 DLL 需要重定位信息。

## 重定位结构体

在 PE 文件中，所有可能需要重定位的地址都被放在一个数组中，即基址重定位表。如果装载地址改变了，就会对数组中所有的地址进行修正。基址重定位表位于节区 .reloc 内，不过找到它的正确方式是通过 `DataDirectory[5]` 即 BASE RELOCATION TABLE 项。

基址重定位数据的组织方式采用按页分割的方法，即将不同页的重定位数据分开存放，每个页的重定位数据组成一个重定位数据块，所有的重定位块组成了重定位表。每个重定位块存放着 4KB 大小的重定位信息，每个重定位数据块的大小必须以 DWORD 对齐。重定位块以一个 `IMAGE_BASE_RELOCATION` 结构作为开始，其结构体如下：

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD    VirtualAddress;  // 重定位页的 RVA
    DWORD    SizeOfBlock;     // 重定位块的大小
     WORD    TypeOffset;      // 重定位条目的类型于偏移

} _IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

接下来详细说明一下结构体中的成员：

- **VirtualAddress 重定位页 RVA。以映像装载基址加上页 RVA 的和作为被加数，再加上重定位项对应的 offset 就能得到其在内存中实际的 VA。最后一个重定位块的尾部也会添加一个 virtualaddress 字段作为结束标志。**
- **SizeOfBlock 基址重定位块的大小。包括 VirtualAddress，SizeOfBlock，以及后面 TypeOffset 的大小。**
- **TypeOffset** 一个数组。数组中每个元素大小为 2 个字节，即 16 位。 
  - **type 高 4 位用于表示重定位的类型。**
  - **offset 低 12 位用于表示重定位数据位置相对于页 RVA 的偏移量。与 VirtualAddress 相加就是要修改的重定位数据的指针，再加上映像装载基址就是修改后的指针。**

## 重定位过程

**利用重定位表定位需要修改的地址。**比如在 me.dll 中，重定位表的开头部分如下：

```text
RVA       Data      Description
00005000  00001000  页 RVA        // page RVA = 0x1000
00005004  00000118  重定位块大小 size   
00005008      3013  Type|Offset   //   offset = 0x013
...
```

由 0x1000+0x013 算出待重定位的数据在文件偏移 0x1013 处，加上默认的 imagebase 就是 0x10001013。如下：

```x86asm
.text:10001012 68 9C 20 00 10        push 1000209C
```

即，文件偏移 0x1013 处的 1000209C 可能需要重定位。

**修改待重定位数据**程序运行后，me.dll 被加载到了 0x633C0000 处：

![dll 装载处](../figure/pe5-relocdll.png)

计算待重定位修正后的值，然后将修正的值写到待重定位地址处：

```
计算待重定位数据地址：
(0x10001013 - DefaultImageBase) + ImageBase 
即 (0x10001013 - 0x10000000) + 0x633C0000 => 0x633C1013

计算待重定位数据修正后的值：
(0x1000209C - DefaultImageBase) + ImageBase 
即 (0x1000209C - 0x10000000) + 0x633C0000 => 0x633C209C

最后： *0x633C1013 = 0x633C209C
```

查看内存中实际的值：

![重定位后的地址](../figure/pe5-relocdata.png)

> 留个问题，什么时候 EXE 会需要重定位？