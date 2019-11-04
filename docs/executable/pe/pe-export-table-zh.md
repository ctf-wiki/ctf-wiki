[EN](./pe-export-table.md) | [ZH](./pe-export-table-zh.md)


# 导出表

DLL 通过导出表向外界提供导出函数名称，序号以及入口地址等信息。从导入角度来看，Windows 装载器完善 IAT 时就是通过 DLL 的导出表读取从其导入的函数的地址的。导出表通常存在于大多数 DLL 中，但在少数 EXE 文件中同样存在。

对于 DLL 里导出函数的调用，既可以通过函数名称，也可以通过函数在导出表的索引进行。Windows 装载器将与进程相关的 DLL 加载到虚拟地址空间后，会根据导入表中登记的与该 DLL 相关的名称或编号来遍历 DLL 的虚拟地址空间并查找导出表结构，从而确定该导出函数在虚拟地址空间中的起始地址 VA，并将该 VA 覆盖写入 IAT 对应项处。

## EAT

`DataDirectory[0]` 处保存者 EXPORT TABLE （即导出表）的 RVA。该 RVA 指向 `IMAGE_EXPORT_DIRECTORY` 结构体。PE 文件中最多只存在 1 个 `IMAGE_EXPORT_DIRECTORY` 结构体。**但 PE 文件可以有多个 `IMAGE_IMPORT_DESCRIPTOR` 结构体，因为 PE 文件可以一次导入多个库。**

看看 `IMAGE_EXPORT_DIRECTORY` 结构体：

```c
typedef struct _IMAGE_EXPORT_DIRECTORY{
  DWORD    Characteristics;
  DWORD    TimeDateStamp;
  WORD     MajorVersion;
  WORD     MinorVersion;
  DWORD    Name;                     // 库文件名称地址
  DWORD    Base;                     // 导出函数起始序号
  DWORD    NumberOfFunctions;        // 导出函数个数
  DWORD    NumberOfNames;            // 导出函数的名称个数
  DWORD    AddressOfFunctions;       // 导出函数地址数组（数组元素个数=NumberOfFunctions）
  DWORD    AddressOfNames;           // 导出函数名称地址数组（数组元素个数=NumberOfNames）
  DWORD    AddressOfNameOrdinals;    // 导出函数序号数组（数组元素个数=NumberOfNames）
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

接下来详细说明一下结构体中的成员：

- **`Name` 双字。该成员保存的地址指向一个以 "\0" 结尾的字符串，字符串记录的是导出表所在文件的最初文件名称。**
- **`Base` 双字。导出函数的起始序号。导出函数的编号 = Base + Ordinals。**
- **`NumberOfFunctions` 双字。导出函数的总个数。**
- **`NumberOfNames0` 双字。在导出表中，有些函数有定义名称，有些函数没有。该成员记录了所有定义了名称的导出函数的个数。如果该值为 0，表示所有函数都没有定义名称。`NumberOfNames**` 总是小于等于 `NumberOfFunctions`。**
- **`AddressOfFunctions` 双字。指向导出函数地址数组的起始处。导出函数地址数组保存了数量为 `NumberOfFunctions` 的导出函数地址。**
- **`AddressOfNames` 双字。指向导出函数名称地址数组的起始处。导出函数名称数组的每一个元素都指向了导出函数对应的名称字符串的地址。**
- **`AddressOfNameOrdinals` 双字。指向导出函数序号地址数组的起始处。与 `AddressOfNames` 是一一对应关系。导出函数序号数组中每一个元素都指向了导出函数对应的序号值。**

接下来通过一个简单示例来学习一下。示例选取的是 Windows 系统中的 version.dll，该文件位于 `C:\Windows\SysWOW64\` 目录下。
首先来看一下示例文件的 `IMAGE_EXPORT_DIRECTORY` 结构体：

```text
// 示例程序 IMAGE_EXPORT_DIRECTORY
RVA       Value      Description
----------------------------------------------------
00003630  00000000   Characteristicss
00003634  FDB2B236   Time Data Stamp
00003638  0000       Major Version
0000363A  0000       Minor Version
0000363C  00003702   Name RVA
00003640  00000001   Base
00003644  00000011   Number of Functions
00003648  00000011   Number of Names
0000364C  00003658   Address Table RVA
00003650  0000369C   Name Pointer Table RVA
00003654  000036E0   Ordinal Table RVA
----------------------------------------------------
```

接着整理一下导出表中的数组：

```text
RVA       Address   Name      Ordinal  Description
---------------------------------------------------------------------
00003658  000014F0  0000370E        0  GetFileVersionInfoA
0000365C  000022E0  00003722        1  GetFileVersionInfoByHandle
00003660  00001F40  0000373D        2  GetFileVersionInfoExA
00003664  00001570  00003753        3  GetFileVersionInfoExW
00003668  00001510  00003769        4  GetFileVersionInfoSizeA
0000366C  00001F60  00003781        5  GetFileVersionInfoSizeExA
00003670  00001590  0000379B        6  GetFileVersionInfoSizeExW
00003674  000015B0  000037B5        7  GetFileVersionInfoSizeW 
00003678  000015D0  000037CD        8  GetFileVersionInfoW
0000357C  00001F80  000037E1        9  VerFindFileA
00003680  00002470  000037EE       10  VerFindFileW
00003684  00001FA0  000037FB       11  VerInstallFileA
00003688  00002F40  0000380B       12  VerInstallFileW
0000368C  0000382C  0000381B       13  VerLanguageNameA
00003690  00003857  00003846       14  VerLanguageNameW
00003694  00001530  00003871       15  VerQueryValueA
00003698  00001550  00003880       16  VerQueryValueW
------------------------------------------------------------------------
```

Address 列对应着导出函数装载到内存中的实际地址，Name 列对应着导出函数名称的 RVA，Ordinal 即为导出函数的序号。
这里再加一张导出表的字符串部分内容，即保存着库文件名称和导出函数名称的部分。通过 PEview 还能方便看出：

![导出表中的字符串](../figure/pe4-eatstrings.png "图 10 - 导出表字符串部分")

导出函数获取函数地址的过程大致如下：

1. 首先利用 `AddressOfNames` 成员定位到导出函数名称数组；
2. 接着通过比较字符串 (strcmp) 查找指定的函数名称，找到后将其索引作为 `name_index`；
3. 接着利用 `AddressOfOrdinals` 成员定位到导出函数序号数组；
4. 接着通过 `name_index` 在导出函数序号数组中定位对应的 `ordinal` 值；
5. 接着利用 `AddressOfFunctions` 成员定位到导出函数地址数组，即 `Export Address Table(EAT)`；
6. 最后通过 `ordinal` 作为索引在导出函数地址数组中定位到对应的项，获取指定函数的起始地址。

对于少见的没有名称的导出函数，利用 Ordinal 成员减去 Base 得到的值作为索引值，在导出函数地址数组中定位对应的函数地址。