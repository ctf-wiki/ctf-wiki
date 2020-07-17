[EN](./pe-excutable.md) | [ZH](./pe-excutable-zh.md)


# PE 文件格式

## PE 简介

PE 文件的全称是 Portable Executable ，意为可移植的可执行的文件，常见的EXE、DLL、OCX、SYS、COM都是PE 文件，PE 文件是微软Windows操作系统上的程序文件，可能是间接被执行，如DLL）。
一个 32-bits 的 PE 文件布局如下图所示：

```text
+-------------------------------+ \
|     MS-DOS MZ header          |  |
+-------------------------------+  |
| MS-DOS Real-Mode Stub program |  |
+-------------------------------+  |
|     PE Signature              |  | -> PE file header
+-------------------------------+  |
|     IMAGE_FILE_HEADER         |  |
+-------------------------------+  |
|     IMAGE_OPTIONAL_HEADER     |  |
+-------------------------------+ /
|     section header #1         | 
+-------------------------------+ 
|     section header #2 
+------------------------- 
: 
: 
 
+------------------------------+ 
|        section #1            | 
+------------------------------+ 
|        section #2 
+-------------------- 
: 
: 
```

接下来将会以一个 32-bit 的 PE 文件作为标本介绍一下 PE 文件。

```c
// 示例代码 test.c
#include <stdio.h>

int main(){
  printf("Hello, PE!\n");

  return 0;
}
```

**通过 `Devcpp` 软件的 `TDM-GCC 4.9.2 32-bit Release` 方式编译文件生成 `test.exe`，作为示例文件。**

### 常用术语及其含义

- **`映像文件` 因为 PE 文件通常需要加载到内存中才能执行，相当于内存中的映像，所以 PE 文件也叫做映像文件。**
- **`RVA` 相对虚拟地址，映像文件在虚拟内存中相对于加载基址的偏移。**
- **`VA` 虚拟地址，映像文件在虚拟内存中的地址。**
- **`FOA` 文件偏移地址，映像文件在磁盘文件中相对于文件开头的偏移。**

因为不论是在磁盘文件上，或是在虚拟内存中，数据相对于其所在节的相对偏移是固定的，据此可以实现 RVA 与 FOA 之间的转换，即`RVA - 节区RVA = FOA - 节区FOA`。

假设某一个属于 .data 节的数据的 RVA 是 0x3100，.data 节的 节区RVA 为 0x3000，那么该数据相对于 .data 节的相对偏移就是 0x100。而 .data 节在的 节区FOA 为 0x1C00，那么该数据在磁盘文件中的 FOA 就是 0x1D00。完整的计算公式是：`FOA = 节区FOA + (RVA - 节区RVA)`。如果该映像文件的加载基址为0x40000000，那么该数据的 VA 就是 0x40003100。

## PE文件头

PE 文件的最开始便是 PE 文件头，它由 `MS-DOS 文件头` 和 `IMAGE_NT_HEADERS` 结构体组成。

### MS-DOS 文件头

`MS-DOS 文件头` 包含 `IMAGE_DOS_HEADER` 和 `DOS Stub` 两个部分。

`IMAGE_DOS_HEADER` 结构体的定义如下：

```c
typedef struct _IMAGE_DOS_HEADER
{
     WORD e_magic;              // "MZ"
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;             // NT 头相对于文件起始处的偏移
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

`IMAGE_DOS_HEADER` 结构体中有 2 个重要成员：
- **`e_magic` 单字。DOS 签名 "4D5A"，即 ASCII 值 "MZ"。所有 PE 文件的开头都有 DOS 签名。**
- **`e_lfanew` 单字。`IMAGE_NT_HEADER`相对于文件起始处的偏移。**

示例程序的 `IMAGE_DOS_HEADER` 如图 2 所示：

![IMAGE_DOS_HEADER](../figure/pe2-imagedosheader.png "图 2 - IMAGE_DOS_HEADER")

`IMAGE_DOS_HEADER` 结构体后紧接着是 `DOS Stub`，它的作用很简单，当系统为 MS-DOS 环境时，输出 `This program cannot be run in DOS mode.` 并退出程序，表明该程序不能在 MS-DOS 环境下运行。这使得所有的 PE 文件都对 MS-DOS 环境兼容。利用该特性可以创建出一个在 MS-DOS 和 Windows 环境中都能运行的程序，在 MS-DOS 中执行 16-bit MS-DOS 代码，在 Windows 中执行 32-bit Windows 代码。

示例程序的 `DOS Stub` 如图 3 所示：

![DOS Stub](../figure/pe2-imagedosstub.png "图 3 - DOS Stub")

### IMAGE_NT_HEADERS

`IMAGE_NT_HEADERS` 结构体，俗称 NT 头。紧跟在 `DOS Stub` 之后，其定义如下：

```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;         /* +0000h PE 标识 */
  IMAGE_FILE_HEADER       FileHeader;        /* +0004h PE 标准头 */
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;    /* +0018h PE 可选头  */
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

示例程序的 `IMAGE_NT_HEADERS` 如图 4 所示：

![NT 头](../figure/pe2-imagentheader.png "图 4 - IMAGE_NT_HEADERS")

接下来详细说一下 NT 头。

#### PE Signature

NT 头的第一个成员是`PE Signature`，它是一个4字节大小的ASCII码字符串 `PE\0\0`，用于指明当前文件是一个 PE 格式的映像文件。其位置可以通过 `IMAGE_DOS_HEADER` 的 `e_lfanew` 成员的值确定。

#### IMAGE_FILE_HEADER

`PE Signature` 后紧跟着是 `IMAGE_FILE_HEADER` 结构体，又称作 `COFF 头（标准通用文件格式头）`。其定义如下：

```c
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;                    /* +0004h 目标机器类型 */
  WORD  NumberOfSections;           /* +0006h PE 中节的数量 */
  DWORD TimeDateStamp;              /* +0008h 时间戳 */
  DWORD PointerToSymbolTable;       /* +000ch 指向符号表的指针 */
  DWORD NumberOfSymbols;            /* +0010h 符号表中符号数目 */
  WORD  SizeOfOptionalHeader;       /* +0012h 可选头的大小 */
  WORD  Characteristics;            /* +0014h 文件属性标志 */
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

接下来依次对每一个字段做出解释：

- **`Machine`  单字。用于指明 CPU 类型。详细了解所支持的 CPU 类型请参考 [微软 PE 格式 COFF 文件头 Machine 类型](https://docs.microsoft.com/zh-cn/windows/win32/debug/pe-format?redirectedfrom=MSDN#machine-types)。**
- **`NumberOfSections` 单字。文件中存在的节区数量。PE 文件将代码、数据、资源的依据属性分类到不同节区中存储。**
- `TimeDateStamp` 双字。低 32 位表示从 1970 年 1 月 1 日 00：00 到文件创建时经过的秒数。
- `PointerToSymbolTable` 双字。符号表的文件偏移。如果不存在符号表，其值为 0。
- `NumberOfSymbols` 双字。该字段表示符号表中的符号数量。由于字符串表紧跟在符号表之后，所有能通过该值定位字符串表。
- **`SizeOfOptionalHeader` 单字。表示可选头的大小。在 32-bit 机器上默认是 0x00E0，在 64-bit 机器上默认是 0x00F0。**
- **`Characteristics` 单字。用于标识文件属性，以 bit OR 方式组合。**下面是一些已定义的文件属性标志：

```c
// 文件属性标志
#define IMAGE_FILE_RELOCS_STRIPPED          0x0001    // 表示文件不包含重定位信息，只能在原定的基址加载。如果原定基址不可用，加载器会报出错误
#define IMAGE_FILE_EXECUTABLE_IMAGE         0x0002    // 表示文件可执行，如果该位未设置，意味着存在链接器错误
#define IMAGE_FILE_LINE_NUMS_STRIPPED       0x0004    // 不存在行信息
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED      0x0008    // 不存在符号信息
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM       0x0010    // 已废弃
#define IMAGE_FILE_LARGE_ADDRESS_AWARE      0x0020    // 应用可处理大于 2GB 的地址
#define IMAGE_FILE_BYTES_REVERSED_LO        0x0080    // 小尾存储。已废弃
#define IMAGE_FILE_32BIT_MACHINE            0x0100    // 基于 32-bit 体系结构
#define IMAGE_FILE_DEBUG_STRIPPED           0x0200    // 不存在调试信息
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  0x0400    // 如果映像文件在可移动介质上，完全加载并复制到内存交换文件中
#define IMAGE_FILE_NET_RUN_FROM_SWAP        0x0800    // 如果映像文件在网络介质上，完全加载并复制到内存交换文件中
#define IMAGE_FILE_SYSTEM                   0x1000    // 映像文件是系统文件
#define IMAGE_FILE_DLL                      0x2000    // 映像文件是动态链接库文件
#define IMAGE_FILE_UP_SYSTEM_ONLY           0x4000    // 文件只能在单处理器机器上运行
#define IMAGE_FILE_BYTES_REVERSED_HI        0x8000    // 大尾存储（已废弃）
```

示例程序的 `IMAGE_FILE_HEADER` 如下：

```text
// 示例程序 IMAGE_FILE_HEADER
RVA       Value      Description
----------------------------------------------------
00000084  014C       机器类型
00000086  000F       节区数量
00000088  5D88E2A6   时间戳
0000008c  00012C00   符号表偏移
00000090  000004E4   符号数量
00000094  00E0       可选头大小
00000096  0107       文件属性
                     0001  IMAGE_FILE_RELOCS_STRIPPED
                     0002  IMAGE_FILE_EXECUTABLE_IMAGE
                     0004  IMAGE_FILE_LINE_NUMS_STRIPPED
                     0100  IMAGE_FILE_32BIT_MACHINE
```

#### IMAGE_OPTIONAL_HEADER

之所以`IMAGE_OPTIONAL_HEADER` 叫做可选头，是因为对于目标文件，它没有任何作用，只是平白增加了目标文件的大小；但对于映像文件来说，它提供了加载时必需的信息。定义如下：

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;                            /* +0018h 魔数 */
  BYTE                 MajorLinkerVersion;               /* +001ah 链接器主要版本号 */
  BYTE                 MinorLinkerVersion;               /* +001bh 链接器次要版本号 */
  DWORD                SizeOfCode;                       /* +001ch 所有含代码的节的总大小 */
  DWORD                SizeOfInitializedData;            /* +0020h 所有含已初始化数据的节的总大小 */
  DWORD                SizeOfUninitializedData;          /* +0024h 所有含未初始化数据的节的总大小 */
  DWORD                AddressOfEntryPoint;              /* +0028h 程序入口点RVA */
  DWORD                BaseOfCode;                       /* +002ch 代码节起始RVA */
  DWORD                BaseOfData;                       /* +0030h 数据节起始RVA */
  DWORD                ImageBase;                        /* +0034h 映像文件加载时的首选地址 */
  DWORD                SectionAlignment;                 /* +0038h 内存中节对齐粒度*/
  DWORD                FileAlignment;                    /* +003ch 文件中节对齐粒度 */
  WORD                 MajorOperatingSystemVersion;      /* +0040h 操作系统主要版本号 */
  WORD                 MinorOperatingSystemVersion;      /* +0042h 操作系统次要版本号 */
  WORD                 MajorImageVersion;                /* +0044h 映像文件主要版本号 */
  WORD                 MinorImageVersion;                /* +0046h 映像文件次要版本号 */
  WORD                 MajorSubsystemVersion;            /* +0048h 子系统主要版本号 */
  WORD                 MinorSubsystemVersion;            /* +004ah 子系统次要版本号 */
  DWORD                Win32VersionValue;                /* +004ch 保留。置0 */
  DWORD                SizeOfImage;                      /* +0050h 内存中映像文件的大小 */
  DWORD                SizeOfHeaders;                    /* +0054h 所有头+节表大小 */
  DWORD                CheckSum;                         /* +0058h 映像文件校验和 */
  WORD                 Subsystem;                        /* +005ch 运行映像所需子系统 */
  WORD                 DllCharacteristics;               /* +005eh 映像文件的DLL属性 */
  DWORD                SizeOfStackReserve;               /* +0060h 初始化时的保留的栈大小 */
  DWORD                SizeOfStackCommit;                /* +0064h 初始化时实际提交的栈大小 */
  DWORD                SizeOfHeapReserve;                /* +0068h 初始化时保留的堆大小 */
  DWORD                SizeOfHeapCommit;                 /* +006ch 初始化时实际提交的堆大小 */
  DWORD                LoaderFlags;                      /* +0070h 已废弃 */
  DWORD                NumberOfRvaAndSizes;              /* +0074h 数据目录结构的数量 */
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];     /* +0078h 指向数据目录中第一个 IMAGE_DATA_DIRECTORY 结构体的指针 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

- **`Magic` 单字。指明映像文件的类型。`0x0107h` 表示 ROM 映像；`0x010B` 表示 PE32；`0x020B` 表示 PE32+，即 64-bit 的 PE 文件。**
- `MajorLinkerVersion` 字节。指定链接器主要版本号。
- `MinorLinkerVersion` 字节。指定链接器次要版本号。
- `SizeOfCode` 双字。所有包含代码的节的总大小。**这里的大小指文件对齐后的大小。判断某个节是否包含代码的方法是根据节属性是否包含 `IMAGE_SCN_CNT_CODE` 标志。**
- `SizeOfInitializedData` 双字。所有包含已初始化数据节的总大小。
- `SizeOfUninitializedData` 双字。所有包含未初始化数据节的总大小。
- **`AddressOfEntryPoint` 双字。入口点函数的指针相对于映像文件加载基址的偏移量。对于可执行文件，这是启动地址；对于设备驱动，这是初始化函数的地址；入口点函数对于 DLL 文件是可选的，如果不存在入口点，该成员必须置 0。**
- `BaseOfCode` 双字。代码节的 RVA，代码节起始处相对于映像文件加载基址的偏移量。通常代码节紧跟在 PE 头 后面，节名为 ".text"。
- `BaseOfData` 双字。数据节的 RVA，数据节起始处相对于映像文件加载基址的偏移量。通常数据节位于文件末尾，节名为 ".data"。
- **`ImageBase` 双字。映像文件加载时的优先载入地址，值必须是 64KB 的整数倍。**应用程序的默认值是 0x00400000；DLL 的默认值是 0x10000000。**当一个程序用到了多个 DLL 文件时，PE 加载器会调整 DLL 的载入地址，使所有 DLL 文件都能够被正确载入。**
- **`SectionAlignment` 双字。内存中的节对齐粒度。该成员的值必须不小于 `FileAlignment` 成员的值。默认的值与系统的页大小相等。**
- **`FileAlignment` 双字。映像文件中原始数据的对齐粒度。值必须是在 512-64K 范围内的 2 的幂。默认值为512，但如果 `SectionAlignment` 成员的值小于系统页大小，则 `FileAlignment` 与 `SectionAlignment` 两者成员的值必须相同。**
- `MajorOperatingSystemVersion` 单字。操作系统主要版本号。
- `MinorOperatingSystemVersion` 单字。操作系统次要版本号。
- `MajorImageVersion` 单字。映像文件主要版本号。
- `MinorImageVersion` 单字。映像文件次要版本号。
- `MajorSubsystemVersion` 单字。子系统主要版本号。
- `MinorSubsystemVersion` 单字。子系统次要版本号。
- `Win32VersionValue` 双字。保留。置0。
- **`SizeOfImage` 双字。映像文件在虚拟内存中所占的大小。值必须为 `SectionAlignment` 的整数倍。**
- **`SizeOfHeaders` 双字。PE 文件头和所有节表大小的总和按照 `FileAlignment` 对齐后的大小。第一节区在文件开始偏移为 `SizeOfHeaders` 处。**
- `CheckSum` 双字。映像文件的校验值。需要在装载时校验的文件有所有的驱动，任何在启动时装载的 DLL，以及任何加载到关键系统进程中的 DLL。
- **`Subsystem` 单字。运行映像文件所需的子系统。已定义的子系统标志如下：**

```c
// Subsystem 标志
#define IMAGE_SUBSYSTEM_UNKNOWN                      0  // 未知子系统
#define IMAGE_SUBSYSTEM_NATIVE                       1  // 不需要子系统。设备驱动和本机系统进程
#define IMAGE_SUBSYSTEM_WINDOWS_GUI                  2  // Windows 图形用户接口（GUI）子系统
#define IMAGE_SUBSYSTEM_WINDOWS_CUI                  3  // Windows 字符模式用户接口子（CUI）系统
#define IMAGE_SUBSYSTEM_OS2_CUI                      5  //  OS/2 CUI 子系统
#define IMAGE_SUBSYSTEM_POSIX_CUI                    7  // POSIX CUI 子系统
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI               9  // Windows CE 系统
#define IMAGE_SUBSYSTEM_EFI_APPLICATION             10  // 可扩展固件接口（EFI）应用程序
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVEICE_DRIVER    11  // 带引导服务的 EFI 驱动程序
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          12  // 带运行时服务的 EFI 驱动程序
#define IMAGE_SUBSYSTEM_EFI_ROM                     13  // EFI ROM 映像
#define IMAGE_SUBSYSTEM_XBOX                        14  // XBOX 系统
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16  // 引导应用程序
```

- **`DllCharacteristics` 单字。映像文件的 DLL 属性，以 bit OR 方式组合。各标志位的含义如下：**

```c
// DLL 属性标志
// 0x0001 0x0002 0x0004 0x0008 保留，值必须为 0。
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE             0x0040  // DLL 可以在加载时重定位
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY          0x0080  // 强制实行代码完整性检验
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT                0x0100  // 映像兼容数据执行保护（DEP）
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION             0x0200  // 映像可以隔离，但不应该被隔离
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                   0x0400  // 映像不使用结构化异常处理（SEH）
#define IMAGE_DLLCHARACTERISTICS_NO_BIND                  0x0800  // 不绑定映像
//#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER           0x1000  // 在 32-bit 保留；64-bit 表示映像必须在 AppContainer 内执行
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER               0x2000  // WDM 驱动
//#define IMAGE_DLLCHARACTERISTICS_GUARD_CF               0x4000  // 在 32-bit 保留；64-bit 表示映像支持控制流保护
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE    0x8000  // 映像可用于终端服务器
```

- `SizeOfStackReserve` 双字。初始化时保留的栈内存大小，默认值是 1MB。具体说是初始化时为栈保留的虚拟内存的大小，但并不是所有保留的虚拟内存都能直接作为栈使用。初始化时实际提交的栈大小由 `SizeOfStackCommit` 成员指定。
- `SizeOfStackCommit` 双字。初始化时实际提交的栈内存大小。
- `SizeOfHeapReserve` 双字。初始化时保留的堆内存大小，默认值为 1MB。每一个进程至少为会有一个默认的进程堆，在进程启动的时候被创建，并且在进程的声明周期内不会被删除。
- `SizeOfHeapCommit` 双字。初始化时实际提交的堆内存大小，默认大小为 1 页。可以通过链接器的 "-heap" 参数指定起始保留的堆内存大小和实际提交的堆内存大小。
- `LoaderFlags` 成员已弃用。
- **`NumberOfRvaAndSizes` 双字。数据目录结构的数量。通常为 0x00000010，即 16 个。**
- **`DataDirectory` 结构体。由 `IMAGE_DATA_DIRECTORY` 结构体组成的数组，数组的每项都有被定义的值。结构体定义如下：**

```c
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;      /* 数据目录的 RVA */
  DWORD Size;                /* 数据目录的大小 */
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

各数组项如下：

```c
// 数据目录
DataDirectory[0] =   EXPORT Directory           // 导入表 RVA 和大小
DataDirectory[1] =   IMPORT Directory           // 导入表 RVA 和大小
DataDirectory[2] =   RESOURCE Directory         // 资源表 RVA 和大小
DataDirectory[3] =   EXCEPTION Directory        // 异常表 RVA 和大小
DataDirectory[4] =   CERTIFICATE Directory      // 证书表 FOA 和大小
DataDirectory[5] =   BASE RELOCATION Directory  // 基址重定位表 RVA 和大小
DataDirectory[6] =   DEBUG Directory            // 调试信息 RVA 和大小
DataDirectory[7] =   ARCH DATA Directory        // 指定架构信息 RVA 和大小
DataDirectory[8] =   GLOBALPTR Directory        // 全局指针寄存器 RVA
DataDirectory[9] =   TLS Directory              // 线程私有存储表 RVA 和大小
DataDirectory[10] =  LOAD CONFIG Directory      // 加载配置表 RVA 和大小
DataDirectory[11] =  BOUND IMPORT Directory     // 绑定导入表 RVA 和大小
DataDirectory[12] =  `IAT` Directory              // 导入地址表 RVA 和大小
DataDirectory[13] =  DELAY IMPORT Directory     // 延迟导入描述符 RVA 和大小
DataDirectory[14] =  CLR Directory              // CLR数据 RVA 和大小
DataDirectory[15] =  Reserverd                  // 保留
```

示例程序的 `IMAGE_OPTIONAL_HEADER` 如下图：
![可选头上](../figure/pe2-imageoptionalheader1.png "图 5 - IMAGE_OPTIONAL_HEADER 结构体")
![可选头下](../figure/pe2-imageoptionalheader2.png "图 6 - DataDirectory 成员")

## PE 数据主体

PE 数据主体包括 `Section Header` 和所有的节区。

### Section Header

紧跟在可选头后面的是 `Section Header`，也称作节表。PE 文件种所有节的属性都被定义在节表中。节表由一系列的 `IMAGE_SECTION_HEADER` 结构体组成，结构体大小均为 40 字节。每一个结构体描述一个节的信息，定义如下：

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];    /* 节区名 */
  union {
    DWORD PhysicalAddress;                /* 物理地址 */
    DWORD VirtualSize;                    /* 虚拟内存中节区大小  */
  } Misc;
  DWORD VirtualAddress;                   /* 虚拟内存中节区 RVA */
  DWORD SizeOfRawData;                    /* 磁盘文件中节区大小 */
  DWORD PointerToRawData;                 /* 磁盘文件中节区 FOA */
  DWORD PointerToRelocations;             /* 指向重定位表的指针 */
  DWORD PointerToLinenumbers;             /* 指向行号表的指针 */
  WORD  NumberOfRelocations;              /* 重定位入口数量 */
  WORD  NumberOfLinenumbers;              /* 行号数量 */
  DWORD Characteristics;                  /* 节区属性 */
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

- `Name` 节名称字符串。长度最多 8 个字节。
- `Misc`
  - `PhysicalAddress` 双字。文件地址。
  - `VirtualSize` 双字。虚拟内存中的节区所占内存大小。 
- `VirtualAddress` 双字。虚拟内存中节区 RVA。
- `SizeOfRawData` 双字。对于映像文件，表示磁盘上初始化数据的大小，值必须为 `FileAlignment` 的整数倍；对于目标文件，表示节的大小。
- `PointerToRawData` 双字。磁盘文件中节区起始处的 FOA。值必须是 `FileAlignment` 的整数倍。
- `PointerToRelocations` 双字。在对象文件中使用，指向重定位表的指针。
- `PointerToLinenumbers` 双字。行号信息位置（供调试用）。如果没有行号信息则置 0；同时因为不建议使用 COFF 调试信息，在映像文件中应置 0。
- `NumberOfRelocations` 单字。重定位入口的数量，在映像文件中置 0。
- `NumberOfLinenumbers` 单字。行号数量（供调试用）。因为不建议使用 COFF 调试信息，所以在映像文件中应置 0。
- **`Characteristics` 双字。节区属性。，以 bit OR 方式组合。各标志位的含义如下：**

```c
// 节区属性
#define IMAGE_SCN_CNT_CODE                0x00000020  // 节区包含代码
#define IMAGE_SCN_CNT_INITIALIZED_DATA    0x00000040  // 节区包含已初始化数据
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA  0x00000080  // 节区包含未初始化数据
#define IMAGE_SCN_ALIGN_1BYTES            0x00100000  // 1-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_2BYTES            0x00200000  // 2-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_4BYTES            0x00300000  // 4-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_8BYTES            0x00400000  // 8-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_16BYTES           0x00500000  // 16-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_32BYTES           0x00600000  // 32-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_64BYTES           0x00700000  // 64-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_128BYTES          0x00800000  // 128-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_256BYTES          0x00900000  // 256-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_512BYTES          0x00A00000  // 512-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_1024BYTES         0x00B00000  // 1024-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_2048BYTES         0x00C00000  // 2048-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_4096BYTES         0x00D00000  // 4096-byte 对齐。仅用于目标文件
#define IMAGE_SCN_ALIGN_8192BYTES         0x00E00000  // 8192-byte 对齐。仅用于目标文件
#define IMAGE_SCN_LNK_NRELOC_OVFL         0x01000000  // 节区包含扩展的重定位项
#define IMAGE_SCN_MEM_DISCARDABLE         0x02000000  // 节区可根据需要丢弃，如 .reloc 在进程开始后被丢弃
#define IMAGE_SCN_MEM_NOT_CACHED          0x04000000  // 节区不会被缓存
#define IMAGE_SCN_MEM_NOT_PAGED           0x08000000  // 节区不可分页
#define IMAGE_SCN_MEM_SHARED              0x10000000  // 节区可共享给不同进程
#define IMAGE_SCN_MEM_EXECUTE             0x20000000  // 节区可作为代码执行
#define IMAGE_SCN_MEM_READ                0x40000000  // 节区可读
#define IMAGE_SCN_MEM_WRITE               0x80000000  // 节区可写
```

示例文件的节区头如下：

```text
No.  Name    VirtualSize  VirtualOffset  RawSize   RawOffset  Characteristics
--------------------------------------------------------------------------
01   .text   00001670     00001000       00001800  00000400   60500020  R-X  包含可执行代码
02   .data   0000002C     00003000       00000200  00001C00   C0300040  RW-  包含已初始化数据
03   .rdata  00000168     00004000       00000600  00001E00   40300040  R--  包含已初始化数据
04   .bss    00000450     00005000       00000000  00000000   C0700080  RW-  包含未初始化数据
05   .idata  00000564     00006000       00000600  00002400   C0300040  RW-  包含已初始化数据
06   .CRT    00000034     00007000       00000200  00002A00   C0300040  RW-  包含已初始化数据
07   .tls    00000020     00008000       00000200  00002C00   C0300040  RW-  包含已初始化数据
08   /4      000002D8     00009000       00000400  00002E00   42400040  R--  包含已初始化数据
09   /19     0000A6D5     0000A000       0000A800  00003200   42100040  R--  包含已初始化数据
0A   /31     0000199E     00015000       00001A00  0000DA00   42100040  R--  包含已初始化数据
0B   /45     000018F3     00017000       00001A00  0000F400   42100040  R--  包含已初始化数据
0C   /57     00000780     00019000       00000800  00010E00   42300040  R--  包含已初始化数据
0D   /70     000002F2     0001A000       00000400  00011600   42100040  R--  包含已初始化数据
0E   /81     00000D1E     0001B000       00000E00  00012800   42100040  R--  包含已初始化数据
0F   /92     00000230     0001C000       00000400  00012C00   42100040  R--  包含已初始化数据
```

### Sections

紧跟在 `Section Header`  后面的就是各个 sections，即节区。PE 文件一般至少要求有两个节区，用于存储可执行数据的代码节区 .text，和存储数据的数据节区 .data。通过节区名可以猜测节区的用途，但节区名不是决定节区用途的因素，只作为一种参考。比如也可以将代码节区的节区名修改为 .data，对于程序执行不会有影响。这里讲一下常见节区的用途：

```text
 .text  默认的代码节区。用于保存可执行代码。
 .data  默认的读/写数据节区。用于保存已初始化的全局变量，静态变量。
.rdata  默认的只读数据节区。
.idata  用于保存导入表信息。包含IAT, INT, 导入函数名称以及导入 DLL 名称等。
.edata  用于保存导出表信息。
 .rsrc  用于保存资源表信息。
  .bss  用于保存未初始化数据。
  .tls  用于保存 TLS（线程局部存储）信息。
.reloc  用于保存重定位表信息。
```

其中有一些 Section 需要重点关注，比如保存着库文件导入相关数据的 .idata 节，或者与线程私有存储相关的 .tls 节等等。对这些重要节进行分析，就是之后学习的主要内容。