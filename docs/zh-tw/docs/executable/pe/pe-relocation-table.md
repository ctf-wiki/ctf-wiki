# 基址重定位表

鏈接器在生成 PE 文件時，它假設執行時 PE 文件會被裝載到默認的基地址處，於是將代碼和數據的絕對地址都寫入到 PE 文件中。如果裝載時 PE 文件確實裝載到了默認基地址處，就不需要進行重定位；但是，如果轉載時 PE 文件裝載到了別處，此時文件中的絕對地址就都失效了，因爲裝載基地址已經改變，代碼和數據的實際地址也相應的改變了，這時就需要通過重定位修復絕對地址，使其都能指向正確的位置。

對於 EXE 文件，每個文件在執行時都會使用獨立的虛擬地址空間，即總是能裝載到在默認基地址處，也就不需要重定位信息；但是，同一個虛擬地址空間中可能存在多個 DLL，可能有的 DLL 就會面臨默認基地址已經被佔用的情況，所以 DLL 需要重定位信息。

## 重定位結構體

在 PE 文件中，所有可能需要重定位的地址都被放在一個數組中，即基址重定位表。如果裝載地址改變了，就會對數組中所有的地址進行修正。基址重定位表位於節區 .reloc 內，不過找到它的正確方式是通過 `DataDirectory[5]` 即 BASE RELOCATION TABLE 項。

基址重定位數據的組織方式採用按頁分割的方法，即將不同頁的重定位數據分開存放，每個頁的重定位數據組成一個重定位數據塊，所有的重定位塊組成了重定位表。每個重定位塊存放着 4KB 大小的重定位信息，每個重定位數據塊的大小必須以 DWORD 對齊。重定位塊以一個 `IMAGE_BASE_RELOCATION` 結構作爲開始，其結構體如下：

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD    VirtualAddress;  // 重定位頁的 RVA
    DWORD    SizeOfBlock;     // 重定位塊的大小
     WORD    TypeOffset;      // 重定位條目的類型於偏移

} _IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

接下來詳細說明一下結構體中的成員：

- **VirtualAddress 重定位頁 RVA。以映像裝載基址加上頁 RVA 的和作爲被加數，再加上重定位項對應的 offset 就能得到其在內存中實際的 VA。最後一個重定位塊的尾部也會添加一個 virtualaddress 字段作爲結束標誌。**
- **SizeOfBlock 基址重定位塊的大小。包括 VirtualAddress，SizeOfBlock，以及後面 TypeOffset 的大小。**
- **TypeOffset** 一個數組。數組中每個元素大小爲 2 個字節，即 16 位。 
  - **type 高 4 位用於表示重定位的類型。**
  - **offset 低 12 位用於表示重定位數據位置相對於頁 RVA 的偏移量。與 VirtualAddress 相加就是要修改的重定位數據的指針，再加上映像裝載基址就是修改後的指針。**

## 重定位過程

**利用重定位表定位需要修改的地址。**比如在 me.dll 中，重定位表的開頭部分如下：

```text
RVA       Data      Description
00005000  00001000  頁 RVA        // page RVA = 0x1000
00005004  00000118  重定位塊大小 size   
00005008      3013  Type|Offset   //   offset = 0x013
...
```

由 0x1000+0x013 算出待重定位的數據在文件偏移 0x1013 處，加上默認的 imagebase 就是 0x10001013。如下：

```x86asm
.text:10001012 68 9C 20 00 10        push 1000209C
```

即，文件偏移 0x1013 處的 1000209C 可能需要重定位。

**修改待重定位數據**程序運行後，me.dll 被加載到了 0x633C0000 處：

![dll 裝載處](figure/pe5-relocdll.png)

計算待重定位修正後的值，然後將修正的值寫到待重定位地址處：

```
計算待重定位數據地址：
(0x10001013 - DefaultImageBase) + ImageBase 
即 (0x10001013 - 0x10000000) + 0x633C0000 => 0x633C1013

計算待重定位數據修正後的值：
(0x1000209C - DefaultImageBase) + ImageBase 
即 (0x1000209C - 0x10000000) + 0x633C0000 => 0x633C209C

最後： *0x633C1013 = 0x633C209C
```

查看內存中實際的值：

![重定位後的地址](figure/pe5-relocdata.png)

> 留個問題，什麼時候 EXE 會需要重定位？