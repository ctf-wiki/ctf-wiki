# Sections

節區包含目標文件中除了 ELF 頭部、程序頭部表、節區頭部表的所有信息。節區滿足以下條件

- 每個節區都有對應的節頭來描述它。但是反過來，節區頭部並不一定會對應着一個節區。
- 每個節區在目標文件中是連續的，但是大小可能爲 0。
- 任意兩個節區不能重疊，即一個字節不能同時存在於兩個節區中。
- 目標文件中可能會有閒置空間（inactive space），各種頭和節不一定會覆蓋到目標文件中的所有字節，**閒置區域的內容未指定**。

許多在 ELF 文件中的節都是預定義的，它們包含程序和控制信息。這些節被操作系統使用，但是對於不同的操作系統，同一節區可能會有不同的類型以及屬性。

可執行文件是由鏈接器將一些單獨的目標文件以及庫文件鏈接起來而得到的。其中，鏈接器會解析引用（不同文件中的子例程的引用以及數據的引用，調整對象文件中的絕對引用）並且重定位指令。加載與鏈接過程需要目標文件中的信息，並且會將處理後的信息存儲在一些特定的節區中，比如 `.dynamic` 。

每一種操作系統都會支持一組鏈接模型，但這些模型都大致可以分爲兩種

| 類型     | 描述                                                         |
| -------- | ------------------------------------------------------------ |
| 靜態鏈接 | 靜態鏈接的文件中所使用的庫文件或者第三方庫都被靜態綁定了，其引用已經被解析了。 |
| 動態鏈接 | 動態鏈接的文件中所使用的庫文件或者第三方庫只是單純地被鏈接到可執行文件中。當可執行文件執行時使用到相應函數時，相應的函數地址纔會被解析。 |

有一些特殊的節可以支持調試，比如說 .debug 以及 .line 節；支持程序控制的節有 .bss，.data， .data1， .rodata， .rodata1。

| 名稱      | 類型         | 屬性                 | 含義                                                         |
| :-------- | :----------- | :------------------- | :----------------------------------------------------------- |
| .comment  | SHT_PROGBITS |                      | 包含版本控制信息。                                           |
| .debug    | SHT_PROGBITS |                      | 此節區包含用於符號調試的信息。                               |
| .dynamic  | SHT_DYNAMIC  | SHF_ALLOC  SHF_WRITE | 此節區包含動態鏈接信息。SHF_WRITE 位設置與否是否被設置取決於具體的處理器。 |
| .dynstr   | SHT_STRTAB   | SHF_ALLOC            | 此節區包含用於動態鏈接的字符串，大多數 情況下這些字符串代表了與符號表項相關的名稱。 |
| .dynsym   | SHT_DYNSYM   | SHF_ALLOC            | 此節區包含動態鏈接符號表。                                   |
| .got      | SHT_PROGBITS |                      | 此節區包含全局偏移表。                                       |
| .line     | SHT_PROGBITS |                      | 此節區包含符號調試的行號信息，描述了源程序與機器指令之間的對應關係，其內容是未定義的。 |
| .plt      | SHT_PROGBITS |                      | 此節區包含過程鏈接表（procedure  linkage  table）。          |
| .relname  | SHT_REL      |                      | 這些節區中包含重定位信息。如果文件中包含可加載的段，段中有重定位內容，節區的屬性將包含SHF_ALLOC位，否則該位置 0。傳統上 name 根據重定位所適用的節區給定。例如 .text 節區的重定位節區名字將是：.rel.text 或者 .rela.text。 |
| .relaname | SHT_RELA     |                      |                                                              |
| .shstrtab | SHT_STRTAB   |                      | 此節區包含節區名稱。                                         |

注意：

- 以 “.” 開頭的節區名稱是系統保留的，當然應用程序也可以使用這些節區。爲了避免與系統節區衝突，應用程序應該儘量使用沒有前綴的節區名稱。
- 目標文件格式允許定義不在上述列表中的節區，可以包含多個名字相同的節區。
- 保留給處理器體系結構的節區名稱一般命名規則爲：處理器體系結構名稱簡寫+ 節區名稱。其中，處理器名稱應該與 e_machine 中使用的名稱相同。例如 .FOO.psect 節區是 FOO 體系結構中的 psect 節區。

這裏我們主要以鏈接視圖中的分類即段類型進行介紹，同時也會加上自己的一些簡單分類。

