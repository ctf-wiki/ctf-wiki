# DEX文件

## 基本介紹

Google 爲 Android 中的 Java 代碼專門設計了對應的可執行文件 DEX（Dalvik eXecutable File），適用於手機這樣的內存低和處理器性能較差的移動平臺。下面，我們就來主要介紹一下DEX文件的格式。

## DEX 文件格式

### 數據類型定義

在介紹 DEX  文件的具體結構之前，我們先來關注一下 DEX 文件中所使用的一些基礎的數據類型。

| 名稱        | 說明                         |
| --------- | -------------------------- |
| byte      | 8 位有符號整數                   |
| ubyte     | 8 位無符號整數                   |
| short     | 16 位有符號整數，採用小端字節序          |
| ushort    | 16 位無符號整數，採用小端字節序          |
| int       | 32 位有符號整數，採用小端字節序          |
| uint      | 32 位無符號整數，採用小端字節序          |
| long      | 64 位有符號整數，採用小端字節序          |
| ulong     | 64 位無符號整數，採用小端字節序          |
| sleb128   | 有符號 LEB128，可變長度（見下文）       |
| uleb128   | 無符號 LEB128，可變長度（見下文）       |
| uleb128p1 | 無符號 LEB128 加 `1`，可變長度（見下文） |

其中之所以會採用變長的數據類型是因爲希望可以儘可能減少可執行文件的佔用空間，比如說如果一個字符串的長度爲5，那麼我們其實只需要一個字節即可，但是我們又不希望直接使用`u1` 來進行定義相應類型，因爲這樣會把所有的字符串長度都限制在相應的範圍內。

可變長度的類型其實都是基於 LEB128(Little-Endian Base) 類型的，可以用於表示 32 位大小的 int 數字，其根據所要表示的數字的大小來選擇合適的長度。如下圖所示，其中每個字節的最高位表示是否使用下一個字節，1 表示使用，0 表示不使用。故而每個字節其實只有 7 個有效的 bit 位用來表示相應的數字。如果有一個 LEB128 類型的變量使用了 5 個字節，並且第五個字節的最高位爲 1 ，那說明出現了問題。

![](./figure/leb128.png)

dalvik中讀取無符號leb128類型的函數如下

```c++
DEX_INLINE int readUnsignedLeb128(const u1** pStream) {
    const u1* ptr = *pStream;
    int result = *(ptr++);      //取第一個字節
    if (result > 0x7f) {        //如果第1個字節大於0x7f,表示第一個字節最高位爲1
        int cur = *(ptr++);     //第2個字節
        result = (result & 0x7f) | ((cur & 0x7f) << 7); //前兩個字節
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    /*
                     * Note: We don't check to see if cur is out of
                     * range here, meaning we tolerate garbage in the
                     * high four-order bits.
                     */
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    *pStream = ptr;
    return result;
}
```

舉個例子，假如我們要計算c0 83 92 25的uleb128值，如下

- 第一個字節的最高位爲1，所以有第二個字節。result1 = 0xc0 & 0x7f=0x40
- 類似的，第二個字節對應的result2 = (0x83 & 0x7f)<<7 = 0x180
- 第三個字節對應的result3 = (0x92 & 0x7f) <<14 =  0x48000
- 第四個字節對應的result4 = (0x25)<<21 = 0x4a00000
- 該字節流對應的值爲result1+result2+result3+result4 = 0x4a481c0

dalvik中讀取有符號的LEB128類型的數字如下

```c++
 DEX_INLINE int readSignedLeb128(const u1** pStream) {
    const u1* ptr = *pStream;
    int result = *(ptr++);
    if (result <= 0x7f) {
        result = (result << 25) >> 25;   //符號擴展
    } else {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur <= 0x7f) {
            result = (result << 18) >> 18; //符號擴展
        } else {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14; //符號擴展
            if (cur <= 0x7f) {
                result = (result << 11) >> 11; //符號擴展
            } else {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur <= 0x7f) {
                    result = (result << 4) >> 4;  //符號擴展
                } else {
                    /*
                     * Note: We don't check to see if cur is out of
                     * range here, meaning we tolerate garbage in the
                     * high four-order bits.
                     */
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    *pStream = ptr;
    return result;
}
```

舉個例子，假如我們要計算d1 c2 b3 40的sleb128值，計算過程如下

- result1 = 0xd1 & 0x7f = 0x51
- result2 = (0xc2 & 0x7f) <<7  = 0x21000
- result3 = (0xb3 & 0x7f) <<14  =0xcc000
- result4 = (0x40)<< 21 = 0x8000000
- 最後結果(r1+r2+r3+r4)<< 4 >>4 = 0xf80ce151


uleb128p1類型主要是用表示無符號數，其適用於以下場景

- 要求數字的表示必須非負
- 當數字爲0xffffffff時，其加上1就爲0，這時候我們就只需要1個字節即可。
- **有待進一步思考。**

### DEX 文件概覽

DEX文件的整體結構如下

![](./figure/dex_structure.png)

主要包括三個部分

- 文件頭，給出dex文件的基本屬性。
- 索引區，給出相關數據的索引，其數據其實放在數據區。
- 數據區，存放真實的字符串，代碼。

### DEX 文件頭

DEX的文件頭主要包含magic字段、alder32校驗值、SHA-1哈希值、string_ids的個數以及偏移地址等，固定佔用0x70個字節，數據結構如下

```c++
struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
};
```

其中具體的描述如下

| 名稱              | 格式                        | 說明                                       |
| --------------- | ------------------------- | ---------------------------------------- |
| magic           | ubyte[8] = DEX_FILE_MAGIC | 標識DEX文件，其中DEX_FILE_MAGIC ="dex\n035\0"   |
| checksum        | uint                      | 除 `magic` 和此字段之外的文件剩下內容的 adler32 校驗和，用於檢測文件損壞情況 |
| signature       | ubyte[20]                 | 除 `magic`、`checksum` 和此字段之外的文件的內容的 SHA-1 簽名（哈希），用於對文件進行唯一標識 |
| file_size       | uint                      | 整個文件（包括文件頭）的大小，以字節爲單位                    |
| header_size     | uint = 0x70               | 文件頭的大小，以字節爲單位。                           |
| endian_tag      | uint = ENDIAN_CONSTANT    | 字節序標記，大端序或者小端序。                          |
| link_size       | uint                      | 如果此文件未進行靜態鏈接，則該值爲 `0`，反之爲鏈接區段的大小，        |
| link_off        | uint                      | 如果 `link_size == 0`，則該值爲 `0`； 反之，該偏移量是文件開頭到到 `link_data` 區段的偏移量。 |
| map_off         | uint                      | 該偏移量必須非零，標識從文件開頭到 `data` 區段的偏移量。         |
| string_ids_size | uint                      | 字符串標識符列表中的字符串數量                          |
| string_ids_off  | uint                      | 如果 `string_ids_size == 0`（不可否認是一種奇怪的極端情況），則該值爲 `0`； 反之表示從文件開頭到`string_ids`的偏移量。 |
| type_ids_size   | uint                      | 類型標識符列表中的元素數量，最大爲 65535                  |
| type_ids_off    | uint                      | 如果 `type_ids_size == 0`（不可否認是一種奇怪的極端情況），則該值爲 `0`； 反之表示從文件開頭到 `type_ids` 區段開頭的偏移量。 |
| proto_ids_size  | uint                      | 原型（方法）標識符列表中的元素數量，最多爲 65535              |
| proto_ids_off   | uint                      | 如果 `proto_ids_size == 0`（不可否認是一種奇怪的極端情況），則該值爲 `0`； 反之該偏移量表示文件開頭到 `proto_ids` 區段開頭的偏移量。 |
| field_ids_size  | uint                      | 字段標識符列表中的元素數量                            |
| field_ids_off   | uint                      | 如果 `field_ids_size == 0`，則該值爲 `0`； 反之該偏移量表示文件開頭到 `field_ids` 區段開頭的偏移量。 |
| method_ids_size | uint                      | 方法標識符列表中的元素數量                            |
| method_ids_off  | uint                      | 如果 `method_ids_size == 0`，則該值爲 `0`。反之該偏移量表示從文件開頭到 `method_ids` 區段開頭的偏移量。 |
| class_defs_size | uint                      | 類定義列表中的元素數量                              |
| class_defs_off  | uint                      | 如果 `class_defs_size == 0`（不可否認是一種奇怪的極端情況），則該值爲 `0` ；反之該偏移量表示文件開頭到 `class_defs` 區段開頭的偏移量。 |
| data_size       | uint                      | `data` 區段的以字節爲單位的大小，必須是 sizeof(uint) 的偶數倍，說明8字節對齊。 |
| data_off        | uint                      | 從文件開頭到 `data` 區段開頭的偏移量。                  |

### DEX 索引區

#### string id

StringIds 區段包含`stringIdsSize`個`DexStringId`結構，其結構如下：

```c++
struct DexStringId {
    u4 stringDataOff;   /* 字符串數據偏移，也就是數據區中各個 StringData 的文件偏移*/
};
```

可以看出DexStringId中存儲的只是每一個字符串的相對偏移。此外，每一個偏移佔據4個字節，字符串部分一共會佔據4*stringIdsSize個字節。

在對應的偏移處，字符串是使用MUTF-8格式存儲的，其開頭存儲了之前我們所說的LEB128類型的變量，表示字符串的長度，之後緊跟着的就是字符串，之後以\x00結尾，字符串的長度不包含\x00。

#### type id

type_ids 區索引了java代碼中使用的所有類型（類、數組或基本類型），此列表必須按 `string_id` 索引進行排序，並且不能重複。

```c++
struct DexTypeId {
    u4 descriptorIdx;    /* 指向 DexStringId列表的索引 */
};
```

#### proto Id

Proto id字段主要是針對於 java 中的方法原型而設計的，這裏面主要包含了一個方法聲明的返回類型與參數列表，對於方法名尚未涉及。其主要包含以下三個數據結構

```c++
struct DexProtoId {
    u4 shortyIdx;       /* 返回類型+參數類型，簡寫，指向DexStringId列表的索引 */
    u4 returnTypeIdx;   /* 返回類型，指向DexTypeId列表的索引 */
    u4 parametersOff;   /* 參數類型，指向DexTypeList的偏移 */
}

struct DexTypeList {
    u4 size;             /* DexTypeItem的個數，即參數個數 */
    DexTypeItem list[1]; /* 指向DexTypeItem開始處 */
};

struct DexTypeItem {
    u2 typeIdx;           /* 參數類型，指向DexTypeId列表的索引，最終指向字符串索引 */
};
```

#### field id

field id區主要是針對於java中每個類的字段而設計的，主要涉及到以下數據結構

```c++
struct DexFieldId {
    u2 classIdx;   /* 類的類型，指向DexTypeId列表的索引 */
    u2 typeIdx;    /* 字段類型，指向DexTypeId列表的索引 */
    u4 nameIdx;    /* 字段名，指向DexStringId列表的索引 */
};
```

#### method id

method id區是直接爲 java 中的方法而設計的，其包含了方法所在的類，方法的原型，方法的名字。

```c++
struct DexMethodId {
    u2 classIdx;  /* 類的類型，指向DexTypeId列表的索引 */
    u2 protoIdx;  /* 聲明類型，指向DexProtoId列表的索引 */
    u4 nameIdx;   /* 方法名，  指向DexStringId列表的索引 */
};
```



#### class def

classDefsSize表明 class def 區域的大小，classDefsOff表明class def 區的偏移。

該區是爲 java 中的類而設計的，包含以下的數據結構，相關信息如下

```c++
// 類的基本信息
struct DexClassDef {
    u4 classIdx;    /* 類的類型，指向DexTypeId列表的索引 */
    u4 accessFlags; /* 訪問標誌 */
    u4 superclassIdx;  /* 父類類型，指向DexTypeId列表的索引 */
    u4 interfacesOff; /* 接口，指向DexTypeList的偏移 */
    u4 sourceFileIdx; /* 源文件名，指向DexStringId列表的索引 */
    u4 annotationsOff; /* 註解，指向DexAnnotationsDirectoryItem結構 */
    u4 classDataOff;   /* 指向DexClassData結構的偏移 */
    u4 staticValuesOff;  /* 指向DexEncodedArray結構的偏移 */
};

// 類的字段與方法概況
struct DexClassData {
    DexClassDataHeader header; /* 指定字段與方法的個數 */
    DexField* staticFields;    /* 靜態字段，DexField結構 */
    DexField* instanceFields;  /* 實例字段，DexField結構 */
    DexMethod* directMethods;  /* 直接方法，DexMethod結構 */
    DexMethod* virtualMethods; /* 虛方法，DexMethod結構 */

// 詳細描述類的字段個數與方法個數
struct DexClassDataHeader {
    u4 staticFieldsSize;  /* 靜態字段個數 */
    u4 instanceFieldsSize; /* 實例字段個數 */
    u4 directMethodsSize;  /* 直接方法個數 */
    u4 virtualMethodsSize; /* 虛方法個數 */
};

// 字段定義
struct DexField {
    u4 fieldIdx;    /* 指向DexFieldId的索引 */
    u4 accessFlags; /* 訪問標誌 */
};

// 方法定義
struct DexMethod {
    u4 methodIdx;   /* 指向DexMethodId的索引 */
    u4 accessFlags; /* 訪問標誌 */
    u4 codeOff;     /* 指向DexCode結構的偏移 */
};

// 代碼概況
struct DexCode {
    u2 registersSize;   /* 使用的寄存器個數 */
    u2 insSize;         /* 參數個數 */
    u2 outsSize;        /* 調用其他方法時其它方法使用的寄存器個數，會在自己的調用棧申請，並壓棧（猜測） */
    u2 triesSize;       /* Try/Catch個數 */
    u4 debugInfoOff;    /* 指向調試信息的偏移 */
    u4 insnsSize;       /* 指令集個數，以2字節爲單位 */
    u2 insns[1];        /* 指令集 */
};
```

#### 小結

可以看出在索引區指向是比較複雜的，但同時也比較巧妙，這裏給出Dalvik設計者在[Google Developer Day 2008 China](https://sites.google.com/site/developerdaychina/) 演講中給出的例子。

![](./figure/dex_structure_designer.png)

### DEX 數據區

這裏存的就是之前所說的各種數據了。

### DEX map section

DexHeader中的mapOff字段給出了DexMapList結構在DEX文件中的偏移。當Dalvik虛擬機解析DEX文件後的內容後，會將內容映射到DexMapList數據結構，可以說該結構描述了對應的DEX文件的整體概況。其具體代碼如下

```c++
struct DexMapList {
    u4 size;               /* DexMapItem的個數，方便解析 */
    DexMapItem list[1];    /* 指向DexMapItem */
};

struct DexMapItem {
    u2 type;      /* kDexType開頭的類型 */
    u2 unused;    /* 未使用，用於字節對齊 */
    u4 size;      /* 指定相應類型的個數 */
    u4 offset;    /* 指定相應類型的數據的文件偏移 */
};

/* type字段爲一個枚舉常量，通過類型名稱很容易判斷它的具體類型。 */
/* map item type codes */
enum {
    kDexTypeHeaderItem               = 0x0000,
    kDexTypeStringIdItem             = 0x0001,
    kDexTypeTypeIdItem               = 0x0002,
    kDexTypeProtoIdItem              = 0x0003,
    kDexTypeFieldIdItem              = 0x0004,
    kDexTypeMethodIdItem             = 0x0005,
    kDexTypeClassDefItem             = 0x0006,
    kDexTypeMapList                  = 0x1000,
    kDexTypeTypeList                 = 0x1001,
    kDexTypeAnnotationSetRefList     = 0x1002,
    kDexTypeAnnotationSetItem        = 0x1003,
    kDexTypeClassDataItem            = 0x2000,
    kDexTypeCodeItem                 = 0x2001,
    kDexTypeStringDataItem           = 0x2002,
    kDexTypeDebugInfoItem            = 0x2003,
    kDexTypeAnnotationItem           = 0x2004,
    kDexTypeEncodedArrayItem         = 0x2005,
    kDexTypeAnnotationsDirectoryItem = 0x2006,
};
```

## DEX實例

具體的可以自己找一個 apk，然後拿 010editor 的模板解析一下就可以看到相應的結果了。

## 參考閱讀

- Android 軟件安全與逆向分析
