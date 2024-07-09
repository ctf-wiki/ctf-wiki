# Smali

## 介紹

在執行 Android Java 層的代碼時，其實就是 Dalvik(ART) 虛擬機（使用 C或 C++ 代碼實現）在解析 Dalvik 字節碼，從而模擬程序的執行過程。

自然，Dalvik 字節碼晦澀難懂，研究人員們給出了 Dalvik 字節碼的一種助記方式：smali 語法。通過一些工具（如 apktool），我們可以把已有的 dex 文件轉化爲若干個 smali 文件（**一般而言，一個 smali 文件對應着一個類**），然後進行閱讀。對於不同的工具來說，其轉換後的 smali 代碼一般都不一樣，畢竟這個語法不是官方的標準。這裏我們介紹比較通用的語法。值得注意的是，在smali 語法中，使用的都是寄存器，但是其在解釋執行的時候，很多都會映射到棧中。

**感覺似乎這裏給個例子比較合適！！！！！**

## 基本結構

一個 Smali 文件的基本信息如下

- 基本類信息
    - 前三行描述轉換爲該 Smali 文件的類的信息
    - 如果類實現了接口，對應的接口信息
- 如果類使用了註解，對應的註解信息
- 字段描述
- 方法描述

比較有意思的是，Smali 代碼基本上還原了 java 代碼中含義。它主要有以下兩種類型的語句

- 聲明語句用來聲明 java 中自頂向下的類，方法，變量類型，以及每個方法中所要使用的寄存器的個數等信息。
- 執行語句來執行 java 中的每一行代碼，包含方法的調用，字段的讀寫，異常的捕捉等操作。

整體來說，Smali 代碼的可讀性還是比較強的。

## 聲明語句

在 smali 代碼中，聲明語句一般都是以 `.` 開始。

### 寄存器

目前，Dalvik 使用的寄存器都是 32 位，對於 64 位類型的變量，如 double 類型，它會使用兩個相鄰的 32 位寄存器來表示。

此外，我們知道 Dalvik 最多支持 65536 個寄存器(編號從 0~65535 )，但是 ARM 架構的 cpu 中只有 37 個寄存器。那 Dalvik 是怎麼做的呢？其實，每個 Dalvik 虛擬機維護了一個調用棧，該調用棧用來支持虛擬寄存器和真實寄存器相互映射的。

#### 寄存器聲明

在執行具體方法時，Dalvik 會根據  `.registers`  指令來確定該函數要用到的寄存器數目，虛擬機會根據申請的寄存器的數目來爲該方法分配相應大小的棧空間，dalvik 在對這些寄存器操作時，其實都是在操作棧空間。

#### 寄存器命名規則

一個方法所申請的寄存器會分配給函數方法的參數 (parameter) 以及局部變量 (local variable) 。在 smali 中，一般有兩種命名規則

- v 命名法
- p 命名法

假設方法申請了 m+n 個寄存器，其中局部變量佔 m 個寄存器，參數佔 n 個寄存器，對於不同的命名規則，其相應的命名如下

|   屬性   |          v命名法          |        p命名法        |
| :------: | :-----------------------: | :-------------------: |
| 局部變量 |   $v_0,v_1,...,v_{m-1}$   | $v_0,v_1,...,v_{m-1}$ |
| 函數參數 | $v_m,v_{m+1},...,v_{m+n}$ | $p_0,p_1,...,p_{n-1}$ |

 一般來說我們更傾向於 p 命名法，因爲其具有較好的可讀性，可以方便地讓我們知道寄存器屬於哪一種類型。

而這其實也就是 smali 語法中常見的寄存器命名規則，p 開頭的寄存器都是參數寄存器，v 開頭的寄存器都是局部變量寄存器，兩者的數量之和爲方法申請的寄存器數量。

### 變量類型

在 Dalvik 字節碼中，變量主要分爲兩種類型

| 類型   | 成員                                       |
| ---- | ---------------------------------------- |
| 基本類型 | boolean，byte，short，char，int，long，float，double，void（只用於返回值類型） |
| 引用類型 | 對象，數組                                    |

但是，我們在 smali 中其實並不需要把一個變量的類型的描述的全稱全部放進去，我們只需要可以識別它即可，那我們可以怎麼做呢？可以對它進行簡寫啊。dalvik 中簡寫方式如下

| java類型  | 類型描述符 |
| :-----: | :---: |
| boolean |   Z   |
|  byte   |   B   |
|  short  |   S   |
|  char   |   C   |
|   int   |   I   |
|  long   |   J   |
|  float  |   F   |
| double  |   D   |
|  void   |   V   |
|  對象類型   |   L   |
|  數組類型   |   [   |

其中對象類型可以表示Java代碼中的所有類。比如說如果一個類在java代碼中的以package.name.ObjectName（全名）的方式被引用，那麼在Davilk中，其描述則是 `Lpackage/name/ObjectName;` ，其中

- L即上面所說的對象類型。
- 全名中的 `.` 被替換爲 `/` 。
- 後面跟了一個 `;` 。

比如說在 `java.lang.String` ，其相應的形式爲`Ljava/lang/String;`

> 注：所謂全名就是它的全程不僅僅是簡寫，比如String其實是java.lang.String。

數組類型可以表示java中的所有數組。其一般的構成形式由前向後依次分爲兩個部分

- **數組維數**個[，但數組的維數最多爲255。
- 數據元素類型，這裏的類型自然就不能是[了。

 比如說int數組 `int []` 在smali中的表示形式爲 `[I ` 。

比如說數組類型 `String[][]` 在smali中的表示形式爲 `[[Ljava/lang/String;` 。

### 字段

在 java 的類中，一般都會有成員變量，也稱爲其屬性或者字段。java中的字段分爲

- 普通字段，實例屬性
- 靜態字段，類屬性，所有的類實例共享。

#### 普通字段

聲明如下

```text
#instance fields
.field <訪問權限修飾符> [非權限修飾符] <字段名>:<字段類型>
```

其中訪問權限修飾符可以爲

- public
- private
- protected

非權限修飾符可以爲(**查明其用法!!!**)

- final
- volidate
- transient

舉個例子，如下

```smali
# instance fields
.field private str1:Ljava/lang/String;
```

這裏聲明其實如下

```java
private java.lang.String str1;
```

#### 靜態字段

一般表示如下

```smali
#static fields
.field <訪問權限> static [修飾詞] <字段名>:<字段類型>
```

這裏我們就不介紹相應內容了，直接給出一個例子

```
# static fields
.field public static str2:Ljava/lang/String;
```

其實聲明如下

```java
public static java.lang.String str2;
```

### 方法

在 smali 代碼中，方法一般的展現形式如下

```text
# 描述方法類型
.method <訪問權限修飾符> [修飾符] <方法原型>
      <.locals>
      [.parameter]
      [.prologue]
      [.line]
      <代碼邏輯>
      [.line]
      <代碼邏輯>
.end
```

其中第一行以註釋形式描述方法的類型，一般是反編譯工具添加上去的，分爲兩種類型

- 直接方法，direct method
- 虛方法，virtual method

訪問權限可能有有以下形式，與 java 中的一一對應

- public
- private
- protected

修飾符主要有以取值範圍

- static，表明該方法是靜態方法

方法原型一般爲 `方法名(參數類型描述符)返回值類型描述符` 。與java方法中不一樣的是，在 smali 的這個方法原型中不會有參數對應的名字的，對應參數的名字可能會在.parameter中進行指定。

.locals 會指定方法使用的局部變量。

.parameter 的個數與方法的使用的參數格式一致，每一條語句聲明一個參數。如果方法是靜態方法的話，我們會使用 p0 來表示this，即當前對象，否則的話，參數就正常用 p0 開始。

.prologue 指定程序的開始處。混淆過後的代碼可能會沒有這一說明。

.line 指定相應的代碼在原 java 文件的行數。如果程序進行了混淆，一般就不會有這一行了。

**舉個例子，，，，找個合適的例子!!!!!!**

### 類

#### 基本類信息

如下

```text
.class <訪問權限修飾符> [非權限修飾符] <類名>
.super <父類名>
.source <源文件名稱>
```

其中，`<>` 中的內容必須存在，`[]` 的內容是可選的。訪問權限修飾符即所謂的 `public`，`protected`，`private`。而非權限修飾符則指的是`final`，`abstract`。舉個例子

```smali
.class public final Lcom/a/b/c;
.super Ljava/lang/Object;
.source "Demo.java"
```

可以看出我們類的訪問權限是`public`，非權限修飾符爲`final`，類名爲`com.a.b.c`，它繼承了父類`java.lang.object`，對應的源文件爲`Demo.java`。

#### 接口

如果一個類實現了某個接口，則會通過`.implements`進行，如下:

```
#interfaces
.implements <接口名稱>
```

給個例子，一般來說，smali都會對其進行註釋表明它是一個接口。

```smali
# interfaces
.implements Landroid/view/View$OnClickListener;
```

#### 類的類別

Java中允許在一個類中定義另外一個類，還允許多層嵌套，我們稱類中的類爲內部類。內部類主要有

- 成員內部類
- 靜態嵌套類
- 方法內部類
- 匿名內部類

在smali中，每個類都會對應一個smali文件。

#### 類的引用

在smali代碼中，我們會使用 this 來表示父類的引用，對於父類的中的子類，我們會根據其層數來進行引用，其格式爲`this$[層數]` ，舉個例子

```java
public class MainActivity extends Activity {   //this$0
   public class firstinner  //this$1
   {
      public class secondinner //this$2
      {
         public class thirdinner //this$3
         {

         }
      }
   }
}
```

比如說`thirdinner` 引用`firstinner` 其會使用`this$1` 來進行引用。而且，對於`this$x` 這樣的字段都會被定義爲`synthetic` 類型，表明這種字段是由編譯器自動生成的，在源代碼裏並沒有這樣的字段。

此外，在smali中，每個類都會對應一個 smali 文件，這幾個類對應的 smali 文件名分別爲

```
MainActivity.smali
MainActivity$firstinner.smali
MainActivity$firstinner$secondinner.smali
MainActivity$firstinner$thirdinner.smali
```

### 註解

註解的格式如下

```smali
#annotations
.annotation [註解的屬性] <註解範圍>
    [註解字段=值]
    ...
.end
```

其中，如果註解範圍是類的話，註解會直接出現在 smali 文件中。如果註解範圍是方法或者字段的話，會包含在相應的方法或者字段的定義中。

## 執行語句

這裏部分參考http://blog.csdn.net/wizardforcel/article/details/54730253。

### Dalvik指令格式

在介紹 smali 語法中的指令之前，我們先來看看 Dalvik 指令的基本格式。

Dalvik 中指令的格式主要包含兩個方面：位描述，格式ID。目前 Dalvik 中基本上所有的指令如下圖所示，其中第一列給出了指令按照位進行描述的格式，第二列是格式化 ID ，第三列表示相應的句法，第四列對其進行說明。

![](./figure/Dalvik-Executable-instruction-formats.png)

#### 位描述

在位描述中，Davik 中的每一類指令一般由如下的元素構成

- 一個op，8位指令碼
- 若干個字符，每一個字符表示4位
- 若干個 `|` ，進行分割，方便閱讀。
- 若干個 $\varnothing$ ，同樣也是4個字符，表示該部分位爲0。

此外，在上面的展現形式種，指令由一個或者多個空格分割的 16 位的 word 組成，其中每一個 word 可以包含上述的幾個元素。

舉個例子，指令 `B|A|op CCCC` 包含2個 word，一共 32 位。其中，第一個字的低 8 位是操作碼，中間 4 位是A，高4位是B。第二個字是單獨的16位的數值。

#### 格式ID

但是，正如表格裏所展現的

![](./figure/Dalvik-Instruction-sample.png)

這樣的一種指令格式，根據ID的不同，仍然可以表示不同的指令含義。

一般來說，格式ID由若干個字符組成，一般來說包含3個字符

- 第一個數字表示word的數量

- 第二個

    - 數字的話，表示指令包含的寄存器的最大數量（這是因爲有些指令可以包含不定個數的寄存器）
    - r的話，表示使用了一定範圍內的寄存器(range)。

- 第三個字符表示指令使用到的額外數據的類型。如下表

  | Mnemonic | Bit Sizes | Meaning                                  |
  | -------- | --------- | ---------------------------------------- |
  | b        | 8         | immediate signed byte                    |
  | c        | 16, 32    | constant pool index                      |
  | f        | 16        | interface constants (only used in statically linked formats) |
  | h        | 16        | immediate signed hat (high-order bits of a 32- or 64-bit value; low-order bits are all `0`) |
  | i        | 32        | immediate signed int, or 32-bit float    |
  | l        | 64        | immediate signed long, or 64-bit double  |
  | m        | 16        | method constants (only used in statically linked formats) |
  | n        | 4         | immediate signed nibble                  |
  | s        | 16        | immediate signed short                   |
  | t        | 8, 16, 32 | branch target                            |
  | x        | 0         | no additional data                       |

- 如果存在第四個字符的話

  - s表示採用靜態鏈接
  - i表示指令應該被內聯處理。

#### 句法

其基本要求如下

- 指令以操作碼op開始，後面直接跟上一個或者多個參數，參數間以逗號分隔。
- 指令的參數從指令第一部分開始，op位於低8位，高8位可以是一個8位的參數，也可以是兩個4位的參數，還可以爲空。如果指令超過16位，則後面部分依次作爲參數。
- 參數`Vx`表示寄存器，如v0、v1等。這裏之所以採用v而不用r是爲了避免與實現該虛擬機架構的機器架構中的寄存器命名產生衝突。
- 參數 `#+X` 表示常量數字。
- 參數 `+X` 表示相對指令的地址偏移。
- 參數 `kind@X`  表示常量池索引值，其中kind表示常量池類型，可以是以下四種類型
    - string，字符串常量池索引
    - type，類型常量池索引
    - field，字段常量池索引
    - meth，方法常量池索引

以指令 `op vAA, type@BBBB` 爲例，指令使用了1個寄存器vAA，一個32位的類型常量池索引。

### 指令特點

Dalvik指令在調用規範上大致模仿常見的架構和 C 樣式的調用規範，如下

- 參數順序爲 Dest-then-source 。

- 利用後綴用來表明運算類型，從而消除歧義：

    - 正常的32 位運算不標記。
    - 正常地64 位運算以 `-wide` 爲後綴。
    - 特定類型的運算碼以其類型（或簡單縮寫）爲後綴，這些類型包括：`-boolean`、`-byte`、`-char`、`-short`、`-int`、`-long`、`-float`、`-double`、`-object`、`-string`、`-class` 和 `-void`。

- 利用運算碼部分後綴區分具有不同指令樣式或者或選項的相同運算，這些後綴與主要名稱之間以 `/` 分開，主要目的是使生成和解析可執行文件的代碼中存在與靜態常量的一對一映射關係，以便於降低讓讀者感到模糊不清的可能性。



  例如，在指令`move-wide/from16 vAA, vBBBB` 中

  - `move`爲基礎運算碼，表示這是基本運算，用來移動寄存器的值。
  - `wide`爲名稱後綴，表示指令對64 位數據進行運算。
  - `from16`爲運算碼後綴，表示源爲一個 16 位寄存器的引用變量。
  - `vAA`爲目的寄存器，取值範圍爲 `v0` - `v255`。
  - `vBBBB`爲源寄存器，取值範圍爲 `v0` - `v65535`。

### 具體指令

這裏，我們具體介紹依次每一條指令的含義，並儘可能地對其進行分類。

#### 空指令

nop指令，無任何操作，一般用於對齊代碼。

#### 數據定義指令

| op&id  | 語法                                       | 參數                                       | 說明                                       |
| ------ | ---------------------------------------- | ---------------------------------------- | ---------------------------------------- |
| 2 11n  | const/4 vA, #+B                          | `A:` 目標寄存器（4 位）           `B:` 有符號整數（4 位） | 將給定的值（符號擴展爲 32 位）移到指定的寄存器中。              |
| 13 21s | const/16 vAA, #+BBBB                     | `A:` 目標寄存器（8 位）           `B:` 有符號整數（16 位） | 將給定的值（符號擴展爲 32 位）移到指定的寄存器中。              |
| 14 31i | const vAA, #+BBBBBBBB                    | `A:` 目標寄存器（8 位）           `B:` 任意 32 位常量 | 將給定的值移到指定的寄存器中。                          |
| 15 21h | const/high16 vAA, #+BBBB0000             | `A:` 目標寄存器（8 位）           `B:` 有符號整數（16 位） | 將給定的值（右零擴展爲 32 位）移到指定的寄存器中。              |
| 16 21s | const-wide/16 vAA, #+BBBB                | `A:` 目標寄存器（8 位）           `B:` 有符號整數（16 位） | 將給定的值（符號擴展爲 64 位）移到指定的寄存器對中。             |
| 17 31i | const-wide/32 vAA, #+BBBBBBBB            | `A:` 目標寄存器（8 位）            `B:` 有符號整數（32 位） | 將給定的值（符號擴展爲 64 位）移到指定的寄存器對中。             |
| 18 51l | const-wide vAA, #+BBBBBBBBBBBBBBBB       | `A:` 目標寄存器（8 位）           `B:` 任意雙字寬度（64 位）常量 | 將給定的值移到指定的寄存器對中。                         |
| 19 21h | const-wide/high16 vAA, #+BBBB000000000000 | `A:` 目標寄存器（8 位）           `B:` 有符號整數（16 位） | 將給定的值（右零擴展爲 64 位）移到指定的寄存器對中。             |
| 1a 21c | const-string vAA, string@BBBB            | `A:` 目標寄存器（8 位）           `B:` 字符串索引     | 將給定的字符串引用賦值給指定的寄存器中。                     |
| 1b 31c | const-string/jumbo vAA, string@BBBBBBBB  | `A:` 目標寄存器（8 位）            `B:` 字符串索引    | 將給定字符串引用（較大）賦值到指定的寄存器中。                  |
| 1c 21c | const-class vAA, type@BBBB               | `A:` 目標寄存器（8 位）           `B:` 類型索引      | 將給定類引用賦值到指定的寄存器中。如果指定的類型是原始類型，則將存儲對原始類型的退化類的引用。 |

舉個例子，如果java代碼如下

```java
boolean z = true;
z = false;
byte b = 1;
short s = 2;
int i = 3;
long l = 4;
float f = 0.1f;
double d = 0.2;
String str = "test";
Class c = Object.class;
```

那麼編譯之後得到的代碼如下

```smali
const/4 v10, 0x1
const/4 v10, 0x0
const/4 v0, 0x1
const/4 v8, 0x2
const/4 v5, 0x3
const-wide/16 v6, 0x4
const v4, 0x3dcccccd    # 0.1f
const-wide v2, 0x3fc999999999999aL    # 0.2
const-string v9, "test"
const-class v1, Ljava/lang/Object;
```

可以看出，根據數據類型大小的不同，會採用不同的語法。此外，我們可以看到float的字面值是0x3dcccccd，這其實就是0.1。關於浮點數在計算機中的存在形式，請自行網上搜索。此外，一般來說，smali會自動幫我們將string的id轉換爲其真正的字符串。

#### 數據移動

數據移動指令主要是將數據從一個寄存器或者內存中移動到另一處。

| op&id  | 語法                            | 參數                                  | 說明                              |
| ------ | ----------------------------- | :---------------------------------- | ------------------------------- |
| 01 12x | move vA, vB                   | `A:` 目標寄存器（4 位）`B:` 源寄存器（4 位）       | vA=vB                           |
| 02 22x | move/from16 vAA, vBBBB        | `A:` 目標寄存器（8 位）`B:` 源寄存器（16 位）      | vAA=vBBBB                       |
| 03 32x | move/16 vAAAA, vBBBB          | `A:` 目標寄存器（16 位）`B:` 源寄存器（16 位）     | vAAAA=VBBBB                     |
| 04 12x | move-wide vA, vB              | `A:` 目標寄存器對（4 位）`B:` 源寄存器對（4 位）     | vA，v(A+1)=vB，V(B+1)             |
| 05 22x | move-wide/from16 vAA, vBBBB   | `A:` 目標寄存器對（8 位）`B:` 源寄存器對(16 bit)  | vAA，v(AA+1)=vBBBB，V(BBBB+1)     |
| 06 32x | move-wide/16 vAAAA, vBBBB     | `A:` 目標寄存器對（16 位）`B:` 源寄存器對(16 bit) | vAAAA，v(AAAA+1)=vBBBB，V(BBBB+1) |
| 07 12x | move-object vA, vB            | `A:` 目標寄存器（4 位）`B:` 源寄存器（4 位）       | 對象引用賦值，vA=vB                    |
| 08 22x | move-object/from16 vAA, vBBBB | `A:` 目標寄存器（8 位）`B:` 源寄存器（16 位）      | 對象引用賦值，vAA=vBBBB                |
| 09 32x | move-object/16 vAAAA, vBBBB   | `A:` 目標寄存器（16 位）`B:` 源寄存器（16 位）     | 對象引用賦值，vAAAA=vBBBB              |
| 0a 11x | move-result vAA               | `A:` 目標寄存器（8 位）                     | 將函數調用返回值放到VAA寄存器中。              |
| 0b 11x | move-result-wide vAA          | `A:` 目標寄存器對（8 位）                    | 將函數調用返回值放到VAA寄存器中。              |
| 0c 11x | move-result-object vAA        | `A:` 目標寄存器（8 位）                     | 將函數調用返回對象引用VAA寄存器中。             |
| 0d 11x | move-exception vAA            | `A:` 目標寄存器（8 位）                     | 將捕獲的異常保存到給定寄存器中。                |

其中，`move`系列指令以及`move-result` 用於處理小於等於 32 位的基本類型。

`move-wide`系列指令和`move-result-wide`用於處理64位類型，包括`long`和`double`類型。

`move-object`系列指令和`move-result-object`用於處理對象引用。

此外，後綴（`/from16`、`/16`）隻影響字節碼的位數和寄存器的範圍，不影響指令的邏輯。

#### 數據轉換指令

數據轉換指令主要是將一種數據類型轉換爲另一種數據類型。目前已有的指令如下

| **指令**          | **說明**            |
| --------------- | ----------------- |
| neg-int         | 對整型數求補            |
| not-int         | 對整型數求反            |
| neg-long        | 對長整型數求補           |
| not-long        | 對長整型數求反           |
| neg-float       | 對單精度浮點型數求補        |
| neg-double      | 對雙精度浮點型數求補        |
| int-to-long     | 將整型數轉換爲長整型        |
| int-to-float    | 將整型數轉換爲單精度浮點型數    |
| int-to-dobule   | 將整型數轉換爲雙精度浮點數     |
| long-to-int     | 將長整型數轉換爲整型        |
| long-to-float   | 將長整型數轉換爲單精度浮點型    |
| long-to-double  | 將長整型數轉換爲雙精度浮點型    |
| float-to-int    | 將單精度浮點數轉換爲整型      |
| float-to-long   | 將單精度浮點數轉換爲長整型數    |
| float-to-double | 將單精度浮點數轉換爲雙精度浮點型數 |
| double-to-int   | 將雙精度浮點數轉換爲整型      |
| double-to-long  | 將雙精度浮點數轉換爲長整型     |
| double-to-float | 將雙精度浮點數轉換爲單精度浮點型  |
| int-to-byte     | 將整型轉換爲字節型         |
| int-to-char     | 將整型轉換爲字符型         |
| int-to-short    | 將整型轉換爲短整型         |

舉個例子`int-to-short v0,v1` 即將寄存器v1的值強制轉換爲short類型，並放入v0中。

#### 數學運算指令

數學算指令包括算術運算指令與邏輯運算指令。其中，算術運算指令包括加，減，乘，除，模，移位等運算，邏輯運算指令主要進行數值間與，或，非，抑或等運算。

數據運算指令有以下四類，其中運算符爲binop。

| **指令**                     | **說明**                         |
| -------------------------- | ------------------------------ |
| binop vAA, vBB, vCC        | 將vBB寄存器與vCC寄存器進行運算，結果保存到vAA寄存器 |
| binop/2addr vA, vB         | 將vA寄存器與vB寄存器進行運算，結果保存到vA寄存器    |
| binop/lit16 vA, vB, #+CCCC | 將vB寄存器與常量 CCCC進行運算，結果保存到vA寄存器  |
| binop/lit8 vAA, vBB, #+CC  | 將vBB寄存器與常量CC進行運算，結果保存到vAA寄存器   |

後面3類指令比第1類指令分別多出了2addr，lit16，lit8後綴。但是，對於基礎字節碼相同的指令來說，其執行的運算操作是類似的。所以這裏我們主要介紹第一類指令。除此之外，根據數據的類型不同會在基礎字節碼後面加上數據類型後綴，如`-int` 或 `-long` 分別表示操作的數據類型爲整型與長整型。第一類指令的運算類型如下

| 運算類型      | **說明**             |
| --------- | ------------------ |
| add-type  | vBB + vCC          |
| sub-type  | vBB - vCC          |
| mul-type  | vBB * vCC          |
| div-type  | vBB / vCC          |
| rem-type  | vBB % vCC          |
| and-type  | vBB & vCC          |
| or-type   | vBB \| vCC         |
| xor-type  | vBB ^ vCC          |
| shl-type  | vBB << vCC ，有符號數左移 |
| shr-type  | vBB >> vCC，有符號數右移  |
| ushr-type | vBB >>> vCC，無符號數右移 |

其中基礎字節碼後面的-type可以是-int，-long， -float，-double。

舉個例子，java源碼爲

```java
int a = 5, b = 2;
a += b;
a -= b;
a *= b;
a /= b;
a %= b;
a &= b;
a |= b;
a ^= b;
a <<= b;
a >>= b;
a >>>= b;
```

其對應的smali爲

```smali
const/4 v0, 0x5
const/4 v1, 0x2
add-int/2addr v0, v1
sub-int/2addr v0, v1
mul-int/2addr v0, v1
div-int/2addr v0, v1
rem-int/2addr v0, v1
and-int/2addr v0, v1
or-int/2addr v0, v1
xor-int/2addr v0, v1
shl-int/2addr v0, v1
shr-int/2addr v0, v1
ushr-int/2addr v0, v1
```

#### 數組操作指令

數組操作指令中實現了獲取數組長度，新建數組，數組賦值，數組元素取值與賦值等操作。

| **指令**                                   | **說明**                                   |
| ---------------------------------------- | ---------------------------------------- |
| array-length vA, vB                      | 獲取給定vB寄存器中數組的長度並賦給vA寄存器，數組長度指的是數組中的元素個數。 |
| new-array vA, vB, type@CCCC              | 構造大小爲vB的元素類型爲type@CCCC的數組，並將引用賦給vA寄存器    |
| filled-new-array {vC, vD, vE, vF, vG},type@BBBB | 構造大小vA的元素類型爲type@BBBB的數組並填充數組內容。vA寄存器是隱含使用的，除了指定數組的大小外還指定了參數的個數，vC~vG是使用到的參數寄存序列 |
| filled-new-array/range {vCCCC  ..vNNNN}, type@BBBB | 指令功能與filled-new-array {vC, vD, vE, vF, vG},type@BBBB相同，只是參數寄存器使用range後綴指定了取值範圍 ，vC是第一個參數寄存器，N = A +C -1 |
| fill-array-data vAA, +BBBBBBBB           | 用指定的數據來填充數組，vAA寄存器爲數組引用，引用必須爲基礎類型的數組，在指令後面會緊跟一個數據表 |
| new-array/jumbo vAAAA, vBBBB,type@CCCCCCCC | 指令功能與new-array vA,vB,type@CCCC相同，但是寄存器值與指令的索引取值範圍更大（Android4.0中新增的指令） |
| filled-new-array/jumbo {vCCCC  ..vNNNN},type@BBBBBBBB | 指令功能與filled-new-array/range {vCCCC  ..vNNNN},type@BBBB相同，只是索引取值範圍更大（Android4.0中新增的指令） |
| arrayop vAA, vBB, vCC                    | 對vBB寄存器指定的數組元素進行取值與賦值。vCC寄存器指定數組元素索引，vAA寄存器用來存放讀取的或需要設置的數組元素的值。讀取元素使用aget類指令，元素賦值使用aput類指定，根據數組中存儲的類型指令後面會緊跟不同的指令後綴，指令列表如下：aget, aget-wide, aget-object, aget-boolean, aget-byte,aget-char, aget-short, aput, aput-wide, aput-object, aput-boolean, aput-byte, aput-char, aput-short。 |

我們可以定義數組如下

```java
int[] arr = new int[10];
```

其對應的smali如下

```smali
const/4 v1, 0xa
new-array v0, v1, I
```

如果我們直接在定義時，對數組進行初始化，如下

```smali
int[] arr = {1, 2, 3, 4, 5};
```

對應的smali如下

```smali
const/4 v1, 0x1
const/4 v2, 0x2
const/4 v3, 0x3
const/4 v4, 0x4
const/4 v5, 0x5
filled-new-array {v1, v2, v3, v4, v5}, I
move-result v0
```

在寄存器連續的情況下，還可以寫成如下代碼

```smali
const/4 v1, 0x1
const/4 v2, 0x2
const/4 v3, 0x3
const/4 v4, 0x4
const/4 v5, 0x5
filled-new-array-range {v1..v5}, I
move-result v0
```

#### 實例操作指令

實例操作指令主要實現了實例的類型轉換，檢查及新建等功能。

| **指令**                                   | **說明**                                   |
| ---------------------------------------- | ---------------------------------------- |
| check-cast vAA, type@BBBB                | 將vAA寄存器中的對象引用轉換成type@BBBB類型，如果失敗的話，拋出ClassCastException異常。如果類型B指定的是基本類型，對於非基本類型的A來說，運行時始終會失敗 |
| instance-of vA, vB, type@CCCC            | 判斷vB寄存器中的對象引用是否可以轉換成指定的類型，如果可以，vA寄存器被賦值爲1，否則vA寄存器被 賦值爲0。 |
| new-instance vAA, type@BBBB              | 構造一個指定類型對象的新實例，並將對象引用賦值給vAA寄存器，類型符type指定的類型不能是數組類 |
| check-cast/jumbo vAAAA, type@BBBBBBBB    | 功能與check-cast vAA, type@BBBB相同，只是寄存器值與指令的索引取值範圍更大（Android4.0中新增的指令） |
| instance-of/jumbo vAAAA, vBBBB, type@CCCCCCCC | 功能與instance-of vA, vB, type@CCCC相同，只是寄存器值與指令的索引取值範圍更大（Android4.0中新增的指令） |
| new-instance/jumbo vAAAA, type@BBBBBBBB  | 功能與new-instance vAA, type@BBBB相同，只是寄存器值與指令的索引取值範圍更大（Android4.0中新增的指令） |

比如，我們定義一個實例

```java
Object obj = new Object();
```

其對應的smali代碼如下

```smali
new-instance v0, Ljava/lang/Object;
invoke-direct-empty {v0}, Ljava/lang/Object;-><init>()V
```

再比如我們可以進行如下的類型判斷

```java
String s = "test";
boolean b = s instanceof String;
```

其對應的smali代碼如下

```smali
const-string v0, "test"
instance-of v1, v0, Ljava/lang/String;
```

如果我們進行類型的強制轉換

```java
String s = "test";
Object o = (Object)s;
```

其對應的smali代碼如下

```smali
const-string v0, "test"
check-cast v0, Ljava/lang/Object;
move-object v1, v0
```

#### 字段操作指令

字段操作指令主要是對實例的字段進行讀寫操作。其中讀操作使用get來標記，即vx=vy.field。寫操作使用put來標記，即vy.field=vx。

其中對於java中的類來說，主要分爲兩種字段，普通字段，靜態字段。對於普通字段採用操作指令前加i來標記，如iget，iput。對於靜態字段採用在操作指令前加s來標記，如sput，sget。

此外，對於不同字段大小的操作會在指令的後面加上後綴來進行區別。如 iget-byte指令表示讀取類型爲字節的實例字段的值，iput-short指令表示設置的實例字段的類型爲短整型。

普通字段操作指令有：

iget，iget-wide，iget-object，iget-boolean，iget-byte，iget-char，iget-short，

iput，iput-wide，iput-object，iput-boolean，iput-byte，iput-char，iput-short。

靜態字段操作指令有：

sget，sget-wide，sget-object，sget-boolean，sget-byte，sget-char，sget-short，

sput，sput-wide，sput-object，sput-boolean，sput-byte，sput-char，sput-short。

如果我們編寫如下代碼

```java
int[] arr = new int[2];
int b = arr[0];
arr[1] = b;
```

其對應的smali如下

```smali
const/4 v0, 0x2
new-array v1, v0, I
const/4 v0, 0x0
aget-int v2, v1, v0
const/4 v0, 0x1
aput-int v2, v1, v0
```

如果我們想獲得類com.example.test的靜態int類型的字段staticField，其smali如下

```smali
sget v0, Lcom/example/Test;->staticField:I
```

#### 比較指令

比較指令實現了對兩個寄存器的值（浮點型或長整型）進行比較的操作。

其格式爲cmp(l/g)-kind vAA, vBB, vCC，其中vBB寄存器與vCC寄存器是需要比較的兩個寄存器或寄存器對，比較的結果放到vAA寄存器。

- l-->less
- g--> great

目前的比較指令如下

| **指令**      | **說明**                                   |
| ----------- | ---------------------------------------- |
| cmpl-float  | 比較兩個單精度浮點數。如果vBB寄存器大於vCC寄存器，結果爲-1，相等則結果爲0，小於的話結果爲1 |
| cmpg-float  | 比較兩個單精度浮點數。如果vBB寄存器大於vCC寄存器，則結果爲1，相等則結果爲0，小於的話結果爲-1 |
| cmpl-double | 比較兩個雙精度浮點數。如果vBB寄存器對大於vCC寄存器對，則結果爲-1，相等則結果爲0，小於則結果爲1 |
| cmpg-double | 比較兩個雙精度浮點數。如果vBB寄存器對大於vCC寄存器對，則結果爲1，相等則結果爲0，小於的話，則結果爲-1 |
| cmp-long    | 比較兩個長整型數。如果vBB寄存器大於vCC寄存器，則結果爲1，相等則結果爲0，小則結果爲-1 |

#### 跳轉指令

跳轉指令實現了從當前地址跳轉到指定的偏移處的操作。Dalvik指令集中有三種跳轉指令

- goto，無條件跳轉
- switch，分支跳轉
- if，條件跳轉

##### goto指令

如下

| 指令                | 含義                      |
| ----------------- | ----------------------- |
| goto +AA          | 無條件跳轉到指定偏移處，偏移量AA不能爲0   |
| goto/16 +AAAA     | 無條件跳轉到指定偏移處，偏移量AAAA不能爲0 |
| goto/32 +AAAAAAAA | 無條件跳轉到指定偏移處             |

##### if指令

if指令中主要分爲兩種if-test與if-testz。`if-test vA,vB,+CCCC` 會比較vA與v，如果比較結果滿足就跳轉到CCCC指定的偏移處（相對當前偏移），偏移量CCCC不能爲0。if-test類型的指令如下：

| 指令                   | 說明           |
| -------------------- | ------------ |
| `if-eq vA,vB,target` | 如果vA=vB，跳轉。  |
| `if-ne vA,vB,target` | 如果vA!=vB，跳轉。 |
| `if-lt vA,vB,target` | 如果vA<vB，跳轉。  |
| `if-gt vA,vB,target` | 如果vA>vB，跳轉。  |
| `if-ge vA,vB,target` | 如果vA>=vB，跳轉。 |
| `if-le vA,vB,target` | 如果vA<=vB，跳轉。 |

if-testz類型的指令如下

| 指令                | 說明          |
| ----------------- | ----------- |
| if-eqz vAA,target | 如果vA=0，跳轉。  |
| if-nez vAA,target | 如果vA!=0，跳轉。 |
| if-ltz vAA,target | 如果vA<0，跳轉。  |
| if-gtz vAA,target | 如果vA>0，跳轉。  |
| if-lez vAA,target | 如果vA<=0，跳轉。 |
| if-gtz vAA,target | 如果vA>=0，跳轉。 |

舉個例子，java代碼如下

```java
int a = 10
if(a > 0)
    a = 1;
else
    a = 0;
```

smali代碼如下

```smali
const/4 v0, 0xa
if-lez v0, :cond_0 # if 塊開始
const/4 v0, 0x1
goto :cond_1       # if 塊結束
:cond_0            # else 塊開始
const/4 v0, 0x0
:cond_1            # else 塊結束
```

在只有if的情況下

```java
int a = 10;
if(a > 0)
    a = 1;
```

smali代碼如下

```smali
const/4 v0, 0xa
if-lez v0, :cond_0 # if 塊開始
const/4 v0, 0x1
:cond_0            # if 塊結束
```

##### switch指令

如下

| 指令                          | 含義                                       |
| --------------------------- | ---------------------------------------- |
| packed-switch vAA,+BBBBBBBB | vAA寄存器爲switch分支中需要判斷的值，BBBBBBBB指向一個packed-switch-payload格式的偏移表，表中的值是有規律遞增的。 |
| sparse-switch vAA,+BBBBBBBB | vAA寄存器爲switch分支中需要判斷的值，BBBBBBBB指向一個sparse-switch-payload格式的偏移表，表中的值是無規律的偏移表，表中的值是無規律的偏移量。 |

對於第一種遞增式的switch，如下

```java
int a = 10;
switch (a){
    case 0:
        a = 1;
        break;
    case 1:
        a = 5;
        break;
    case 2:
        a = 10;
        break;
    case 3:
        a = 20;
        break;
}
```

對應的smali如下

```smali
const/16 v0, 0xa

packed-switch v0, :pswitch_data_0 # switch 開始

:pswitch_0                        # case 0
const/4 v0, 0x1
goto :goto_0

:pswitch_1                        # case 1
const/4 v0, 0x5
goto :goto_0

:pswitch_2                        # case 2
const/16 v0, 0xa
goto :goto_0

:pswitch_3                        # case 3
const/16 v0, 0x14
goto :goto_0

:goto_0                           # switch 結束
return-void

:pswitch_data_0                   # 跳轉表開始
.packed-switch 0x0                # 從 0 開始
    :pswitch_0
    :pswitch_1
    :pswitch_2
    :pswitch_3
.end packed-switch                # 跳轉表結束
```

對於非遞增的switch，代碼如下

```smali
int a = 10;
switch (a){
    case 0:
        a = 1;
        break;
    case 10:
        a = 5;
        break;
    case 20:
        a = 10;
        break;
    case 30:
        a = 20;
        break;
}
```

對應的smali如下

```smali
const/16 v0, 0xa

sparse-switch v0, :sswitch_data_0 # switch 開始

:sswitch_0                        # case 0
const/4 v0, 0x1
goto :goto_0

:sswitch_1                        # case 10
const/4 v0, 0x5

goto :goto_0

:sswitch_2                        # case 20
const/16 v0, 0xa
goto :goto_0

:sswitch_3                        # case 15
const/16 v0, 0x14
goto :goto_0

:goto_0                           # switch 結束
return-void

.line 55
:sswitch_data_0                   # 跳轉表開始
.sparse-switch
    0x0 -> :sswitch_0
    0xa -> :sswitch_1
    0x14 -> :sswitch_2
    0x1e -> :sswitch_3
.end sparse-switch                # 跳轉表結束
```



#### 鎖指令

鎖指令用於在多線程程序。包含以下兩個指令

| **指令**            | **說明**    |
| ----------------- | --------- |
| monitor-enter vAA | 爲指定的對象獲取鎖 |
| monitor-exit vAA  | 釋放指定的對象的鎖 |

#### 方法調用指令

方法調用指令實現了調用實例的方法的操作。其基礎爲invoke，在其基礎上會根據調用方法的類別不同，如虛方法，父類方法等添加後綴，最後會選擇性地使用range來指定寄存器範圍。一般來說會分爲兩類

- invoke-kind {vC, vD, vE, vF, vG},meth@BBBB

- invoke-kind/range {vCCCC  .. vNNNN},meth@BBBB兩類


  總體來說，一般有如下指令

| **指令**                                   | **說明**    |
| ---------------------------------------- | --------- |
| invoke-virtual 或 invoke-virtual/range    | 調用實例的虛方法  |
| invoke-super 或 invoke-super/range        | 調用實例的父類方法 |
| invoke-direct 或 invoke-direct/range      | 調用實例的直接方法 |
| invoke-static 或 invoke-static/range      | 調用實例的靜態方法 |
| invoke-interface 或 invoke-interface/range | 調用實例的接口方法 |

Dalvik中直接方法是指類的所有實例構造器和`private`實例方法，對於`protected`或者`public`方法都叫做虛方法。

#### 異常指令

利用 throw vAA 指令拋出vAA寄存器中指定類型的異常。

##### try catch

首先，我們來看一下try catch，如下

```java
int a = 10;
try {
    callSomeMethod();
} catch (Exception e) {
    a = 0;
}
callAnotherMethod();
```

對應的smali如下

```smali
const/16 v0, 0xa

:try_start_0            # try 塊開始
invoke-direct {p0}, Lnet/flygon/myapplication/SubActivity;->callSomeMethod()V
:try_end_0              # try 塊結束

.catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

:goto_0
invoke-direct {p0}, Lnet/flygon/myapplication/SubActivity;->callAnotherMethod()V
return-void

:catch_0                # catch 塊開始
move-exception v1
const/4 v0, 0x0
goto :goto_0            # catch 塊結束
```

可以看到，`:try_start_0`和`:try_end_0`之間如果存在異常，則會向下尋找`.catch`（或者`.catch-all`）語句，符合條件時跳到標籤的位置，這裏是`:catch_0`，結束之後會有個`goto`跳回去。

##### try-finally

java代碼如下

```java
int a = 10;
try {
    callSomeMethod();
} finally {
    a = 0;
}
callAnotherMethod();
```

其對應的smali代碼如下

```smali
const/16 v0, 0xa

:try_start_0            # try 塊開始
invoke-direct {p0}, Lnet/flygon/myapplication/SubActivity;->callSomeMethod()V
:try_end_0              # try 塊結束

.catchall {:try_start_0 .. :try_end_0} :catchall_0

const/4 v0, 0x0         # 複製一份到外面
invoke-direct {p0}, Lnet/flygon/myapplication/SubActivity;->callAnotherMethod()V
return-void

:catchall_0             # finally 塊開始
move-exception v1
const/4 v0, 0x0
throw v1                # finally 塊結束
```

可以看出，由於`finally`中的邏輯無論有沒有異常都會執行，所以代碼裏一共有兩部分。

##### try-catch-finally

當我們同時使用catch與finally時，如下

```java
int a = 10;
try {
    callSomeMethod();
} catch (Exception e) {
    a = 1;
}
finally {
    a = 0;
}
callAnotherMethod();
```

其對應的smali代碼如下

```smali
const/16 v0, 0xa

:try_start_0            # try 塊開始
invoke-direct {p0}, Lnet/flygon/myapplication/SubActivity;->callSomeMethod()V
:try_end_0              # try 塊結束

.catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
.catchall {:try_start_0 .. :try_end_0} :catchall_0

const/4 v0, 0x0         # 複製一份到外面

:goto_0
invoke-direct {p0}, Lnet/flygon/myapplication/SubActivity;->callAnotherMethod()V
return-void

:catch_0                # catch 塊開始
move-exception v1
const/4 v0, 0x1
const/4 v0, 0x0         # 複製一份到 catch 塊裏面
goto :goto_0            # catch 塊結束

:catchall_0             # finally 塊開始
move-exception v2
const/4 v0, 0x0
throw v2                # finally 塊結束
```

#### 返回指令

在java中我們會利用Return返回方法的執行結果。同樣的，在Davilk中我們也需要return指令來返回方法運行結果。

| 指令                | 說明             |
| ----------------- | -------------- |
| return-void       | 什麼也不返回         |
| return vAA        | 返回一個32位非對象類型的值 |
| return-wide vAA   | 返回一個64位非對象類型的值 |
| return-object vAA | 返回一個對象類型的引用    |

## java2smali

**！！從java代碼到smali代碼！！**

該例子來自於<u>http://blog.csdn.net/dd864140130/article/details/52076515</u>。

java代碼如下

```java
public class MainActivity extends Activity implements View.OnClickListener {

    private String TAG = "MainActivity";
    private static final float pi = (float) 3.14;

    public volatile boolean running = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    @Override
    public void onClick(View view) {
        int result = add(4, 5);
        System.out.println(result);

        result = sub(9, 3);

        if (result > 4) {
            log(result);
        }
    }

    public int add(int x, int y) {
        return x + y;
    }

    public synchronized int sub(int x, int y) {
        return x + y;
    }

    public static void log(int result) {
        Log.d("MainActivity", "the result:" + result);
    }


}
```

其對應的smali代碼如下

```smali
#文件頭描述
.class public Lcom/social_touch/demo/MainActivity;
.super Landroid/app/Activity;#指定MainActivity的父類
.source "MainActivity.java"#源文件名稱

#表明實現了View.OnClickListener接口
# interfaces
.implements Landroid/view/View$OnClickListener;

#定義float靜態字段pi
# static fields
.field private static final pi:F = 3.14f

#定義了String類型字段TAG
# instance fields
.field private TAG:Ljava/lang/String;

#定義了boolean類型的字段running
.field public volatile running:Z

#構造方法,如果你還納悶這個方法是怎麼出來的化,就去看看jvm的基礎知識吧
# direct methods
.method public constructor <init>()V
    .locals 1#表示函數中使用了一個局部變量

    .prologue#表示方法中代碼正式開始
    .line 8#表示對應與java源文件的低8行
    #調用Activity中的init()方法
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    .line 10
    const-string v0, "MainActivity"

    iput-object v0, p0, Lcom/social_touch/demo/MainActivity;->TAG:Ljava/lang/String;

    .line 13
    const/4 v0, 0x0

    iput-boolean v0, p0, Lcom/social_touch/demo/MainActivity;->running:Z

    return-void
.end method

#靜態方法log()
.method public static log(I)V
    .locals 3
    .parameter "result"#表示result參數

    .prologue
    .line 42
    #v0寄存器中賦值爲"MainActivity"
    const-string v0, "MainActivity"
    #創建StringBuilder對象,並將其引用賦值給v1寄存器
    new-instance v1, Ljava/lang/StringBuilder;

    #調用StringBuilder中的構造方法
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    #v2寄存器中賦值爲ther result:
    const-string v2, "the result:"

    #{v1,v2}大括號中v1寄存器中存儲的是StringBuilder對象的引用.
    #調用StringBuilder中的append(String str)方法,v2寄存器則是參數寄存器.
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    #獲取上一個方法的執行結果,此時v1中存儲的是append()方法執行後的結果,此處之所以仍然返回v1的    #原因在與append()方法返回的就是自身的引用
    move-result-object v1

    #繼續調用append方法(),p0表示第一個參數寄存器,即上面提到的result參數
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    #同上
    move-result-object v1

    #調用StringBuilder對象的toString()方法
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    #獲取上一個方法執行結果,toString()方法返回了一個新的String對象,因此v1中此時存儲了String對象的引用
    move-result-object v1

    #調用Log類中的靜態方法e().因爲e()是靜態方法,因此{v0,v1}中的成了參數寄存器
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 43
    #調用返回指令,此處沒有返回任何值
    return-void
.end method


# virtual methods
.method public add(II)I
    .locals 1
    .parameter "x"#第一個參數
    .parameter "y"#第二個參數

    .prologue
    .line 34

    #調用add-int指令求和之後將結果賦值給v0寄存器
    add-int v0, p1, p2

    #返回v0寄存器中的值
    return v0
.end method


.method public onClick(Landroid/view/View;)V
    .locals 4
    .parameter "view" #參數view

    .prologue
    const/4 v3, 0x4 #v3寄存器中賦值爲4

    .line 23#java源文件中的第23行
    const/4 v1, 0x5#v1寄存器中賦值爲5

    #調用add()方法
    invoke-virtual {p0, v3, v1}, Lcom/social_touch/demo/MainActivity;->add(II)I

    #從v0寄存器中獲取add方法的執行結果
    move-result v0

    .line 24#java源文件中的24行
    .local v0, result:I

    #v1寄存器中賦值爲PrintStream對象的引用out
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    #執行out對象的println()方法
    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(I)V

    .line 26

    const/16 v1, 0x9#v1寄存器中賦值爲9
    const/4 v2, 0x3#v2寄存器中賦值爲3

    #調用sub()方法,{p0,v1,v2},p0指的是this,即當前對象,v1,v2則是參數
    invoke-virtual {p0, v1, v2}, Lcom/social_touch/demo/MainActivity;->sub(II)I
    #從v0寄存器中獲取sub()方法的執行結果
    move-result v0

    .line 28
    if-le v0, v3, :cond_0#如果v0寄存器的值小於v3寄存器中的值,則跳轉到cond_0處繼續執行

    .line 29

    #調用靜態方法log()
    invoke-static {v0}, Lcom/social_touch/demo/MainActivity;->log(I)V

    .line 31
    :cond_0
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    .parameter "savedInstanceState" #參數savedInstancestate

    .prologue
    .line 17

    #調用父類方法onCreate()
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 18

    const v0, 0x7f04001a#v0寄存器賦值爲0x7f04001a

    #調用方法setContentView()
    invoke-virtual {p0, v0}, Lcom/social_touch/demo/MainActivity;->setContentView(I)V

    .line 19
    return-void
.end method

#declared-synchronized表示該方法是同步方法
.method public declared-synchronized sub(II)I
    .locals 1
    .parameter "x"
    .parameter "y"

    .prologue
    .line 38

    monitor-enter p0#爲該方法添加鎖對象p0
     add-int v0, p1, p2
    #釋放鎖對象
    monitor-exit p0

    return v0
.end method
```

## 編譯-smali2dex

給定一個  smali 文件，我們可以使用如下方式將 smali 文件編譯爲 dex 文件。

```shell
java -jar smali.jar assemble  src.smali -o src.dex
```

其中，smali.jar 來自於 <u>https://bitbucket.org/JesusFreke/smali/overview</u>。

## 運行 smali

在將 smali 文件編譯成 dex 文件後，我們可以進一步執行

首先，使用 adb 將 dex 文件 push 到手機上

```shell
adb push main.dex /sdcard/
```

 其次使用如下命令執行

```shell
adb shell dalvikvm -cp /sdcard/main.dex main
```

 其中

-   這裏我們使用 dalvikvm 命令。
-   -cp 指的是 classpath 路徑，這裏就是 /sdcard/main.dex。
-   main 指的是類名。

## 參考閱讀

- Android 軟件安全與逆向分析
- http://blog.csdn.net/wizardforcel/article/details/54730253
- http://blog.csdn.net/dd864140130/article/details/52076515
