# 取證隱寫前置技術

大部分的 CTF 比賽中，取證及隱寫兩者密不可分，兩者所需要的知識也相輔相成，所以這裏也將對兩者一起介紹。

任何要求檢查一個靜態數據文件從而獲取隱藏信息的都可以被認爲是隱寫取證題（除非單純地是密碼學的知識），一些低分的隱寫取證又常常與古典密碼學結合在一起，而高分的題目則通常用與一些較爲複雜的現代密碼學知識結合在一起，很好地體現了 Misc 題的特點。

## 前置技能

-   瞭解常見的編碼

    能夠對文件中出現的一些編碼進行解碼，並且對一些特殊的編碼（Base64、十六進制、二進制等）有一定的敏感度，對其進行轉換並得到最終的 flag。

-   能夠利用腳本語言（Python 等）去操作二進制數據
-   熟知常見文件的文件格式，尤其是各類 [文件頭](https://en.wikipedia.org/wiki/List_of_file_signatures)、協議、結構等
-   靈活運用常見的工具

## Python 操作二進制數據

### struct 模塊

有的時候需要用 Python 處理二進制數據，比如，存取文件，socket 操作時。這時候，可以使用 Python 的 struct 模塊來完成。

struct 模塊中最重要的三個函數是 `pack()`、`unpack()` 和 `calcsize()`

-   `pack(fmt, v1, v2, ...)` 按照給定的格式（fmt），把數據封裝成字符串（實際上是類似於c結構體的字節流）
-   `unpack(fmt, string)` 按照給定的格式（fmt）解析字節流 string，返回解析出來的 tuple
-   `calcsize(fmt)` 計算給定的格式（fmt）佔用多少字節的內存

這裏打包格式 `fmt` 確定了將變量按照什麼方式打包成字節流，其包含了一系列的格式字符串。這裏就不再給出不同格式字符串的含義了，詳細細節可以參照 [Python Doc](https://docs.python.org/2/library/struct.html)

```python
>>> import struct
>>> struct.pack('>I',16)
'\x00\x00\x00\x10'
```

`pack` 的第一個參數是處理指令，`'>I'` 的意思是：`>` 表示字節順序是 Big-Endian，也就是網絡序，`I` 表示 4 字節無符號整數。

後面的參數個數要和處理指令一致。

讀入一個 BMP 文件的前 30 字節，文件頭的結構按順序如下

-   兩個字節：`BM` 表示 Windows 位圖，`BA` 表示 OS/2 位圖
-   一個 4 字節整數：表示位圖大小
-   一個 4 字節整數：保留位，始終爲 0
-   一個 4 字節整數：實際圖像的偏移量
-   一個 4 字節整數：Header 的字節數
-   一個 4 字節整數：圖像寬度
-   一個 4 字節整數：圖像高度
-   一個 2 字節整數：始終爲 1
-   一個 2 字節整數：顏色數

```python
>>> import struct
>>> bmp = '\x42\x4d\x38\x8c\x0a\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x80\x02\x00\x00\x68\x01\x00\x00\x01\x00\x18\x00'
>>> struct.unpack('<ccIIIIIIHH',bmp)
('B', 'M', 691256, 0, 54, 40, 640, 360, 1, 24)
```

### bytearray 字節數組

將文件以二進制數組形式讀取

```python
data = bytearray(open('challenge.png', 'rb').read())
```

字節數組就是可變版本的字節

```python
data[0] = '\x89'
```

## 常用工具

### [010 Editor](http://www.sweetscape.com/010editor/)

SweetScape 010 Editor 是一個全新的十六進位文件編輯器，它有別於傳統的十六進位編輯器在於它可用「範本」來解析二進位文件，從而讓你讀懂和編輯它。它還可用來比較一切可視的二進位文件。

利用它的模板功能可以非常輕鬆的觀察文件內部的具體結構並且依此快速更改內容。

![](figure/010.png)

### `file` 命令

`file` 命令根據文件頭（魔法字節）去識別一個文件的文件類型。

```shell
root in ~/Desktop/tmp λ file flag
flag: PNG image data, 450 x 450, 8-bit grayscale, non-interlaced
```

### `strings` 命令

打印文件中可打印的字符，經常用來發現文件中的一些提示信息或是一些特殊的編碼信息，常常用來發現題目的突破口。

-   可以配合 `grep` 命令探測指定信息

    ```shell
    strings test|grep -i XXCTF
    ```

-   也可以配合 `-o` 參數獲取所有 ASCII 字符偏移

    ```shell
    root in ~/Desktop/tmp λ strings -o flag|head
        14 IHDR
        45 gAMA
        64  cHRM
        141 bKGD
        157 tIME
        202 IDATx
        223 NFdVK3
        361 |;*-
        410 Ge%<W
        431 5duX@%
    ```

### `binwalk` 命令

binwalk 本是一個固件的分析工具，比賽中常用來發現多個文件粘合再在一起的情況。根據文件頭去識別一個文件中夾雜的其他文件，有時也會存在誤報率（尤其是對Pcap流量包等文件時）。

```shell
root in ~/Desktop/tmp λ binwalk flag

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 450 x 450, 8-bit grayscale, non-interlaced
134           0x86            Zlib compressed data, best compression
25683         0x6453          Zip archive data, at least v2.0 to extract, compressed size: 675, uncompressed size: 1159, name: readme.txt
26398         0x671E          Zip archive data, at least v2.0 to extract, compressed size: 430849, uncompressed size: 1027984, name: trid
457387        0x6FAAB         End of Zip archive
```

配合 `-e` 參數可以進行自動化提取。

也可以結合 `dd` 命令進行手動切割。

```shell
root in ~/Desktop/tmp λ dd if=flag of=1.zip bs=1 skip=25683
431726+0 records in
431726+0 records out
431726 bytes (432 kB, 422 KiB) copied, 0.900973 s, 479 kB/s
```
