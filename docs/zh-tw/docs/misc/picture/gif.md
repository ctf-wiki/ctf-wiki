# GIF

## 文件結構

一個GIF文件的結構可分爲

-   文件頭（File Header）
    - GIF 文件署名（Signature）
    - 版本號（Version）
-   GIF 數據流（GIF Data Stream）
    - 控制標識符
    - 圖象塊（Image Block）
    - 其他的一些擴展塊
-   文件終結器（Trailer）

下表顯示了一個 GIF 文件的組成結構：

![](./figure/gif.png)

中間的那個大塊可以被重複任意次

### 文件頭

GIF 署名（Signature）和版本號（Version）。GIF 署名用來確認一個文件是否是 GIF 格式的文件，這一部分由三個字符組成：`GIF`；文件版本號也是由三個字節組成，可以爲 `87a` 或 `89a`。

### 邏輯屏幕標識符（Logical Screen Descriptor）

Logical Screen Descriptor（邏輯屏幕描述符）緊跟在 header 後面。這個塊告訴 decoder（解碼器）圖片需要佔用的空間。它的大小固定爲 7 個字節，以 canvas width（畫布寬度）和 canvas height（畫布高度）開始。

### 全局顏色列表（Global Color Table）

GIF格式可以擁有global color table，或用於針對每個子圖片集，提供local color table。每個color
table由一個RGB（就像通常我們見到的（255，0，0）紅色 那種）列表組成。

### 圖像標識符（Image Descriptor）

一個 GIF 文件一般包含多個圖片。之前的圖片渲染模式一般是將多個圖片繪製到一個大的（virtual
canvas）虛擬畫布上，而現在一般將這些圖片集用於實現動畫。

每個 image 都以一個 image descriptor block（圖像描述塊）作爲開頭，這個塊固定爲 10 字節。

![](./figure/imagesdescription.png)

### 圖像數據（Image Data）

終於到了圖片數據實際存儲的地方。Image Data是由一系列的輸出編碼（output codes）構成，它們告訴decoder（解碼器）需要繪製在畫布上的每個顏色信息。這些編碼以字節碼的形式組織在這個塊中。

### 文件終結器（Trailer）

該塊爲一個單字段塊，用來指示該數據流的結束。取固定值0x3b.

更多參見 [gif 格式圖片詳細解析](http://www.jianshu.com/p/df52f1511cf8)

## 空間軸

由於GIF的動態特性，由一幀幀的圖片構成，所以每一幀的圖片，多幀圖片間的結合，都成了隱藏信息的一種載體。

對於需要分離的GIF文件,可以使用`convert`命令將其每一幀分割開來

```console
$ convert cake.gif cake.png
$ ls
cake-0.png  cake-1.png  cake-2.png  cake-3.png  cake.gif
```

### 例題

> WDCTF-2017:3-2

打開gif後，思路很清晰，分離每一幀圖片後，將起合併得到完整的二維碼即可

```python
from  PIL import Image


flag = Image.new("RGB",(450,450))

for i in range(2):
    for j in range(2):
        pot = "cake-{}.png".format(j+i*2)
        potImage = Image.open(pot)
        flag.paste(potImage,(j*225,i*225))
flag.save('./flag.png')
```

掃碼後得到一串16進制字符串

`03f30d0ab8c1aa5....74080006030908`

開頭`03f3`爲`pyc`文件的頭，恢復爲`python`腳本後直接運行得到flag

## 時間軸

GIF文件每一幀間的時間間隔也可以作爲信息隱藏的載體。

例如在當時在XMan選拔賽出的一題

> XMAN-2017:100.gif

通過`identify`命令清晰的打印出每一幀的時間間隔

```shell
$ identify -format "%s %T \n" 100.gif
0 66
1 66
2 20
3 10
4 20
5 10
6 10
7 20
8 20
9 20
10 20
11 10
12 20
13 20
14 10
15 10
```

推斷 `20 & 10`  分別代表 `0 & 1`，提取每一幀間隔並進行轉化。

```shell
$ cat flag|cut -d ' ' -f 2|tr -d '66'|tr -d '\n'|tr -d '0'|tr '2' '0'
0101100001001101010000010100111001111011001110010011011000110101001101110011010101100010011001010110010101100100001101000110010001100101011000010011000100111000011001000110010101100100001101000011011100110011001101010011011000110100001100110110000101100101011000110110011001100001001100110011010101111101#
```

最後轉 ASCII 碼得到 flag。

## 隱寫軟件

- [F5-steganography](https://github.com/matthewgao/F5-steganography)
