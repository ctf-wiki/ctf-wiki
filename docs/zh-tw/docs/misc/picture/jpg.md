# JPG

## 文件結構

-   JPEG 是有損壓縮格式，將像素信息用 JPEG 保存成文件再讀取出來，其中某些像素值會有少許變化。在保存時有個質量參數可在 0 至 100 之間選擇，參數越大圖片就越保真，但圖片的體積也就越大。一般情況下選擇 70 或 80 就足夠了
-   JPEG 沒有透明度信息

JPG 基本數據結構爲兩大類型：「段」和經過壓縮編碼的圖像數據。

| 名 稱   | 字節數 | 數據 | 說明                                        |
| ------- | ------ | ---- | ------------------------------------------- |
| 段 標識 | 1      | FF   | 每個新段的開始標識                          |
| 段類型  | 1      |      | 類型編碼（稱作標記碼）                      |
| 段長 度 | 2      |      | 包括段內容和段長度本身,不包括段標識和段類型 |
| 段內容  | 2      |      | ≤65533字節                                  |

-   有些段沒有長度描述也沒有內容，只有段標識和段類型。文件頭和文件尾均屬於這種段。
-   段與段之間無論有多少 `FF` 都是合法的，這些 `FF` 稱爲「填充字節」，必須被忽略掉。

一些常見的段類型

![](./figure/jpgformat.png)

`0xffd8` 和 `0xffd9`爲 JPG 文件的開始結束的標誌。

## 隱寫軟件

### [Stegdetect](https://github.com/redNixon/stegdetect)

通過統計分析技術評估 JPEG 文件的 DCT 頻率係數的隱寫工具, 可以檢測到通過 JSteg、JPHide、OutGuess、Invisible
Secrets、F5、appendX 和 Camouflage 等這些隱寫工具隱藏的信息，並且還具有基於字典暴力破解密碼方法提取通過 Jphide、outguess 和 jsteg-shell 方式嵌入的隱藏信息。

```shell
-q 僅顯示可能包含隱藏內容的圖像。
-n 啓用檢查JPEG文件頭功能，以降低誤報率。如果啓用，所有帶有批註區域的文件將被視爲沒有被嵌入信息。如果JPEG文件的JFIF標識符中的版本號不是1.1，則禁用OutGuess檢測。
-s 修改檢測算法的敏感度，該值的默認值爲1。檢測結果的匹配度與檢測算法的敏感度成正比，算法敏感度的值越大，檢測出的可疑文件包含敏感信息的可能性越大。
-d 打印帶行號的調試信息。
-t 設置要檢測哪些隱寫工具（默認檢測jopi），可設置的選項如下：
j 檢測圖像中的信息是否是用jsteg嵌入的。
o 檢測圖像中的信息是否是用outguess嵌入的。
p 檢測圖像中的信息是否是用jphide嵌入的。
i 檢測圖像中的信息是否是用invisible secrets嵌入的。
```

### [JPHS](http://linux01.gwdg.de/~alatham/stego.html)

JPEG 圖像的信息隱藏軟件 JPHS，它是由 Allan Latham 開發設計實現在 Windows 和 Linux 系統平臺針對有損壓縮 JPEG 文件進行信息加密隱藏和探測提取的工具。軟件裏面主要包含了兩個程序 JPHIDE和 JPSEEK。JPHIDE 程序主要是實現將信息文件加密隱藏到 JPEG 圖像功能，而 JPSEEK 程序主要實現從用 JPHIDE 程序加密隱藏得到的 JPEG 圖像探測提取信息文件，Windows 版本的 JPHS 裏的 JPHSWIN 程序具有圖形化操作界面且具備 JPHIDE 和 JPSEEK 的功能。

### [SilentEye](http://silenteye.v1kings.io/)

> SilentEye is a cross-platform application design for an easy use of steganography, in this case hiding messages into pictures or sounds. It provides a pretty nice interface and an easy integration of new steganography algorithm and cryptography process by using a plug-ins system.
