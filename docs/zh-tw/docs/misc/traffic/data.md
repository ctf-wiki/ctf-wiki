# 數據提取

這一塊是流量包中另一個重點,通過對協議分析,找到了題目的關鍵點,如何提取數據成了接下來的關鍵問題

## wireshark

### wireshark自動分析

`file -> export objects -> http`

### 手動數據提取

`file->export selected Packet Bytes`


## tshark

tshark作爲wireshark的命令行版,高效快捷是它的優點,配合其餘命令行工具(awk,grep)等靈活使用,可以快速定位,提取數據從而省去了繁雜的腳本編寫

再看`Google CTF 2016 Forensic-200`這一題,可以通過tshark迅速完成解題

```shll
what@kali:/tmp$ tshark -r capture.pcapng -T fields -e usb.capdata > data2.txt
what@kali:/tmp$ # awk -F: 'function comp(v){if(v>127)v-=256;return v}{x+=comp(strtonum("0x"$2));y+=comp(strtonum("0x"$3))}$1=="01"{print x,y}' data.txt > data3.txt
what@kali:/tmp$ gnuplot
> plot "data3.txt"
```

- Step 1 鼠標協議中數據提取
- Step 2 通過awk進行位置座標轉換
- Step 3 形成圖形

---

### 常用方法

> `tshark -r **.pcap –Y ** -T fields –e ** | **** > data`

```
Usage:
  -Y <display filter>      packet displaY filter in Wireshark display filter
                           syntax
  -T pdml|ps|psml|json|jsonraw|ek|tabs|text|fields|?
                           format of text output (def: text)
  -e <field>               field to print if -Tfields selected (e.g. tcp.port,
                           _ws.col.Info)
```

通過`-Y`過濾器(與wireshark一致),然後用`-T filds -e`配合指定顯示的數據段(比如usb.capdata)

- `tips`
    - `-e`後的參數不確定可以由 `wireshark` 右擊需要的數據選中後得到

### 例題

> 題目：`google-ctf-2016 : a-cute-stegosaurus-100`

這題的數據隱藏的非常巧妙,而且有一張圖片混淆視聽,需要對`tcp`協議非常熟悉,所以當時做出來的人並不多,全球只有 `26` 支隊伍

在`tcp`報文段中有6Bit的狀態控制碼,分別如下

- URG：緊急比特（urgent）,當URG＝1時，表明緊急指針字段有效,代表該封包爲緊急封包。它告訴系統此報文段中有緊急數據，應儘快傳送(相當於高優先級的數據)
- ACK：確認比特（Acknowledge）。只有當ACK＝1時確認號字段纔有效,代表這個封包爲確認封包。當ACK＝0時，確認號無效。
- PSH：（Push function）若爲1時，代表要求對方立即傳送緩衝區內的其他對應封包，而無需等緩衝滿了才送。
- RST：復位比特(Reset) ,當RST＝1時，表明TCP連接中出現嚴重差錯（如由於主機崩潰或其他原因），必須釋放連接，然後再重新建立運輸連接。
- SYN：同步比特(Synchronous)，SYN置爲1，就表示這是一個連接請求或連接接受報文,通常帶有 SYN 標誌的封包表示『主動』要連接到對方的意思。。
- FIN：終止比特(Final)，用來釋放一個連接。當FIN＝1時，表明此報文段的發送端的數據已發送完畢，並要求釋放運輸連接。

而這裏的`tcp.urg`卻爲

![urg](figure/urg.png)

通過tshark提取`tcp.urg`然後去除0的字段,換行符轉`,`直接轉換成python的列表,轉ascii即可得到flag

```
⚡ root@kali:  tshark -r Stego-200_urg.pcap -T fields -e  tcp.urgent_pointer|egrep -vi "^0$"|tr '\n' ','
Running as user "root" and group "root". This could be dangerous.
67,84,70,123,65,110,100,95,89,111,117,95,84,104,111,117,103,104,116,95,73,116,95,87,97,115,95,73,110,95,84,104,101,95,80,105,99,116,117,114,101,125,#
...
>>> print "".join([chr(x) for x in arr]) #python轉換ascii
CTF{And_You_Thought_It_Was_In_The_Picture}
```

> 題目：`stego-150_ears.xz`

**Step 1**

通過`file`命令不斷解壓得到 `pcap` 文件

```shell
➜  Desktop file ears
ears: XZ compressed data
➜  Desktop unxz < ears > file_1
➜  Desktop file file_1
file_1: POSIX tar archive
➜  Desktop 7z x file_1

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU Intel(R) Core(TM) i7-4710MQ CPU @ 2.50GHz (306C3),ASM,AES-NI)

    Scanning the drive for archives:
    1 file, 4263936 bytes (4164 KiB)

    Extracting archive: file_1
    --
    Path = file_1
    Type = tar
    Physical Size = 4263936
    Headers Size = 1536
    Code Page = UTF-8

    Everything is Ok

    Size:       4262272
    Compressed: 4263936
```

**Step 2**

通過 `wireshark` 發現 `dns` 中回應名字存在異常，組成 `16` 進制的 `png` 文件

採用 `tshark` 進行提取，提取 `dns` 中的數據,篩選具體報文形式`\w{4,}.asis.io`

`tshark -r forensic_175_d78a42edc01c9104653776f16813d9e5 -T fields -e dns.qry.name -e dns.flags|grep 8180|awk '{if ($1~/\w{4,}.asis.io/) print $1}'|awk -F '.' '{print $1}'|tr -d '\n' > png`

**Step 3**

`16` 進制還原圖片

`xxd -p -r png flag`


## 自定義協議

提取數據存在一類特殊情況，即傳輸的數據本身使用自定義協議，下面用 `HITCON 2018` 的兩道 Misc 爲例說明。

### 例題分析

- [HITCON-2018 : ev3 basic](https://github.com/ctf-wiki/ctf-challenges/tree/master/misc/cap/2018HITCON-ev3-basic)

- [HITCON-2018 : ev3 scanner](https://github.com/ctf-wiki/ctf-challenges/tree/master/misc/cap/2018HITCON-ev3-scanner)

**ev3 basic**

#### 確定數據

對於這類題目，首先分析有效數據位於哪些包中。觀察流量，通訊雙方爲 `localhost` 和 `LegoSystem` 。其中大量標爲 `PKTLOG` 的數據包都是日誌，此題中不需關注。簡單瀏覽其餘各個協議的流量，發現僅 `RFCOMM` 協議中存在沒有被 `wireshark` 解析的 `data` 段，而 `RFCOMM` 正是藍牙使用的[傳輸層協議](https://en.wikipedia.org/wiki/List_of_Bluetooth_protocols#Radio_frequency_communication_(RFCOMM))之一。

由前述 `tshark` 相關介紹，可以通過以下命令提取數據：

`tshark -r .\ev3_basic.pklg -T fields -e data -Y "btrfcomm"`

#### 分析協議

找到數據後，需要確定數據格式。如何查找資料可以參考 `信息蒐集技術` 一節，此處不再贅述。總之由 `ev3` 這個關鍵詞出發，我們最終知道這種通信方式傳輸的內容被稱之爲 [Direct Command](http://ev3directcommands.blogspot.com/2016/01/no-title-specified-page-table-border_94.html)，所使用的是樂高自定義的一種[簡單應用層協議](https://le-www-live-s.legocdn.com/sc/media/files/ev3-developer-kit/lego%20mindstorms%20ev3%20communication%20developer%20kit-f691e7ad1e0c28a4cfb0835993d76ae3.pdf?la=en-us)，`Command` 本身格式由樂高的手冊 [EV3 Firmware Developer Kit](http://www.lego.com/en-gb/mindstorms/downloads) 定義。*（查找過程並不像此處簡單而直觀，也是本題的關鍵點之一。）*

在樂高的協議中，發送和回覆遵從不同格式。在 `ev3 basic` 中，所有回覆流量都相同，通過手冊可知內容代表 `ok` ，沒有實際含義，而發送的每個數據包都包含了一條指令。由協議格式解析出指令的 `Opcode` 均爲 `0x84` ，代表 `UI_DRAW` 函數，且 `CMD` 是 `0x05` ，代表 `TEXT` 。之後是四個參數，`Color`, `X0`, `Y0`, `STRING` 。此處需要注意樂高的單個參數字節數並不固定，即便手冊上標明瞭數據類型是 `DATA16` ，仍然可能使用一個字節長度的參數，需要參照手冊中 `Parameter encoding` 一節及[相關文章](http://ev3directcommands.blogspot.com/2016/01/ev3-direct-commands-lesson-02-pre.html)。

嘗試分析幾個命令，發現每個指令都會在屏幕特定位置打印一個字符，這與提供的圖片相符。

#### 處理結果

理解數據內容後，通過腳本提取所有命令並解析參數，需要注意單個參數的字節數不固定。

得到所有命令的參數後，可以將每個字符其按照座標繪製在屏幕上。較簡單的做法是先按 `X` 後按 `Y` 排序，直接輸出即可。

**ev3 scanner**

第二題的做法與第一題基本相同，難度增加的地方在於：

- 發送的命令不再單一，包括讀取傳感器信息、控制 ev3 運動

- 回覆也包含信息，主要是傳感器讀取的內容

- 函數的參數更復雜，解析難度更大

- 解析命令得到的結果需要更多處理

`ev3 scanner` 此處不再提供詳細方法，可作爲練習加深對這一類型題目的理解。

### Python Script

TODO

