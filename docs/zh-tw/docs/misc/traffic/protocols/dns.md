# DNS

## 簡介


`DNS` 通常爲 `UDP` 協議,報文格式

```sh
+-------------------------------+
| 報文頭                         |
+-------------------------------+
| 問題 (向服務器提出的查詢部分)    |
+-------------------------------+
| 回答 (服務器回覆的資源記錄)      |
+-------------------------------+
| 授權 (權威的資源記錄)           |
+-------------------------------+
| 額外的 (額外的資源記錄)         |
+-------------------------------+
```

查詢包只有頭部和問題兩個部分， `DNS` 收到查詢包後，根據查詢到的信息追加回答信息、授權機構、額外資源記錄，並且修改了包頭的相關標識再返回給客戶端。

每個 `question` 部分

```
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                                               |
 /                     QNAME                     /
 /                                               /
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     QTYPE                     |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                     QCLASS                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

- `QNAME` ：爲查詢的域名，是可變長的，編碼格式爲：將域名用.號劃分爲多個部分，每個部分前面加上一個字節表示該部分的長度，最後加一個 `0` 字節表示結束
- `QTYPE` ：佔 `16` 位，表示查詢類型，共有 `16` 種，常用值有：`1` ( `A` 記錄，請求主機 `IP` 地址)、`2` ( `NS` ，請求授權 `DNS` 服務器)、`5` ( `CNAME` 別名查詢)



## 例題

> 題目：`BSides San Francisco CTF 2017` ： `dnscap.pcap` 

我們通過 `wireshark` 打開發現全部爲 `DNS` 協議,查詢名爲大量字符串`([\w\.]+)\.skullseclabs\.org`

我們通過 `tshark -r dnscap.pcap -T fields -e dns.qry.name > hex`提取後，利用 `python` 轉碼：

```python
import re


find = ""

with open('hex','rb') as f:
    for i in f:
        text = re.findall(r'([\w\.]+)\.skull',i)
        if text:
            find += text[0].replace('.','')
print find
```

我們發現了幾條關鍵信息：

```
Welcome to dnscap! The flag is below, have fun!!
Welcome to dnscap! The flag is below, have fun!!
!command (sirvimes)
...
IHDR
gAMA
bKGD
        pHYs
IHDR
gAMA
bKGD
        pHYs
tIME
IDATx
...
2017-02-01T21:04:00-08:00
IEND
console (sirvimes)
console (sirvimes)
Good luck! That was dnscat2 traffic on a flaky connection with lots of re-transmits. Seriously,
Good luck! That was dnscat2 traffic on a flaky connection with lots of re-transmits. Seriously, d[
good luck. :)+
```

`flag` 確實包含在其中,但是有大量重複信息,一是應爲`question` 。在 `dns` 協議中查詢和反饋時都會用到，` -Y "ip.src == 192.168.43.91"`進行過濾後發現還是有不少重複部分。

```
%2A}
%2A}
%2A}q
%2A}x
%2A}
IHDR
gAMA
bKGD
        pHYs
tIME
IDATx
HBBH
CxRH!
C1%t
ceyF
i4ZI32
rP@1
ceyF
i4ZI32
rP@1
ceyF
i4ZI32
rP@1
ceyF
i4ZI32
rP@1
```

根據發現的 `dnscat` 找到 https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md 這裏介紹了 `dnscat` 協議的相關信息,這是一種通過 `DNS` 傳遞數據的變種協議,題目文件中應該未使用加密,所以直接看這裏的數據塊信息

```
MESSAGE_TYPE_MSG: [0x01]
(uint16_t) packet_id
(uint8_t) message_type [0x01]
(uint16_t) session_id
(uint16_t) seq
(uint16_t) ack
(byte[]) data
```

在`qry.name`中去除其餘字段,只留下 `data` 快,從而合併數據,再從 `16` 進制中檢索`89504e.....6082`提取`png`,得到 `flag` 。

```python
import re


find = []

with open('hex','rb') as f:
    for i in f:
        text = re.findall(r'([\w\.]+)\.skull',i)
        if text:
            tmp =  text[0].replace('.','')
            find.append(tmp[18:])
last = []

for i in find:
    if i not in last:
        last.append(i)


print  ''.join(last)
```

*flag*

![dnscat_flag](./figure/dnscat_flag.png)



## 相關題目

- [IceCTF-2016:Search](https://mrpnkt.github.io/2016/icectf-2016-search/)
- [EIS-2017:DNS 101](https://github.com/susers/Writeups/blob/master/2017/EIS/Misc/DNS%20101/Write-up.md)

## 參考文獻

- https://github.com/lisijie/homepage/blob/master/posts/tech/dns%E5%8D%8F%E8%AE%AE%E8%A7%A3%E6%9E%90.md
- https://xpnsec.tumblr.com/post/157479786806/bsidessf-ctf-dnscap-walkthrough
