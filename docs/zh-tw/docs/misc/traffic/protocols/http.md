# HTTP

`HTTP` ( `Hyper Text Transfer Protocol` ，也稱爲超文本傳輸協議)是一種用於分佈式、協作式和超媒體信息系統的應用層協議。 `HTTP` 是萬維網的數據通信的基礎。

## 例題

> 題目：江蘇省領航杯-2017：hack

總體觀察可以得出:

- `HTTP`爲主
- `192.168.173.134`爲主
- 不存在附件

![linghang_hack](./figure/linghang_hack.png)

從這張圖,基本可以判斷初這是一個在`sql注入-盲注時產生的流量包`

到此爲止,基本可以判斷flag的方向,提取出所有的url後,用`python`輔助即可得到flag

- 提取url: `tshark -r hack.pcap -T fields  -e http.request.full_uri|tr -s '\n'|grep flag > log`
- 得到盲注結果

```python
import re

with open('log') as f:
    tmp = f.read()
    flag = ''
    data = re.findall(r'=(\d*)%23',tmp)
    data = [int(i) for i in data]
    for i,num in enumerate(data):
        try:
            if num > data[i+1]:
                flag += chr(num)
        except Exception:
            pass
    print flag
```
