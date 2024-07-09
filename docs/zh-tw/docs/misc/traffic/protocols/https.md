# HTTPS

`HTTPs = HTTP + SSL / TLS`.服務端和客戶端的信息傳輸都會通過TLS進行加密，所以傳輸的數據都是加密後的數據

- [wireshark分析HTTPs](http://www.freebuf.com/articles/system/37900.html)

## 例題

> 題目：hack-dat-kiwi-ctf-2015:ssl-sniff-2

打開流量包發現是 `SSL` 加密過的數據,導入題目提供的`server.key.insecure`,即可解密

```xml
GET /key.html HTTP/1.1
Host: localhost

HTTP/1.1 200 OK
Date: Fri, 20 Nov 2015 14:16:24 GMT
Server: Apache/2.4.7 (Ubuntu)
Last-Modified: Fri, 20 Nov 2015 14:15:54 GMT
ETag: "1c-524f98378d4e1"
Accept-Ranges: bytes
Content-Length: 28
Content-Type: text/html

The key is 39u7v25n1jxkl123
```