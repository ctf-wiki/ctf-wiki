[EN](./HTTPS.md) | [ZH](./HTTPS-zh.md)
### HTTPS



`HTTPs = HTTP + SSL / TLS`. The information transmission between the server and the client is encrypted by TLS, so the transmitted data is encrypted data.


- [wireshark分析HTTPs](http://www.freebuf.com/articles/system/37900.html)



### Example


&gt; Title: hack-dat-kiwi-ctf-2015: ssl-sniff-2


Open the traffic packet and find that it is `SSL` encrypted data. Import the `server.key.insecure` provided by the topic to decrypt it.


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