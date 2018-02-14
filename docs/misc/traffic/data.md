这一块是流量包中另一个重点,通过对协议分析,找到了题目的关键点,如何提取数据成了接下来的关键问题

## wireshark

### wireshark自动分析

`file -> export objects -> http`

### 手动数据提取

`file->export selected Packet Bytes`


## tshark

tshark作为wireshark的命令行版,高效快捷是它的优点,配合其余命令行工具(awk,grep)等灵活使用,可以快速定位,提取数据从而省去了繁杂的脚本编写

再看`Google CTF 2016 Forensic-200`这一题,可以通过tshark迅速完成解题

```shll
what@kali:/tmp$ tshark -r capture.pcapng -T fields -e usb.capdata > data2.txt
what@kali:/tmp$ # awk -F: 'function comp(v){if(v>127)v-=256;return v}{x+=comp(strtonum("0x"$2));y+=comp(strtonum("0x"$3))}$1=="01"{print x,y}' data.txt > data3.txt
what@kali:/tmp$ gnuplot
> plot "data3.txt"
```

- Step 1 鼠标协议中数据提取
- Step 2 通过awk进行位置坐标转换
- Step 3 形成图形

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

通过`-Y`过滤器(与wireshark一致),然后用`-T filds -e`配合指定显示的数据段(比如usb.capdata)

- tips
    - `-e`后的参数不确定可以由wireshark右击需要的数据选中后得到


**例题**

- [google-ctf-2016 : a-cute-stegosaurus-100](https://github.com/ctfs/write-ups-2016/tree/master/google-ctf-2016/forensics/a-cute-stegosaurus-100)

这题的数据隐藏的非常巧妙,而且有一张图片混淆视听,需要对`tcp`协议非常熟悉,所以当时做出来的人并不多,全球只有26支队伍

在`tcp`报文段中有6Bit的状态控制码,分别如下

- URG：紧急比特（urgent）,当URG＝1时，表明紧急指针字段有效,代表该封包为紧急封包。它告诉系统此报文段中有紧急数据，应尽快传送(相当于高优先级的数据)
- ACK：确认比特（Acknowledge）。只有当ACK＝1时确认号字段才有效,代表这个封包为确认封包。当ACK＝0时，确认号无效。
- PSH：（Push function）若为1时，代表要求对方立即传送缓冲区内的其他对应封包，而无需等缓冲满了才送。
- RST：复位比特(Reset) ,当RST＝1时，表明TCP连接中出现严重差错（如由于主机崩溃或其他原因），必须释放连接，然后再重新建立运输连接。
- SYN：同步比特(Synchronous)，SYN置为1，就表示这是一个连接请求或连接接受报文,通常带有 SYN 标志的封包表示『主动』要连接到对方的意思。。
- FIN：终止比特(Final)，用来释放一个连接。当FIN＝1时，表明此报文段的发送端的数据已发送完毕，并要求释放运输连接。

而这里的`tcp.urg`却为

![urg](figure/urg.png)

通过tshark提取`tcp.urg`然后去除0的字段,换行符转`,`直接转换成python的列表,转ascii即可得到flag

```
⚡ root@kali:  tshark -r Stego-200_urg.pcap -T fields -e  tcp.urgent_pointer|egrep -vi "^0$"|tr '\n' ','
Running as user "root" and group "root". This could be dangerous.
67,84,70,123,65,110,100,95,89,111,117,95,84,104,111,117,103,104,116,95,73,116,95,87,97,115,95,73,110,95,84,104,101,95,80,105,99,116,117,114,101,125,#
...
>>> print "".join([chr(x) for x in arr]) #python转换ascii
CTF{And_You_Thought_It_Was_In_The_Picture}
```


**例题**

- <a href="file\stego-150_ears.xz">stego-150_ears.xz</a>


- Step 1

通过`file`命令不断解压得到pcap文件

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

- Step 2

通过wireshark发现dns中回应名字存在异常，组成16进制的png文件

采用tshark进行提取,提取dns中的数据,筛选具体报文形式`\w{4,}.asis.io`

`tshark -r forensic_175_d78a42edc01c9104653776f16813d9e5 -T fields -e dns.qry.name -e dns.flags|grep 8180|awk '{if ($1~/\w{4,}.asis.io/) print $1}'|awk -F '.' '{print $1}'|tr -d '\n' > png`

- Step 3

16进制还原图片

`xxd -p -r png flag`


## Python Script

TODO

