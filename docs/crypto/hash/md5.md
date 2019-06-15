[EN](./md5.md) | [ZH](./md5-zh.md)
# MD5



## Basic description


The input and output of MD5 are as follows


- Input: Any long message, 512-bit long packet.
- Output: 128-bit message digest.


For a detailed introduction, please search for yourself.


In addition, sometimes the md5 we get is 16-bit. In fact, the 16-bit is the length of the 32-bit md5, which is derived from the 32-bit md5 value. It is to remove the first eight bits of 32-bit md5 and get the last eight bits.


In general, we can determine whether it is an MD5 function by initializing the function. In general, if a function has the following four initialized variables, you can guess that the function is an MD5 function, because this is the initialization IV of the MD5 function.


```

0x67452301，0xEFCDAB89，0x98BADCFE，0x10325476

```



## Crack


At present, it can be said that md5 has been basically broken. The general MD5 collision can be obtained on the following online.


- http://www.cmd5.com/

- http://www.ttmd5.com/

- http://pmd5.com/

- https://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip (generate md5 collision with the specified prefix)


## topic


- CFF 2016 a lot of salt
- JarvisOJ a lot of salt