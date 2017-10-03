## GIF
- 帧隐写

  将数据隐写到 GIF 文件的每一帧。
  通过分解获取图片中的每一帧图片。

  - stegsolve
  - [在线分解](http://zh.bloggif.com/gif-extract)
  - 例题
    - ISCC 2014 此为 GIF 图片

## JPG
- [深入理解 JPEG 图像格式 Jphide 隐写](http://wooyun.com.com.sb/static/drops/tips-15661.html)

- Exif 隐写

  JPG 图片的 Exif 处可以存储照片拍摄的具体信息，比如使用什么相机。可以通过修改 Exif 来存储信息。

- 帧隐写
  - stegsolve

- 例题
  - Exif
    - carter--sctf 2016 banana-boy-20

## PNG
- Zlib 隐写

  一般 IDAT 都是是在长度大于 65524 的时候才会开启新的 IDAT 块，我们可以自己单独加一块 IDAT 块来隐写自己的信息。


- 题目
  - SCTF 2014 400