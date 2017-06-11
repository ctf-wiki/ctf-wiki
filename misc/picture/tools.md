# 常用工具

- `strings`
  查看是否有特殊字符串，比如 flag。

- `dd`

  读写文件中的固定部分。

- `binwalk`

  - [介绍](http://www.freebuf.com/sectool/15266.html)
  - `binwalk -e filename`：提取文件中包含的其他内容。

- `foremost`

  用于分离文件。

- 010 Editor

  - 十六进制编辑器；
  - 解析文件的格式；
  - 有时候文件本身的格式可能会有问题，需要我们自己去进行简单的修补。

- StegSolve

  - 各种文件隐写处理；
  - [stegsolve](http://www.caesum.com/handbook/Stegsolve.jar) 下载。

* Stegdetect

  ```bash
  stegdetect -s 1.5 xxx.jpg
  stegdetect -tF xxx.jpg
  ```

* Mp3Stego

  ```bash
  decode -X -P pass sound.mp3
  ```

* outguess

  ```bash
  outguess -e -k "ddtek" -r xxxx
  ```

* StegSecret

* GFE Stealth

* OurSecret

* Jphide