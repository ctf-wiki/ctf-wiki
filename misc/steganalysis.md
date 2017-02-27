# Steganalysis 隐写分析

## 隐写术

### 隐写载体

* 文本
* 图片
* 音频
* 视频

### 隐写方法和工具

- RSD、LSB、DCT
- [Steganography tools](https://en.wikipedia.org/wiki/Steganography_tools)

## 隐写分析

### 识别隐写

* 统计分析
* Noise floor consistency analysis

### 隐写识别工具

* Stegdetect

  ```bash
  stegdetect -s 1.5 xxx.jpg
  stegdetect -tF xxx.jpg
  ```

* StegSolve

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

## 扩展阅读

* [An Overview of Steganography for the Computer Forensics Examiner](http://www.garykessler.net/library/fsc_stego.html)
* [深入理解JPEG图像格式Jphide隐写](http://wooyun.com.com.sb/static/drops/tips-15661.html)
* [隐写术总结](http://wooyun.com.com.sb/static/drops/tips-4862.html)