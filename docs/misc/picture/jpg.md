[EN](./jpg.md) | [ZH](./jpg-zh.md)
## File Structure


- JPEG is a lossy compression format. Pixel information is saved as a file in JPEG and then read out. Some of the pixel values will change slightly. There is a quality parameter that can be selected between 0 and 100 when saving. The larger the parameter, the more fidelity the picture will be, but the larger the size of the picture. In general, choosing 70 or 80 is enough.
- JPEG has no transparency information


The JPG basic data structure is of two major types: &quot;segment&quot; and compression-encoded image data.


| Name | Bytes | Data | Description |
| ------- | ------ | ---- | ------------------------------------------- |

| Segment Identification | 1 | FF | Start ID of each new segment |
| Segment Type | 1 | | Type Encoding (called Tag) |
| Segment length | 2 | | Includes segment content and segment length itself, excluding segment ID and segment type |
| Section content | 2 | | ≤65533 bytes |


- Some segments have no length description and no content, only segment identification and segment type. Both the header and the end of the file belong to this segment.
- No matter how many `FF` are legal between segments and segments, these `FF` are called &quot;fill bytes&quot; and must be ignored.


Some common segment types


![](./figure/jpgformat.png)



`0xffd8` and `0xffd9` are flags for the beginning of the JPG file.


## 隐写软件


### [Stegdetect](https://github.com/redNixon/stegdetect)



A steganographic tool for evaluating DCT frequency coefficients of JPEG files by statistical analysis techniques, which can be detected by JSteg, JPHide, OutGuess, Invisible
Information hidden by steganographic tools such as Secrets, F5, appendX, and Camouflage, and also has hidden information embedded in Jphide, outguess, and jsteg-shell methods based on the dictionary brute force cryptography method.


```shell

-q Displays only images that may contain hidden content.
-n Enables checking the JPEG header function to reduce the false positive rate. If enabled, all files with annotated areas will be treated as if they were not embedded. If the version number in the JFIF identifier of the JPEG file is not 1.1, OutGuess detection is disabled.
-s Modifies the sensitivity of the detection algorithm. The default value of this value is 1. The matching degree of the detection result is directly proportional to the sensitivity of the detection algorithm. The larger the value of the algorithm sensitivity, the more likely the detected suspicious file contains sensitive information.
-d Prints debugging information with line numbers.
-t Set which steganographic tools to detect (default detection jobi), the options that can be set are as follows:
j Check if the information in the image is embedded in jsteg.
o Detect if the information in the image is embedded with outguess.
p Detects whether the information in the image is embedded in jphide.
i Detects if the information in the image is embedded with invisible secrets.
```



### [JPHS] (http://linux01.gwdg.de/~alatham/stego.html)


JPHS, an information hiding software for JPEG images, is a tool developed by Allan Latham to implement information encryption and detection extraction for lossy compressed JPEG files on Windows and Linux system platforms. The software mainly contains two programs JPHIDE and JPSEEK. The JPHIDE program mainly implements the function of hiding information file encryption into JPEG image. The JPSEEK program mainly implements the JPEG image detection and extraction information file obtained by encrypting and hiding with the JPHIDE program. The JPHSWIN program in the Windows version of JPHS has a graphical operation interface and has The features of JPHIDE and JPSEEK.


### [SilentEye](http://silenteye.v1kings.io/)



> SilentEye is a cross-platform application design for an easy use of steganography, in this case hiding messages into pictures or sounds. It provides a pretty nice interface and an easy integration of new steganography algorithm and cryptography process by using a plug-ins system.
