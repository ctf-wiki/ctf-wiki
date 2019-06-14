[EN](./prefix.md) | [ZH](./prefix-zh.md)
In most CTF competitions, both forensics and steganography are inseparable, and the knowledge required for the two complement each other, so the two will be introduced here.


Any requirement to inspect a static data file for hidden information can be considered a cryptographic forensic question (unless it is simply cryptographic knowledge), and some low-level steganography forensics is often combined with classical cryptography. The high-scoring questions are often combined with some of the more complex modern cryptography knowledge to best embody the characteristics of the Misc problem.


## Pre-skills


- Learn about common coding


It is able to decode some of the codes that appear in the file and have some sensitivity to some special encodings (Base64, hexadecimal, binary, etc.), convert them and get the final flag.


- Ability to manipulate binary data using scripting languages (Python, etc.)
- Familiar with the file formats of common files, especially the various [file headers] (https://en.wikipedia.org/wiki/List_of_file_signatures), protocols, structures, etc.
- Flexible use of common tools


## Python Operating Binary Data


### struct module


Sometimes you need to use Python to process binary data, such as accessing files and socket operations. At this time, you can use Python&#39;s struct module to complete.


The three most important functions in the struct module are `pack()`, `unpack()`, and `calcsize()`


- `pack(fmt, v1, v2, ...)` encapsulates the data into a string according to the given format (fmt) (actually a byte stream similar to the c structure)
- `unpack(fmt, string)` parses the byte stream string according to the given format (fmt) and returns the parsed tuple
- `calcsize(fmt)` Calculates how many bytes of memory are used in a given format (fmt)


The packing format `fmt` here determines how the variables are packed into a byte stream, which contains a series of format strings. The meaning of different format strings is no longer given here. For details, please refer to [Python Doc] (https://docs.python.org/2/library/struct.html)


```python

>>> import struct

>>> struct.pack('>I',16)

'\x00\x00\x00\x10'

```



The first argument to `pack` is the processing instruction. `&#39;&gt;I&#39;` means: `&gt;` indicates that the byte order is Big-Endian, which is the network order, and `I` indicates a 4-byte unsigned integer.


The number of parameters that follow is consistent with the processing instructions.


Read the first 30 bytes of a BMP file. The structure of the file header is as follows:


- Two bytes: `BM` for Windows bitmap, `BA` for OS/2 bitmap
- a 4-byte integer: indicates the bitmap size
- a 4-byte integer: reserved bits, always 0
- a 4-byte integer: the offset of the actual image
- a 4-byte integer: the number of bytes in the Header
- a 4-byte integer: image width
- a 4-byte integer: image height
- a 2-byte integer: always 1
- a 2 byte integer: number of colors


```python

>>> import struct

>>> bmp = '\x42\x4d\x38\x8c\x0a\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x80\x02\x00\x00\x68\x01\x00\x00\x01\x00\x18\x00'

>>> struct.unpack('<ccIIIIIIHH',bmp)

('B', 'M', 691256, 0, 54, 40, 640, 360, 1, 24)

```



### bytearray byte array


Read the file as a binary array


```python

data = bytearray(open('challenge.png', 'rb').read())

```



Byte array is the variable version of the byte


```python

data[0] = '\x89'

```



## Common tools


### [010 Editor](http://www.sweetscape.com/010editor/)



SweetScape 010 Editor is a new hexadecimal file editor that differs from the traditional hexadecimal editor in that it can use a &quot;template&quot; to parse binary files so that you can read and edit it. It can also be used to compare all visible binary files.


With its templating feature, it&#39;s very easy to observe the specific structure inside the file and quickly change the content accordingly.


![](figure/010.png)



### `file` command


The `file` command identifies the file type of a file based on the file header (magic byte).


```shell

root in ~/Desktop/tmp λ file flag

flag: PNG image data, 450 x 450, 8-bit grayscale, non-interlaced

```



### `strings` command


The printable characters in the print file are often used to find some hint information in the file or some special coded information, which is often used to find the breakthrough of the title.


- Can detect the specified information with the `grep` command


    ```shell

    strings test|grep -i XXCTF

    ```



- You can also get all ASCII character offsets with the `-o` parameter


    ```shell

    root in ~/Desktop/tmp λ strings -o flag|head

14 IHDR
45 gAMA
        64  cHRM

        141 bKGD

        157 tIME

202 IDATx
        223 NFdVK3

        361 |;*-

410 Ge% <W
        431 5duX@%

    ```



### `binwalk` command


Binwalk is a firmware analysis tool that is commonly used in competitions to find multiple files that are glued together. According to the file header to identify other files in a file, sometimes there is a false positive rate (especially for files such as Pcap traffic packets).


```shell

root in ~/Desktop/tmp λ binwalk flag



DECIMAL       HEXADECIMAL     DESCRIPTION

--------------------------------------------------------------------------------

0             0x0             PNG image, 450 x 450, 8-bit grayscale, non-interlaced

134           0x86            Zlib compressed data, best compression
25683         0x6453          Zip archive data, at least v2.0 to extract, compressed size: 675, uncompressed size: 1159, name: readme.txt

26398         0x671E          Zip archive data, at least v2.0 to extract, compressed size: 430849, uncompressed size: 1027984, name: trid

457387        0x6FAAB         End of Zip archive

```



Automatic extraction with the `-e` parameter.


Manual cutting can also be done in conjunction with the `dd` command.


```shell

root in ~/Desktop/tmp λ dd if=flag of=1.zip bs=1 skip=25683

431726+0 records in

431726+0 records out

431726 bytes (432 kB, 422 KiB) copied, 0.900973 s, 479 kB/s

```
