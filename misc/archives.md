常见压缩包格式有 Zip、RAR 等。

## Zip 压缩包

[Zip 文件结构](http://lib.yoekey.com/?p=236)

特征是以 `50 4B 03 04` 开头，有时也会出现 `50 4B 05 06` 和 `50 4B 07 08` 的情况。

[010 Editor ZIPTemplate](http://www.sweetscape.com/010editor/templates/files/ZIPTemplate.bt)

### 常见题型

- [伪加密](http://blog.csdn.net/etf6996/article/details/51946250)

  通过修改 Zip 文件中的加密位标记，打开压缩包时就会提示「该文件是加密的」。

  - 用 Mac OS 或 部分 Linux 系统（如 Kali Linux）打开该压缩包，可以正常使用。
  - 用十六进制编辑器修改加密位，改为 0 即可去除加密。
  - `binwalk` 会忽略伪加密，可以直接 `binwalk -e`。
  - 使用 [Ziprello](http://tools.40huo.cn/#!misc.md#压缩包)，会提示无加密。


- CRC32 碰撞

  CRC32 本身是「冗余校验码」，所以当压缩包中出现多个只有几个字节的文件时可以考虑使用 CRC32 校验碰撞。

  利用开源的[碰撞脚本](https://github.com/theonlypwner/crc32/blob/master/crc32.py)。

  > ```bash
  > crc32.py -h
  > usage: crc32.py [-h] action ...
  >
  > Reverse, undo, and calculate CRC32 checksums
  >
  > positional arguments:
  >   action
  >     flip      flip the bits to convert normal(msbit-first) polynomials to
  >               reversed (lsbit-first) and vice versa
  >     reciprocal
  >               find the reciprocal (Koopman notation) of a reversed (lsbit-
  >               first) polynomial and vice versa
  >     table     generate a lookup table for a polynomial
  >     reverse   find a patch that causes the CRC32 checksum to become a desired
  >               value
  >     undo      rewind a CRC32 checksum
  >     calc      calculate the CRC32 checksum
  >
  > optional arguments:
  >   -h, --help  show this help message and exit
  > ```

- 明文攻击

  已经通过其他手段知道 Zip 加密文件中的某些内容，比如在某些网站上发现它的 readme.txt 文件，或者其他文件，这时就可以尝试破解了，使用 [AZPR](http://tools.40huo.cn/#!misc.md#压缩包)，选用明文攻击。

?> [拓展阅读](http://bobao.360.cn/ctf/detail/203.html)

## RAR 压缩包

[RAR 编码文件格式分析](http://xueshu.baidu.com/s?wd=paperuri%3A%28dcac534bd083dea651191591bf2f30dc%29&filter=sc_long_sign&tn=SE_xueshusource_2kduw22v&sc_vurl=http%3A%2F%2Fwww.cqvip.com%2FQK%2F94433X%2F201002%2F33216705.html&ie=utf-8&sc_us=5189982121073495471)

[010 Editor RARTemplate](http://www.sweetscape.com/010editor/templates/files/RARTemplate.bt)

特征是以 `Rar!` 开头。

### 常见题型

- CRC32 碰撞
- 明文攻击