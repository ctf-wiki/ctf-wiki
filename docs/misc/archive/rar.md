## 文件格式

RAR 文件主要由标记块，压缩文件头块，文件头块，结尾块组成。

其每一块大致分为以下几个字段：

| 名称       | 大小 | 描述                  |
| ---------- | ---- | --------------------- |
| HEAD_CRC   | 2    | 全部块或块部分的CRC   |
| HEAD_TYPE  | 1    | 块类型                |
| HEAD_FLAGS | 2    | 阻止标志              |
| HEAD_SIZE  | 2    | 块大小                |
| ADD_SIZE   | 4    | 可选字段 - 添加块大小 |

Rar压缩包的文件头为 `0x 52 61 72 21 1A 07 00`。

紧跟着文件头（0x526172211A0700）的是标记块（MARK_HEAD），其后还有文件头（File Header）。

| 名称          | 大小            | 描述                                                                                                                     |
| ------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| HEAD_CRC      | 2               | CRC of fields from HEAD_TYPE to FILEATTR and file name                                                                   |
| HEAD_TYPE     | 1               | Header Type: 0x74                                                                                                        |
| HEAD_FLAGS    | 2               | Bit Flags (Please see ‘Bit Flags for File in Archive’ table for all possibilities)（伪加密）                           |
| HEAD_SIZE     | 2               | File header full size including file name and comments                                                                   |
| PACK_SIZE     | 4               | Compressed file size                                                                                                     |
| UNP_SIZE      | 4               | Uncompressed file size                                                                                                   |
| HOST_OS       | 1               | Operating system used for archiving (See the ‘Operating System Indicators’ table for the flags used)                   |
| FILE_CRC      | 4               | File CRC                                                                                                                 |
| FTIME         | 4               | Date and time in standard MS DOS format                                                                                  |
| UNP_VER       | 1               | RAR version needed to extract file (Version number is encoded as 10 * Major version + minor version.)                    |
| METHOD        | 1               | Packing method (Please see ‘Packing Method’ table for all possibilities                                                |
| NAME_SIZE     | 2               | File name size                                                                                                           |
| ATTR          | 4               | File attributes                                                                                                          |
| HIGH_PACK_SIZ | 4               | High 4 bytes of 64-bit value of compressed file size. Optional value, presents only if bit 0x100 in HEAD_FLAGS is set.   |
| HIGH_UNP_SIZE | 4               | High 4 bytes of 64-bit value of uncompressed file size. Optional value, presents only if bit 0x100 in HEAD_FLAGS is set. |
| FILE_NAME     | NAME_SIZE bytes | File name - string of NAME_SIZE bytes size                                                                               |
| SALT          | 8               | present if (HEAD_FLAGS & 0x400) != 0                                                                                     |
| EXT_TIME      | variable size   | present if (HEAD_FLAGS & 0x1000) != 0                                                                                    |

每个 RAR 文件的结尾快（Terminator）都是固定的。

| Field Name | Size (bytes) | Possibilities       |
| ---------- | ------------ | ------------------- |
| HEAD_CRC   | 2            | Always 0x3DC4       |
| HEAD_TYPE  | 1            | Header type: 0x7b   |
| HEAD_FLAGS | 2            | Always 0x4000       |
| HEAD_SIZE  | 2            | Block size = 0x0007 |

更多详见 <http://www.forensicswiki.org/wiki/RAR>

## 主要攻击

### 爆破

-   Linux下的 [RarCrack](http://rarcrack.sourceforge.net/)

### 伪加密

RAR 文件的伪加密在文件头中的位标记字段上，用 010 Editor 可以很清楚的看见这一位，修改这一位可以造成伪加密。

![](/misc/archive/figure/6.png)

其余明文攻击等手法依旧同 ZIP 中介绍的一样。
