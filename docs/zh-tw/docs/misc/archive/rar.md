# RAR 格式

## 文件格式

RAR 文件主要由標記塊，壓縮文件頭塊，文件頭塊，結尾塊組成。

其每一塊大致分爲以下幾個字段：

| 名稱       | 大小 | 描述                  |
| ---------- | ---- | --------------------- |
| HEAD_CRC   | 2    | 全部塊或塊部分的CRC   |
| HEAD_TYPE  | 1    | 塊類型                |
| HEAD_FLAGS | 2    | 阻止標誌              |
| HEAD_SIZE  | 2    | 塊大小                |
| ADD_SIZE   | 4    | 可選字段 - 添加塊大小 |

Rar壓縮包的文件頭爲 `0x 52 61 72 21 1A 07 00`。

緊跟着文件頭（0x526172211A0700）的是標記塊（MARK_HEAD），其後還有文件頭（File Header）。

| 名稱          | 大小            | 描述                                                                                                                     |
| ------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------ |
| HEAD_CRC      | 2               | CRC of fields from HEAD_TYPE to FILEATTR and file name                                                                   |
| HEAD_TYPE     | 1               | Header Type: 0x74                                                                                                        |
| HEAD_FLAGS    | 2               | Bit Flags (Please see ‘Bit Flags for File in Archive’ table for all possibilities)（僞加密）                           |
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

每個 RAR 文件的結尾塊（Terminator）都是固定的。

| Field Name | Size (bytes) | Possibilities       |
| ---------- | ------------ | ------------------- |
| HEAD_CRC   | 2            | Always 0x3DC4       |
| HEAD_TYPE  | 1            | Header type: 0x7b   |
| HEAD_FLAGS | 2            | Always 0x4000       |
| HEAD_SIZE  | 2            | Block size = 0x0007 |

更多詳見 [Rar - Forensics Wiki](https://forensics.wiki/rar/)

## 主要攻擊

### 爆破

-   Linux下的 [RarCrack](http://rarcrack.sourceforge.net/)

### 僞加密

RAR 文件的僞加密在文件頭中的位標記字段上，用 010 Editor 可以很清楚的看見這一位，修改這一位可以造成僞加密。

![](./figure/6.png)

其餘明文攻擊等手法依舊同 ZIP 中介紹的一樣。
