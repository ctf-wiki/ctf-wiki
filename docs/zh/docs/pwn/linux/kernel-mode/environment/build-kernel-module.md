# 编译内核驱动

这里我们来尝试编译一个驱动模块。驱动代码如下

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
MODULE_LICENSE("Dual BSD/GPL");
static int ko_test_init(void) 
{
    printk("This is a test ko!\n");
    return 0;
}
static void ko_test_exit(void) 
{
    printk("Bye Bye~\n");
}
module_init(ko_test_init);
module_exit(ko_test_exit);
```

Makefile 文件如下

```makefile
obj-m += ko_test.o
 
KDIR =/home/iromise/dev/kernel/linux-5.4.98/
 
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
 
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
```

这里简单介绍一下这个 Makefile

- `obj-m` 指定要声称哪些模块
- `KDIR` 用来标识内核源码目录，提供驱动编译所需环境
- `$(MAKE) -C $(KDIR) M=$(PWD) modules`
    - `-C` 表示进入到指定的内核目录
    - `M` 指定驱动源码的环境，M 并不是 Makefile 的选项，而是内核根目录下 Makefile 中使用的变量。这会使得该 Makefile 在构造模块之前返回到 M 指定的目录，并在指定的目录中生成驱动模块。

编译驱动

```bash
make
```
