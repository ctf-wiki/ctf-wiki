# 編譯內核驅動

這裏我們來嘗試編譯一個驅動模塊。驅動代碼如下

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

這裏簡單介紹一下這個 Makefile

- `obj-m` 指定要聲稱哪些模塊
- `KDIR` 用來標識內核源碼目錄，提供驅動編譯所需環境
- `$(MAKE) -C $(KDIR) M=$(PWD) modules`
    - `-C` 表示進入到指定的內核目錄
    - `M` 指定驅動源碼的環境，M 並不是 Makefile 的選項，而是內核根目錄下 Makefile 中使用的變量。這會使得該 Makefile 在構造模塊之前返回到 M 指定的目錄，並在指定的目錄中生成驅動模塊。

編譯驅動

```bash
make
```
