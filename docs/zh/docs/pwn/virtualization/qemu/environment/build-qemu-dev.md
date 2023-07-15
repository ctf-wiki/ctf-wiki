# 编写 QEMU 模拟设备

本节我们将介绍如何在 QEMU 中编写一个新的模拟设备。

> 注1：在开始之前你可能需要补充一些[PCI 设备的基础知识](https://arttnba3.cn/2022/08/30/HARDWARE-0X00-PCI_DEVICE/)
>
> 注2：qemu 官方在 `hw/misc/edu.c` 中也提供了一个教学用的设备样例，red hat 则在 `hw/misc/pci-testdev.c` 中提供了一个测试设备，我们可以参考这两个设备来构建我们的设备

## QEMU Object Model

在 Qemu 当中有着一套叫做 **Qemu Object Model** 的东西来实现面向对象，主要由这四个组件构成：

- `Type`：用来定义一个「类」的基本属性，例如类的名字、大小、构造函数等。
- `Class`：用来定义一个「类」的静态内容，例如类中存储的静态数据、方法函数指针等。
- `Object`：动态分配的一个「类」的具体的实例（instance），储存类的动态数据。
- `Property`：动态对象数据的访问器（accessor），可以通过监视器接口进行检查。

类似于 Golang，在 QOM 当中使用成员嵌套的方式来完成类的继承，父类作为类结构体的第一个成员 `parent` 而存在，因此也不支持多继承。

> 参见[这个ppt](https://www.linux-kvm.org/images/f/f6/2012-forum-QOM_CPU.pdf)

### I、TypeInfo - 类的基本属性

`TypeInfo` 这一结构体用来定义一个 `类` 的基本属性，该结构体定义于 `include/qom/object.h` 当中：

```c
/**
 * TypeInfo:
 * @name: 类型名.
 * @parent: 父类型名.
 * @instance_size: 对象大小 (#Object 的衍生物). 
 *   若 @instance_size 为 0, 则对象的大小为其父类的大小
 * @instance_init: 该函数被调用以初始化对象（译注：构造函数）. 
 *   （译注：调用前）父类已被初始化，因此子类只需要初始化他自己的成员。
 * @instance_post_init: 该函数被调用以结束一个对象的初始化，
 *   在所有的 @instance_init 函数被调用之后.
 * @instance_finalize: 该函数在对象被析构时调用. 其在
 *   父类的 @instance_finalize 被调用之前被调用.
 *   在该函数中一个对象应当仅释放该对象特有的成员。
 * @abstract: 若该域为真，则该类为一个虚类，不能被直接实例化。
 * @class_size: 这个对象的类对象的大小 (#Object 的衍生物)
 *   若 @class_size 为 0, 则类的大小为其父类的大小。
 *   这允许一个类型在没有添加额外的虚函数时避免实现一个显式的类型。
 * @class_init: 该函数在所有父类初始化结束后被调用，
 *   以允许一个类设置他的默认虚方法指针.
 *   这也允许该函数重写父类的虚方法。
 * @class_base_init: 在所有的父类被初始化后、但
 *   在类自身初始化前，为所有的基类调用该函数。
 *   该函数用以撤销从父类 memcpy 到子类的影响.
 * @class_data: 传递给 @class_init 与 @class_base_init 的数据,
 *   这会在建立动态类型时有用。
 * @interfaces: 与这个类型相关的接口. 
 *   其应当指向一个以 0 填充元素结尾的静态数组
 */
struct TypeInfo
{
    const char *name;
    const char *parent;

    size_t instance_size;
    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;
    size_t class_size;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);
    void *class_data;

    InterfaceInfo *interfaces;
};
```

当我们在 Qemu 中要定义一个**类**的时候，我们实际上需要定义一个 `TypeInfo` 类型的变量，以下是一个在 Qemu 定义一个自定义类的例子：

```c
static const TypeInfo a3_type_info = {
    .name = "a3_type",
    .parent = TYPE_OBJECT,
    .interfaces = (InterfaceInfo[]) {
        { },
    },
}

static void a3_register_types(void) {
    type_register_static(&a3_type_info);
}

type_init(a3_register_types);
```

`type_init()` 其实就是 `constructor` 这一 gcc attribute 的封装，其作用就是将一个函数加入到一个 `init_array` 当中，在 Qemu 程序启动时在进入到 main 函数之前会先调用 `init_array` 中的函数，因此这里会调用我们自定义的函数，其作用便是调用 `type_register_static()` 将我们自定义的类型 `a3_type_info` 注册到全局的类型表中。

### II、Class - 类的静态内容

当我们通过一个 `TypeInfo` 结构体定义了一个类之后，我们还需要定义一个 Class 结构体来定义这个类的静态内容，包括函数表、静态成员等，其应当继承于对应的 Class 结构体类型，例如我们若是要定义一个新的机器类，则其 Class 应当继承于 `MachineClass`。

所有 Class 结构体类型的最终的父类都是 `ObjectClass` 结构体：

```c
/**
 * ObjectClass:
 *
 * 所有类的基类.  #ObjectClass 仅包含一个整型类型 handler
 */
struct ObjectClass
{
    /*< private >*/
    Type type;
    GSList *interfaces;

    const char *object_cast_cache[OBJECT_CLASS_CAST_CACHE];
    const char *class_cast_cache[OBJECT_CLASS_CAST_CACHE];

    ObjectUnparent *unparent;

    GHashTable *properties;
};
```

下面是一个最简单的示例：

```c
struct A3Class
{
    /*< private >*/
    ObjectClass parent;
}
```

完成 Class 的定义之后我们还应当在前面定义的 `a3_type_info` 中添加上 Class size 与 Class 的构造函数：

```c
static void a3_class_init(ObjectClass *oc, void *data)
{
    // 这里的 oc 参数便是新创建的 Class，全局只有一个该实例
    // 我们应当 cast 为我们自己的 Class 类型，之后再进行相应操作
    // do something
}

static const TypeInfo a3_type_info = {
    .name = "a3_type",
    .parent = TYPE_OBJECT,
    .class_size = sizeof(A3Class),
    .class_init = a3_class_init,
    .interfaces = (InterfaceInfo[]) {
        { },
    },
}
```

### III、Object - 类的实例对象

我们还需要定义一个相应的 Object 类型来表示一个实例对象，其包含有这个类实际的具体数据，且应当继承于对应的 Object 结构体类型，例如我们若是要定义一个新的机器类型，其实例类型应当继承自 `MachineState`

所有 Object 结构体类型的最终的父类都是 `Object` 结构体：

```c
/**
 * Object:
 *
 * 所有对象的基类。该对象的第一个成员为一个指向 #ObjectClass 的指针。
 * 因为 C 中将一个结构体的第一个成员组织在该结构体的 0 字节起始处，
 * 只要任何的子类将其父类作为第一个成员，我们都能直接转化为一个 #Object.
 *
 * 因此, #Object 包含一个对对象类的引用作为其第一个成员。 
 * 这允许在运行时识别对象的真实类型
 */
struct Object
{
    /*< private >*/
    ObjectClass *class;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};
```

下面是一个示例：

```c
struct A3Object
{
    /*< private >*/
    Object parent;
}
```

完成 Object 的定义之后我们还应当在前面定义的 `a3_type_info` 中添加上 Object size 与 Object 的构造函数：

```c
static void a3_object_init(Object *obj)
{
    // 这里的 obj 参数便是动态创建的类型实例
    // do something
}

static const TypeInfo a3_type_info = {
    .name = "a3_type",
    .parent = TYPE_OBJECT,
    .instance_init = a3_object_init,
    .instance_size = sizeof(A3Object),
    .class_size = sizeof(A3Class),
    .class_init = a3_class_init,
    .interfaces = (InterfaceInfo[]) {
        { },
    },
}
```

### IV、类的创建与释放

类似于在 C++ 当中使用 `new` 与 `delete` 来创建与释放一个类实例，在 QOM 中我们应当使用 `object_new()` 与 `object_delete()` 来创建与销毁一个 QOM 类实例，本质上就是 `分配/释放类空间 + 显示调用构造/析构函数`

QOM 判断创建类实例的类型是通过类的名字，即 `TypeInfo->name`，当创建类实例时 Qemu 会遍历所有的 TypeInfo 并寻找名字匹配的那个，从而调用到对应的构造函数，并将其基类 `Object->class` 指向对应的 class

下面是一个示例：

```c
// create a QOM object
A3Object *a3obj = object_new("a3_type");
// delete a QOM object
object_delete(a3obj);
```

## Qemu 中 PCI 设备的编写

在补充了这么多的 Qemu 相关的知识之后，现在我们可以开始在 Qemu 中编写 PCI 设备了，这里笔者将编写一个最简单的 Qemu 设备，并将源码放在 `hw/misc/a3dev.c` 中

Qemu 当中 PCI 设备实例的基类是 `PCIDevice`，因此我们应当创建一个继承自 `PCIDevice` 的类来表示我们的设备实例，这里笔者仅声明了两个 `MemoryRegion` 用作 MMIO 与 PMIO，以及一个用作数据存储的 buffer：

```c
#define A3DEV_BUF_SIZE 0x100

typedef struct A3PCIDevState {
    /*< private >*/
    PCIDevice parent_obj;

    /*< public >*/
    MemoryRegion mmio;
    MemoryRegion pmio;
    uint8_t buf[A3DEV_BUF_SIZE];
} A3PCIDevState;
```

以及定义一个空的 Class 模板，继承自 PCI 设备的静态类型 `PCIDeviceClass`，不过这一步并不是必须的，事实上我们可以直接用 `PCIDeviceClass` 作为我们设备类的 Class：

```c
typedef struct A3PCIDevClass {
    /*< private >*/
    PCIDeviceClass parent;
} A3PCIDevClass;
```

以及两个将父类转为子类的宏，因为 QOM 基本函数传递的大都是父类指针，所以我们需要一个宏来进行类型检查 + 转型，这也是 Qemu 中惯用的做法：

```c
#define TYPE_A3DEV_PCI "a3dev-pci"
#define A3DEV_PCI(obj) \
    OBJECT_CHECK(A3PCIDevState, (obj), TYPE_A3DEV_PCI)
#define A3DEV_PCI_GET_CLASS(obj) \
    OBJECT_GET_CLASS(A3PCIDevClass, obj, TYPE_A3DEV_PCI)
#define A3DEV_PCI_CLASS(klass) \
    OBJECT_CLASS_CHECK(A3PCIDevClass, klass, TYPE_A3DEV_PCI)
```

下面我们开始定义 MMIO 与 PMIO 的操作函数，这里笔者就简单地设置为读写设备内部的 buffer，并声明上两个 MemoryRegion 对应的函数表，需要注意的是这里传入的 `hwaddr` 类型参数其实为相对地址而非绝对地址：

```c
static uint64_t
a3dev_read(void *opaque, hwaddr addr, unsigned size)
{
    A3PCIDevState *ds = A3DEV_PCI(opaque);
    uint64_t val = ~0LL;

    if (size > 8)
        return val;

    if (addr + size > A3DEV_BUF_SIZE)
        return val;
    
    memcpy(&val, &ds->buf[addr], size);
    return val;
}

static void
a3dev_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    A3PCIDevState *ds = A3DEV_PCI(opaque);

    if (size > 8)
        return ;

    if (addr + size > A3DEV_BUF_SIZE)
        return ;
    
    memcpy(&ds->buf[addr], &val, size);
}

static uint64_t
a3dev_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    return a3dev_read(opaque, addr, size);
}

static uint64_t
a3dev_pmio_read(void *opaque, hwaddr addr, unsigned size)
{
    return a3dev_read(opaque, addr, size);
}

static void
a3dev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    a3dev_write(opaque, addr, val, size);
}

static void
a3dev_pmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    a3dev_write(opaque, addr, val, size);
}

static const MemoryRegionOps a3dev_mmio_ops = {
    .read = a3dev_mmio_read,
    .write = a3dev_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static const MemoryRegionOps a3dev_pmio_ops = {
    .read = a3dev_pmio_read,
    .write = a3dev_pmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};
```

然后是设备实例的初始化函数，在 `PCIDeviceClass` 当中定义了一个名为 `realize` 的函数指针，当 PCI 设备被载入时便会调用这个函数指针指向的函数来初始化，所以这里我们也定义一个自己的初始化函数，不过我们需要做的工作其实基本上就只有初始化两个 `MemoryRegion`，`memory_region_init_io()` 会为这两个 `MemoryRegion` 进行初始化的工作，并设置函数表为我们指定的函数表，`pci_register_bar()` 则用来注册 BAR：

```c
static void a3dev_realize(PCIDevice *pci_dev, Error **errp)
{
    A3PCIDevState *ds = A3DEV_PCI(pci_dev);

    memory_region_init_io(&ds->mmio, OBJECT(ds), &a3dev_mmio_ops,
                        pci_dev, "a3dev-mmio", A3DEV_BUF_SIZE);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &ds->mmio);
    memory_region_init_io(&ds->pmio, OBJECT(ds), &a3dev_pmio_ops,
                        pci_dev, "a3dev-pmio", A3DEV_BUF_SIZE);
    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &ds->pmio);
}
```

最后是 Class 与 Object（也就是 instance）的初始化函数，这里需要注意的是在 Class 的初始化函数中我们应当设置父类 `PCIDeviceClass` 的一系列基本属性（也就是 PCI 设备的基本属性）：

```c
static void a3dev_instance_init(Object *obj)
{
    // do something
}

static void a3dev_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pci = PCI_DEVICE_CLASS(oc);

    pci->realize = a3dev_realize;
    pci->vendor_id = PCI_VENDOR_ID_QEMU;
    pci->device_id = 0x1919;
    pci->revision = 0x81;
    pci->class_id = PCI_CLASS_OTHERS;

    dc->desc = "arttnba3 test PCI device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}
```

最后就是为我们的 PCI 设备类型注册 TypeInfo 了，这里别忘了**我们的接口中应当增加上 PCI 的接口**：

```c
static const TypeInfo a3dev_type_info = {
    .name = TYPE_A3DEV_PCI,
    .parent = TYPE_PCI_DEVICE,
    .instance_init = a3dev_instance_init,
    .instance_size = sizeof(A3PCIDevState),
    .class_size = sizeof(A3PCIDevClass),
    .class_init = a3dev_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void a3dev_register_types(void) {
    type_register_static(&a3dev_type_info);
}

type_init(a3dev_register_types);
```

最后我们在 meson 构建系统中加入我们新增的这个设备，在 `hw/misc/meson.build` 中加入如下语句：

```meson
softmmu_ss.add(when: 'CONFIG_PCI_A3DEV', if_true: files('a3dev.c'))
```

并在 `hw/misc/Kconfig` 中添加如下内容，这表示我们的设备会在 `CONFIG_PCI_DEVICES=y` 时编译：

```kconfig
config PCI_A3DEV
    bool
    default y if PCI_DEVICES
    depends on PCI
```

之后编译 Qemu 并附加上 `-device a3dev-pci` ，之后随便起一个 Linux 系统，此时使用 `lspci` 指令我们便能看到我们新添加的 pci 设备：

![使用 lspci 查看新添加的 pci 设备](./figure/new-qemu-dev-lspci.png)

我们可以使用如下程序来测试我们的设备的输入输出，需要注意的是这需要 root 权限：

> PMIO，使用 iopl 更改端口权限后便能通过 in/out 类指令读写端口

```c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/io.h>

int main(int argc, char **argv, char **envp)
{
        unsigned short port_addr;

        if (argc < 2) {
                puts("[x] no port provided!");
                exit(EXIT_FAILURE);
        }

        if (iopl(3) < 0) {
                puts("[x] no privilege!");
                exit(EXIT_FAILURE);
        }

        port_addr = atoi(argv[1]);

        printf("[+] a3dev port addr start at: %d\n", port_addr);

        puts("[*] now writing into a3dev-pci...");

        for (int i = 0; i < 0x100 / 4; i++) {
                outl(i, port_addr + i * 4);
        }

        puts("[+] writing done!");

        printf("[*] now reading from a3dev-pci...");
        for (int i = 0; i < 0x100 / 4; i++) {
                if (i % 8 == 0) {
                        printf("\n[--%d--]", port_addr + i * 4);
                }
                printf(" %d ", inl(port_addr + i * 4));
        }

        puts("\n[+] reading done!");
}
```

> MMIO，使用 mmap 映射 `sys` 目录下设备的 `resource0` 文件即可直接读写

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

void mmio_write(uint32_t *addr, uint32_t val)
{
        *addr = val;
}

uint32_t mmio_read(uint32_t *addr)
{
        return *addr;
}

int main(int argc, char **argv, char **envp)
{
        uint32_t *mmio_addr;
        int dev_fd;

        dev_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0",
                        O_RDWR | O_SYNC);
        if (dev_fd < 0) {
                puts("[x] failed to open mmio file! wrong path or no root!");
                exit(EXIT_FAILURE);
        }

        mmio_addr = (uint32_t*)
                mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, 0);
        if (mmio_addr == MAP_FAILED) {
                puts("failed to mmap!");
                exit(EXIT_FAILURE);
        }

        puts("[*] start writing to a3dev-pci...");
        for (int i = 0; i < 0x100 / 4; i++) {
                mmio_write(mmio_addr + i, i);
        }
        puts("[+] write done!");

        printf("[*] start reading from a3dev-pci...");
        for (int i = 0; i < 0x100 / 4; i++) {
                if (i % 8 == 0) {
                        printf("\n[--%p--]", mmio_addr);
                }
                printf(" %u ", mmio_read(mmio_addr + i));
        }
        puts("\n[+] read done!");
}
```

## REFERENCE

[【VIRT.0x00】Qemu - I：Qemu 简易食用指南](https://arttnba3.cn/2022/07/15/VIRTUALIZATION-0X00-QEMU-PART-I/)

[QOM Vadis?Taking Objects To The CPU And Beyond](https://www.linux-kvm.org/images/f/f6/2012-forum-QOM_CPU.pdf)

[在 QEMU 中模拟设备 - 知乎](https://zhuanlan.zhihu.com/p/57526565)