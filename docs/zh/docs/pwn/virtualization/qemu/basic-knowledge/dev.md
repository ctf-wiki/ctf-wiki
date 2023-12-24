# QEMU 设备模拟

QEMU 在用户空间中独立进行设备模拟，虚拟设备被其他的 VM 通过 hypervisor 提供的接口进行调用。由于设备的模拟是独立于 hypervisor 的，因此我们可以模拟任何设备，且该模拟设备可以在其他 hypervisor 间进行共享。

本章我们讲述 QEMU 如何进行设备模拟。

## QEMU 设备 IO 处理

当 VM 在访问某一虚拟设备对应的物理内存/端口时，控制权由 VM 转交到 Hypervisor，此时 QEMU 会根据触发 VM-exit 的事件类型进行不同的处理。

> accel/kvm/kvm-all.c

```c
int kvm_cpu_exec(CPUState *cpu)
{
    //...

    do {
        //...

        run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);

        // VCPU 退出运行，处理对应事件

        trace_kvm_run_exit(cpu->cpu_index, run->exit_reason);
        switch (run->exit_reason) {
        case KVM_EXIT_IO:
            DPRINTF("handle_io\n");
            /* Called outside BQL */
            kvm_handle_io(run->io.port, attrs,
                          (uint8_t *)run + run->io.data_offset,
                          run->io.direction,
                          run->io.size,
                          run->io.count);
            ret = 0;
            break;
        case KVM_EXIT_MMIO:
            DPRINTF("handle_mmio\n");
            /* Called outside BQL */
            address_space_rw(&address_space_memory,
                             run->mmio.phys_addr, attrs,
                             run->mmio.data,
                             run->mmio.len,
                             run->mmio.is_write);
            ret = 0;
            break;
```

### MMIO

对于 MMIO 而言会调用到 `address_space_rw()` 函数，该函数会先将全局地址空间 `address_space_memory` 展开成 `FlatView` 后再调用对应的函数进行读写操作。

> softmmu/physmem.c

```c
MemTxResult address_space_read_full(AddressSpace *as, hwaddr addr,
                                    MemTxAttrs attrs, void *buf, hwaddr len)
{
    MemTxResult result = MEMTX_OK;
    FlatView *fv;

    if (len > 0) {
        RCU_READ_LOCK_GUARD();
        fv = address_space_to_flatview(as);
        result = flatview_read(fv, addr, attrs, buf, len);
    }

    return result;
}

MemTxResult address_space_write(AddressSpace *as, hwaddr addr,
                                MemTxAttrs attrs,
                                const void *buf, hwaddr len)
{
    MemTxResult result = MEMTX_OK;
    FlatView *fv;

    if (len > 0) {
        RCU_READ_LOCK_GUARD();
        fv = address_space_to_flatview(as);
        result = flatview_write(fv, addr, attrs, buf, len);
    }

    return result;
}

MemTxResult address_space_rw(AddressSpace *as, hwaddr addr, MemTxAttrs attrs,
                             void *buf, hwaddr len, bool is_write)
{
    if (is_write) {
        return address_space_write(as, addr, attrs, buf, len);
    } else {
        return address_space_read_full(as, addr, attrs, buf, len);
    }
}
```

操作函数最后会根据 `FlatView` 找到目标内存对应的 `MemoryRegion`，对于函数表中定义了读写指针的 MR 而言最后会调用对应的函数指针完成内存访问工作，代码过多这里就不继续展开了：

> softmmu/physmem.c

```c
/* Called from RCU critical section.  */
static MemTxResult flatview_write(FlatView *fv, hwaddr addr, MemTxAttrs attrs,
                                  const void *buf, hwaddr len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;

    l = len;
    mr = flatview_translate(fv, addr, &addr1, &l, true, attrs);
    if (!flatview_access_allowed(mr, attrs, addr, len)) {
        return MEMTX_ACCESS_ERROR;
    }
    return flatview_write_continue(fv, addr, attrs, buf, len,
                                   addr1, l, mr);
}

/* Called from RCU critical section.  */
static MemTxResult flatview_read(FlatView *fv, hwaddr addr,
                                 MemTxAttrs attrs, void *buf, hwaddr len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;

    l = len;
    mr = flatview_translate(fv, addr, &addr1, &l, false, attrs);
    if (!flatview_access_allowed(mr, attrs, addr, len)) {
        return MEMTX_ACCESS_ERROR;
    }
    return flatview_read_continue(fv, addr, attrs, buf, len,
                                  addr1, l, mr);
}
```

### PMIO

对于 `PMIO` 而言会调用到 `kvm_handle_io()` 函数，该函数实际上也是对 `address_space_rw()` 的封装，只不过使用的是**端口地址空间** `address_space_io`，最后也会调用到对应 `MemoryRegion` 的函数表中的读写函数。

```c
static void kvm_handle_io(uint16_t port, MemTxAttrs attrs, void *data, int direction,
                          int size, uint32_t count)
{
    int i;
    uint8_t *ptr = data;

    for (i = 0; i < count; i++) {
        address_space_rw(&address_space_io, port, attrs,
                         ptr, size,
                         direction == KVM_EXIT_IO_OUT);
        ptr += size;
    }
}
```

## QEMU PCI 设备

> 待施工。

## REFERENCE

《QEMU/KVM 源码解析与应用》——李强 著

[【HARDWARE.0x00】PCI 设备简易食用手册](https://arttnba3.cn/2022/08/30/HARDWARE-0X00-PCI_DEVICE/)

[【VIRT.0x02】系统虚拟化导论](https://arttnba3.cn/2022/08/29/VURTUALIZATION-0X02-BASIC_KNOWLEDGE)