# QEMU 設備模擬

QEMU 在用戶空間中獨立進行設備模擬，虛擬設備被其他的 VM 通過 hypervisor 提供的接口進行調用。由於設備的模擬是獨立於 hypervisor 的，因此我們可以模擬任何設備，且該模擬設備可以在其他 hypervisor 間進行共享。

本章我們講述 QEMU 如何進行設備模擬。

## QEMU 設備 IO 處理

當 VM 在訪問某一虛擬設備對應的物理內存/端口時，控制權由 VM 轉交到 Hypervisor，此時 QEMU 會根據觸發 VM-exit 的事件類型進行不同的處理。

> accel/kvm/kvm-all.c

```c
int kvm_cpu_exec(CPUState *cpu)
{
    //...

    do {
        //...

        run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);

        // VCPU 退出運行，處理對應事件

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

對於 MMIO 而言會調用到 `address_space_rw()` 函數，該函數會先將全局地址空間 `address_space_memory` 展開成 `FlatView` 後再調用對應的函數進行讀寫操作。

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

操作函數最後會根據 `FlatView` 找到目標內存對應的 `MemoryRegion`，對於函數表中定義了讀寫指針的 MR 而言最後會調用對應的函數指針完成內存訪問工作，代碼過多這裏就不繼續展開了：

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

對於 `PMIO` 而言會調用到 `kvm_handle_io()` 函數，該函數實際上也是對 `address_space_rw()` 的封裝，只不過使用的是**端口地址空間** `address_space_io`，最後也會調用到對應 `MemoryRegion` 的函數表中的讀寫函數。

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

## QEMU PCI 設備

> 待施工。

## REFERENCE

《QEMU/KVM 源碼解析與應用》——李強 著

[【HARDWARE.0x00】PCI 設備簡易食用手冊](https://arttnba3.cn/2022/08/30/HARDWARE-0X00-PCI_DEVICE/)

[【VIRT.0x02】系統虛擬化導論](https://arttnba3.cn/2022/08/29/VURTUALIZATION-0X02-BASIC_KNOWLEDGE)