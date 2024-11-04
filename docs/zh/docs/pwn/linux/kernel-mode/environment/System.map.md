# System.map

`System.map` 文件是Linux内核编译过程中生成的一个重要文件。它包含了内核符号和它们对应的内存地址。这些符号包括内核函数、变量以及其他在内核中定义的重要符号。当我们获得的vmlinux是stripped时就需要System.map来帮助我们调试。
`System.map` 文件是一个纯文本文件，每一行包含三个字段：

符号地址（内存地址）
符号类型（例如：函数、变量）如果为小写，则符号为本地符号;如果大写，符号为全局（外部）。
符号名（标识符）
```
└─$ head System.map                 
0000000000000000 A VDSO32_PRELINK
0000000000000000 D __per_cpu_start
0000000000000000 D per_cpu__irq_stack_union
0000000000000000 A xen_irq_disable_direct_reloc
0000000000000000 A xen_save_fl_direct_reloc
0000000000000040 A VDSO32_vsyscall_eh_frame_size
00000000000001e7 A kexec_control_code_size
00000000000001f0 A VDSO32_NOTE_MASK
0000000000000400 A VDSO32_sigreturn
0000000000000410 A VDSO32_rt_sigreturn
```

## 在ida中为stripped的vmlinux添加System.map

加载以下脚本，然后选择对应的System.map文件
```python
import idaapi

def load_system_map(file_path):
    with open(file_path, "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            
            addr = int(parts[0], 16)
            symbol_type = parts[1]
            symbol_name = parts[2]
            
            # if symbol_type in ['T', 't', 'D', 'd', 'B', 'b']:     #如果符号表太大，可以针对性添加
            if not idaapi.add_entry(addr, addr, symbol_name, 0):
                print(f"Failed to add symbol: {symbol_name} at {hex(addr)}")
            else:
                print(f"Added symbol: {symbol_name} at {hex(addr)}")

system_map_path = idaapi.ask_file(0, "*.map", "Select System.map file")
if system_map_path:
    load_system_map(system_map_path)
else:
    print("No file selected")

```

加载前后对比
![System.map-load-diff](figure/System.map-load-diff.png)


## 直接修复vmlinux

如果你想直接修复vmlinux，可以参考https://github.com/marin-m/vmlinux-to-elf

## 参考
https://linux.die.net/man/1/nm
