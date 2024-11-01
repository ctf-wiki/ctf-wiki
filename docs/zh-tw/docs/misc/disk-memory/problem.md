# 題目

## 2018 網鼎杯第一場 clip

通過010 editor 可以看到文件的頭部包含有 cloop 字樣，搜了搜發現這是一個古老的 linux 壓縮後的設備，題目中又說這個設備損壞了，所以就想辦法找一個正常的。於是搜索如何壓縮得到一個 cloop 文件，如下

```shell
mkisofs -r test | create_compressed_fs - 65536 > test.cloop
```

參考https://github.com/KlausKnopper/cloop，於是壓縮一個文件，然後發現源文件文件頭存在問題，於是進行修復，從而考慮如何從 cloop 文件中提取文件，即使用

```
extract_compressed_fs test.cloop now
```

參考https://manned.org/create_compressed_fs/f2f838da。

得到一個 ext4 類型的文件，進一步想辦法獲取這個文件系統的內容

```shell
➜  clip losetup -d /dev/loop0
losetup: /dev/loop0: detach failed: Permission denied
➜  clip sudo losetup -d /dev/loop0
➜  clip sudo losetup /dev/loop0 now                                                 
losetup: now: failed to set up loop device: Device or resource busy
➜  clip sudo losetup /dev/loop0 /home/iromise/ctf/2018/0820網鼎杯/misc/clip/now        
losetup: /home/iromise/ctf/2018/0820網鼎杯/misc/clip/now: failed to set up loop device: Device or resource busy
➜  clip losetup -f           
/dev/loop10
➜  clip sudo losetup /dev/loop10 /home/iromise/ctf/2018/0820網鼎杯/misc/clip/now
➜  clip sudo mount /dev/loop10 /mnt/now
➜  clip cd /mnt/now 
➜  now ls        
clip-clip.png  clip-clop.png  clop-clip.png  clop-clop.jpg  flag.png
```

最後一步就是修復 flag 了。就是少了文件頭那幾個字符。