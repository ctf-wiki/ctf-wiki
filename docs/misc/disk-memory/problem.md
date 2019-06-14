# 题目

## 2018 网鼎杯第一场 clip

通过010 editor 可以看到文件的头部包含有 cloop 字样，搜了搜发现这是一个古老的 linux 压缩后的设备，题目中又说这个设备损坏了，所以就想办法找一个正常的。于是搜索如何压缩得到一个 cloop 文件，如下

```shell
mkisofs -r test | create_compressed_fs - 65536 > test.cloop
```

参考https://github.com/KlausKnopper/cloop，于是压缩一个文件，然后发现源文件文件头存在问题，于是进行修复，从而考虑如何从 cloop 文件中提取文件，即使用

```
extract_compressed_fs test.cloop now
```

参考https://manned.org/create_compressed_fs/f2f838da。

得到一个 ext4 类型的文件，进一步想办法获取这个文件系统的内容

```shell
➜  clip losetup -d /dev/loop0
losetup: /dev/loop0: detach failed: Permission denied
➜  clip sudo losetup -d /dev/loop0
➜  clip sudo losetup /dev/loop0 now                                                 
losetup: now: failed to set up loop device: Device or resource busy
➜  clip sudo losetup /dev/loop0 /home/iromise/ctf/2018/0820网鼎杯/misc/clip/now        
losetup: /home/iromise/ctf/2018/0820网鼎杯/misc/clip/now: failed to set up loop device: Device or resource busy
➜  clip losetup -f           
/dev/loop10
➜  clip sudo losetup /dev/loop10 /home/iromise/ctf/2018/0820网鼎杯/misc/clip/now
➜  clip sudo mount /dev/loop10 /mnt/now
➜  clip cd /mnt/now 
➜  now ls        
clip-clip.png  clip-clop.png  clop-clip.png  clop-clop.jpg  flag.png
```

最后一步就是修复 flag 了。就是少了文件头那几个字符。