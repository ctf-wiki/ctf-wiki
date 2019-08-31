[EN](./problem.md) | [ZH](./problem-zh.md)
#题


## 2018 Net Ding Cup first clip


Through the 010 editor, you can see that the header of the file contains the word cloop. The search found that this is an old linux-compressed device. The problem is that the device is damaged, so I will find a way to find a normal one. So search how to compress to get a cloop file, as follows


```shell

mkisofs -r test | create_compressed_fs - 65536 > test.cloop

```



Refer to https://github.com/KlausKnopper/cloop, so compress a file, and then find that there is a problem with the source file header, so fix it and consider how to extract the file from the cloop file, that is, use


```

extract_compressed_fs test.cloop now

```



See https://manned.org/create_compressed_fs/f2f838da.


Get an ext4 type of file, and further find a way to get the contents of this file system


```shell

➜  clip losetup -d /dev/loop0

losetup: /dev/loop0: detach failed: Permission denied

➜  clip sudo losetup -d /dev/loop0

➜  clip sudo losetup /dev/loop0 now                                                 

losetup: now: failed to set up loop device: Device or resource busy

➜  clip sudo losetup /dev/loop0 /home/iromise/ctf/2018/0820网鼎杯/misc/clip/now        

losetup: /home/iromise/ctf/2018/0820网鼎杯/misc/clip/now: failed to set up loop device: Device or resource busy

➜  clip losetup -f           

/ dev / loop10
➜  clip sudo losetup /dev/loop10 /home/iromise/ctf/2018/0820网鼎杯/misc/clip/now

➜  clip sudo mount /dev/loop10 /mnt/now

➜  clip cd /mnt/now 

➜  now ls        

clip-clip.png  clip-clop.png  clop-clip.png  clop-clop.jpg  flag.png

```



The final step is to fix the flag. That is, the few characters of the file header are missing.