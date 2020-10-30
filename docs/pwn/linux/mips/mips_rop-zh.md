[EN](./mips_rop.md) | [ZH](./mips_rop-zh.md)
# mips - ROP
## 介绍
本章目前只打算介绍 mips 下的 rop，其他漏洞的利用以后会逐渐介绍
## 预备知识
架构回顾见： https://ctf-wiki.github.io/ctf-wiki/assembly/mips/readme-zh/
栈结构如图：
![img](https://sw-blog.oss-cn-hongkong.aliyuncs.com/img/image001.gif)
有几个特殊的地方需要注意

1. MIPS32架构中是没有EBP寄存器的，程序函数调用的时候是将当前栈指针向下移动 n 比特到该函数的 stack frame 存储组空间，函数返回的时候再加上偏移量恢复栈
2. 传参过程中，前四个参数$a0-$a3，多余的会保存在调用函数的预留的栈顶空间内
3. MIPS调用函数时会把函数的返回地址直接存入$RA 寄存器
## 简单环境适配
我们目前以用户态的形式调试程序, 所以需要安装 且，qemu-user  等依赖
```bash
$ sudo apt install qemu-user
$ sudo apt install libc6-mipsel-cross
$ sudo mkdir /etc/qemu-binfmt
$ sudo ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel
```



