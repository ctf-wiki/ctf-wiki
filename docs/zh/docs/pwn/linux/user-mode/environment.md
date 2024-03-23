## 简介

现有的 CTF Pwn 题主要以 Linux 下的用户态 Pwn 为主，因此我们通常需要在本地拥有一个 Linux 运行环境，这通常可以通过安装 Linux 虚拟机来完成，此外你也可以在物理机上安装 Linux 操作系统。

绝大多数 Linux Pwn 题目的远程环境以 [Ubuntu](https://ubuntu.com/) 为主，因此为了方便在本地调试题目，你通常需要搭建一个与题目版本相匹配的 Ubuntu 运行环境，不过 _这并不意味着你必须要使用 Ubuntu 作为你的主力操作系统_ 。你仍旧可以选择继续使用你喜欢的其他 Linux 发行版（如，Arch、Debian、openSUSE、Fedora、NixOS 等），并使用 Docker 来搭建相应的 Ubuntu 做题环境。

传统 CTF Pwn 题目通常仅需要以下工具便能完成解题：

- IDA：用于对题目进行逆向分析。
- Python + pwntools：用于编写漏洞利用脚本。
- gdb + pwndbg/peda：用于调试题目二进制文件。

此外，部分题目可能需要一些额外的环境（例如 kernel pwn 需要 qemu），我们将在后续介绍到对应题目时单独进行介绍。

## 使用 Docker 搭建 CTF Pwn 做题环境（推荐）

为了保证利用脚本能够正常打通，我们通常需要在本地准备相同的运行环境，并在进行远程利用之前先在本地进行测试，但由于 CTF 题目远程环境众多，若是为每个不同的环境都单独准备一个 Ubuntu 虚拟机，则不仅要在每个虚拟机上都完整搭建一遍调试环境，且会占用大量磁盘空间，同时也无法保证本地环境小版本和远程环境一定相同——除非每个小版本都单独创建一个虚拟机并永不升级，这种解决方案并不优雅。

通过 `LD_PRELOAD` 参数在程序执行前 预先加载 libc 在某些程度上是一个可行的解决方案，在 libc 大版本相同的情况下载入不同的小版本通常并不会出现问题，但是由于不同系统环境中 ld 版本不同的缘故，对于跨 ld 版本加载不同版本的 libc 则可能出现 segmentation fault，从而导致无法正常运行与调试题目。

虽然 Linux 的用户环境并不似 Windows 那样有着强壮的二进制前向兼容性，但是用户环境依托于内核环境、依托于内核向用户态暴露的接口——系统调用，而这并不是会轻易发生变动以及兼容性破坏的一个东西，由此，通过重新开辟一个对应的新的用户环境的方式—— 即形如 Docker 这样的操作系统层上的虚拟化方案，我们便能非常简单地搭建不同的 Pwn 题所对应的原始环境。

### Docker 环境搭建

Docker 的安装请大家根据自己所使用的 Linux 发行版自行参照 [Docker 官网](https://docs.docker.com/engine/install/) 或是发行版自己的 Wiki 进行配置，这里不再赘叙。

### 创建 Docker 镜像

我们以以下 Dockerfile 所创建的镜像作为模板，大家可以根据自己的需求自行修改：

```dockerfile
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# pre-install softwares
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get -y update && \
    apt-get install -y lib32z1 apt-transport-https python3 python3-pip git \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
    vim nano netcat openssh-server unzip make wget bison flex build-essential \
    curl qemu qemu-system-x86 gcc gdb clang lldb tmux konsole

# enable ssh login
RUN rm -f /etc/service/sshd/down
RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config &&\
    sed -ri 's/#UseDNS\ no/UseDNS\ no/g' /etc/ssh/sshd_config && \
    sed -ri "s/StrictModes yes/StrictModes no/g" /etc/ssh/sshd_config && \
    sed -ri "s/UsePAM yes/UsePAM no/g" /etc/ssh/sshd_config

# enable login with password
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# set username and password
RUN groupadd arttnba3 && \
    useradd -g arttnba3 arttnba3 -m -s /bin/bash && \
    echo "arttnba3:123456" | chpasswd && \
    echo "root:root123456" | chpasswd

# enable ssh key login
#RUN mkdir /home/arttnba3/.ssh && \
#    echo "Your ssh key" > /home/arttnba3/.ssh/authorized_keys

# keep container running
RUN echo "#!/bin/sh\nservice ssh restart\nsleep infinity" > /root/start.sh
RUN chmod +x /root/start.sh

# enable sudo
RUN apt-get install -y sudo && \
       usermod -aG sudo arttnba3

# pwn-related tools
RUN python3 -m pip config set global.index-url http://pypi.tuna.tsinghua.edu.cn/simple && \
    python3 -m pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn && \
    python3 -m pip install -U pip && \
    python3 -m pip install --no-cache-dir \
    pwntools \
    ropgadget \
    z3-solver \
    smmap2 \
    apscheduler \
    ropper \
    unicorn \
    keystone-engine \
    capstone \
    angr \
    pebble \
    r2pipe \
    LibcSearcher

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && chmod +x setup.sh && ./setup.sh

CMD ["/root/start.sh"]

EXPOSE 22
```

在一个空白文件夹中创建一个名为 `Dockerfile` 的文件，并写入上述内容，随后运行如下指令：

```shell
$ docker build -t pwnenv_ubuntu22 .
```

完成之后你便拥有了一个名为 `pwnenv_ubuntu22` 的带有做题环境的 Ubuntu22 镜像，可以通过 `docker images` 指令查看：

```shell
$ docker images                                              
REPOSITORY               TAG         IMAGE ID       CREATED          SIZE                                     
pwnenv_ubuntu22          latest      c129ca086a72   15 seconds ago   2.81GB
```

你也可以根据需求修改第一行的基镜像，从而创建基于不同 Ubuntu 发行版的 docker 镜像。

### 从 Docker 镜像创建容器

我们只需要通过如下命令便能基于我们刚刚创建的 Docker 镜像创建一个名为 `pwn22` 的 Docker 容器，并将容器的 `22` 端口映射到本地的 `25000` 端口：

```shell
$ docker run -d -p 25000:22 --name=pwn22 pwnenv_ubuntu22
```

之后通过如下命令便能进入到容器当中：

```shell
$ docker exec -w ~ -e TERM=xterm-256color -u arttnba3 -it pwn22 bash
```

若是我们想要在容器与本地间进行文件传输，则可以使用 `docker cp` 命令：

```shell
$ docker cp 本地源文件路径 容器名:容器内目的路径
$ docker cp 容器名:容器内源文件路径 本地目的路径
```

由于我们为容器设置了 ssh 服务，我们也可以通过 ssh 连接入容器环境，这允许我们使用 vscode 等工具连接到容器内部：

```shell
$ ssh root@localhost -p 25000
```

若是容器环境被我们折腾坏了，则可以直接通过 `docker rm 容器名` 进行删除（注：容器内文件会丢失），之后再重新使用 `docker run` 创建新容器即可。

### 将 Docker 容器接入本地图形界面

pwntools 自带的调试命令 `gdb.attach()` 需要创建新的窗口，而在容器中直接运行会失败，因此我们需要为容器接入本地的图形服务，以达成原生的运行效果（直接弹出一个新的窗口）。

对于 Wayland 环境，在创建容器时我们需要额外附加一些参数：

```shell
$ docker run -d -p "25000:22" \
	--name=pwn22 \
	-e XDG_RUNTIME_DIR=/tmp \
	-e DISPLAY=$DISPLAY \
	-e WAYLAND_DISPLAY=$WAYLAND_DISPLAY \
	-v $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY:/tmp/$WAYLAND_DISPLAY \
	-e QT_QPA_PLATFORM=wayland \
	pwnenv_ubuntu20
```

之后在运行 `gdb.attach()` 之前运行如下 python 语句之一进行配置即可，请根据自己所使用的桌面环境进行选择：

```python
context.terminal = ['konsole', '-e', 'sh', '-c'] # for KDE
context.terminal = ['gnome-terminal', '-e', 'sh', '-c'] #  for Gnome
```

对于使用 X11 图形服务的，请参考 [Running pwnlib gdb (pwntools) feature inside Docker](https://gist.github.com/turekt/71f6950bc9f048daaeb69479845b672b) 进行配置。

## 在本地直接搭建 CTF Pwn 做题环境

> TODO