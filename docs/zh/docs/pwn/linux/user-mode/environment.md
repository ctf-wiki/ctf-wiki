## 简介

现有的 CTF Pwn 题主要以 Linux 下的用户态 Pwn 为主，因此我们通常需要在本地拥有一个 Linux 运行环境，这通常可以通过安装 Linux 虚拟机来完成，此外你也可以在物理机上安装 Linux 操作系统。

绝大多数 Linux Pwn 题目的远程环境以 [Ubuntu](https://ubuntu.com/) 为主，因此为了方便在本地调试题目，你通常需要搭建一个与题目版本相匹配的 Ubuntu 运行环境，不过 _这并不意味着你必须要使用 Ubuntu 作为你的主力操作系统_ 。你仍旧可以选择继续使用你喜欢的其他 Linux 发行版（如，Gentoo、openSUSE、Debian、Fedora、Arch、NixOS 等），并使用 Docker 来搭建相应的 Ubuntu 做题环境。

传统 CTF Pwn 题目通常仅需要以下工具便能完成解题：

- IDA：用于对题目进行逆向分析。
- Python + pwntools：用于编写漏洞利用脚本。
- gdb + pwndbg/peda：用于调试题目二进制文件。

需要注意的是，在初学阶段我们并不推荐任何基于 pwntools 进行过度二次包装的软件包，也不推荐你在利用脚本中使用 lambda 语句进行过度简化，我们更推荐你在学习到一定程度后再去根据个人使用习惯进行决定。

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
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# pre-install softwares
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN dpkg --add-architecture i386
RUN apt-get -y update && apt-get upgrade -y
RUN apt-get install -y lib32z1 apt-transport-https \
    python3 python3-pip python3-venv python3-poetry python3-dev python3-setuptools \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libc6-dbg libc6-dbg:i386 libgcc-s1:i386 \
    vim nano netcat-openbsd openssh-server git unzip curl tmux konsole wget sudo \
    bison flex build-essential gcc-multilib \
    qemu-system-x86 qemu-user qemu-user-binfmt \
    gcc gdb gdbserver gdb-multiarch clang lldb make cmake

# enable ssh login
RUN rm -f /etc/service/sshd/down
RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config &&\
    sed -ri 's/#UseDNS\ no/UseDNS\ no/g' /etc/ssh/sshd_config && \
    sed -ri "s/StrictModes yes/StrictModes no/g" /etc/ssh/sshd_config && \
    sed -ri "s/UsePAM yes/UsePAM no/g" /etc/ssh/sshd_config

# enable login with password
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# defaultly we have a user `ubuntu` in the image
RUN echo "ubuntu:123456" | chpasswd && \
    echo "root:123456" | chpasswd

# add sudo
RUN usermod -aG sudo ubuntu

# enable ssh key login
#RUN mkdir /home/ubuntu/.ssh && \
#    echo "Your ssh key" > /home/ubuntu/.ssh/authorized_keys

# keep container running
RUN echo "#!/bin/sh\nservice ssh restart\nsleep infinity" > /root/start.sh
RUN chmod +x /root/start.sh

# create venv for pip
RUN python3 -m venv /pip_venv && \
    chown -R ubuntu:ubuntu /pip_venv && \
    echo "\n\n# pip venv\nsource /pip_venv/bin/activate" >> /home/ubuntu/.bashrc

# pwn-related tools
RUN /pip_venv/bin/pip config set global.index-url http://pypi.tuna.tsinghua.edu.cn/simple && \
    /pip_venv/bin/pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn && \
    /pip_venv/bin/pip install -U pip && \
    /pip_venv/bin/pip install --no-cache-dir \
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
    LibcSearcher \
    poetry

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && chmod +x setup.sh && ./setup.sh

CMD ["/root/start.sh"]

EXPOSE 22

```

在一个空白文件夹中创建一个名为 `Dockerfile` 的文件，并写入上述内容，随后运行如下指令：

```shell
$ docker build -t pwnenv_ubuntu24 .
```

> 注：若因网络原因无法完成镜像构建，可以选择为镜像构建配置代理，这通常只需要在 Dockerfile 当中添加如下内容：
> 
> ```dockerfile
> ENV HTTP_PROXY=http://your-proxy:port
> ENV HTTPS_PROXY=http://your-proxy:port
> ```
> 
> 若你的代理服务器位于本地，也可以选择使用本地网络进行构建：
> 
> ```shell
> docker build --network="host" -t pwnenv_ubuntu24 .
> ```

完成之后你便拥有了一个名为 `pwnenv_ubuntu24` 的带有做题环境的 Ubuntu24 镜像，可以通过 `docker images` 指令查看：

```shell
$ docker images                                              
REPOSITORY                                       TAG       IMAGE ID       CREATED             SIZE
pwnenv_ubuntu24                                  latest    64f87a598f87   2 hours ago    3.6GB
```

你也可以根据需求修改第一行的基镜像，从而创建基于不同 Ubuntu 发行版的 docker 镜像。

### 从 Docker 镜像创建容器

我们只需要运行如下命令便能基于我们刚刚创建的 Docker 镜像创建一个新的容器，方便起见你可以将其创建为一个脚本，各参数说明如下：

- `-d`： 使容器在后台运行
- `-p 25000:22`： 容器的 `22` 端口映射到本地的 `25000` 端口
- `--name=pwn24`： 容器名为 `pwn24`
- `-v ~/Desktop/CTF:/CTF` ： 将本地的 `~/Desktop/CTF` 目录映射到容器中的 `/CTF` 目录，这样我们便能在容器内访问到本地文件，而无需将文件重复拷贝进容器中
- `pwnenv_ubuntu24`：创建容器所使用的镜像

```shell
$ docker run \
	-d \
	-p 25000:22 \
	--name=pwn24 \
	-v ~/Desktop/CTF:/CTF \
	pwnenv_ubuntu24
```

之后通过如下命令便能进入到容器当中：

```shell
$ docker exec -w /CTF \
        -e TERM=xterm-256color \
        -u ubuntu \
        -it pwn24 \
        bash
```

如果你不想直接将本地目录与容器进行共享，而是想要将所需文件拷贝一份到容器中，则可以使用 docker cp 命令：

```shell
$ docker cp 本地源文件路径 容器名:容器内目的路径
$ docker cp 容器名:容器内源文件路径 本地目的路径
```

由于我们为容器设置了 ssh 服务，我们也可以通过 ssh 连接入容器环境，这允许我们使用 vscode 等工具连接到容器内部：

```shell
$ ssh root@localhost -p 25000
```

若是容器环境被我们折腾坏了，则可以直接通过 `docker rm 容器名` 进行删除，之后再重新使用 `docker run` 创建新容器即可，需要注意的是这种方式会将新拷贝进容器的文件给删除（但不会删除挂载目录）。

### 将 Docker 容器接入本地图形界面

pwntools 自带的调试命令 `gdb.attach()` 需要创建新的窗口，而在容器中直接运行会失败，因此我们需要为容器接入本地的图形服务，以达成原生的运行效果（直接弹出一个新的窗口）。

> 若是觉得这种办法比较麻烦，也可以选择使用 tmux 配置多窗口，只需在运行 `gdb.attach()` 命令前运行 `context.terminal = ['tmux', 'splitw', '-h']` 即可。

#### For Wayland

对于 Wayland 环境，在创建容器时我们需要额外附加一些参数：

```shell
$ docker run \
	-d \
	-p "25000:22" \
	--name=pwn24 \
	-v ~/Desktop/CTF:/CTF \
	-e XDG_RUNTIME_DIR=/tmp \
	-e DISPLAY=$DISPLAY \
	-e WAYLAND_DISPLAY=$WAYLAND_DISPLAY \
	-v $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY:/tmp/$WAYLAND_DISPLAY \
	-e QT_QPA_PLATFORM=wayland \
	pwnenv_ubuntu24
```

之后在运行 `gdb.attach()` 之前运行如下 python 语句之一进行配置即可，请根据自己所使用的桌面环境进行选择。

```python
context.terminal = ['konsole', '-e', 'sh', '-c'] # for KDE
context.terminal = ['gnome-terminal', '-e', 'sh', '-c'] # for Gnome
```

#### For X11

对于使用 X11 图形服务的，在创建容器时我们则需要附加如下参数：

```shell
$ docker run \
	-d \
	-p "25000:22" \
	--name=pwn24 \
	-v ~/Desktop/CTF:/CTF \
	-v /tmp/.X11-unix:/tmp/.X11-unix \
	-e DISPLAY=$DISPLAY \
	pwnenv_ubuntu24
```

之后在运行 `gdb.attach()` 之前运行如下 python 语句之一进行配置即可，请根据自己所使用的桌面环境进行选择。

```python
context.terminal = ['konsole', '-e', 'sh', '-c'] # for KDE
context.terminal = ['gnome-terminal', '-e', 'sh', '-c'] # for Gnome
```

> 参考 [Running pwnlib gdb (pwntools) feature inside Docker](https://gist.github.com/turekt/71f6950bc9f048daaeb69479845b672b) 。

## 在本地直接搭建 CTF Pwn 做题环境

除了使用 Docker 之外，你也可以直接在本地搭建做题环境，对于常规的 Linux 用户态 pwn 题目，我们通常仅需要如下软件：

- IDA：用于对题目进行逆向分析。
- Python + pwntools：用于编写漏洞利用脚本。
- gdb + pwndbg/peda：用于调试题目二进制文件。

### 获取 IDA

IDA Pro（interactive Disassembler Professional）是由 Hex-Rays 公司出品的一款交互式反汇编工具，也是软件逆向工程当中最流行的一个静态分析工具。通过 IDA Pro 我们可以很方便地复原二进制程序的运行逻辑，从而进一步审计出其中存在的漏洞。

[IDA Pro](https://hex-rays.com/ida-pro/) 为付费软件，软件本体与不同架构的反编译引擎单独进行收费，你可以根据自己的需求在 Hex-rays 的官网自行购买相应的软件许可证以进行使用。

> 截至 2024 年 4 月， IDA Pro 本体许可证的价格为 1975 USD，任一指令集架构反编译功能的许可证价格为 2765 USD。

此外，Hex-rays 公司还提供基于云引擎的免费逆向工具 [IDA Free](https://hex-rays.com/ida-free/)，目前仅支持 x86 逆向，不过对于绝大部分 CTF 中 Linux 下的用户态 Pwn 题目而言通常已足够使用。

### 安装 Python

绝大部分 Linux 发行版目前已经自带 Python 运行环境，因此通常我们并不需要手动安装 Python。若你的计算机上不存在 Python 运行环境，则可以根据自己所使用的发行版手动使用包管理器进行安装。

需要注意的是，部分 Linux 发行版中 Python 版本默认为 Python2，因此你可能需要手动指定安装 Python3。

### 配置 venv python 环境（可选）

在部分 Linux 发行版上（如 `openSUSE Tumbleweed` ）使用 `pip` 命令时，你可能会遇到如下报错，这是由于发行版自身安全策略限制的缘故：

```
error: externally-managed-environment

× This environment is externally managed
╰─> To install Python packages system-wide, try
    zypper install python311-xyz, where xyz is the package
    you are trying to install.
    
    If you wish to install a non-rpm packaged Python package,
    create a virtual environment using python3.11 -m venv path/to/venv.
    Then use path/to/venv/bin/python and path/to/venv/bin/pip.
    
    If you wish to install a non-rpm packaged Python application,
    it may be easiest to use `pipx install xyz`, which will manage a
    virtual environment for you. Install pipx via `zypper install python311-pipx` .

note: If you believe this is a mistake, please contact your Python installation or OS distribution provider. You can override this, at the risk of breaking your Python installation or OS, by passing --break-system-packages.
```

对于这种情况，我们可以选择使用 [venv](https://docs.python.org/zh-cn/3/library/venv.html#module-venv) 模块创建“虚拟环境”。虚拟环境在默认情况下与其他虚拟环境中的软件以及操作系统中安装的 Python 解释器和库保持隔离，这确保了软件包安装的安全性，且使得我们能够简单地删除并从头开始重建环境。

我们可以通过如下命令创建一个新的虚拟环境（若路径不存在，则将被创建）：

```shell
python3 -m venv 自定义的venv文件夹路径
```

完成创建之后，我们便可以通过 `source` 命令进入到 venv 中，请根据你所使用的 shell 进行选择其中之一：

```shell
source 自定义的venv文件夹路径/bin/activate         # for bash
source 自定义的venv文件夹路径/bin/activate.fish    # for fish
source 自定义的venv文件夹路径/bin/activate.csh     # for csh/tcsh
```

> 你也可以选择将这条命令加入到 `~/.bashrc` 文件中，从而在打开 shell 时默认执行。

由于虚拟环境具有轻量、安全、可重构建的特性，因此即便是在你的计算机上并不存在安全策略限制，我们也更推荐你为 CTF/Pwn 创建一个单独的 Python 虚拟环境。

### 安装 pwntools

[pwntools](https://docs.pwntools.com/en/stable/) 是一个强大的 Python 软件包，其为我们提供了基本的 pwn 脚本编写环境，以及各类方便的利用工具，在安装好 Python 以及 pip 之后你可以很方便地使用如下指令进行安装：

```shell
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

之后在 Python 中便能很方便地通过 `from pwn import *` 指令使用该包中的各类工具，你也可以使用 `from pwn import 名字` 来仅导入所需的特定工具，或是使用 `import pwn` 导入包名后通过 `pwn.名字` 来使用对应的工具。

### 安装 gdb

GNU Debugger（GDB）是 GNU 项目开发的软件调试器，使用 gdb 我们可以很方便地对二进制程序进行动态调试。

gdb 在绝大部分 Linux 发行版上都已默认安装，你可以在 shell 中输入 `gdb` 命令进行确认（输入 `q` 退出）:

```shell
$ gdb
GNU gdb (GDB; SUSE Linux Enterprise 15) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-suse-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://bugs.opensuse.org/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
(gdb) 
```

若你的计算机尚未安装 gdb，则可以使用如下命令进行安装，请自行分辨你所使用的发行版。

Debian / Ubuntu:

```shell
sudo apt-get install -y gdb
```

openSUSE Leap / Tumbleweed / SLE:

```shell
sudo zypper install gdb
```

Arch Linux / Manjaro / EndeavourOS:

```shell
sudo yay -S gdb # 若未配置 AUR，你也可以使用 pacman -S gdb 进行安装
```

Fedora / CentOS / RHEL:

```shell
sudo yum install gdb # 事实上，yum 被软链接到 dnf
```

### 安装 pwndbg

[pwndbg](https://github.com/pwndbg/pwndbg) (/paʊnˈdiˌbʌɡ/) 是一个强大的 GDB 插件，通过该插件我们可以在调试时很方便地查看运行环境以及获取堆内存布局等信息。

pwndbg 项目自带了安装脚本，因此我们可以很方便地从源码进行安装：

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

对于使用 nix 包管理器的发行版（如 NixOS），你可以通过如下命令进行安装：

```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```

### 安装 peda

> 注：peda 和 pwndbg 你只需要安装其中之一，由于功能重复，且为了避免插件冲突，我们并不推荐你同时安装这两个插件。

[peda](https://github.com/longld/peda) 是一个强大的 GDB 插件，通过该插件我们可以在调试时很方便地查看运行环境以及获取堆内存布局等信息。

peda 插件无需过多配置，我们只需要将源码下载到本地后更新 gdb 配置即可。

```shell
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"
```
