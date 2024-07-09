## 簡介

現有的 CTF Pwn 題主要以 Linux 下的用戶態 Pwn 爲主，因此我們通常需要在本地擁有一個 Linux 運行環境，這通常可以通過安裝 Linux 虛擬機來完成，此外你也可以在物理機上安裝 Linux 操作系統。

絕大多數 Linux Pwn 題目的遠程環境以 [Ubuntu](https://ubuntu.com/) 爲主，因此爲了方便在本地調試題目，你通常需要搭建一個與題目版本相匹配的 Ubuntu 運行環境，不過 _這並不意味着你必須要使用 Ubuntu 作爲你的主力操作系統_ 。你仍舊可以選擇繼續使用你喜歡的其他 Linux 發行版（如，Arch、Debian、openSUSE、Fedora、NixOS 等），並使用 Docker 來搭建相應的 Ubuntu 做題環境。

傳統 CTF Pwn 題目通常僅需要以下工具便能完成解題：

- IDA：用於對題目進行逆向分析。
- Python + pwntools：用於編寫漏洞利用腳本。
- gdb + pwndbg/peda：用於調試題目二進制文件。

需要注意的是，在初學階段我們並不推薦任何基於 pwntools 進行過度二次包裝的軟件包，也不推薦你在利用腳本中使用 lambda 語句進行過度簡化，我們更推薦你在學習到一定程度後再去根據個人使用習慣進行決定。

此外，部分題目可能需要一些額外的環境（例如 kernel pwn 需要 qemu），我們將在後續介紹到對應題目時單獨進行介紹。

## 使用 Docker 搭建 CTF Pwn 做題環境（推薦）

爲了保證利用腳本能夠正常打通，我們通常需要在本地準備相同的運行環境，並在進行遠程利用之前先在本地進行測試，但由於 CTF 題目遠程環境衆多，若是爲每個不同的環境都單獨準備一個 Ubuntu 虛擬機，則不僅要在每個虛擬機上都完整搭建一遍調試環境，且會佔用大量磁盤空間，同時也無法保證本地環境小版本和遠程環境一定相同——除非每個小版本都單獨創建一個虛擬機並永不升級，這種解決方案並不優雅。

通過 `LD_PRELOAD` 參數在程序執行前 預先加載 libc 在某些程度上是一個可行的解決方案，在 libc 大版本相同的情況下載入不同的小版本通常並不會出現問題，但是由於不同系統環境中 ld 版本不同的緣故，對於跨 ld 版本加載不同版本的 libc 則可能出現 segmentation fault，從而導致無法正常運行與調試題目。

雖然 Linux 的用戶環境並不似 Windows 那樣有着強壯的二進制前向兼容性，但是用戶環境依託於內核環境、依託於內核向用戶態暴露的接口——系統調用，而這並不是會輕易發生變動以及兼容性破壞的一個東西，由此，通過重新開闢一個對應的新的用戶環境的方式—— 即形如 Docker 這樣的操作系統層上的虛擬化方案，我們便能非常簡單地搭建不同的 Pwn 題所對應的原始環境。

### Docker 環境搭建

Docker 的安裝請大家根據自己所使用的 Linux 發行版自行參照 [Docker 官網](https://docs.docker.com/engine/install/) 或是發行版自己的 Wiki 進行配置，這裏不再贅敘。

### 創建 Docker 鏡像

我們以以下 Dockerfile 所創建的鏡像作爲模板，大家可以根據自己的需求自行修改：

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
    echo "root:123456" | chpasswd

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

在一個空白文件夾中創建一個名爲 `Dockerfile` 的文件，並寫入上述內容，隨後運行如下指令：

```shell
$ docker build -t pwnenv_ubuntu22 .
```

完成之後你便擁有了一個名爲 `pwnenv_ubuntu22` 的帶有做題環境的 Ubuntu22 鏡像，可以通過 `docker images` 指令查看：

```shell
$ docker images                                              
REPOSITORY               TAG         IMAGE ID       CREATED          SIZE                                     
pwnenv_ubuntu22          latest      c129ca086a72   15 seconds ago   2.81GB
```

你也可以根據需求修改第一行的基鏡像，從而創建基於不同 Ubuntu 發行版的 docker 鏡像。

### 從 Docker 鏡像創建容器

我們只需要運行如下命令便能基於我們剛剛創建的 Docker 鏡像創建一個新的容器，方便起見你可以將其創建爲一個腳本，各參數說明如下：

- `-d`： 使容器在後臺運行
- `-p 25000:22`： 容器的 `22` 端口映射到本地的 `25000` 端口
- `--name=pwn22`： 容器名爲 `pwn22`
- `-v ~/Desktop/CTF:/CTF` ： 將本地的 `~/Desktop/CTF` 目錄映射到容器中的 `/CTF` 目錄，這樣我們便能在容器內訪問到本地文件，而無需將文件重複拷貝進容器中
- `pwnenv_ubuntu22`：創建容器所使用的鏡像

```shell
$ docker run \
	-d \
	-p 25000:22 \
	--name=pwn22 \
	-v ~/Desktop/CTF:/CTF \
	pwnenv_ubuntu22
```

之後通過如下命令便能進入到容器當中：

```shell
$ docker exec -w /CTF -e TERM=xterm-256color -it pwn22 bash
```

如果你不想將本地目錄與容器進行共享，而是想要將所需文件拷貝一份到容器中，則可以使用 docker cp 命令：

```shell
$ docker cp 本地源文件路徑 容器名:容器內目的路徑
$ docker cp 容器名:容器內源文件路徑 本地目的路徑
```

由於我們爲容器設置了 ssh 服務，我們也可以通過 ssh 連接入容器環境，這允許我們使用 vscode 等工具連接到容器內部：

```shell
$ ssh root@localhost -p 25000
```

若是容器環境被我們折騰壞了，則可以直接通過 `docker rm 容器名` 進行刪除，之後再重新使用 `docker run` 創建新容器即可，需要注意的是這種方式會將新拷貝進容器的文件給刪除（但不會刪除掛載目錄）。

### 將 Docker 容器接入本地圖形界面

pwntools 自帶的調試命令 `gdb.attach()` 需要創建新的窗口，而在容器中直接運行會失敗，因此我們需要爲容器接入本地的圖形服務，以達成原生的運行效果（直接彈出一個新的窗口）。

> 若是覺得這種辦法比較麻煩，也可以選擇使用 tmux 配置多窗口，只需在運行 `gdb.attach()` 命令前運行 `context.terminal = ['tmux', 'splitw', '-h']` 即可。

#### For Wayland

對於 Wayland 環境，在創建容器時我們需要額外附加一些參數：

```shell
$ docker run \
	-d \
	-p "25000:22" \
	--name=pwn22 \
	-v ~/Desktop/CTF:/CTF \
	-e XDG_RUNTIME_DIR=/tmp \
	-e DISPLAY=$DISPLAY \
	-e WAYLAND_DISPLAY=$WAYLAND_DISPLAY \
	-v $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY:/tmp/$WAYLAND_DISPLAY \
	-e QT_QPA_PLATFORM=wayland \
	pwnenv_ubuntu22
```

之後在運行 `gdb.attach()` 之前運行如下 python 語句之一進行配置即可，請根據自己所使用的桌面環境進行選擇。

```python
context.terminal = ['konsole', '-e', 'sh', '-c'] # for KDE
context.terminal = ['gnome-terminal', '-e', 'sh', '-c'] # for Gnome
```

#### For X11

對於使用 X11 圖形服務的，在創建容器時我們則需要附加如下參數：

```shell
$ docker run \
	-d \
	-p "25000:22" \
	--name=pwn22 \
	-v ~/Desktop/CTF:/CTF \
	-v /tmp/.X11-unix:/tmp/.X11-unix \
	-e DISPLAY=$DISPLAY \
	pwnenv_ubuntu22
```

之後在運行 `gdb.attach()` 之前運行如下 python 語句之一進行配置即可，請根據自己所使用的桌面環境進行選擇。

```python
context.terminal = ['konsole', '-e', 'sh', '-c'] # for KDE
context.terminal = ['gnome-terminal', '-e', 'sh', '-c'] # for Gnome
```

> 參考 [Running pwnlib gdb (pwntools) feature inside Docker](https://gist.github.com/turekt/71f6950bc9f048daaeb69479845b672b) 。

## 在本地直接搭建 CTF Pwn 做題環境

除了使用 Docker 之外，你也可以直接在本地搭建做題環境，對於常規的 Linux 用戶態 pwn 題目，我們通常僅需要如下軟件：

- IDA：用於對題目進行逆向分析。
- Python + pwntools：用於編寫漏洞利用腳本。
- gdb + pwndbg/peda：用於調試題目二進制文件。

### 獲取 IDA

IDA Pro（interactive Disassembler Professional）是由 Hex-Rays 公司出品的一款交互式反彙編工具，也是軟件逆向工程當中最流行的一個靜態分析工具。通過 IDA Pro 我們可以很方便地復原二進製程序的運行邏輯，從而進一步審計出其中存在的漏洞。

[IDA Pro](https://hex-rays.com/ida-pro/) 爲付費軟件，軟件本體與不同架構的反編譯引擎單獨進行收費，你可以根據自己的需求在 Hex-rays 的官網自行購買相應的軟件許可證以進行使用。

> 截至 2024 年 4 月， IDA Pro 本體許可證的價格爲 1975 USD，任一指令集架構反編譯功能的許可證價格爲 2765 USD。

此外，Hex-rays 公司還提供基於雲引擎的免費逆向工具 [IDA Free](https://hex-rays.com/ida-free/)，目前僅支持 x86 逆向，不過對於絕大部分 CTF 中 Linux 下的用戶態 Pwn 題目而言通常已足夠使用。

### 安裝 Python

絕大部分 Linux 發行版目前已經自帶 Python 運行環境，因此通常我們並不需要手動安裝 Python。。若你的計算機上不存在 Python 運行環境，則可以根據自己所使用的發行版手動使用包管理器進行安裝。

需要注意的是，部分 Linux 發行版中 Python 版本默認爲 Python2，因此你可能需要手動指定安裝 Python3。

### 配置 venv python 環境（可選）

在部分 Linux 發行版上（如 `openSUSE Tumbleweed` ）使用 `pip` 命令時，你可能會遇到如下報錯，這是由於發行版自身安全策略限制的緣故：

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

對於這種情況，我們可以選擇使用 [venv](https://docs.python.org/zh-cn/3/library/venv.html#module-venv) 模塊創建“虛擬環境”。虛擬環境在默認情況下與其他虛擬環境中的軟件以及操作系統中安裝的 Python 解釋器和庫保持隔離，這確保了軟件包安裝的安全性，且使得我們能夠簡單地刪除並從頭開始重建環境。

我們可以通過如下命令創建一個新的虛擬環境（若路徑不存在，則將被創建）：

```shell
python3 -m venv 自定義的venv文件夾路徑
```

完成創建之後，我們便可以通過 `source` 命令進入到 venv 中，請根據你所使用的 shell 進行選擇其中之一：

```shell
source 自定義的venv文件夾路徑/bin/activate         # for bash
source 自定義的venv文件夾路徑/bin/activate.fish    # for fish
source 自定義的venv文件夾路徑/bin/activate.csh     # for csh/tcsh
```

> 你也可以選擇將這條命令加入到 `~/.bashrc` 文件中，從而在打開 shell 時默認執行。

由於虛擬環境具有輕量、安全、可重構建的特性，因此即便是在你的計算機上並不存在安全策略限制，我們也更推薦你爲 CTF/Pwn 創建一個單獨的 Python 虛擬環境。

### 安裝 pwntools

[pwntools](https://docs.pwntools.com/en/stable/) 是一個強大的 Python 軟件包，其爲我們提供了基本的 pwn 腳本編寫環境，以及各類方便的利用工具，在安裝好 Python 以及 pip 之後你可以很方便地使用如下指令進行安裝：

```shell
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

之後在 Python 中便能很方便地通過 `from pwn import *` 指令使用該包中的各類工具，你也可以使用 `from pwn import 名字` 來僅導入所需的特定工具，或是使用 `import pwn` 導入包名後通過 `pwn.名字` 來使用對應的工具。

### 安裝 gdb

GNU Debugger（GDB）是 GNU 項目開發的軟件調試器，使用 gdb 我們可以很方便地對二進製程序進行動態調試。

gdb 在絕大部分 Linux 發行版上都已默認安裝，你可以在 shell 中輸入 `gdb` 命令進行確認（輸入 `q` 退出）:

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

若你的計算機尚未安裝 gdb，則可以使用如下命令進行安裝，請自行分辨你所使用的發行版。

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
sudo yay -S gdb # 若未配置 AUR，你也可以使用 pacman -S gdb 進行安裝
```

Fedora / CentOS / RHEL:

```shell
sudo yum install gdb # 事實上，yum 被軟鏈接到 dnf
```

### 安裝 pwndbg

[pwndbg](https://github.com/pwndbg/pwndbg) (/paʊnˈdiˌbʌɡ/) 是一個強大的 GDB 插件，通過該插件我們可以在調試時很方便地查看運行環境以及獲取堆內存佈局等信息。

pwndbg 項目自帶了安裝腳本，因此我們可以很方便地從源碼進行安裝：

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

對於使用 nix 包管理器的發行版（如 NixOS），你可以通過如下命令進行安裝：

```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```

### 安裝 peda

> 注：peda 和 pwndbg 你只需要安裝其中之一，由於功能重複，且爲了避免插件衝突，我們並不推薦你同時安裝這兩個插件。

[peda](https://github.com/longld/peda) 是一個強大的 GDB 插件，通過該插件我們可以在調試時很方便地查看運行環境以及獲取堆內存佈局等信息。

peda 插件無需過多配置，我們只需要將源碼下載到本地後更新 gdb 配置即可。

```shell
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"
```
