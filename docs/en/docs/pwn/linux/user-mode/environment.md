## Introduction

Currently most of Pwn challenges in CTF are mainly about the binary exploitation under user mode in Linux, which means that usually we'll need to deploy a Linux operating environment locally for solving that. Generally it can be done by creating a Linux virtual machine as the challenge-solving environment, or just installing a Linux operating environment directly on your physical machine.

[Ubuntu](https://ubuntu.com/) is the Linux distro that are mostly chosen as Pwn challenges' operating environment in CTF, therefore you might need to deploy a Ubuntu operating environment locally which is of the same version to the challenge's remote environment, so that you can have the same executing environment compared to that(including Libc binaries, etc.) for you to run  the target and exploit it correctly on your own PC. However, _it doesn't mean that you have to choose Ubuntu as youor primary Linux distro_, you can still choose to firstly use your favourite Linux distros as your primary OS(e.g., Gentoo Linux, openSUSE, Debian, Fedora, Arch Linux, NixOS, etc.), and deploy Pwn challenges' environments on your PC with tools like Docker and Podman which adopt container techniques to create dedicated environments conveniently.

For legacy Pwn challenges in CTF, the following tools are usually the core ones for solving challenges:

- IDA: A reverse engineering tool for analyzing binaries provided by challenges.
- Python + pwntools: Core utilities for crafting scripts for binary exploitation.
- gdb + pwndbg or peda: Debugger with enhanced plugins to run and debug the target.

Note that at the earliest stage of learning Pwn, we do not recommend you to use software packages that have been over-wrapped base on pwntools to craft your exploitation script, while over-using lambda statements to simplify the exploitation script is also not recommended, as which might have some potential negative effects on your thoughts on some deep aspects of the whole computer science. What we recommend to do is that you should start to use such custom configuration after you have enough knowledge and skills on computer science and Pwn.

## Deploy local environment for solving Pwn challenges in CTF

To make sure that our exploitation script can make attacks on remote successfully, usually we need to deploy a same operating environment locally, and have the local attacking test successfully on local before exploiting on remote. However, as various CTF challenges will always have different environments, it will waste lots of your storage to hold many of different and entire OS environments.

As what we usually need to only the Libc environment besides the target itself, it might be a solution to try to load different `libc.so.6` executables with arguments like `LD_PRELOAD` while running the target programs of Pwn challenges. However such approaches are not always avaliable due to complex executation-dependencies chains including `ld` and some other things, which will result in `segmentation falut` while doing the crossing-version Libc loading and executing.

Though user-mode executables in Linux do not have a strong compatibility compared to those under Windows, the whole executing environment in fact relies on the system APIs known as `system call` provided by the OS kernel, which are generally not being changed to result in the compatibility to be broken. Thus light weight virtualization solutions like Docker can easily help us to build corresponding environments for running and debugging Pwn challenges.

### Install Docker

Please refer to Docker's [official website](https://docs.docker.com/engine/install/) to see how to install docker on your machine, or you can also do that refer to your distro's official Wiki (e.g., like [Gentoo Wiki - Docker](https://wiki.gentoo.org/wiki/Docker)). We do not keep a copy here due to Linux distros vary.

### Build a Docker image for Pwn

Here's a Docker template including usual tools for solving Pwn challenegs. You can also modify it freely according to your needs:

```dockerfile
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# pre-install softwares
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
RUN /pip_venv/bin/pip install -U pip && \
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

You shall create a file named `Dockerfile` in an empty directory with contents above, and then run the following commands in terminal:

```shell
$ docker build -t pwnenv_ubuntu24 .
```

> If you could not build the docker image due to some network issues, using proxy may be a solution. All you need to do is to add following configurations in your Dockerfile:
> 
> ```dockerfile
> ENV HTTP_PROXY=http://your-proxy:port
> ENV HTTPS_PROXY=http://your-proxy:port
> ```
> 
> If your proxy server is on local, you can also choose to build the docker image with local network by following command:
> 
> ```shell
> docker build --network="host" -t pwnenv_ubuntu24 .
> ```

After the building has been done, you will get a Ubuntu24 image called `pwnenv_ubuntu24` locally, which can be find with `docker images` command:

```shell
$ docker images                                              
REPOSITORY                                       TAG       IMAGE ID       CREATED             SIZE
pwnenv_ubuntu24                                  latest    64f87a598f87   2 hours ago    3.6GB
```

Now you can change the base image defined at the first line in Dockerfilw to build docker images for different Ubuntu distros.

### Create container from Docker image

We can run the following command to create a container from the Docker image we've just built:

```shell
$ docker run \
	-d \
	-p 25000:22 \
	--name=pwn24 \
	-v ~/Desktop/CTF:/CTF \
	pwnenv_ubuntu24
```

Arguments of this command are:

- `-d`： Running the container in the background.
- `-p 25000:22`： map the port `22` of the container to the local port `25000`
- `--name=pwn24`： name of the container is assigned as `pwn24`
- `-v ~/Desktop/CTF:/CTF` ： map the local directory `~/Desktop/CTF` into the directory `/CTF` inside the container, so that we can access local files directly inside the container
- `pwnenv_ubuntu24`：Docker image used to create the container

Then we can execute into the container with following command:

```shell
$ docker exec -w /CTF \
        -e TERM=xterm-256color \
        -u ubuntu \
        -it pwn24 \
        bash
```

If you do not want to share your local directory with the docker container, you can also use following commands to do the copy work between the container and the local:

```shell
$ docker cp local_source_path container_name:target_path_in_container
$ docker cp container_name:source_path_in_container local_target_path
```

As we have set up the ssh service for the container, we can also use ssh to connect, which allow us to use tools like `vscode` to manipulating files in container conveniently: 

```shell
$ ssh root@localhost -p 25000
```

If the environment of the container has been made to be broken unintentionally, we can just do the `docker remove container_name` to remove it, and just create a new one again with `docker run`. Note that this method will let us lose all the files we've copied into the container(except for attached local directories).

### Connect the Docker container to local graphic system

As debug functions `gdb.attach()` from `pwntools` will need to create new window, running this inside the docker container directly will fail. Therefore we need to connect the container to local graphic system, so that we can run this function correctly.

> You can also choose to configure the multi-windows system for the container with `tmux`, in which all we need to do is to run the `tmux` and run `context.terminal = ['tmux', 'splitw', '-h']` before calling the `gdb.attach()`.

#### For Wayland

For DE under Wayland, we need to add the following additional arguments while creating the container:

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

Then all we need to do is to configure the `context.terminal` before calling `gdb.attach()` as follow, note that you should choose the right statement according to your desktop environment:

```python
context.terminal = ['konsole', '-e', 'sh', '-c'] # for KDE
context.terminal = ['gnome-terminal', '-e', 'sh', '-c'] # for Gnome
```

#### For X11

For DE under X11, we need to add the following additional arguments while creating the container:

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

Then all we need to do is to configure the `context.terminal` before calling `gdb.attach()` as follow, note that you should choose the right statement according to your desktop environment:

```python
context.terminal = ['konsole', '-e', 'sh', '-c'] # for KDE
context.terminal = ['gnome-terminal', '-e', 'sh', '-c'] # for Gnome
```

> Refer to [Running pwnlib gdb (pwntools) feature inside Docker](https://gist.github.com/turekt/71f6950bc9f048daaeb69479845b672b).

## Build the CTF Pwn environment locally

Besides using the Docker, you can also directly build an environment for solving Pwn challenges locally. For legacy Pwn challenges in CTF, the following tools are usually the core ones for solving challenges:

- IDA: A reverse engineering tool for analyzing binaries provided by challenges.
- Python + pwntools: Core utilities for crafting scripts for binary exploitation.
- gdb + pwndbg or peda: Debugger with enhanced plugins to run and debug the target.

### Get the IDA

IDA Pro (interactive Disassembler Professional) is a reverse-engineering tool developed by Hex-Rays, which is also the most popular tool for static analyzation in reverse engineering. With IDA Pro, we can easily recover the original code logic from the target binary, so that we can find vulnerabilities more conveniently.

Note that [IDA Pro](https://hex-rays.com/ida-pro/) is not a free software, and the software itself and discompiler plugins for different ISA are charged dedicately.

> Until 2024.04, the price of license for IDA is 1975USD, the price of discompiler plugin for a specific ISA is 2765USD.

What's more is that, Hex-rays also provides a free reverse engineering tool called [IDA Free](https://hex-rays.com/ida-free/), which is based on cloud and only supports discompiler on X86. It might be enough to use for solving most of Linux Pwn challenges.

### Install Python

Most of Linux distros are installed with Python by default, therefore generally we do not need to install it manually. If you do not have a Python environment in the Linux environment on your computer, you can also choose to install it with your distro's package manager.

Note that the default Python on some Linux distros might be Python2, and you might need to install the Python3 manually.

### Confiogure venv

Sometimes you may encounter error messages like this while running `pip` command, which is due to the security restriction configuration of the Linux distro you use: 

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

To handle this problem, we can choose to use the [venv](https://docs.python.org/zh-cn/3/library/venv.html#module-venv) module to create a virtual environment, which ensures the security of the system, and using such strategy also make us easy to rebuild the whole environment while in need. 

To create a `venv`, we just need to run the following command(if the directory dose not existed, it'll be created):

```shell
python3 -m venv your_venv_direcory_path
```

Then we can easily get into the `vent` environment with `source` command:

```shell
source your_venv_direcory_path/bin/activate         # for bash
source your_venv_direcory_path/bin/activate.fish    # for fish
source your_venv_direcory_path/bin/activate.csh     # for csh/tcsh
```

> You can also add this into your `~/.bashrc` file to run it by default.

As virtual environment provides us with features including lightweight, security, and rebuildability, we recommand you to create a Python venv for CTF/Pwn even if there's no security restriction for your `pip`.

### Install pwntools

[pwntools](https://docs.pwntools.com/en/stable/) is a powerful Python package for crafting exploitation script. You can install it with following commands:

```shell
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

### Install gdb

GNU Debugger (GDB) is a program debugger developed by GNU, we can use it to debug the binary executable conveniently.

GDB is installed defaultlly on most of Linux distro, you can execute `gdb` command in your terminal to check for that (enter `q` to exit):

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

If you do not have gdb on your computer, you can install it with package manager for your Linux distro. Following is the command you may need to run. Note that we only list some of the most common Linux distros here:

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
sudo yay -S gdb # `pacman -S gdb` also works if you do not use the AUR
```

Fedora / CentOS / RHEL:

```shell
sudo yum install gdb # yum is linked to dnf in fact
```

### Install pwndbg

[pwndbg](https://github.com/pwndbg/pwndbg) (/paʊnˈdiˌbʌɡ/) is a powerful GDB plugin to enhance the debugging functionality of GDB. With this plugin we can get more detailed information like the layout of heap memory easily while debugging.

pwndbg itself has an installing script, so all we need to do is clone the project and run it:

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

For Linux distros using `nix` as their package manager (e.g. NixOS), you can install it with following commands:

```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```

### Install peda

> Note: Only one of pwndbg and peda is needed to be installed. To avoid the potential conflicts, we do NOT recommand you to install both of them together.

[peda](https://github.com/longld/peda) is a powerful GDB plugin to enhance the debugging functionality of GDB. With this plugin we can get more detailed information like the layout of heap memory easily while debugging.

To install the `peda`, all we need to do is clone the source code to local and update the GDB's configuration with following commands:

```shell
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"
```
