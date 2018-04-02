
# CTF Wiki

[![Build Status](https://travis-ci.org/ctf-wiki/ctf-wiki.svg?branch=master)](https://travis-ci.org/ctf-wiki/ctf-wiki)
[![Requirements Status](https://requires.io/github/ctf-wiki/ctf-wiki/requirements.svg?branch=master)](https://requires.io/github/ctf-wiki/ctf-wiki/requirements/?branch=master)
[![BearyChat](https://img.shields.io/badge/bearychat-join_chat-green.svg)](https://ctf-wiki.bearychat.com)

欢迎来到 **CTF Wiki**。

**CTF**（Capture The Flag，夺旗赛）起源于 1996 年 **DEFCON** 全球黑客大会，是网络安全爱好者之间的竞技游戏。

**CTF** 竞赛涉及众多领域，内容繁杂。目前，安全技术发展地越来越快，**CTF** 题目的难度越来越高，初学者需要面对的门槛因此也越来越高。而网上资料大都零散琐碎，初学者往往并不知道该如何系统性地学习 **CTF** 相关领域知识，常常需要花费大量时间，苦不堪言。

为了使得热爱 **CTF** 的小伙伴们更好地入门 **CTF**，2016 年 10 月份，**CTF Wiki** 在 Github 有了第一次 commit。随着内容不断完善，**CTF Wiki** 受到了越来越多安全爱好者的喜爱，也渐渐有素未谋面的小伙伴们参与其中。 

围绕 **CTF** 近几年赛题，作为一个自由的站点，**CTF Wiki** 对 **CTF** 中的各个方向知识和技术进行介绍，以便于初学者更好地学习 **CTF** 相关的知识。

目前，**CTF Wiki** 主要包含 **CTF** 各大方向的基础知识。

当然，**CTF Wiki** 基于 **CTF**，却不会局限于 **CTF**，在未来，**CTF Wiki** 会更专注于完善于以下内容：

- CTF 竞赛中的进阶知识
- CTF 竞赛中的优质题目
- 安全研究中的工具介绍
- 更多地与安全实战结合

与此同时，CTF Wiki 源于社区，提倡知识自由，在未来也绝不会商业化，将始终保持独立自由的性质。

## How to build？

本文档目前采用 [mkdocs](https://github.com/mkdocs/mkdocs) 部署在 [https://ctf-wiki.github.io/ctf-wiki/](https://ctf-wiki.github.io/ctf-wiki/)。当然也可以部署在本地，具体方式如下：

### 安装依赖

```shell
# mkdocs
pip install mkdocs
# extensions
pip install pymdown-extensions
# theme
pip install mkdocs-material
```

### 本地部署

```shell
# generate static file in site/
mkdocs build
# deploy at http://127.0.0.1:8000
mkdocs serve
```

**mkdocs 本地部署的网站是动态更新的，即当你修改并保存 md 文件后，刷新页面就能随之动态更新。**

## How to practice？

Wiki 中的所有题目在对应分类的 example 文件夹下，如 `Pwn` 中栈溢出的题目都在这个目录下 https://github.com/ctf-wiki/ctf-wiki/tree/master/docs/pwn/stackoverflow/example 。

## 我能收获什么？

* 一个不一样的思考方式以及一颗乐于解决问题的心
* 锻炼你的快速学习能力，不断学习新事物
* 一些有趣的安全技术与相应的挑战
* 一段充实奋斗的时光

在阅读 Wiki 之前，我们希望能给予你几点建议：

* 至少掌握一门编程语言，比如 Python
* 阅读短文 [提问的智慧](http://www.jianshu.com/p/60dd8e9cd12f)
* 善用 Google 搜索能帮助你更好地提升自己
* 动手实践比什么都要管用
* 保持对技术的好奇与渴望并坚持下去

> 世界很大，互联网让世界变小，真的黑客们应该去思考并创造，无论当下是在破坏还是在创造，记住，未来，那条主线是创造的就对了。 ——by 余弦

安全圈很小，安全的海洋很深。安全之路的探险，不如就从 **CTF Wiki** 开始！

## 想要帮助 Wiki 更加完善？

我们非常欢迎你为 Wiki 编写内容，将自己的所学所得与大家分享，具体的贡献方式请参见 [CONTRIBUTING](.github/CONTRIBUTING.md)。 

**在你决定要贡献内容之前，请你务必看完这些内容**。我们期待着你的加入。
