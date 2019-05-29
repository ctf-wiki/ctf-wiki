
# CTF Wiki

[![Build Status](https://travis-ci.org/ctf-wiki/ctf-wiki.svg?branch=master)](https://travis-ci.org/ctf-wiki/ctf-wiki)
[![Requirements Status](https://requires.io/github/ctf-wiki/ctf-wiki/requirements.svg?branch=master)](https://requires.io/github/ctf-wiki/ctf-wiki/requirements/?branch=master)
[![Slack](https://img.shields.io/badge/slack-join%20chat-brightgreen.svg)](https://join.slack.com/t/ctf-wiki/shared_invite/enQtNTkwNDg5NDUzNzAzLWExOTRhZTE0ZTMzYjVlNDk5OGI3ZDA1NmQyZjE4NWRlMGU3NjEwM2Y2ZTliMTg4Njg1MjliNWRhNTk2ZmY0NmI)

[中文](./README-zh_CN.md)  [English](./README.md)

欢迎来到 **CTF Wiki**。

**CTF**（Capture The Flag，夺旗赛）起源于 1996 年 **DEFCON** 全球黑客大会，是网络安全爱好者之间的竞技游戏。

**CTF** 竞赛涉及众多领域，内容繁杂。与此同时，安全技术的发展速度越来越快，**CTF** 题目的难度越来越高，初学者面对的门槛越来越高。而网上资料大都零散琐碎，初学者往往并不知道该如何系统性地学习 **CTF** 相关领域知识，常需要花费大量时间，苦不堪言。

为了使得热爱 **CTF** 的小伙伴们更好地入门 **CTF**，2016 年 10 月份，**CTF Wiki** 在 Github 有了第一次 commit。随着内容不断完善，**CTF Wiki** 受到了越来越多安全爱好者的喜爱，也渐渐有素未谋面的小伙伴们参与其中。 

作为一个自由的站点，围绕 **CTF** 近几年赛题，**CTF Wiki** 对 **CTF** 中的各个方向的知识和技术进行介绍，以便于初学者更好地学习 **CTF** 相关的知识。

目前，**CTF Wiki** 主要包含 **CTF** 各大方向的基础知识，正在着力完善以下内容

- CTF 竞赛中的进阶知识
- CTF 竞赛中的优质题目

关于上述部分待完善内容，请参见 CTF Wiki 的 [Projects](https://github.com/ctf-wiki/ctf-wiki/projects)，详细列举了正在做的事情以及待做事项。

虽然 **CTF Wiki** 基于 **CTF**，却不会局限于 **CTF**，在未来，**CTF Wiki** 将会

- 介绍安全研究中的工具
- 更多地与安全实战结合

此外，鉴于以下两点

- 技术应该以开放的方式分享。
- 安全攻防技术在快速迭代更新，在面对新的防御技术时，旧的攻击技术随时可能失效。

因此，**CTF Wiki** 永远不会出版书籍。

最后，**CTF Wiki** 源于社区，作为**独立的组织**，提倡**知识自由**，在未来也绝不会商业化，将始终保持**独立自由**的性质。

## How to build？

本文档目前采用 [mkdocs](https://github.com/mkdocs/mkdocs) 部署在 [https://ctf-wiki.github.io/ctf-wiki/](https://ctf-wiki.github.io/ctf-wiki/)。

本项目可以直接部署在本地，具体方式如下：

```shell
# 1. clone
git clone https://github.com/ctf-wiki/ctf-wiki.git
# 2. requirements
pip install -r requirements.txt
# generate static file in site/
mkdocs build
# deploy at http://127.0.0.1:8000
mkdocs serve
```

**mkdocs 本地部署的网站是动态更新的，即当你修改并保存 md 文件后，刷新页面就能随之动态更新。**


如果你只是想本地浏览，并不想修改文档？试试 Docker 把！
```
docker run -d --name=ctf-wiki -p 4100:80 ctfwiki/ctf-wiki
```
随后即可在浏览器中访问 [http://localhost:4100/](http://localhost:4100/) 阅读 CTF Wiki 。

## How to practice？

首先，通过在线阅读来学习一些基本的安全知识。

其次，CTF Wiki 还有两个姊妹项目

- CTF Wiki 中涉及的题目在 [ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) 仓库中，请根据对应的分类自行寻找。
    - 注：目前仍有部分题目在该仓库下，正在迁移中。。。（misc，web）
- CTF Wiki 中涉及的工具会不断补充到 [ctf-tools](https://github.com/ctf-wiki/ctf-tools) 仓库中。

## How to make CTF Wiki Better？

我们非常欢迎你为 Wiki 编写内容，将自己的所学所得与大家分享。我们期待着你的加入！

**在你决定要贡献内容之前，请你务必看完  [CONTRIBUTING](https://github.com/ctf-wiki/ctf-wiki/wiki/%E4%B8%AD%E6%96%87%E8%B4%A1%E7%8C%AE%E6%8C%87%E5%8D%97)**。其中包含了详细的贡献方式。 

非常感谢一起完善 CTF Wiki 的小伙伴们

<a href="https://github.com/ctf-wiki/ctf-wiki/graphs/contributors"><img src="https://opencollective.com/ctf-wiki/contributors.svg?width=890&button=false" /></a>

## What can you get?

- 快速学习新事物的能力
- 不一样的思考方式
- 乐于解决问题的心
- 有趣的安全技术
- 充实奋斗的时光

在阅读 Wiki 之前，我们希望能给予你几点建议：

- 学习 [提问的智慧](https://github.com/ryanhanwu/How-To-Ask-Questions-The-Smart-Way)
- 善用 Google 搜索能帮助你更好地提升自己
- 至少掌握一门编程语言，比如 Python
- 动手实践比什么都要管用
- 保持对技术的好奇与渴望并坚持下去

> 世界很大，互联网让世界变小，真的黑客们应该去思考并创造，无论当下是在破坏还是在创造，记住，未来，那条主线是创造的就对了。 ——by 余弦

安全圈很小，安全的海洋很深。安全之路的探险，不如就从 **CTF Wiki** 开始！

## Copyleft
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="知识共享许可协议" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png" /></a><br />本作品采用<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">知识共享署名-非商业性使用-相同方式共享 4.0 国际许可协议</a>进行许可。

