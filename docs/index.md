# CTF Wiki

[![Build Status](https://travis-ci.org/ctf-wiki/ctf-wiki.svg?branch=master)](https://travis-ci.org/ctf-wiki/ctf-wiki)
[![Requirements Status](https://requires.io/github/ctf-wiki/ctf-wiki/requirements.svg?branch=master)](https://requires.io/github/ctf-wiki/ctf-wiki/requirements/?branch=master)
[![BearyChat](https://img.shields.io/badge/bearychat-join_chat-green.svg)](https://ctf-wiki.bearychat.com)

欢迎来到 **CTF Wiki**。

**CTF**（Capture The Flag，夺旗赛）起源于 1996 年 **DEFCON** 全球黑客大会，是网络安全爱好者之间的竞技游戏。

**CTF** 竞赛涉及众多领域，内容繁杂。目前，安全技术发展地越来越快，**CTF** 题目的难度越来越高，初学者需要面对的门槛因此也越来越高。而网上资料大都零散琐碎，初学者往往并不知道该如何系统性地学习 **CTF** 相关领域知识，常需要花费大量时间，苦不堪言。

为了使得热爱 **CTF** 的小伙伴们更好地入门 **CTF**，2016 年 10 月份，**CTF Wiki** 在 Github 有了第一次 commit。随着内容不断完善，**CTF Wiki** 受到了越来越多安全爱好者的喜爱，也渐渐有素未谋面的小伙伴们参与其中。 

围绕 **CTF** 近几年赛题，作为一个自由的站点，**CTF Wiki** 对 **CTF** 中的各个方向知识和技术进行介绍，以便于初学者更好地学习 **CTF** 相关的知识。

目前，**CTF Wiki** 主要包含 **CTF** 各大方向的基础知识。

当然，**CTF Wiki** 基于 **CTF**，却不会局限于 **CTF**，在未来，**CTF Wiki** 会更专注于完善于以下内容：

- CTF 竞赛中的进阶知识
- CTF 竞赛中的优质题目
- 安全研究中的工具介绍
- 更多地与安全实战结合

关于上述部分待完善内容，请参见 [CTF Wiki 中的 Projects](https://github.com/ctf-wiki/ctf-wiki/projects)。

与此同时，CTF Wiki 源于社区，提倡知识自由，在未来也绝不会商业化，将始终保持独立自由的性质。

## How to build？

本文档目前采用 [mkdocs](https://github.com/mkdocs/mkdocs) 部署在 [https://ctf-wiki.github.io/ctf-wiki/](https://ctf-wiki.github.io/ctf-wiki/)。当然也可以部署在本地，具体方式如下：

```shell
# 1. clone
git clone git@github.com:ctf-wiki/ctf-wiki.git
# 2. requirements
pip install -r requirements.txt
# generate static file in site/
mkdocs build
# deploy at http://127.0.0.1:8000
mkdocs serve
```

**mkdocs 本地部署的网站是动态更新的，即当你修改并保存 md 文件后，刷新页面就能随之动态更新。**

## How to practice？

Wiki 中的所有题目在 [ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) 仓库中，请根据对应的分类自行寻找。

注：目前仍有部分题目在该仓库下，正在迁移中。。。（misc，web）

## How to make CTF Wiki Better？

我们非常欢迎你为 Wiki 编写内容，将自己的所学所得与大家分享，具体的贡献方式请参见 [CONTRIBUTING](https://github.com/ctf-wiki/ctf-wiki/blob/master/.github/CONTRIBUTING.md)。 

**在你决定要贡献内容之前，请你务必看完这些内容**。我们期待着你的加入。

非常感谢一起完善 CTF Wiki 的小伙伴们

<a href="https://github.com/ctf-wiki/ctf-wiki/graphs/contributors"><img src="https://opencollective.com/ctf-wiki/contributors.svg?width=890&button=false" /></a>

## What can you get?

- 一个不一样的思考方式以及一颗乐于解决问题的心
- 锻炼你的快速学习能力，不断学习新事物
- 一些有趣的安全技术与相应的挑战
- 一段充实奋斗的时光

在阅读 Wiki 之前，我们希望能给予你几点建议：

- 至少掌握一门编程语言，比如 Python
- 阅读短文 [提问的智慧](http://www.jianshu.com/p/60dd8e9cd12f)
- 善用 Google 搜索能帮助你更好地提升自己
- 动手实践比什么都要管用
- 保持对技术的好奇与渴望并坚持下去

> 世界很大，互联网让世界变小，真的黑客们应该去思考并创造，无论当下是在破坏还是在创造，记住，未来，那条主线是创造的就对了。 ——by 余弦

安全圈很小，安全的海洋很深。安全之路的探险，不如就从 **CTF Wiki** 开始！

## Material color palette 颜色主题

### Primary colors 主色

> 默认 `white`

点击色块可更换主题的主色

<button data-md-color-primary="red">Red</button>
<button data-md-color-primary="pink">Pink</button>
<button data-md-color-primary="purple">Purple</button>
<button data-md-color-primary="deep-purple">Deep Purple</button>
<button data-md-color-primary="indigo">Indigo</button>
<button data-md-color-primary="blue">Blue</button>
<button data-md-color-primary="light-blue">Light Blue</button>
<button data-md-color-primary="cyan">Cyan</button>
<button data-md-color-primary="teal">Teal</button>
<button data-md-color-primary="green">Green</button>
<button data-md-color-primary="light-green">Light Green</button>
<button data-md-color-primary="lime">Lime</button>
<button data-md-color-primary="yellow">Yellow</button>
<button data-md-color-primary="amber">Amber</button>
<button data-md-color-primary="orange">Orange</button>
<button data-md-color-primary="deep-orange">Deep Orange</button>
<button data-md-color-primary="brown">Brown</button>
<button data-md-color-primary="grey">Grey</button>
<button data-md-color-primary="blue-grey">Blue Grey</button>
<button data-md-color-primary="white">White</button>

<script>
  var buttons = document.querySelectorAll("button[data-md-color-primary]");
  Array.prototype.forEach.call(buttons, function(button) {
    button.addEventListener("click", function() {
      document.body.dataset.mdColorPrimary = this.dataset.mdColorPrimary;
      localStorage.setItem("data-md-color-primary",this.dataset.mdColorPrimary);
    })
  })
</script>

### Accent colors 辅助色

> 默认 `red`

点击色块更换主题的辅助色

<button data-md-color-accent="red">Red</button>
<button data-md-color-accent="pink">Pink</button>
<button data-md-color-accent="purple">Purple</button>
<button data-md-color-accent="deep-purple">Deep Purple</button>
<button data-md-color-accent="indigo">Indigo</button>
<button data-md-color-accent="blue">Blue</button>
<button data-md-color-accent="light-blue">Light Blue</button>
<button data-md-color-accent="cyan">Cyan</button>
<button data-md-color-accent="teal">Teal</button>
<button data-md-color-accent="green">Green</button>
<button data-md-color-accent="light-green">Light Green</button>
<button data-md-color-accent="lime">Lime</button>
<button data-md-color-accent="yellow">Yellow</button>
<button data-md-color-accent="amber">Amber</button>
<button data-md-color-accent="orange">Orange</button>
<button data-md-color-accent="deep-orange">Deep Orange</button>

<script>
  var buttons = document.querySelectorAll("button[data-md-color-accent]");
  Array.prototype.forEach.call(buttons, function(button) {
    button.addEventListener("click", function() {
      document.body.dataset.mdColorAccent = this.dataset.mdColorAccent;
      localStorage.setItem("data-md-color-accent",this.dataset.mdColorAccent);
    })
  })
</script>
