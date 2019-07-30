[EN](./index-en.md) | [ZH](./index.md)

# CTF Wiki

[![Build Status](https://travis-ci.org/ctf-wiki/ctf-wiki.svg?branch=master)](https://travis-ci.org/ctf-wiki/ctf-wiki)
[![Requirements Status](https://requires.io/github/ctf-wiki/ctf-wiki/requirements.svg?branch=master)](https://requires.io/github/ctf-wiki/ctf-wiki/requirements/?branch=master)
[![Slack](https://img.shields.io/badge/slack-join%20chat-brightgreen.svg)](https://join.slack.com/t/ctf-wiki/shared_invite/enQtNTkwNDg5NDUzNzAzLWExOTRhZTE0ZTMzYjVlNDk5OGI3ZDA1NmQyZjE4NWRlMGU3NjEwM2Y2ZTliMTg4Njg1MjliNWRhNTk2ZmY0NmI)

欢迎来到 **CTF Wiki**。

*读者注意*：CTF Wiki最近转为双语，因此CTF Wiki中的每一页都将提供英文和中文。你只需点击
每个页面的顶部按钮，顶部按钮看起来像这样:
[EN](./index-en.md) | [ZH](./index.md)

*NOTE TO READER*: CTF Wiki has recently moved to being bilingual, so each page in CTF 
Wiki will now be available in both English and Chinese. Simply click the button AT the 
top of each page that looks like the link below: 
[EN](./index-en.md) | [ZH](./index.md)
 
**CTF**（Capture The Flag，夺旗赛）起源于 1996 年 **DEFCON** 全球黑客大会，是网络安全爱好者之间的竞技游戏。

**CTF** 竞赛涉及众多领域，内容繁杂。与此同时，安全技术的发展速度越来越快，**CTF** 题目的难度越来越高，初学者面对的门槛越来越高。而网上资料大都零散琐碎，初学者往往并不知道该如何系统性地学习 **CTF** 相关领域知识，常需要花费大量时间，苦不堪言。

为了使得热爱 **CTF** 的小伙伴们更好地入门 **CTF**，2016 年 10 月份，**CTF Wiki** 在 Github 有了第一次 commit。随着内容不断完善，**CTF Wiki** 受到了越来越多安全爱好者的喜爱，也渐渐有素未谋面的小伙伴们参与其中。 

作为一个自由的站点，围绕 **CTF** 近几年赛题，**CTF Wiki** 对 **CTF** 中的各个方向的知识和技术进行介绍，以便于初学者更好地学习 **CTF** 相关的知识。

目前，**CTF Wiki** 主要包含 **CTF** 各大范畴的基础知识，並正在着力完善以下内容

- CTF 竞赛中的进阶知识
- CTF 竞赛中的优质题目

关于上述部分待完善内容，请参见 CTF Wiki 的 [Projects](https://github.com/ctf-wiki/ctf-wiki/projects)，详细列出了正在做的事项以及待做事项。

当然，**CTF Wiki** 基于 **CTF**，却不会局限于 **CTF**，在未来，**CTF Wiki** 将会

- 介绍安全研究中的工具
- 更多地与安全实战结合

此外，鉴于以下两点

- 技术应该以开放的方式共享。
- 安全攻防技术总是保持不断更新，旧的技术在面对新的技术时随时可能失效。

因此，**CTF Wiki** 永远不会出版书籍。

最后，**CTF Wiki** 源于社区，作为**独立的组织**，提倡**知识自由**，在未来也绝不会商业化，将始终保持**独立自由**的性质。

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


只是想本地浏览，并不想修改文档？试试 Docker 吧！
```
docker run -d --name=ctf-wiki -p 4100:80 ctfwiki/ctf-wiki
```
随后即可在浏览器中访问 [http://localhost:4100/](http://localhost:4100/) 阅读 CTF Wiki 。

## How to practice？

 首先，可以通过浏览网上资料来学习一些基本的安全知识。

其次，CTF Wiki 还有两个姊妹项目

- CTF Wiki 中涉及的题目在 [ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) 仓库中，请根据对应的分类自行寻找。
    - 注：目前仍有部分题目正在迁移中。。。（misc，web）
- CTF Wiki 中涉及的工具会不断补充到 [ctf-tools](https://github.com/ctf-wiki/ctf-tools) 仓库中。

## How to make CTF Wiki Better？

我们非常欢迎你为 Wiki 编写内容，将自己的所学所得与大家分享，具体的贡献方式请参见 [CONTRIBUTING](https://github.com/ctf-wiki/ctf-wiki/wiki/Contributing-Guide)。 

**在你决定要贡献内容之前，请你务必看完这些内容**。我们期待着你的加入。

非常感谢一起完善 CTF Wiki 的小伙伴们

<a href="https://github.com/ctf-wiki/ctf-wiki/graphs/contributors"><img src="https://opencollective.com/ctf-wiki/contributors.svg?width=890&button=false" /></a>

## What can you get?

- 快速学习新事物的能力
- 一个不一样的思考方式
- 一颗乐于解决问题的心
- 一些有趣的网络安全技术
- 一段充实奋斗的时光

在阅读 Wiki 之前，我们希望能给予你一些建议：

- 阅读 [提问的智慧](http://www.jianshu.com/p/60dd8e9cd12f)
- 善用 Google 搜索可以帮助你更好地提升自己
- 掌握至少一门编程语言，比如 Python
- 实践比什么都要管用
- 保持对技术的好奇与渴望并坚持下去

> 世界很大，互联网让世界变小，真的黑客们应该去思考并创造，无论当下是在破坏还是在创造，记住，未来，那主线是创造就对了。 ——by 余弦

安全圈很小，安全的海洋很深。与其盲目地进行在安全之路的探险，不如就从 **CTF Wiki** 开始！

## Copyleft
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="知识共享许可协议" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png" /></a><br />本作品采用<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">知识共享署名-非商业性使用-相同方式共享 4.0 国际许可协议</a>进行许可。



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
