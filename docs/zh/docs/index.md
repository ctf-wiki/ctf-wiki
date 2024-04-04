# 简介

[![Discord](https://dcbadge.vercel.app/api/server/ekv7WDa9pq)](https://discord.gg/ekv7WDa9pq)

欢迎来到 **CTF Wiki**。

**CTF**（Capture The Flag，夺旗赛）起源于 1996 年 **DEFCON** 全球黑客大会，是网络安全爱好者之间的竞技游戏。

**CTF** 竞赛涉及众多领域，内容繁杂。与此同时，安全技术的发展速度越来越快，**CTF** 题目的难度越来越高，初学者面对的门槛越来越高。而网上资料大都零散琐碎，初学者往往并不知道该如何系统性地学习 **CTF** 相关领域知识，常需要花费大量时间，苦不堪言。

为了使得热爱 **CTF** 的小伙伴们更好地入门 **CTF**，2016 年 10 月份，**CTF Wiki** 在 Github 有了第一次 commit。随着内容不断完善，**CTF Wiki** 受到了越来越多安全爱好者的喜爱，也渐渐有素未谋面的小伙伴们参与进来。 

作为一个自由的站点，围绕 **CTF** 近几年赛题，**CTF Wiki** 对 **CTF** 中的各个方向的知识和技术进行介绍，以便于初学者更好地学习 **CTF** 相关的知识。

目前，**CTF Wiki** 主要包含 **CTF** 各大范畴的基础知识，并正在着力完善以下内容

- CTF 竞赛中的进阶知识
- CTF 竞赛中的优质题目

关于上述部分待完善内容，请参见 CTF Wiki 的 [Projects](https://github.com/ctf-wiki/ctf-wiki/projects)，详细列出了正在做的事项以及待做事项。

当然，**CTF Wiki** 基于 **CTF**，却不会局限于 **CTF**。在未来，**CTF Wiki** 将会

- 介绍安全研究中的工具
- 更多地与安全实战结合

此外，鉴于以下两点

- 技术应该以开放的方式共享。
- 安全攻防技术总是在不断演进，旧的技术在面对新的技术时可能失效。

因此，**CTF Wiki** 永远不会出版书籍。

最后，**CTF Wiki** 源于社区，作为**独立的组织**，提倡**知识自由**，在未来也绝不会商业化，将始终保持**独立自由**的性质。

## Material color palette 颜色主题

### Color Scheme 配色方案

根据浏览器与系统设置自动切换明暗主题，也可手动切换
<div class="tx-switch">
<button data-md-color-scheme="default"><code>Default</code></button>
<button data-md-color-scheme="slate"><code>Slate</code></button>
</div>
<script>
  var buttons = document.querySelectorAll("button[data-md-color-scheme]")
  Array.prototype.forEach.call(buttons, function(button) {
    button.addEventListener("click", function() {
      document.body.dataset.mdColorScheme = this.dataset.mdColorScheme;
      localStorage.setItem("data-md-color-scheme",this.dataset.mdColorScheme);
    })
  })
</script>

### Primary colors 主色

点击色块可更换主题的主色
<div class="tx-switch">
<button data-md-color-primary="red"><code>Red</code></button>
<button data-md-color-primary="pink"><code>Pink</code></button>
<button data-md-color-primary="purple"><code>Purple</code></button>
<button data-md-color-primary="deep-purple"><code>Deep Purple</code></button>
<button data-md-color-primary="indigo"><code>Indigo</code></button>
<button data-md-color-primary="blue"><code>Blue</code></button>
<button data-md-color-primary="light-blue"><code>Light Blue</code></button>
<button data-md-color-primary="cyan"><code>Cyan</code></button>
<button data-md-color-primary="teal"><code>Teal</code></button>
<button data-md-color-primary="green"><code>Green</code></button>
<button data-md-color-primary="light-green"><code>Light Green</code></button>
<button data-md-color-primary="lime"><code>Lime</code></button>
<button data-md-color-primary="yellow"><code>Yellow</code></button>
<button data-md-color-primary="amber"><code>Amber</code></button>
<button data-md-color-primary="orange"><code>Orange</code></button>
<button data-md-color-primary="deep-orange"><code>Deep Orange</code></button>
<button data-md-color-primary="brown"><code>Brown</code></button>
<button data-md-color-primary="grey"><code>Grey</code></button>
<button data-md-color-primary="blue-grey"><code>Blue Grey</code></button>
<button data-md-color-primary="white"><code>White</code></button>
</div>
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

点击色块更换主题的辅助色
<div class="tx-switch">
<button data-md-color-accent="red"><code>Red</code></button>
<button data-md-color-accent="pink"><code>Pink</code></button>
<button data-md-color-accent="purple"><code>Purple</code></button>
<button data-md-color-accent="deep-purple"><code>Deep Purple</code></button>
<button data-md-color-accent="indigo"><code>Indigo</code></button>
<button data-md-color-accent="blue"><code>Blue</code></button>
<button data-md-color-accent="light-blue"><code>Light Blue</code></button>
<button data-md-color-accent="cyan"><code>Cyan</code></button>
<button data-md-color-accent="teal"><code>Teal</code></button>
<button data-md-color-accent="green"><code>Green</code></button>
<button data-md-color-accent="light-green"><code>Light Green</code></button>
<button data-md-color-accent="lime"><code>Lime</code></button>
<button data-md-color-accent="yellow"><code>Yellow</code></button>
<button data-md-color-accent="amber"><code>Amber</code></button>
<button data-md-color-accent="orange"><code>Orange</code></button>
<button data-md-color-accent="deep-orange"><code>Deep Orange</code></button>
</div>
<script>
  var buttons = document.querySelectorAll("button[data-md-color-accent]");
  Array.prototype.forEach.call(buttons, function(button) {
    button.addEventListener("click", function() {
      document.body.dataset.mdColorAccent = this.dataset.mdColorAccent;
      localStorage.setItem("data-md-color-accent",this.dataset.mdColorAccent);
    })
  })
</script>

<style>
button[data-md-color-accent]> code {
    background-color: var(--md-code-bg-color);
    color: var(--md-accent-fg-color);
  }
button[data-md-color-primary] > code {
    background-color: var(--md-code-bg-color);
    color: var(--md-primary-fg-color);
  }
button[data-md-color-primary='white'] > code {
    background-color: var(--md-primary-bg-color);
    color: var(--md-primary-fg-color);
  }
button[data-md-color-accent],button[data-md-color-primary],button[data-md-color-scheme]{
    width: 8.4rem;
    margin-bottom: .4rem;
    padding: 2.4rem .4rem .4rem;
    transition: background-color .25s,opacity .25s;
    border-radius: .2rem;
    color: #fff;
    font-size: .8rem;
    text-align: left;
    cursor: pointer;
}
button[data-md-color-accent]{
  background-color: var(--md-accent-fg-color);
}
button[data-md-color-primary]{
  background-color: var(--md-primary-fg-color);
}
button[data-md-color-scheme='default']{
  background-color: hsla(0, 0%, 100%, 1);
}
button[data-md-color-scheme='slate']{
  background-color: var(--md-default-bg-color);
}
button[data-md-color-accent]:hover, button[data-md-color-primary]:hover {
    opacity: .75;
}
</style>