# 簡介

[![Discord](https://dcbadge.vercel.app/api/server/ekv7WDa9pq)](https://discord.gg/ekv7WDa9pq)

歡迎來到 **CTF Wiki**。

**CTF**（Capture The Flag，奪旗賽）起源於 1996 年 **DEFCON** 全球黑客大會，是網絡安全愛好者之間的競技遊戲。

**CTF** 競賽涉及衆多領域，內容繁雜。與此同時，安全技術的發展速度越來越快，**CTF** 題目的難度越來越高，初學者面對的門檻越來越高。而網上資料大都零散瑣碎，初學者往往並不知道該如何系統性地學習 **CTF** 相關領域知識，常需要花費大量時間，苦不堪言。

爲了使得熱愛 **CTF** 的小夥伴們更好地入門 **CTF**，2016 年 10 月份，**CTF Wiki** 在 Github 有了第一次 commit。隨着內容不斷完善，**CTF Wiki** 受到了越來越多安全愛好者的喜愛，也漸漸有素未謀面的小夥伴們參與進來。 

作爲一個自由的站點，圍繞 **CTF** 近幾年賽題，**CTF Wiki** 對 **CTF** 中的各個方向的知識和技術進行介紹，以便於初學者更好地學習 **CTF** 相關的知識。

目前，**CTF Wiki** 主要包含 **CTF** 各大範疇的基礎知識，並正在着力完善以下內容

- CTF 競賽中的進階知識
- CTF 競賽中的優質題目

關於上述部分待完善內容，請參見 CTF Wiki 的 [Projects](https://github.com/ctf-wiki/ctf-wiki/projects)，詳細列出了正在做的事項以及待做事項。

當然，**CTF Wiki** 基於 **CTF**，卻不會侷限於 **CTF**。在未來，**CTF Wiki** 將會

- 介紹安全研究中的工具
- 更多地與安全實戰結合

此外，鑑於以下兩點

- 技術應該以開放的方式共享。
- 安全攻防技術總是在不斷演進，舊的技術在面對新的技術時可能失效。

因此，**CTF Wiki** 永遠不會出版書籍。

最後，**CTF Wiki** 源於社區，作爲**獨立的組織**，提倡**知識自由**，在未來也絕不會商業化，將始終保持**獨立自由**的性質。

## Material color palette 顏色主題

### Color Scheme 配色方案

根據瀏覽器與系統設置自動切換明暗主題，也可手動切換
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

點擊色塊可更換主題的主色
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

### Accent colors 輔助色

點擊色塊更換主題的輔助色
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