# 基本贡献方式

## 我之前没怎么用过 Github

参与 Wiki 的编写**需要**一个 Github 账号， **不需要**高超的 Github 技巧。

举个栗子，假如我想要修改一个页面内容，应该怎么操作呢？

1. 在 [CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/) 上找到对应页面
2. 点击 正文右上方、目录左侧的 **“编辑此页”** 按钮
3. （应该已经跳转到了 Github 上的对应页面吧？）这时候右上方还会有一个 **“编辑此页”** 的按钮，点击它就可以在线编辑了
4. 写好了之后点下方的绿色按钮，可能会提示没有权限。不必担心！Github 会自动帮你 fork 一份项目的文件并创建 Pull Request

（有木有很简单？）

如果还是不放心，可以参考以下资料：  

https://guides.github.com/activities/hello-world/  
https://guides.github.com/activities/forking/  

## 我之前用过 Github

基本协作方式如下

1. Fork 主仓库到自己的仓库中。
2. 当想要贡献某部分内容时，请务必仔细查看 **[Issue](https://github.com/ctf-wiki/ctf-wiki/issues)** 与 **[Project](https://github.com/ctf-wiki/ctf-wiki/projects)**，以便确定是否有人已经开始了这项工作。当然，我们更希望你可以加入 [Discord](https://discord.gg/ekv7WDa9pq)，以便于沟通与交流。
3. 在决定将内容推送到本仓库时，**请你首先拉取本仓库代码进行合并，自行处理好冲突，同时确保在本地可以正常生成文档**，然后再 PR 到主仓库的 master 分支上。其中，PR 需要包含以下基本信息
    * 标题：本次 PR 的目的（做了什么工作，修复了什么问题）
    * 内容：如果必要的话，请给出对修复问题的叙述
    * **注意，所有的内容都应该使用英语**
4. 如果发现 PR 中有什么问题，请在 PR 中直接评论，并尽量给出修正的方式，或者也可以直接进行修改。 
5. 提出该 PR 的人根据评论修正内容，然后将修改后的内容 Merge 到 master 分支中。

目前，在人员较少的前提下，基本上可以忽略 4-5 步。

## 注意

- 每次 Pull Request 应只解决一个主要的事情，这样方便于进行修改。
- 在每次 Pull Request 时，请确保自己在本地生成时，可以正确显示，并在 Pull Request 页面的评论中查看预览的站点是否为自己期望的样子。
- 如果你想要开启一个新的章节，即编写目前 CTF Wiki 中没有的内容，请务必加入 [Discord](https://discord.gg/ekv7WDa9pq) 中交流，并在交流完毕后**将自己想要开启的新的章节以简明扼要的方式发起一个新的 issue**，以便于管理人员把这个放到对应 Project 的 In Process 栏中。
- 在你成为团队成员后，你可以自由地编写 Project 中的内容。
- 更多信息，请参见 [F.A.Q](https://github.com/ctf-wiki/ctf-wiki/wiki/F.A.Q)。
