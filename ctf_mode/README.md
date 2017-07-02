# CTF 竞赛模式简介

## 解题模式 - Jeopardy

在解题模式 CTF 赛制中，参赛队伍可以通过互联网或者现场网络参与，这种模式的 CTF 竞赛与 ACM 编程竞赛、信息学奥赛比较类似，以解决网络安全技术挑战题目的分值和时间来排名，通常用于在线选拔赛。题目主要包含逆向、漏洞挖掘与利用、Web 渗透、密码、取证、隐写、安全编程等类别。

## 战争分享模式 - Belluminar

在2016年世界黑客大师挑战赛(WCTF)国内首次引入韩国 POC SECURITY 团队开创的 BELLUMINAR CTF (战争与分享)赛制， 从此国内陆陆续续也有开始 BELLUMINAR 模式的比赛， 目前采取这一赛制的有2016年诸葛建伟老师集合的XMan夏令营分享赛以及同年9月的”百度杯”CTF比赛。

同时这里也有 BELLUMINAR 赛制的介绍官网: [http://belluminar.org/](http://belluminar.org/)

### 赛制介绍

> Belluminar， hacking contest of POC， started at POC2015 in KOREA for the first time。 Belluminar is from ‘Bellum’(war in Latin) and ‘seminar’。 It is not a just hacking contest but a kind of festival consisted of CTF & seminar for the solution about challenges。 Only invited teams can join Belluminar。 Each team can show its ability to attack what other teams want to protect and can defend what others want to attack。

如官网介绍这样， BELLUMINAR CTF赛制由受邀参赛队伍相互出题挑战， 并在比赛结束后进行赛题的出题思路，学习过程以及解题思路等进行分享。 战队评分依据出题得分， 解题得分和分享得分进行综合评价并得出最终的排名。

### 出题阶段

> Each team is required to submit 2 challenges to the challenge bank of the sponsor。

首先各个受邀参赛队伍都必须在正式比赛前出题， 题量为2道。 参赛队伍将有1~2周的时间准备题目。出题积分占总分的30%。

> Challenge 1: must be on the Linux platform; Challenge 2: No platform restriction(except Linux) No challenge type restriction (Pwn， Reverse…)

传统的 BELLUMINAR 赛制要求出的两道题中一道 Challenge 必须是在 Linux 平台，另外一个则为非Linux平台的 Challenge。 两个 Challenge 的类型则没有做出限制。因此队伍可以尽情展现自己的技术水平。

为使比赛题目类型比较均衡， 也有采用队伍抽签出题的方式抽取自己的题， 这要求队伍能力水平更为全面， 因此为了不失平衡性， 也会将两道 Challenge 的计入不同分值(比如要求其中一道 Challenge 分值为200， 而另外一道分值则为100)。

### 提交部署

题目提交截止之前， 各个队伍需要提交完整的出题文档以及解题 Writeup， 要求出题文档中详细标明题目分值， 题面， 出题负责人， 考察知识点列表以及题目源码。 而解题 Writeup 中则需要包含操作环境， 完整解题过程， 解题代码。

题目提交之后主办方会对题目和解题代码进行测试， 期间出现问题则需要该题负责人配合解决。最终部署到比赛平台上。

### 解题竞技

进入比赛后， 各支队伍可以看到所有其他团队出的题目并发起挑战， 但是不能解答本队出的题目， 不设置 First Blood 奖励， 根据解题积分进行排名。 解题积分占总分的 60%。

### 分享讨论

比赛结束后， 队伍休息， 并准备制作分享 PPt (也可以在出题阶段准备好)。 分享会时， 各队派2名队员上台进行出题解题思路，学习过程以及考察知识点等的分享。 在演示结束后进入互动讨论环节， 解说代表需要回答评委和其他选手提出的问题。 解说没有太大的时间限制， 但是时间用量是评分的一个标准。

### 计分规则

出题积分(占总分30%)有50%由评委根据题目提交的详细程度， 完整质量， 提交时间等进评分， 另外50%则根据比赛结束后最终解题情况进行评分。 计分公式示例: Score = MaxScore – | N – Expect_N | 。 这里N是指解出该题的队伍数量， 而Expect_N则是这道题预期应该解出的题目数量。 只有当题目难度适中， 解题队伍数量越接近预期数量Expect_N， 则这道题的出题队伍得到的出题积分越高。

解题积分(占总积分 60% )在计算时不考虑First Blood奖励。

分享积分(占 10% )由评委和其他队伍根据其技术分享内容进行评分(考虑分享时间以及其他限制)， 计算平均值得出。

### 赛制总评

赛制中将 Challenge 的出题方交由受邀战队， 让战队能尽自己所能互相出题， 比赛难度和范围不会被主办方水平限制， 同时也能提高 Challenge 的质量， 每个战队都能有不一样的体验与提升。 在”分享”环节， 对本队题目进行讲解的同时也在深化自己的能力水平， 在讨论回答的过程更是一种思维互动的环节。 在赛后的学习总结中能得到更好的认知。


## 攻防模式 - Attack & Defense

在攻防模式 CTF 赛制中，参赛队伍在网络空间互相进行攻击和防守，挖掘网络服务漏洞并攻击对手服务来得分，修补自身服务漏洞进行防御来避免丢分。攻防模式 CTF 赛制可以实时通过得分反映出比赛情况，最终也以得分直接分出胜负，是一种竞争激烈，具有很强观赏性和高度透明性的网络安全赛制。在这种赛制中，不仅仅是比参赛队员的智力和技术，也比体力（因为比赛一般都会持续 48 小时及以上），同时也比团队之间的分工配合与合作。

![攻防模式网络拓扑](/ctf_mode/images/network.jpg)

?> 致谢：刘松同学的总结。
