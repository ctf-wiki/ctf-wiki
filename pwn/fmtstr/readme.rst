格式化字符串漏洞
================

**格式化字符串利用问题**\ 在1989年被威斯康星大学进行模糊测试时首次被发现，他们发现在当时的C
shell中的命令历史机制如果输入特定的字符串，会出现一些奇怪的问题。当时，人们认为这并没有什么危害。后来，Tymm
Twillman在审计ProFTPD守护进程期间，发现可以\ **利用格式化字符串问题来进行攻击**\ ，并在1999年9月的bugtraq邮件列表中发布了一篇关于ProFTPD漏洞的文章(http://seclists.org/bugtraq/1999/Sep/328)。但是，当时安全界的人士也并没有重视这个问题。后来，直到2000年6月，用户名为tf8的PrzemysławFrasunek
在Bugtraq中发表了\ `**WuFTPD: Providing \*remote\* root since at
least1994** <http://seclists.org/bugtraq/2000/Jun/297>`__
，文中说明了可以利用wu-ftpd中\ **格式化字符串漏洞来实现任意代码执行**\ 。此后，格式化字符串漏洞才逐渐被安全界所重视。

此后，格式化字符串漏洞被广泛利用。在MITR的CVE项目中，格式化字符串漏洞曾经被列为2001年至2006年期间第九大漏洞类型。但是，由于格式化字符串相对于一般的缓冲区漏洞亦或者是堆漏洞，更加具有结构型特征，基本是输出函数中只有一个参数，所以比较容易被自动化工具发现。故而现在程序中基本上就很少出现了，但是，偶尔还是会有出现的。

参考阅读

-  https://en.wikipedia.org/wiki/Uncontrolled\_format\_string
-  **https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf**\ ，非常经典。
