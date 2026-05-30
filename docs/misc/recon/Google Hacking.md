# Google Hacking

## 介绍

我们都知道渗透测试中信息收集的重要性，它是渗透的第一步也是最重要的一步。有的人渗透测试使出浑身解数破门而不入，可对有的人来说却如同囊中取物一般简单，也许两者的区别就在于信息收集的是否全面彻底，下面就为大家介绍 Google 这款信息收集利器。

## 你不得不知道的谷歌基础

### 谷歌周边

#### **谷歌图片**

谷歌图片是一个图片识别的非常强大的工具，一张你不知道来源的图片上传之后不仅能知道来源，还能自动寻找相似图片。

**例子：**

上传图片以后 Google 会帮你自动搜索相关的匹配项

![](/misc/recon/figure/TP1.png)

下面显示的是匹配的结果：

![](/misc/recon/figure/TP2.png)

#### **谷歌地球**

谷歌拥有世界各地的 3D 全景图，比如你 IP 地址定位到了一个地方，你甚至可以直接从这里看到机房的长相。 


![](/misc/recon/figure/DQ1.png)

![](/misc/recon/figure/DQ2.png)


#### **谷歌高级搜索**

在谷歌搜索页面的右下的设置中你能找到高级搜索这这个选项，它可以图形化界面下让用户方便的进行设置，细化用户的搜索选项，使搜索得到更精确的结果。

![](/misc/recon/figure/GJ.png)

#### **谷歌自定义搜索引擎**

![](/misc/recon/figure/ZDY1.png)

**例子：**

[Google 自定义搜索引擎介绍](https://www.cnblogs.com/mingjiatang/p/6048193.html)

#### **GHDB 谷歌黑客数据库**

![](/misc/recon/figure/GHDB1.png)

**例子：**

[谷歌黑客数据库](https://www.exploit-db.com/google-hacking-database/)


### 搜索基础

#### **语法基础**

1. 谷歌查询是**不区分**大小写的
（但是有一个最显著的例外就是 or 当它被用作是布尔运算符的时候必须写成大写 OR）

2. 谷歌的通配符
`*` 在谷歌搜索的时候只能当做**一个单词**使用

3. 谷歌保留忽略的权利
有些词在某些情况下搜索中会忽略，包括 WHERE、HOW 

4. 谷歌有 32 词的搜索限制
当然可以通过 `*` 代替某些单词突破这种限制

5. 短语搜索是要带上双引号的，严格按照顺序对其搜索

6. 对谷歌来说 AND 是多余的，谷歌会自动查询你输入的所有元素

7. 谷歌会忽略特别常见的字符，但是在这些字符前加上 + 就能强制查询（ + 后面不能有空格）

8. NOT 使用 - 代替（ - 前要有空格）

9. 布尔查询 | 或者 OR

**注意：**

1. 加入括号分割这些令人困惑的运算规则将增强可读性


## 不得不说的高级运算符

如果在一个查询中没有使用高级运算符，谷歌就会在任何区域寻找你的搜索项，包括标题、文本、URL 等

### 总览

    intitle，allintitle
    inurl,allinurl
    filetype
    allintext
    site
    link
    inanchor
    datarange
    cache
    info
    related
    phonebook
    rphonebook
    bphonebook
    uthor
    group
    msgid
    insubject
    stocks
    define

**规则**

operator:search_term

**注意**

1. 在操作符、冒号、搜索项之间**没有**空格

2. 布尔运算符和特殊字符不能用来冒号的作用

3. all运算符（以all开头的运算符)都是有些奇怪的,通常一个查询只能使用一次，而且不和和其他运算符一起使用

	①allintitle 会告诉谷歌，它后面的每一个单词或者短语都要在标题中出现

	② allintext 除了在标题、URL、链接以外的任何地方找到某个内容（它后面的每一个单词或者短语都要在内容中出现）

4. intitle:"index of" 等价于 intitle:index.of
因为 `.` 休止符能够代替任何字符(这个技术也提供了一个无需键入空格和两边引号的短语)

5. intitle:"index of" private 返回标题中有 index of 以及在任何地方有 private 的页面（intitle 只对后面的第一个搜索项有效）

### 常见运算符解释

**site 把搜索精确到特定的网站**

site 允许你搜索仅仅位于一个特定服务器上的或者在一个特定域名里的页面
		
**注意：**

1. 整个因特网是从右到左读取 web 服务器的名字，而人类习惯从左到右读取网站的名字

**filetype 搜索特定后缀的文件** 

搜索以一个特别的文件扩展名结尾的页面，谷歌会以网页快照的形式来将这种格式转换成 html 页面，但是你直接点击标题就会下载

**link 包含指定网页的链接的网页**

搜索包含指定网页的链接的网页，link后面跟的是完整的 URL 可以包含目录名、文件名、参数等，信息量越大查询结果越精确。

**注意：**

1. 不要认为 Link 能搜索链接中的文本，inanchor 才执行的是这个操作，如果输入错误，那么并不会执行link查询而是把 link:短语 当做一个整体直接默认查询

2. link 运算符不能和其他运算符一起使用

**inanchor 寻找链接的锚点**

inanchor 用于寻找链接的锚点，或者在链接中显示的文本（就是显示在页面上的提供点击的文字）

**cache 显示页面的缓存版本**

直接跳转到页面的缓存版本

**numberange 搜索一个数字**

numberange 需要两个参数：一个低位数字，一个高位数字，中间用连字符分割。

**例子：**

1. 为了找到 12345  numberange:12344-12346

**注意：**

1. 这个运算符还有简化版： 12344..12346
 
2. 可以和其他运算符一起使用

**daterange 搜索在特定日期范围内发布额的页面**

谷歌每次重新抓取一个网页，网页日期就会更新

两个日期都必须是自公元前 4713年1月1日起经过的天数，中间用连字符分割（不如使用谷歌的高级搜索引擎实现）

**info 显示谷歌的总结信息**

显示一个网站的总结信息还提供了可能关于该网站的其他搜索链接

**注意：**

1. 不能和其他运算符一起使用

**related 显示相关站点**

参数是一个 URL 

**注意：**

1. 使用高级搜索引擎能实现相同的功能

2. 不能和其他运算符一起使用

#### define 显示一个术语的定义



## Google Hacking 基础

### 缓存

1. 谷歌会把抓取到的绝大部分 web 数据保存一份拷贝（这种行为是可以预防的），但是点击缓存的连接不仅会访问 Google 的服务器还会访问原始的服务器去加载非 html 文件

2. 把缓存链接拷贝到剪切板，然后直接在后面加上参数 &script=1 就会显示缓存页面的 html 文件，不去访问原始服务器

### 目录列表

目录列表能列出存在于一个 web 服务器上的文件和目录

**问题：**

1. 无法阻止用户下载特定的文件或者访问特定的目录

2. 会显示一些服务器的细节

3. 不会分辨哪些是公共文件，哪些是后台文件

4. 一般是偶然被显示，当顶层索引文件如 index.php 消失时

**攻击：**

**查找目录列表**

实例：

1. intitle:index.of （这里的休止符代表的是单个字母的通配符）

![](/misc/recon/figure/MLLB1.png)

**更优化的查找**

实例：

1. intitle:index.of "parent directory"

2. intitle:index.of name size

**查找特定的目录**

我们有时候不仅要查找目录列表，还要查找能访问特定目录的目录列表

实例：

1. intitle:index.of.admin

2. intitle:index.of inurl:admin

**查找特定的文件**

我们可以直接在这个目录中搜索敏感文件

实例：

1. intitle:index.of ws_ftp.log

2. filetype:log inurl:ws_ftp.log

**服务器版本**

能被攻击者用来决定攻击 web 服务器最佳方法的一小段信息就是确切的服务器版本，虽然攻击者能直接连接那个服务器的网页端口，并发送 http 请求来获取版本信息，但是 Google 也可以

实例：

1. intitle:index.of ""server at;

2. intitle:index.of "Apache/1.3.27 Server at"

![](/misc/recon/figure/MLLB2.png)

**操作系统**

我们还可以确定服务器的操作系统、模块和其他信息

我们会把操作系统写在括号里
    
    Apache/1/3/26(Unix)
    CentOS
    Debian
    Debian GNU/Linux
    Fedora
    FreeBSD
    Linux/SUSE
    Linux/SuSE
    NETWRE
    Red Hat
    Ubuntu
    UNIX
    Win32

攻击者能结合这个操作系统标签里的信息以及 web 服务器的版本制定有针对性的攻击

### 遍历技术 

#### **目录遍历**

实例：

1. intitle:index.of inurl:"admin"

**注意：**

1. 在目录列表中 点击 parent directory 就能得到父目录

2. 我们甚至能利用漏洞得到我们无权看到的目录方法是  file=././././etc/passwd

#### **增量替换**

这个技术包括在 URL 里面通过替换数字尝试查找隐藏的目录或者文件，或者从其他网页链接不到的内容（谷歌通常只能查找到从别的网页能链接都的文件，一般带有数字的都可以这么试）

#### **扩展遍历**

经常会出现 web 页面的备份文件，他们有泄露源码的倾向。

常常在配置错误的时候出现这种问题，把 php 代码备份到不是以php结尾的文件中，比如 bak

我们可以

实例：

1. intitle:index.of index.php.bak

2. inurl:index.php.bak

![](/misc/recon/figure/MLLB3.png)


**注意：**

1. 目录列表的问题可能会在缓存中出现，即使现在已经补上了顶层索引文件


### 文档细分

Google 只搜索做过语法分析的或者是可见的一个文档视图

Google 并不会搜索文档的元数据或者叫做域值（就是文件内部的一些属性），这些值只能你自己把文档下载下来右键查看

#### **配置文件**

配置文件存放程序的设置信息，攻击者或者是安全专家能通过这些文件洞察程序的使用情况，正在运行的系统的信息以及网络的使用和配置情况

不管配置文件的数据类型，一个配置文件本身的存在就很说明问题，配置文件的存在说明服务就在附近

**实例：**

1. filetype:conf inurl:firewall

![](/misc/recon/figure/MLLB4.png)

**注意：**

1. 配置文件名 conf 的使用，也可以组合其他的通用的命名规则来查找其他等价的命名规则

	**例如：**

	inurl:conf OR inurl:config OR inurl:cfg

2. 如果你能知道配置文件的名字也是一个非常好的搜索方式，当然你可以从配置文件中抽取特定的字符串来查询

3. 如果能再配上软件名字的话就效果更好了

**考虑的点:**

1. 使用配置文件中独一无二的单词或者短语
 
2. 过滤掉单词 sample example test how to tutorial 来过滤示例文件

3. 用 -cvs 来过滤到 CVS 库，里面经常存放默认的配置文件

4. 如果你正在搜索一个 UNIX 的配置文件，过滤掉 manpage 或者是 Manual

5. 在默认配置文件中寻找一个修改域生成查询


#### **日志文件**

日志文件中也记录着很多的敏感信息

日志文件也有一个默认的名字可以被我们用作基础的搜索，最常见的扩展名就是 log 了

**实例：**

1. filetype:log inurl:log 

2. ext:log log 

3. filetype:log username putty

![](/misc/recon/figure/MLLB5.png)

#### **office文档**

**实例：**

1. filetype:xls inurl:password.xls

2. filetype:xls username password email

![](/misc/recon/figure/YHMMA1.png)

### 数据库挖掘

#### **登录入口**

登录入口是第一道防线，很容易泄露软硬件的信息

查找入口一般使用关键字 login 

大的厂商一般会把版权的注意事项放在页面的底部

![](/misc/recon/figure/DL1.png)

#### **支持的文件**

另一种方法就是通过查询支持文件，该文件和数据库软件一同安装或者由其创建，包括配置文件，调试脚本，甚至是样例数据库文件，这些支持文件要么和流行的数据库客户端服务器包含在一起，要么完全由他们创建

使用 mysql_connect 函数的 php 脚本泄露的信息几乎是全部的，但是 inc 扩展名使之成为了一个 includefile

#### **错误消息**

数据库的错误消息能够用来分析操作系统和web服务器的版本
还可能更多

SQL command not properly ended 

这个表示没有在sql语句的最后找到正确的终止符，所以可能会被用于注入攻击

#### **数据库的转储**

数据库基于文本的转换在网络上是很常见的，使用数据库的转储数据库管理员能完整地重建数据库，也就意味着一个完整的转储的细节并不只是数据表格的结构还有每张表的每一条记录。

攻击者可以搜索转储的标题 

`# Dumping data for table`

并且通过执行必要的关键词 username、password 等能够缩小范围

`# Dumping data for table(user|username|password|pass)`

还可以关注一些由别的工具添加到数据库转储中最后的文件名

**实例：**

1. filetype:sql sql 

![](/misc/recon/figure/SJK1.png)

#### **真实的数据库文件**

攻击者还能直接搜索到数据库本身，并不适合所有的数据库系统，只适合哪些有着特定名字或者扩展名的数据库,因为是二进制文件，所以没法在里面搜索字符

**实例：**

2. filetype:mdb inurl:com

![](/misc/recon/figure/SJK2.png)

## 谷歌在一个信息收集框架中的身影

所有的搜索都遵循几个步骤

1. 定义一个原始的搜索项

2. 扩展该搜索项

3. 从数据源获得数据

4. 语义分析该数据

5. 把该数据加工成信息

#### **原始搜索项**

清晰的定一个目标是搜索中最困难的一项，聪明的搜索不会获得一个不明确的目标，记住：无用输入，无用输出。

目标的分解工作尤为重要

#### **扩展搜索项**

自动化搜索的真正的力量在于想象出人操作的过程并翻译成某种形式的算法

##### **Email地址：**

很多网站都会尝试模糊处理 email 来欺骗数据挖掘程序，因为很多的垃圾邮件的发送者会通过数据挖掘程序来收集 email 地址。
当然我们有办法解决

email 地址可以扩展，比如：
   
    qazwsx@k0rz3n.com
    qazwsx at k0rz3n.com
    qazwsx at k0rz3n dot com
    qazwsx@k0rz3n dot com
    qazwsx_at_k0rz3n.com
    qazwsx_at_k0rz3n dot com
    qazwsx_at_k0rz3n_dot_com
    qazwsx@k0rz3n.remove.com
    qazwsx@_removethis_k0rz3n.com

**注意：**

1. @符号能被篡改成很多的形式，比如说： -(at) _at_ -at- 这也同样适用与 dot 

2. @ 和 dot 会被搜索引擎忽略
 
**验证一个email的地址**

Linux 上使用 host 命令 host -t xxx.gmail.com

windows 上使用 nslookup -qutype = xxx.gmail.com

##### **电话号码**

email 地址是有格式的，但是电话号码没有

在一定的范围内查找结果中包含电话号码的有趣的地方是，你可以使用 Google 的 numrange 运算符，最好的方法就是指定起始数字然后在数字最后带上`..`（ `..` 是 numberange 的简写形式）

**实例：**

1. 252793..9999

##### **人**
 
1. 找到某人信息最好的方法就是 Google 他们，最常见的方式就是直接放到 google 中，但是这样会存在大量的无用结果，我们需要增加信息，
"Andrew Williams" Syngress publishing security 

2. 另一种方法就是把搜索结果限制在国家中

如果他曾经在英国待过， site:uk



##### **获得大量的结果**

比如你想找到某个顶级域名中的所有的网站或者 email 地址，你要完成以下两件事

1. 突破 1000 个结果的限制

2. 增加你每次搜索的结果

**实例：**

1. site:xxxx.gov -www.xxxx.gov

相当于查询子域名

![](/misc/recon/figure/ZYM1.png)

我们可以给每个查询添加一些通用的额外关键字

about offical page site 等

##### **更多组合**

我们可以把自己的搜索与能获取更好的结果的搜索项一起使用

1. 当查找 email 时，能添加类似：通讯录、邮件、电子邮件、发送这种关键词

2. 查找电话号码的时候可以使用一些类似： 电话、移动电话、通讯录、数字、手机的关键词


#### **使用特别的运算符**

扩展名有时候能使用布尔运算符再次组合起来

**实例：**

1. filetype:ppt or filetype:doc site:xxxx.gov

#### **从数据源获取数据**

##### 自行挖掘请求和接受响应的几个自动化的工具

**Netcat(nc)**:

TCP/IP的瑞士军刀，功能异常强大，但是这里我们仅仅用它来接收响应：
    
    $(echo "GET/HTTP/1.0"; echo "Host:www.google.com";echo)|nc www.google.com 80 -vv

当然我们也可以把请求头写入文件

1.txt
    
    GET /HTTP/1.1
    Host:www.google.com
    ~
    ~

**注意:这两个波浪线代表两个空行**

    
    nc www.google.com 80 -vv < 1.txt >2.txt

这里直接把响应写入了 2.txt

**wget:**

    
    wget "http://www.baidu.com" -O output.txt

我们还能够指定请求头的参数来规避谷歌的反爬虫机制
    
    wget -U my_diesel_driven_browser "https://www.google.com" -O output.txt

**curl:**

curl就更加简单了，带有一个可选的参数 -A 代表 UA 
    
    curl -A xxxx "https://www.google.com"

**lynx:**

纯文本模式的网页浏览器,不支持图形、音视频等多媒体信息。用法参见 http://man.linuxde.net/lynx

当然你可以选择使用脚本实现网页的抓取

##### 使用其他的搜索引擎如 Bing



**思考：如何发现一个透明代理：**

1. telnet 到网络外面的一些随机的 IP 地址的 80 端口，如果你每次都能获得一个连接的话，你就在一个透明代理后面

2. 直接 telnet 到网站里，然后发 送 GET/HTTP/1.0 查看响应，不要给 Host 参数（一些代理使用 Host:header 确定你想去的位置，如果你不给就会报出 400 的错误）


## 查找漏洞寻找目标

### **查找漏洞代码**

**实例：**

1. inurl:exploits

### **查找公开漏洞的网站**

查找漏洞代码的一种方法就是关乎源代码中的文件扩展名，然后搜索该代码中的特定的内容。

**实例：**

1. filetype:c exploit

使用下面的命令把这些网站从转储的 Google 结果页面中隔离出来

**实例：**

1. grep Cached exploit_file|awk =F "-" '{print $1}'|sort -u

或者也可以使用 lynx -dump 

### **利用常见的代码字符串查找漏洞**

关注源代码中的常用字符，一种重要的方法就会是关注源代码中的包含的文件或者头文件的引用。以 C 文件为例，通常会被包含在一个 #include<stdio.h>中，不管文件的扩展名是什么

**实例：**

1. `"#include<stdio.h>"` usage expoit

### **查找易受攻击的目标**

#### **利用漏洞的公告查找目标**

软件供货商和安全研究员会定期发布关于易受攻击的软件的报告，这些报告会显示一个受影响软件供应商网站的链接，我们的目标是通过建立一个查询字符串来找到网页上易受攻击的目标。

特别有用的是使用 **Powered by xxxx**

## 十大简单有效的搜索参数

### **site:**

在一个安全评估的信息收集阶段，site 运算符非常的重要 

site 运算符应该作为一个基础的搜索而不是一个单独的搜索

谷歌会将最受欢迎的页面浮动到搜索结果的最上方

site 搜索能够搜集由一个目标维护的服务器和主机的信息

**实例：**

1. site:nytimes.com -site:www.nytimes.com 

这个查询很快就找到了在 mytimes.com 而不在 www.nytimes.com 域中的主机，得到的这些可能是主机也可能是子域

### **intitle:index.of**

解释见前文

### **error|warning**

错误信息会泄露大量的关于目标的信息，我们常常将其与site结合在一起使用

**实例：**

1. ("for more information"|"noot found") (error|warning)

### **login|logon**

关联到登录入口的文档列出了 email 电话 或者是帮助忘记密码的用户重获权限的人工助手的 URL,这些人工助手或许就是社会工程攻击的完美目标，安全系统最大的弱点是键盘后面的人

login trouble 也是很有价值的

### **username|userid|employee.ID "your username is"**

有很多的方法能从目标系统获取用户名，即使用户名是大多数认证机制中不太重要的部分

![](/misc/recon/figure/DLCW.png)

### **password|passcode|"your password is" reminder forgotten**

某些情况下，这种查询与 site 结合会找到提供创建密码策略信息的帮助页面，这对后面的密码的猜解提供了巨大的帮助

![](/misc/recon/figure/CZMM1.png)

### **admin|administrator**

我们还可以加上 contact you/contact your (system) administrator

返回的结果可能会涉及本地、公司、网站、部门、服务器、系统、网络、数据库、email 等

![](/misc/recon/figure/DLQX.png)

**实例：**

1. "administrative login"|"admin login" 

很容易就能找到登录的界面

![](/misc/recon/figure/DLJM1.png)

**注意：**

1. 另一种方式就是用 inurl 在 URL 查找 adminstrator 类似的词语，十有八九就是网站的登录界面

### **-ext:html|-ext:htm|-ext:shtml|-ext:asp|-ext:php**

ext 是 filetype 类型的同义词，上面的查询也是一个否定查询，要和 site 结合起来用，单独使用是没有效果的

但是如果 site 搜索与排除了前十个最常见文件类型的搜索组合使用的话，就能直接找到有趣的文档，这能给攻击者节省大量的时间

### **inurl:temp|inurl:tmp|inurl:backup|inurl:bak**

与 site 相结合就能在一个服务器上查找备份和临时文件，尽管临时和备份文件可能会被命名成奇怪的样子，但是他们的格式是不会变的

### **intrnet|help.desk**

intranet 已经变成了描述一个小团体中局域网的通用名词，这个名词代表着封闭的网络，不对外开放

但是现在很多的站点已经配置了从因特网访问一个局域网的入口，这就把攻击者与封闭网络拉近了距离

**注意：**

1. 少数情况下，由于网络设备的错误配置，私有的局域网会在公网上被发现，而管理员却毫不知情。

2. 一般过滤器只会允许来自某机构或者是某校园的特定的地址访问

**这里有两个问题：**

1. 对特别页面的访问权限的跟踪记录是一个管理噩梦

2. 如果一个攻击者能访问一个本地代理服务器的话，向一个配置错误的代理服务器发送请求或者是，把一台同网络的机器转变成被信任的内网用户
这个搜索是用来查找描述技术支持服务程序的页面，结合 site 威力更大


## 追踪web服务器，登录入口和网络硬件

### 查找和分析web服务器

攻击者关注操作系统，web 服务器版本、品牌、默认配置、有漏洞的脚本。

很多不同的方法可以找到一台服务器，最常用的手段就是端口扫描

使用 nmap、Nessus、openvas 、qualys 这类工具,但是谷歌的查询相比会更加的不明显


#### **目录列表：**

一个目录列表底部的 server 标签能够提供正在运行的 web 服务器软件明确的细节

server.at "Apache/2.4.12"

并非所有的 web 服务器会把标签放在目录列表的底部，但是 apache 的大多数衍生产品都默认打开这个功能，其他平台也有类似的信息

"Microsoft-IIS/7.0 server at"

#### **web 服务器的软件错误消息**

错误信息的文件常常会保存在某个地方，通常以错误的名字来命名的，我们可以分析这些文件之间的共性和特性，从而利用 Google 找到这个错误页面

虽然可以通过服务器的配置设置自定义的错误页面，但是含有404、403、500 等错误消息的页面是不能定制的

以 Apache 为例

**实例：**

1. "Apache/2.4.12 Server at" "-intitle:index.of intitle:inf"

2. "Apache/2/4/12 Server at" -intitle:index.of intitle:error

就能找到由错误信息暴露出服务器版本的 apache 服务器

但是我们从服务器自身查找线索更有效

apache 会有一个叫做 httpd.conf 的配置文件，对 httpd.conf 的搜索泄露了错误消息模板的位置，比如

/error/http_BAD_REQUEST.html.var 涉及文件系统中的 error 目录

我们会在这些文件包含的其他文件中找到这样一句话

think this is a server error 

于是我们可以这样搜索

**实例：**

1. intitle:"Object not found!" "think this is a server error"

使用基本 shell 命令就能既分离一个错误页面的标题又分离可能出现在错误页面上的文本

**实例：**

1. grep -h -r "Content-language:en" * -A 10|grep -A5 "TITLE"|grep -v virtual

我们还能支持其他语言类型的错误，只要把 en 换成 de、es、fr 或者 sv

#### **默认页面**

另一个查找特定类型的服务器或者 web 软件的方法就是搜索默认的 web 页面，大多数的 web 软件或者是服务器自身都带有一页或者是更多页的 web 页面，这些页面使得网站管
理员很容易地测试一个 web 服务器或者是应用的安装情况。

在网站的早期，也就是默认页面还存在的时候谷歌就抓取到信息，导致实时显示的页面与缓存页面有不同。

而当我们提交查询的时候查询的就是页面的缓存版本，

#### **默认文档**

web 服务器软件经常会将 web 目录里存放的手册和文档一起提供给用户，而攻击者能用这些文档查找软件

虽然文档提供的信息可能无法描述服务器的版本，但是这种管理员的疏忽给我们足够的信心相信，类似的问题还会发生

### 查找登录入口

黑客们把登录入口当做是描述运行在服务器上程序的一种方法，同时也是给攻击提供有用的信息和链接的方法

如果你能通过默认的页面找到登录入口的话，那么只能说明这个网站的管理员的安全意识不太强，侧面反映出网站的安全性比较差，有些入口还显示了软件的版本，这对攻击者寻找已知的漏洞很有帮助。

### 使用和查找各种 web工具

Network Query Tool 是一款网页版的扫描器，NQT 的功能看起来是来源于带有NQT应用的网站，我们能通过简单的查询寻找带有 NQT 功能的服务器，NQT程序通常叫做 nqt.php，并且页面上通常偶 Network Query Tool 的字样

inurl:nqt.php intitle:"Network Query Tool" 

NQT 程序也接受 POST 请求，我们可以向服务器传递参数，服务器就会以你的名义来执行这个 NQT 指令

### 定位开启的网络设备

谷歌也能用来探测很多开启 web 的网络设备，很多设备都装有网络界面使得管理员能远程控制，但是只要是被 Google 抓取过得页面都会存在于网络映射中
intitle:"BorderManager alert" 就能泄露代理防火墙服务器的存在，

如果这台设备是一个代理服务器的话，攻击者就能利用这台主机获得可信网络的访问权限

**实例：**

1. "Version Info" "BootVesion" "Internet Settings" 能找到 Belkin Cable/DSL 路由器
......

### 查找网络报告

ntop 程序显示了网络流量统计数据，这些数据能用来确定一个目标网络的结构

intitle:"Welcome to ntop!" 会找到已经公开了他们 ntop 程序的服务器

### 查找网络硬件

比如网络打查找网络硬件印机、网络摄像头，这些设备能提供大量有价值的信息，列出周围的网络命名规则以及其他信息


##  用户名、密码以及其他信息

### 搜索用户名

大多数的认证机制会使用用户名和密码，数据库的错误消息，web 服务器的错误消息等都会泄露用户信息

某些情况下用户名能从检查 web 行为的 web 统计程序中找到，Webalizer 程序显示了关于一个 web 服务器使用情况的各种信息

**实例：**

1. +intext:webalizer+intext:"Total Username" + intext:"Usage Statistics for" 可以找到windows 注册表存有各种的认证信息，包括用户名和密码。虽然搜索到导出的 windows 注册表文件不常见，但是查询：filetype:reg HKEY_CURRENT_USER username 还是能找到许多结果

有很多方法能找到一个已知的文件名

**实例：**

1. intitle:index.of install.log

2. filetype:log nurl:install.log

### 搜索密码：

大多数在 Google 上发现的密码都是别被加密的，但是大多数情况下还是能找到破解办法，比如 http://www.openwall.com/John 的 John the Ripper 一个强大的密码破解网站

**实例：**

1. ext:pwd inurl:_vti_pvt inurl:(Server|authors|administrators)

2. intext:(password|passcode|pass) intext:(username|userid|user)

### 搜索信用卡号码、社会保险后妈等

往往是钓鱼者放在自己服务器上的信息，以为只有自己能看到，实际谷歌早就发现了

### 其他信息

**实例：**

1. filetype:ctt messager MSN 信使联系人列表

2. filetype:blt blt + intext:screenname AIM 好友列表

我们甚至还能找扫描器生成的报告

This file was generated by Nessus


## 总结

Google 搜索引擎是我们我们随手可得的强大信息收集工具，在我们的渗透测试过程中发挥着无可匹敌的作用。

