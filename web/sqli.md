# SQL 注入

## 基本概念

* SQL 注入是一种将 SQL 代码插入或添加到应用（用户）的输入参数中，之后再讲这些参数传递给后台的 SQL 服务器加以解析并执行的攻击。
* 攻击者能够修改 SQL 语句，该进程将与执行命令的组件（如数据库服务器、应用服务器或 WEB 服务器）拥有相同的权限。
* 如果 WEB 应用开发人员无法确保在将从 WEB 表单、cookie、输入参数等收到的值传递给 SQL 查询（该查询在数据库服务器上执行）之前已经对其进行过验证，通常就会出现 SQL 注入漏洞。

## 常用工具

* Burp Suite: [Burp Suite 使用介绍](http://static.hx99.net/static/drops/tools-1548.html)
* Tamper Data (Firefox addon)
* HackBar (Firefox addon)
* sqlmap: [sqlmap 用户手册](http://static.hx99.net/static/drops/tips-143.html)

