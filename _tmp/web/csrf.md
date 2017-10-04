# CSRF 跨站请求伪造

## CSRF 简介

CSRF，全名 Cross Site Request Forgery，跨站请求伪造。很容易将它与 XSS 混淆，对于 CSRF，其两个关键点是跨站点的请求与请求的伪造，由于目标站无 token 或 referer 防御，导致用户的敏感操作的每一个参数都可以被攻击者获知，攻击者即可以伪造一个完全一样的请求以用户的身份达到恶意目的。

## CSRF 类型

按请求类型，可分为 GET 型和 POST 型。

按攻击方式，可分为 HTML CSRF、JSON HiJacking、Flash CSRF 等。

### HTML CSRF

利用 HTML 元素发出 CSRF 请求，这是最常见的 CSRF 攻击。

HTML 中能设置`src/href`等链接地址的标签都可以发起一个 GET 请求，如：

```html
<link href="">
<img src="">
<img lowsrc="">
<img dynsrc="">
<meta http-equiv="refresh" content="0; url=">
<iframe src="">
<frame src="">
<script src=""></script>
<bgsound src=""></bgsound>
<embed src=""></bgsound>
<video src=""></video>
<audio src=""></audio>
<a href=""></a>
<table background=""></table>
等
```

还有 CSS 样式中的：

```css
@import ""
background:url("")
等
```

也可使用表单来对 POST 型的请求进行伪造。

```html
<form action="http://www.a.com/register" id="register" method="post">
  <input type=text name="username" value="" />
  <input type=password name="password" value="" />
</form>
<script>
  var f = document.getElementById("register");
  f.inputs[0].value = "test";
  f.inputs[1].value = "passwd";
  f.submit();
</script>
```

### Flash CSRF

Flash 也有各种方式可以发起网络请求，包括 POST。

```javascript
import flash.net.URLRequest;
import flash.system.Security;
var url = new URLRequest("http://target/page");
var param = new URLVariables();
param = "test=123";
url.method = "POST";
url.data = param;
sendToURL(url);
stop();
```

Flash 中还可以使用 `getURL`、`loadVars`等方式发起请求。

```javascript
req = new LoadVars();
req.addRequestHeader("foo", "bar");
req.send("http://target/page?v1=123&v2=222", "_blank", "GET");
```

## CSRF 的防御

### 验证码

验证码强制用户必须与应用进行交互，才能完成最终请求。

### Referer Check

检查请求是否来自合法的源。但服务器并非什么时候都能取得 Referer。

### Token

CSRF 能够攻击成功的本质原因是重要操作的所有参数都可以被攻击者猜测得到。

保持原参数不变，新增一个参数 Token，值是随机的，在实际应用中，Token 可以放在用户的 Session 中，或浏览器的 Cookies 中。

Token 一定要足够随机。此外，Token 的目的不是为了防止重复提交，所以为了使用方便，可以允许在一个用户的有效生命周期内，在 Token 消耗掉之前都使用同一个 Token，但如果用户已经提交了表单，则这个 Token 已经消耗掉，应该重新生成 Token。

Token 还应注意其保密性，如果 Token 出现在 URL 中，则可能会通过 Referer 泄露，应尽量把 Token 放在表单中，把敏感操作由 GET 改为 POST，以表单或 AJAX 的形式提交，避免 Token 泄露。