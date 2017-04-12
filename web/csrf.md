# CSRF 跨站请求伪造

## CSRF 简介

CSRF，全名 Cross Site Request Forgery，跨站请求伪造。很容易将它与 XSS 混淆，对于 CSRF，其两个关键点是跨站点的请求与请求的伪造，由于目标站无 token 或 referer 防御，导致用户的敏感操作的每一个参数都可以被攻击者获知，攻击者即可以伪造一个完全一样的请求以用户的身份达到恶意目的。

## CSRF 类型

按请求类型，可分为 GET 型和 POST 型。

按攻击方式，可分为 HTML CSRF、JSON HiJacking、Flash CSRF 等。

### HTML CSRF

利用 HTML 元素发出 CSRF 请求，这是最常见的CSRF 攻击。

HTML中能设置`src/href`等链接地址的标签都可以发起一个GET 请求，如：

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
```

还有 CSS 样式中的：

```css
@import ""
background:url("")
```

还可以通过JavaScript动态生成的标签对象或CSS对象发起GET请求，而发出POST请求则只能通过表单提交的方式。

### JSON HiJacking

