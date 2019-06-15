[EN](./csrf.md) | [ZH](./csrf-zh.md)
## CSRF Introduction


CSRF, full name Cross Site Request Forgery, cross-site request forgery. It is easy to confuse it with XSS. For CSRF, the two key points are the cross-site request and request forgery. Since the target station has no token or referer defense, each parameter of the user&#39;s sensitive operation can be known by the attacker. The attacker can forge a completely identical request to achieve malicious purposes as the user.


## CSRF type


According to the request type, it can be divided into GET type and POST type.


According to the attack method, it can be divided into HTML CSRF, JSON HiJacking, Flash CSRF, and so on.


### HTML CSRF



The CSRF request is issued with HTML elements, which is the most common CSRF attack.


Tags in the HTML that can be set to a link address such as `src/href` can initiate a GET request, such as:


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

......

```



Also in the CSS style:


```css

@import ""

background:url("")

......

```



Forms can also be used to forge POST-type requests.


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



Flash also has a variety of ways to initiate network requests, including POST.


`` `js
import flash.net.URLRequest;

import flash.system.Security;

var url = new URLRequest("http://target/page");

var param = new URLVariables ();
param = "test=123";

url.method = "POST";

url.data = param;
sendToURL(url);

stop();

```



Flash can also use the methods `getURL`, `loadVars`, etc. to initiate a request.


`` `js
req = new LoadVars();

req.addRequestHeader("foo", "bar");

req.send("http://target/page?v1=123&v2=222", "_blank", "GET");

```



## CSRF&#39;s defense


### Verification code


The verification code forces the user to interact with the app to complete the final request.


### Referer Check



Check if the request is from a legitimate source. But the server does not always get the Referer.


### Token



The essential reason why CSRF can attack success is that all parameters of important operations can be guessed by the attacker.


Keep the original parameters unchanged, add a parameter Token, the value is random, in the actual application, the Token can be placed in the user&#39;s Session, or in the browser&#39;s Cookies.


Token must be random enough. In addition, the purpose of Token is not to prevent duplicate submissions, so for the convenience of use, it is allowed to use the same Token in the lifetime of a user before the Token is consumed, but if the user has already submitted the form, the Token has Consumed, the token should be regenerated.


Token should also pay attention to its confidentiality. If the Token appears in the URL, it may be leaked through the Referer. Try to put the Token in the form, change the sensitive operation from GET to POST, submit it as a form or AJAX, avoid Token. Give way.