[EN](./ssrf.md) | [ZH](./ssrf-zh.md)
## SSRF Introduction


SSRF, Server-Side Request Forgery, server request forgery, is a vulnerability that is constructed by an attacker to form a request initiated by the server. In general, the target of an SSRF attack is an internal system that is inaccessible from the external network.


The reason for the vulnerability is mostly because the server provides the function of obtaining data from other server applications and does not filter and limit the target address.


There are five main types of attacks that an attacker can make using SSRF:


1. You can perform port scanning on the external network, the intranet where the server is located, and local, and obtain banner information for some services.
2. Attack applications running on intranet or local (such as overflow)
3. Fingerprint recognition of the intranet WEB application, by accessing the default file
4. Attack web applications inside and outside the network, mainly attacks that can be implemented using GET parameters (such as Struts2, sqti, etc.)
5. Use the `file` protocol to read local files, etc.


## SSRF Vulnerability scenarios


- Where there is a possibility to initiate a network request, there may be an SSRF vulnerability
- Request resources from a remote server (Upload from URL, Import &amp; Export RSS Feed)
- Database built-in functions (Oracle, MongoDB, MSSQL, Postgres, CouchDB)
- Webmail collects other emails (POP3, IMAP, SMTP)
- File processing, encoding processing, attribute information processing (ffmpeg, ImageMagic, DOCX, PDF, XML)


## Common backend implementation


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



This code uses the `file_get_contents` function to get the image from the URL specified by the user. It is then saved to the hard disk with a random file name and presented to the user.


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



This code uses the `fsockopen` function to get the data (file or HTML) from the user&#39;s URL. This function uses a socket to establish a TCP connection with the server to transfer raw data.


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



Use `curl` to get the data.


## Scenarios that hinder SSRF exploits


- Server open OpenSSL cannot be used interactively
- The server needs authentication (Cookies &amp; User: Pass) is not perfect
- The port that restricts requests is the commonly used port of http, for example, 80, 443, 8080, 8090.
- Disable unwanted protocols. Only http and https requests are allowed. Can prevent problems similar to file:///, gopher://, ftp://, etc.
- Unify the error message to prevent the user from judging the port status of the remote server based on the error message.
## Port scanning with SSRF


According to the return information of the server, most applications will not judge the port, and the status of the port can be judged by the returned banner information.


Backend implementation


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



Construct a front page


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



Requesting a non-HTTP port can return banner information.


Or you can use the 302 jump to bypass the limitations of the HTTP protocol.


Auxiliary script


```php

<?php

$ip = $_GET['ip'];

$port = $_GET['port'];

$scheme = $_GET['s'];

$data = $_GET['data'];

header("Location: $scheme://$ip:$port/$data");

?>

```



[Tencent SSRF vulnerability (very good use point) with script] (https://_thorns.gitbooks.io/sec/content/teng_xun_mou_chu_ssrf_lou_6d1e28_fei_chang_hao_de_.html)


## Agreement Utilization


- Dict agreement


    ```

    dict://fuzz.wuyun.org:8080/helo:dict

    ```



- Gopher protocol


    ```

    gopher://fuzz.wuyun.org:8080/gopher

    ```



- File protocol


    ```

    file:///etc/passwd

    ```

    

## Bypass posture
1. Change the IP address
For example `192.168.0.1`
    

- octal format: `0300.0250.0.1`
- Hexadecimal format: `0xC0.0xA8.0.1`
- 10-digit integer format: `3232235521`
- Hexadecimal integer format: `0xC0A80001`
- There is also a special omission mode, such as `10.0.0.1` which can be written as `10.1`


2. Use the URL to resolve the problem
In some cases, the backend program may parse the accessed URL and filter the resolved host address. At this time, the URL parameters may be parsed improperly, which may bypass the filtering.
E.g:
- `http://www.baidu.com@192.168.0.1/` and `http://192.168.0.1` are all requested for `192.168.0.1`
- Can point to any ip domain name `xip.io`:`http://127.0.0.1.xip.io/`==&gt;`http://127.0.0.1/`
- Short address `http://dwz.cn/11SMa`==&gt;`http://127.0.0.1`
- Use the period `. `:`127.0.0.1`==&gt;`127.0.0.1`
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

        

## Hazard


* You can scan the port on the external network, the intranet where the server is located, and the local port to obtain the banner information of some services.
* Attack applications running on intranet or local (such as overflow);
* Fingerprint recognition for intranet web applications, by accessing default files;
* Attacking internal and external web applications, mainly using get parameters to achieve attacks (such as struts2, sqti, etc.);
* Use the file protocol to read local files and so on.


## References


- [Build Your SSRF EXP Autowork] (http://tools.40huo.cn/#!papers.md)
- [Tencent SSRF vulnerability (very good use point) with script] (https://_thorns.gitbooks.io/sec/content/teng_xun_mou_chu_ssrf_lou_6d1e28_fei_chang_hao_de_.html)
- [Bilibili a substation leaked from information to ssrf to command execution] (https://_thorns.gitbooks.io/sec/content/bilibilimou_fen_zhan_cong_xin_xi_xie_lu_dao_ssrf_z.html)