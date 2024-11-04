# 靜態分析 java 層例子

## 2014 tinyCTF Ooooooh! What does this button do

### 確定文件類型

通過linux的file命令可以看出該文件是一個壓縮包，解壓打開發現它其實是一個apk文件。

### 安裝apk

安裝文件之後，查看一下

![](./figure/2014-tinyCTF-screen.png)

可以看出其就是輸入一個字符串，然後應該會彈出結果。

### 查看程序

```java
    class C00721 implements OnClickListener {
        C00721() {
        }

        public void onClick(View view) {
            if (((EditText) MainActivity.this.findViewById(C0073R.id.passwordField)).getText().toString().compareTo("EYG3QMCS") == 0) {
                MainActivity.this.startActivity(new Intent(MainActivity.this, FlagActivity.class));
            }
        }
    }

```

在主程序中，可以發現，如果我們輸入的字符串爲EYG3QMCS就會執行flagActivity.class。那麼我們輸入一下，可以得到如下結果

![](./figure/2014-tinyCTF-flag.png)

即得到flag。

## 2014 ASIS Cyber Security Contest Finals Numdroid

### 判斷文件類型

首先利用file判斷一下文件類型，發現是個壓縮包，解壓縮一下，得到對應的文件，然後繼續看一下，發現該文件是apk文件。

### 安裝程序

安裝一下程序。簡單看一下頁面，可以發現程序主要是輸入密碼，然後登陸。如果輸入錯的話會爆出“Wrong Password”的信息。

![](./figure/2014-Numdroid-screen.png)

### 分析程序

根據相應的字符串來定位一下源程序中的關鍵函數。根據strings.xml可以發現該字符串的變量名爲wrong，繼而我們找到了如下代碼。

```java
    protected void ok_clicked() {
        DebugTools.log("clicked password: " + this.mScreen.getText());
        boolean result = Verify.isOk(this, this.mScreen.getText().toString());
        DebugTools.log("password is Ok? : " + result);
        if (result) {
            Intent i = new Intent(this, LipSum.class);
            Bundle b = new Bundle();
            b.putString("flag", this.mScreen.getText().toString().substring(0, 7));
            i.putExtras(b);
            startActivity(i);
            return;
        }
        Toast.makeText(this, R.string.wrong, 1).show();
        this.mScreen.setText("");
    }

```

繼續定位到Verify.isOk中。如下

```java
    public static boolean isOk(Context c, String _password) {
        String password = _password;
        if (_password.length() > 7) {
            password = _password.substring(0, 7);
        }
        String r = OneWayFunction(password);
        DebugTools.log("digest: " + password + " => " + r);
        if (r.equals("be790d865f2cea9645b3f79c0342df7e")) {
            return true;
        }
        return false;
    }

```

可以發現程序主要是取password的前7位進行OneWayFunction加密，然後與be790d865f2cea9645b3f79c0342df7e進行比較。如果相等就會返回true。這裏我們再看一下OneWayFunction，如下

```java
    private static String OneWayFunction(String password) {
        List<byte[]> bytes = ArrayTools.map(ArrayTools.select(ArrayTools.map(new String[]{"MD2", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"}, new AnonymousClass1(password)), new SelectAction<byte[]>() {
            public boolean action(byte[] element) {
                return element != null;
            }
        }), new MapAction<byte[], byte[]>() {
            public byte[] action(byte[] element) {
                int i;
                byte[] b = new byte[8];
                for (i = 0; i < b.length / 2; i++) {
                    b[i] = element[i];
                }
                for (i = 0; i < b.length / 2; i++) {
                    b[(b.length / 2) + i] = element[(element.length - i) - 2];
                }
                return b;
            }
        });
        byte[] b2 = new byte[(bytes.size() * 8)];
        for (int i = 0; i < b2.length; i++) {
            b2[i] = ((byte[]) bytes.get(i % bytes.size()))[i / bytes.size()];
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(b2);
            byte[] messageDigest = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte aMessageDigest : messageDigest) {
                String h = Integer.toHexString(aMessageDigest & MotionEventCompat.ACTION_MASK);
                while (h.length() < 2) {
                    h = "0" + h;
                }
                hexString.append(h);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }
```

函數大概就是執行了幾個hash值，但是自己去分析的話，太過於複雜，，由於本題的答案空間($10^7$)比較小，所以我們可以把verify類中的方法拿出來自己暴力跑一下。

### 構造程序

提取出java程序之後，在Verify類中添加main函數並修復部分錯誤，從而得到對應的答案。

這裏對應的代碼放在了example對應的文件夾中。

需要注意的是，這裏如果對應的hash函數不存在的話，源程序會跳過對應的函數。我直接全部跑沒有找到，然後去掉了一個不常見的MD2算法，從而得到了答案。這說明android應該是沒有md2算法的。

輸入之後得到如下

![](./figure/2014-Numdroid-flag.png)

然後我們計算對應的MD值，從而獲得flag爲ASIS_3c56e1ed0597056fef0006c6d1c52463。

## 2014 Sharif University Quals CTF Commercial Application

### 安裝程序

首先，安裝程序，隨便點了點按鈕，在右上方點擊按鈕會讓我們輸入key

![](./figure/2014-Sharif-key.png)

隨便輸入了下，發現程序直接報錯，告訴我們不對，那麼我們可以根據這些信息來進行定位關鍵代碼。

![](./figure/2014-Sharif-key1.png)

### 定位關鍵代碼

```java
    public static final String NOK_LICENCE_MSG = "Your licence key is incorrect...! Please try again with another.";
    public static final String OK_LICENCE_MSG = "Thank you, Your application has full licence. Enjoy it...!";

	private void checkLicenceKey(final Context context) {
        if (this.app.getDataHelper().getConfig().hasLicence()) {
            showAlertDialog(context, OK_LICENCE_MSG);
            return;
        }
        View inflate = LayoutInflater.from(context).inflate(C0080R.layout.propmt, null);
        Builder builder = new Builder(context);
        builder.setView(inflate);
        final EditText editText = (EditText) inflate.findViewById(C0080R.id.editTextDialogUserInput);
        builder.setCancelable(false).setPositiveButton("Continue", new OnClickListener() {
            public void onClick(DialogInterface dialogInterface, int i) {
                if (KeyVerifier.isValidLicenceKey(editText.getText().toString(), MainActivity.this.app.getDataHelper().getConfig().getSecurityKey(), MainActivity.this.app.getDataHelper().getConfig().getSecurityIv())) {
                    MainActivity.this.app.getDataHelper().updateLicence(2014);
                    MainActivity.isRegisterd = true;
                    MainActivity.this.showAlertDialog(context, MainActivity.OK_LICENCE_MSG);
                    return;
                }
                MainActivity.this.showAlertDialog(context, MainActivity.NOK_LICENCE_MSG);
            }
        }).setNegativeButton("Cancel", new C00855());
        builder.create().show();
    }
```

我們發現，其實 MainActivity.NOK_LICENCE_MSG就存儲着報錯的字符串信息，再繼續讀一下發現程序使用

```java
KeyVerifier.isValidLicenceKey(editText.getText().toString(), MainActivity.this.app.getDataHelper().getConfig().getSecurityKey(), MainActivity.this.app.getDataHelper().getConfig().getSecurityIv())
```

來進行驗證，如果驗證通過就會跳出成功信息。

### 詳細分析

進而我們仔細分析一下這三個參數。

#### 參數1

參數1其實就是我們輸入的字符串。

#### 參數2

是利用函數來獲取getSecurityKey，我們簡單閱讀一下，可以發現程序在getConfig函數中設置了SecurityKey

```java
    public AppConfig getConfig() {
        boolean z = false;
        AppConfig appConfig = new AppConfig();
        Cursor rawQuery = this.myDataBase.rawQuery(SELECT_QUERY, null);
        if (rawQuery.moveToFirst()) {
            appConfig.setId(rawQuery.getInt(0));
            appConfig.setName(rawQuery.getString(1));
            appConfig.setInstallDate(rawQuery.getString(2));
            if (rawQuery.getInt(3) > 0) {
                z = true;
            }
            appConfig.setValidLicence(z);
            appConfig.setSecurityIv(rawQuery.getString(4));
            appConfig.setSecurityKey(rawQuery.getString(5));
            appConfig.setDesc(rawQuery.getString(7));
        }
        return appConfig;
    }
```

其中，函數首先進行了數據庫訪問，SELECT_QUERY如下

```java
    private static String DB_NAME = "db.db";
    private static String DB_PATH = "/data/data/edu.sharif.ctf/databases/";
    public static final String SELECT_QUERY = ("SELECT  * FROM " + TABLE_NAME + " WHERE a=1");
    private static String TABLE_NAME = "config";
```

同時，我們可以得到該數據庫的路徑。

在進一步分析，我們可以發現程序在這裏首先獲取了表config的首行，然後將iv設置爲第四列的值，key設置爲第5列的值。

```java
            appConfig.setSecurityIv(rawQuery.getString(4));
            appConfig.setSecurityKey(rawQuery.getString(5));
```

#### 參數3

其實，參數3類似於參數2。這裏就不做說明瞭。

### 獲取數據庫文件

首先，我們需要將該apk文件裝到手機上，然後利用如下指令獲取

```shell
adb pull /data/data/edu.sharif.ctf/databases/db.db
```

進而使用電腦上可以查看sqlite的軟件查看一下，這裏我使用的是<u>http://sqlitebrowser.org/</u>。如下

![](./figure/2014-Sharif-db.png)

這裏，我們可以直接得到

```text
SecurityIv=a5efdbd57b84ca36
SecurityKey=37eaae0141f1a3adf8a1dee655853714
```

### 分析加密代碼

```java
public class KeyVerifier {
    public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String VALID_LICENCE = "29a002d9340fc4bd54492f327269f3e051619b889dc8da723e135ce486965d84";

    public static String bytesToHexString(byte[] bArr) {
        StringBuilder stringBuilder = new StringBuilder();
        int length = bArr.length;
        for (int i = 0; i < length; i++) {
            stringBuilder.append(String.format("%02x", new Object[]{Integer.valueOf(bArr[i] & 255)}));
        }
        return stringBuilder.toString();
    }

    public static String encrypt(String str, String str2, String str3) {
        String str4 = "";
        try {
            Key secretKeySpec = new SecretKeySpec(hexStringToBytes(str2), "AES");
            Cipher instance = Cipher.getInstance(CIPHER_ALGORITHM);
            instance.init(1, secretKeySpec, new IvParameterSpec(str3.getBytes()));
            str4 = bytesToHexString(instance.doFinal(str.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return str4;
    }

    public static byte[] hexStringToBytes(String str) {
        int length = str.length();
        byte[] bArr = new byte[(length / 2)];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }

    public static boolean isValidLicenceKey(String str, String str2, String str3) {
        return encrypt(str, str2, str3).equals(VALID_LICENCE);
    }
}
```

可以看到程序首先使用了encrypt函數對三個字符串加密。其實就是利用上面所說的AES/CBC/PKCS5Padding方法加密，將str2作爲key，將str3作爲初始向量。那麼我們可以很容易地添加解密函數如下

```java
	public static String decrypt(String input, String secretKey, String iv) {
		String encryptedText = "";
		try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(hexStringToBytes(secretKey), "AES");
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(2, secretKeySpec, new IvParameterSpec(iv.getBytes()));
			encryptedText = bytesToHexString(cipher.doFinal(hexStringToBytes(userInput)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedText;
	}
```

然後運行得到正常輸入的product key

```text
fl-ag-IS-se-ri-al-NU-MB-ER
```

## 2015-0CTF-vezel

### 分析

首先，分析代碼，如下

```
public void confirm(View v) {
    if("0CTF{" + String.valueOf(this.getSig(this.getPackageName())) + this.getCrc() + "}".equals(
            this.et.getText().toString())) {
        Toast.makeText(((Context)this), "Yes!", 0).show();
    }
    else {
        Toast.makeText(((Context)this), "0ops!", 0).show();
    }
}

private String getCrc() {
    String v1;
    try {
        v1 = String.valueOf(new ZipFile(this.getApplicationContext().getPackageCodePath()).getEntry(
                "classes.dex").getCrc());
    }
    catch(Exception v0) {
        v0.printStackTrace();
    }

    return v1;
}

private int getSig(String packageName) {
    int v4;
    PackageManager v2 = this.getPackageManager();
    int v5 = 64;
    try {
        v4 = v2.getPackageInfo(packageName, v5).signatures[0].toCharsString().hashCode();
    }
    catch(Exception v0) {
        v0.printStackTrace();
    }

    return v4;
}
```

可以看出我們想要的flag的分爲兩個部分

- String.valueOf(this.getSig(this.getPackageName()))
- this.getCrc()

其中第一部分，我們可以採用自己編寫一個app來獲取對應的值。第二部分我們可以直接將dex文件提取出來，利用網上的工具計算一下。

### hashcode

隨便找了個（放在對應的example文件夾下）

```
package com.iromise.getsignature;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    private StringBuilder builder;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        PackageManager manager = getPackageManager();
        builder = new StringBuilder();
        String pkgname = "com.ctf.vezel";
        boolean isEmpty = TextUtils.isEmpty(pkgname);
        if (isEmpty) {
            Toast.makeText(this, "應用程序的包名不能爲空！", Toast.LENGTH_SHORT);
        } else {
            try {
                PackageInfo packageInfo = manager.getPackageInfo(pkgname, PackageManager.GET_SIGNATURES);
                Signature[] signatures = packageInfo.signatures;
                Log.i("hashcode", String.valueOf(signatures[0].toCharsString().hashCode()));
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
}

```

然後再ddms中過濾出hashcode

```
07-18 11:05:11.895 16124-16124/? I/hashcode: -183971537
```

**注：其實這個程序可以寫成一個小的app，很多程序都會計算簽名。**

### classes.dex crc32

隨便找個在線網站獲取一下`classes.dex`的CRC32值。

```text
CRC-32	46e26557
MD5 Hash	3217b0ad6c769233ea2a49d17885b5ba
SHA1 Hash	ec3b4730654248a02b016d00c9ae2425379bf78f
SHA256 Hash	6fb1df4dacc95312ec72d8b79d22529e1720a573971f866bbf8963b01499ecf8
```

需要注意的是，這裏需要轉成十進制

```
>>> print int("46E26557", 16)
1189242199
```

### flag

兩部分算完合起來就是Flag

Flag：0ctf{-1839715371189242199}

## 2017 XMAN HelloSmali2

給的是一個 smali 文件，我們可以按照如下思路來做

利用 smali.jar 將 smali 彙編爲 dex 文件。

```shell
java -jar smali.jar assemble  src.smali -o src.dex
```

使用 jadx 反編譯 dex，如下

```java
package com.example.hellosmali.hellosmali;

public class Digest {
    public static boolean check(String input) {
        String str = "+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        if (input == null || input.length() == 0) {
            return false;
        }
        int i;
        char[] charinput = input.toCharArray();
        StringBuilder v2 = new StringBuilder();
        for (char toBinaryString : charinput) {
            String intinput = Integer.toBinaryString(toBinaryString);
            while (intinput.length() < 8) {
                intinput = "0" + intinput;
            }
            v2.append(intinput);
        }
        while (v2.length() % 6 != 0) {
            v2.append("0");
        }
        String v1 = String.valueOf(v2);
        char[] v4 = new char[(v1.length() / 6)];
        for (i = 0; i < v4.length; i++) {
            int v6 = Integer.parseInt(v1.substring(0, 6), 2);
            v1 = v1.substring(6);
            v4[i] = str.charAt(v6);
        }
        StringBuilder v3 = new StringBuilder(String.valueOf(v4));
        if (input.length() % 3 == 1) {
            v3.append("!?");
        } else if (input.length() % 3 == 2) {
            v3.append("!");
        }
        if (String.valueOf(v3).equals("xsZDluYYreJDyrpDpucZCo!?")) {
            return true;
        }
        return false;
    }
}
```

簡單看一下，其實是一個變種的 base64 加密，我們可以在網上找一個 base64 編碼，然後設置一下就好了，這裏使用的腳本來自於 http://www.cnblogs.com/crazyrunning/p/7382693.html。

```python
#coding=utf8
import string

base64_charset = '+/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'




def decode(base64_str):
    """
    解碼base64字符串
    :param base64_str:base64字符串
    :return:解碼後的bytearray；若入參不是合法base64字符串，返回空bytearray
    """
    # 對每一個base64字符取下標索引，並轉換爲6爲二進制字符串
    base64_bytes = ['{:0>6}'.format(str(bin(base64_charset.index(s))).replace('0b', '')) for s in base64_str if
                    s != '=']
    resp = bytearray()
    nums = len(base64_bytes) // 4
    remain = len(base64_bytes) % 4
    integral_part = base64_bytes[0:4 * nums]

    while integral_part:
        # 取4個6位base64字符，作爲3個字節
        tmp_unit = ''.join(integral_part[0:4])
        tmp_unit = [int(tmp_unit[x: x + 8], 2) for x in [0, 8, 16]]
        for i in tmp_unit:
            resp.append(i)
        integral_part = integral_part[4:]

    if remain:
        remain_part = ''.join(base64_bytes[nums * 4:])
        tmp_unit = [int(remain_part[i * 8:(i + 1) * 8], 2) for i in range(remain - 1)]
        for i in tmp_unit:
            resp.append(i)

    return resp

if __name__=="__main__":
    print decode('A0NDlKJLv0hTA1lDAuZRgo==')
```

結果如下

```shell
➜  tmp python test.py
eM_5m4Li_i4_Ea5y
```

## 題目

- GCTF 2017 Android1
- GCTF 2017 Android2
- ISG 2017 Crackme
- XMAN 2017 mobile3 rev1
