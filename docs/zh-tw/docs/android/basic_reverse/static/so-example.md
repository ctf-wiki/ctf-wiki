# 靜態分析原生層程序

## 基本方法

靜態分析原生層程序基本的過程如下

1. 提取 so 文件
2. ida 反編譯 so 文件閱讀 so 代碼
3. 根據 java 層的代碼來分析 so 代碼。
4. 根據 so 代碼的邏輯輔助整個程序的分析。

## 原生層靜態分析例子

### 2015-海峽兩岸-一個APK，逆向試試吧

#### 反編譯

利用jadx反編譯apk，確定應用的主活動

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:app="http://schemas.android.com/apk/res-auto" android:versionCode="1" android:versionName="1.0" package="com.example.mobicrackndk">
    <uses-sdk android:minSdkVersion="8" android:targetSdkVersion="17" />
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@drawable/ic_launcher" android:allowBackup="true">
        <activity android:label="@string/app_name" android:name="com.example.mobicrackndk.CrackMe">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

不難看出，程序的主活動爲 com.example.mobicrackndk.CrackMe。

#### 分析主活動

不難看出，程序的基本情況就是利用 native 函數 testFlag 判斷用戶傳入的 pwdEditText 是否滿足要求。

```java
public native boolean testFlag(String str);

static {
  System.loadLibrary("mobicrackNDK");
}

protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView((int) R.layout.activity_crack_me);
  this.inputButton = (Button) findViewById(R.id.input_button);
  this.pwdEditText = (EditText) findViewById(R.id.pwd);
  this.inputButton.setOnClickListener(new OnClickListener() {
    public void onClick(View v) {
      CrackMe.this.input = CrackMe.this.pwdEditText.getText().toString();
      if (CrackMe.this.input == null) {
        return;
      }
      if (CrackMe.this.testFlag(CrackMe.this.input)) {
        Toast.makeText(CrackMe.this, CrackMe.this.input, 1).show();
      } else {
        Toast.makeText(CrackMe.this, "Wrong flag", 1).show();
      }
    }
  });
}
```

#### 分析so文件

自然我們首先會去直接找 testFlag 函數，凡是並沒有直接找到。我們只好首先分析 JNI_Onload 函數，如下

```c
signed int __fastcall JNI_OnLoad(JNIEnv *a1)
{
  JNIEnv *v1; // r4
  int v2; // r5
  char *v3; // r7
  int v4; // r1
  const char *v5; // r1
  int v7; // [sp+Ch] [bp-1Ch]

  v1 = a1;
  v7 = 0;
  printf("JNI_OnLoad");
  if ( ((*v1)->FindClass)(v1, &v7, 65540) )
    goto LABEL_7;
  v2 = v7;
  v3 = classPathName[0];
  fprintf((&_sF + 168), "RegisterNatives start for '%s'", classPathName[0]);
  v4 = (*(*v2 + 24))(v2, v3);
  if ( !v4 )
  {
    v5 = "Native registration unable to find class '%s'";
LABEL_6:
    fprintf((&_sF + 168), v5, v3);
LABEL_7:
    fputs("GetEnv failed", (&_sF + 168));
    return -1;
  }
  if ( (*(*v2 + 860))(v2, v4, off_400C, 2) < 0 )
  {
    v5 = "RegisterNatives failed for '%s'";
    goto LABEL_6;
  }
  return 65540;
}
```

可以發現，程序在這裏動態註冊了類和相應的函數 off_400C。仔細看一下該函數

```text
.data:0000400C off_400C        DCD aTestflag           ; DATA XREF: JNI_OnLoad+68↑o
.data:0000400C                                         ; .text:off_1258↑o
.data:0000400C                                         ; "testFlag"
.data:00004010                 DCD aLjavaLangStrin_0   ; "(Ljava/lang/String;)Z"
.data:00004014                 DCD abcdefghijklmn+1
.data:00004018                 DCD aHello              ; "hello"
.data:0000401C                 DCD aLjavaLangStrin_1   ; "()Ljava/lang/String;"
.data:00004020                 DCD native_hello+1
.data:00004020 ; .data         ends
```

可以發現，確實就是 testflag 函數，其對應的函數名爲 abcdefghijklmn。

#### 分析abcdefghijklmn

可以發現，程序主要在三個部分對輸入的 v10 進行了判斷

- 判斷1

```c
  if ( strlen(v10) == 16 )
```

說明輸入的字符串長度爲16。

- 判斷2

```c
    v3 = 0;
    do
    {
      s2[v3] = v10[v3] - v3;
      ++v3;
    }
    while ( v3 != 8 );
    v2 = 0;
    v12 = 0;
    if ( !strcmp(seed[0], s2) )
```

- 判斷3

```c
      v9 = ((*jniEnv)->FindClass)();
      if ( !v9 )
      {
        v4 = "class,failed";
LABEL_11:
        _android_log_print(4, "log", v4);
        exit(1);
      }
      v5 = ((*jniEnv)->GetStaticMethodID)();
      if ( !v5 )
      {
        v4 = "method,failed";
        goto LABEL_11;
      }
      _JNIEnv::CallStaticVoidMethod(jniEnv, v9, v5);
      v6 = ((*v1)->GetStaticFieldID)(v1, v9, "key", "Ljava/lang/String;");
      if ( !v6 )
        _android_log_print(4, "log", "fid,failed");
      ((*v1)->GetStaticObjectField)(v1, v9, v6);
      v7 = ((*jniEnv)->GetStringUTFChars)();
      while ( v3 < strlen(v7) + 8 )
      {
        v13[v3 - 8] = v10[v3] - v3;
        ++v3;
      }
      v14 = 0;
      v2 = strcmp(v7, v13) <= 0;
```

根據彙編代碼，可知第三個判斷中調用了calcKey類中的靜態方法

```asm
.text:00001070                 LDR     R0, [R5]
.text:00001072                 LDR     R2, =(aCalckey - 0x1080)
.text:00001074                 LDR     R3, =(aV - 0x1084)
.text:00001076                 LDR     R4, [R0]
.text:00001078                 MOVS    R1, #0x1C4
.text:0000107C                 ADD     R2, PC          ; "calcKey"
.text:0000107E                 LDR     R4, [R4,R1]
.text:00001080                 ADD     R3, PC          ; "()V"
```

並在之後獲得了key的內容。

```Java
    public static String key;

    public static void calcKey() {
        key = new StringBuffer("c7^WVHZ,").reverse().toString();
    }
}
```

#### 獲取flag

根據這三個判斷，我們可以得到輸入的字符串內容

```python
s = "QflMn`fH,ZHVW^7c"
flag = ""
for idx,c in enumerate(s):
    flag +=chr(ord(c)+idx)
print flag
```

結果如下

```shell
QgnPrelO4cRackEr
```

輸入之後並不對。

#### 再次分析

想到這裏就要考慮下，程序是不是在哪裏修改了對應的字符串。這裏首先看一下seed。對 x 進行交叉引用，發現其在 _init_my 中使用了，如下

```c
size_t _init_my()
{
  size_t i; // r7
  char *v1; // r4
  size_t result; // r0

  for ( i = 0; ; ++i )
  {
    v1 = seed[0];
    result = strlen(seed[0]);
    if ( i >= result )
      break;
    t[i] = v1[i] - 3;
  }
  seed[0] = t;
  byte_4038 = 0;
  return result;
}
```

所以最初程序對 seed 進行了修改。

#### 再次獲取flag

修改腳本如下

```python
s = "QflMn`fH,ZHVW^7c"
flag = ""
for idx,c in enumerate(s):
    tmp = ord(c)
    if idx<8:
        tmp-=3
    flag +=chr(tmp+idx)
print flag
```

flag 如下

```
➜  2015-海峽兩岸一個APK，逆向試試吧 python exp.py
NdkMobiL4cRackEr
```

當然該題目也可以使用動態調試。



