# 静态分析原生层程序

## 基本方法

静态分析原生层程序基本的过程如下

1. 提取 so 文件
2. ida 反编译 so 文件阅读 so 代码
3. 根据 java 层的代码来分析 so 代码。
4. 根据 so 代码的逻辑辅助整个程序的分析。

## 原生层静态分析例子

### 2015-海峡两岸-一个APK，逆向试试吧

#### 反编译

利用jadx反编译apk，确定应用的主活动

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

不难看出，程序的主活动为 com.example.mobicrackndk.CrackMe。

#### 分析主活动

不难看出，程序的基本情况就是利用 native 函数 testFlag 判断用户传入的 pwdEditText 是否满足要求。

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

自然我们首先会去直接找 testFlag 函数，凡是并没有直接找到。我们只好首先分析 JNI_Onload 函数，如下

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

可以发现，程序在这里动态注册了类和相应的函数 off_400C。仔细看一下该函数

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

可以发现，确实就是 testflag 函数，其对应的函数名为 abcdefghijklmn。

#### 分析abcdefghijklmn

可以发现，程序主要在三个部分对输入的 v10 进行了判断

- 判断1

```c
  if ( strlen(v10) == 16 )
```

说明输入的字符串长度为16。

- 判断2

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

- 判断3

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

根据汇编代码，可知第三个判断中调用了calcKey类中的静态方法

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

并在之后获得了key的内容。

```Java
    public static String key;

    public static void calcKey() {
        key = new StringBuffer("c7^WVHZ,").reverse().toString();
    }
}
```

#### 获取flag

根据这三个判断，我们可以得到输入的字符串内容

```python
s = "QflMn`fH,ZHVW^7c"
flag = ""
for idx,c in enumerate(s):
    flag +=chr(ord(c)+idx)
print flag
```

结果如下

```shell
QgnPrelO4cRackEr
```

输入之后并不对。

#### 再次分析

想到这里就要考虑下，程序是不是在哪里修改了对应的字符串。这里首先看一下seed。对 x 进行交叉引用，发现其在 _init_my 中使用了，如下

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

所以最初程序对 seed 进行了修改。

#### 再次获取flag

修改脚本如下

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
➜  2015-海峡两岸一个APK，逆向试试吧 python exp.py
NdkMobiL4cRackEr
```

当然该题目也可以使用动态调试。



