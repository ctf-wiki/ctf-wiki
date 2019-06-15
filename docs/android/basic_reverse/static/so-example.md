[EN](./so-example.md) | [ZH](./so-example-zh.md)
# Static analysis of the native layer program


## basic method


The basic process of static analysis of the native layer program is as follows


1. Extract the so file
2. ida decompile so file read so code
3. Analyze the so code based on the code of the java layer.
4. Assist in the analysis of the entire program based on the logic of the so code.


## Native layer static analysis example


### 2015-Straits on both sides - an APK, try it backwards


#### Decompilation


Decompose apk with jadx to determine the main activity of the app


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



It is not difficult to see that the main activity of the program is com.example.mobicrackndk.CrackMe.


#### Analysis main activity


It is not difficult to see that the basic situation of the program is to use the native function testFlag to determine whether the pwdEditText passed in by the user meets the requirements.


```java

public native boolean testFlag(String str);



static {

System.loadLibrary ( &quot;mobicrackNDK&quot;);
}



protected void onCreate(Bundle savedInstanceState) {

super.onCreate (savedInstanceState);
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



#### Analyzing so files


Naturally we will first go directly to the testFlag function, which is not directly found. We had to analyze the JNI_Onload function first, as follows


```c

signed int __fastcall JNI_OnLoad(JNIEnv *a1)

{

JNIEnv * v1; // r4
  int v2; // r5

char * v3; // r7
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

v4 = (* (v2 + 24)) (v2, v3);
  if ( !v4 )

  {

    v5 = "Native registration unable to find class '%s'";

LABEL_6:

fprintf ((&amp; _ sF + 168), v5, v3);
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



It can be found that the program dynamically registers the class and the corresponding function off_400C here. Take a closer look at the function


```text

.data:0000400C off_400C        DCD aTestflag           ; DATA XREF: JNI_OnLoad+68↑o

.data:0000400C                                         ; .text:off_1258↑o

.data: 0000400C; &quot;Test flag&quot;
.data: 00004010 DCD andLjavaLangStrin_0; &quot;(Ljava / lang / String;)&quot;
.data: 00004014 DCD abcdefghijklmn + 1
.data:00004018                 DCD aHello              ; "hello"

.data:0000401C                 DCD aLjavaLangStrin_1   ; "()Ljava/lang/String;"

.data:00004020                 DCD native_hello+1

.data:00004020 ; .data         ends

```



It can be found that it is indeed the testflag function, and its corresponding function name is abcdefghijklmn.


####分析abcdefghijklmn

It can be found that the program mainly judges the input v10 in three parts.


- Judgment 1


```c

  if ( strlen(v10) == 16 )

```



Description The length of the input string is 16.


- Judgment 2


```c

v3 = 0;
    do

    {

s2 [v3] = v10 [v3] - v3;
++ v3;
    }

    while ( v3 != 8 );

    v2 = 0;

    v12 = 0;

    if ( !strcmp(seed[0], s2) )

```



- Judgment 3


```c

v9 = ((* jniEnv) -&gt; FindClass) ();
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

_JNIEnv :: CallStaticVoidMethod (jniEnv, v9, v5);
v6 = ((* v1) -&gt; GetStaticFieldID) (v1, v9, &quot;key&quot;, &quot;Ljava / lang / String;&quot;);
      if ( !v6 )

        _android_log_print(4, "log", "fid,failed");

((* v1) -&gt; GetStaticObjectField) (v1, v9, v6);
      v7 = ((*jniEnv)->GetStringUTFChars)();

      while ( v3 < strlen(v7) + 8 )

      {

v13 [v3 - 8] = v10 [v3] - v3;
++ v3;
      }

v14 = 0;
      v2 = strcmp(v7, v13) <= 0;

```



According to the assembly code, we can see that the static method in the calcKey class is called in the third judgment.


`` `asm
.text:00001070                 LDR     R0, [R5]

.text:00001072                 LDR     R2, =(aCalckey - 0x1080)

.text: 00001074 LDR R3, = (aV - 0x1084)
.text:00001076                 LDR     R4, [R0]

.text:00001078                 MOVS    R1, #0x1C4

.text:0000107C                 ADD     R2, PC          ; "calcKey"

.text:0000107E                 LDR     R4, [R4,R1]

.text:00001080                 ADD     R3, PC          ; "()V"

```



And after that, I got the contents of the key.


```Java

    public static String key;



    public static void calcKey() {

        key = new StringBuffer("c7^WVHZ,").reverse().toString();

    }

}

```



#### Get flag


Based on these three judgments, we can get the input string content.


```python

s = &quot;QflMn`fH, ZHVW ^ 7c&quot;
flag = ""

for idx,c in enumerate(s):

    flag +=chr(ord(c)+idx)

print flag

```



Results are as follows


```shell

QgnPrelO4cRackEr

```



It is not correct after the input.


#### Again analysis


Think about it here, the program is not where to modify the corresponding string. Here first look at the seed. Cross-referenced x and found it used in _init_my as follows


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



So the original program modified the seed.

#### Get flag again


Modify the script as follows


```python

s = &quot;QflMn`fH, ZHVW ^ 7c&quot;
flag = ""

for idx,c in enumerate(s):

tmp = word (c)
    if idx<8:

        tmp-=3

    flag +=chr(tmp+idx)

print flag

```



Flag is as follows


```

➜ 2015- an APK on both sides of the strait, try it backwards python exp.py
NdkMobiL4cRackEr

```



Of course, this topic can also use dynamic debugging.





