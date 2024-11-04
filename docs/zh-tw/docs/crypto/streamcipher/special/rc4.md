# RC4

## 基本介紹

RSA 由 Ron Rivest 設計，最初隸屬於 RSA 安全公司，是一個專利密碼產品。它是面向字節的流密碼，密鑰長度可變，非常簡單，但也很有效果。RC4 算法廣泛應用於 SSL/TLS 協議和 WEP/WPA 協議。

## 基本流程

RC4 主要包含三個流程

- 初始化 S 和 T 數組。
- 初始化置換 S。
- 生成密鑰流。

### 初始化 S 和 T 數組 

初始化 S 和 T 的代碼如下

```c
for i = 0 to 255 do
	S[i] = i
	T[i] = K[i mod keylen])
```

 ![image-20180714192918699](figure/rc4_s_t.png)

### 初始化置換 S

```c
j = 0
for i = 0 to 255 do 
	j = (j + S[i] + T[i]) (mod 256) 
	swap (S[i], S[j])
```

![image-20180714193448454](figure/rc4_s.png)

### 生成流密鑰

```c
i = j = 0 
for each message byte b
	i = (i + 1) (mod 256)
	j = (j + S[i]) (mod 256)
	swap(S[i], S[j])
	t = (S[i] + S[j]) (mod 256) 
	print S[t]
```

![image-20180714193537976](figure/rc4_key.png)

我們一般稱前兩部分爲 KSA ，最後一部分是 PRGA。

## 攻擊方法

待補充。

