# 整數溢出

## 介紹

在C語言中，整數的基本數據類型分爲短整型(short)，整型(int)，長整型(long)，這三個數據類型還分爲有符號和無符號，每種數據類型都有各自的大小範圍，(因爲數據類型的大小範圍是編譯器決定的，所以之後所述都默認是 64 位下使用 gcc-5.4)，如下所示:


| 類型 | 字節 | 範圍 |
| :-: | :-: | :-: |
| short int | 2byte(word) | 0\~32767(0\~0x7fff) <br> -32768\~-1(0x8000\~0xffff)  |
| unsigned short int | 2byte(word) | 0\~65535(0\~0xffff) |
| int | 4byte(dword) | 0\~2147483647(0\~0x7fffffff) <br> -2147483648\~-1(0x80000000\~0xffffffff) |
| unsigned int | 4byte(dword) | 0\~4294967295(0\~0xffffffff) |
| long int | 8byte(qword) | 正: 0\~0x7fffffffffffffff <br> 負:0x8000000000000000\~0xffffffffffffffff |
| unsigned long int | 8byte(qword) | 0\~0xffffffffffffffff |

當程序中的數據超過其數據類型的範圍，則會造成溢出，整數類型的溢出被稱爲整數溢出。

## 原理

接下來簡單闡述下整數溢出的原理

### 上界溢出

```
# 僞代碼
short int a;

a = a + 1;
# 對應的彙編
movzx  eax, word ptr [rbp - 0x1c]
add    eax, 1
mov    word ptr [rbp - 0x1c], ax

unsigned short int b;

b = b + 1;
# assembly code
add    word ptr [rbp - 0x1a], 1
```

上界溢出有兩種情況，一種是 `0x7fff + 1`， 另一種是 `0xffff + 1`。

因爲計算機底層指令是不區分有符號和無符號的，數據都是以二進制形式存在(編譯器的層面纔對有符號和無符號進行區分，產生不同的彙編指令)。

所以 `add 0x7fff, 1 == 0x8000`，這種上界溢出對無符號整型就沒有影響，但是在有符號短整型中，`0x7fff` 表示的是 `32767`，但是 `0x8000` 表示的是 `-32768`，用數學表達式來表示就是在有符號短整型中 `32767+1 == -32768`。

第二種情況是 `add 0xffff, 1`，這種情況需要考慮的是第一個操作數。

比如上面的有符號型加法的彙編代碼是 `add eax, 1`，因爲 `eax=0xffff`，所以 `add eax, 1 == 0x10000`，但是無符號的彙編代碼是對內存進行加法運算 `add word ptr [rbp - 0x1a], 1 == 0x0000`。

在有符號的加法中，雖然 `eax` 的結果爲 0x10000，但是隻把 `ax=0x0000` 的值儲存到了內存中，從結果看和無符號是一樣的。

再從數字層面看看這種溢出的結果，在有符號短整型中，`0xffff==-1，-1 + 1 == 0`，從有符號看這種計算沒問題。

但是在無符號短整型中，`0xffff == 65535, 65535 + 1 == 0`。

### 下界溢出

下屆溢出的道理和上界溢出一樣，在彙編代碼中，只是把 `add` 替換成了 `sub`。

一樣也是有兩種情況：

第一種是 `sub 0x0000, 1 == 0xffff`，對於有符號來說 `0 - 1 == -1` 沒問題，但是對於無符號來說就成了 `0 - 1 == 65535`。

第二種是 `sub 0x8000, 1 == 0x7fff`，對於無符號來說是 `32768 - 1 == 32767` 是正確的，但是對於有符號來說就變成了 `-32768 - 1 = 32767`。

## 例子

在我見過的整數溢出的漏洞中，我認爲可以總結爲兩種情況。

### 未限制範圍

這種情況很好理解，比如有一個固定大小的桶，往裏面倒水，如果你沒有限制倒入多少水，那麼水則會從桶中溢出來。

一個有固定大小的東西，你沒有對其進行約束，就會造成不可預期的後果。

簡單的寫一個示例:

```c
$ cat test.c
#include<stddef.h>
int main(void)
{
    int len;
    int data_len;
    int header_len;
    char *buf;
    
    header_len = 0x10;
    scanf("%uld", &data_len);
    
    len = data_len+header_len
    buf = malloc(len);
    read(0, buf, data_len);
    return 0;
}
$ gcc test.c
$ ./a.out
-1
asdfasfasdfasdfafasfasfasdfasdf
# gdb a.out
► 0x40066d <main+71>    call   malloc@plt <0x400500>
        size: 0xf
```

只申請 `0x20` 大小的堆，但是卻能輸入 `0xffffffff` 長度的數據，從整型溢出到堆溢出

### 錯誤的類型轉換

即使正確的對變量進行約束，也仍然有可能出現整數溢出漏洞，我認爲可以概括爲錯誤的類型轉換，如果繼續細分下去，可以分爲：

1. 範圍大的變量賦值給範圍小的變量

```c
$ cat test2.c
void check(int n)
{
    if (!n)
        printf("vuln");
    else
        printf("OK");
}

int main(void)
{
    long int a;
    
    scanf("%ld", &a);
    if (a == 0)
        printf("Bad");
    else
        check(a);
    return 0;
}
$ gcc test2.c
$ ./a.out
4294967296
vuln
```

上述代碼就是一個範圍大的變量(長整型a)，傳入 check 函數後變爲範圍小的變量(整型變量n)，造成整數溢出的例子。

已經長整型的佔有 8 byte 的內存空間，而整型只有 4 byte 的內存空間，所以當 long -> int，將會造成截斷，只把長整型的低 4byte 的值傳給整型變量。

在上述例子中，就是把 `long: 0x100000000 -> int: 0x00000000`。

但是當範圍更小的變量就能完全的把值傳遞給範圍更大的變量，而不會造成數據丟失。

2. 只做了單邊限制

這種情況只針對有符號類型

```c
$ cat test3.c
int main(void)
{
    int len, l;
    char buf[11];

    scanf("%d", &len);
    if (len < 10) {
        l = read(0, buf, len);
        *(buf+l) = 0;
        puts(buf);
    } else
        printf("Please len < 10");        
}
$ gcc test3.c
$ ./a.out
-1
aaaaaaaaaaaa
aaaaaaaaaaaa
```

從表面上看，我們對變量 len 進行了限制，但是仔細思考可以發現，len 是有符號整型，所以 len 的長度可以爲負數，但是在 read 函數中，第三個參數的類型是 `size_t`，該類型相當於 `unsigned long int`，屬於無符號長整型

上面舉例的兩種情況都有一個共性，就是函數的形參和實參的類型不同，所以我認爲可以總結爲錯誤的類型轉換

## CTF例題

題目：[Pwnhub 故事的開始 calc](http://atum.li/2016/12/05/calc/)
