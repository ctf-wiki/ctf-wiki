# Detecting Breakpoints

gdb通過替換目標地址的字節爲`0xcc`來實現斷點, 這裏給出一個簡單的檢測`int 3`斷點的示例:

``` c
void foo() {
    printf("Hello\n");
}
int main() {
    if ((*(volatile unsigned *)((unsigned)foo) & 0xff) == 0xcc) {
        printf("BREAKPOINT\n");
        exit(1);
    }
    foo();
}
```

正常運行程序會輸出Hello, 但是如果之前有在`foo`函數這裏設置`cc`斷點並運行, gdb則無法斷下, 並會輸出`BREAKPOINT`. 

```
# gdb ./x
gdb> bp foo
Breakpoint 1 at 0x804838c
gdb> run
BREAKPOINT
Program exited with code 01.
```

這個要繞過也很簡單, 那就是需要閱讀彙編代碼並注意設置斷點不要在`foo`函數入口處. 實際情況就要看檢測斷點的位置是哪裏.

這種監視斷點的反調試技術, 關鍵不在於如何繞過它, 而是在於如何檢測它. 在這個示例中可以很輕鬆的發現, 程序也有打印出相應的信息. 在實際情況中, 程序不會輸出任何信息, 斷點也無法輕易地斷下. 我們可以使用`perl`腳本過濾反彙編代碼中有關`0xcc`的代碼出來進行檢查.

我們可以使用perl腳本過濾反彙編代碼中有關0xcc的代碼出來進行檢查


``` perl
#!/usr/bin/perl
while(<>)
{
    if($_ =~ m/([0-9a-f][4]:\s*[0-9a-f \t]*.*0xcc)/ ){ print; }
}
```

顯示結果

```
# objdump -M intel -d xxx | ./antibp.pl
      80483be: 3d cc 00 00 00 cmp eax,0xcc
```

檢測到後, 既可以將0xcc修改成0x00或0x90, 也可以做任何你想做的操作.

改變0xcc也同樣可能帶來問題, 就如上篇介紹一樣, 程序如果有進行文件校驗, 那麼我們的改變是會被檢測到的. 可能的情況下, 程序也不只是對函數入口點進行檢測, 也會在一個循環裏對整個函數進行檢測.

因此你也可以用十六進制編輯器手動放置一個`ICEBP(0xF1)`字節到需要斷下的位置(而非`int 3`). 因爲`ICEBP`也一樣能讓gdb斷下來.



> Reference: [Beginners Guide to Basic Linux Anti Anti Debugging Techniques](http://www.stonedcoder.org/~kd/lib/14-61-1-PB.pdf)