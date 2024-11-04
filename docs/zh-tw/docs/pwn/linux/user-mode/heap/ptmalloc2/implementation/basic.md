# 基礎操作

## unlink

unlink 用來將一個雙向鏈表（只存儲空閒的 chunk）中的一個元素取出來，可能在以下地方使用

- malloc
    - 從恰好大小合適的 large bin 中獲取 chunk。
        - **這裏需要注意的是 fastbin 與 small bin 就沒有使用 unlink，這就是爲什麼漏洞會經常出現在它們這裏的原因。**
        - 依次遍歷處理 unsorted bin 時也沒有使用 unlink 。
    - 從比請求的 chunk 所在的 bin 大的 bin 中取 chunk。
- free
    - 後向合併，合併物理相鄰低地址空閒 chunk。
    - 前向合併，合併物理相鄰高地址空閒 chunk（除了 top chunk）。
- malloc_consolidate
    - 後向合併，合併物理相鄰低地址空閒 chunk。
    - 前向合併，合併物理相鄰高地址空閒 chunk（除了 top chunk）。
- realloc
    - 前向擴展，合併物理相鄰高地址空閒 chunk（除了top chunk）。

由於 unlink 使用非常頻繁，所以 unlink 被實現爲了一個宏，如下

```c
/* Take a chunk off a bin list */
// unlink p
#define unlink(AV, P, BK, FD) {                                            \
    // 由於 P 已經在雙向鏈表中，所以有兩個地方記錄其大小，所以檢查一下其大小是否一致。
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;                                                                      \
    BK = P->bk;                                                                      \
    // 防止攻擊者簡單篡改空閒的 chunk 的 fd 與 bk 來實現任意寫的效果。
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {                                                                      \
        FD->bk = BK;                                                              \
        BK->fd = FD;                                                              \
        // 下面主要考慮 P 對應的 nextsize 雙向鏈表的修改
        if (!in_smallbin_range (chunksize_nomask (P))                              \
            // 如果P->fd_nextsize爲 NULL，表明 P 未插入到 nextsize 鏈表中。
            // 那麼其實也就沒有必要對 nextsize 字段進行修改了。
            // 這裏沒有去判斷 bk_nextsize 字段，可能會出問題。
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                      \
            // 類似於小的 chunk 的檢查思路
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);                                              \
            // 這裏說明 P 已經在 nextsize 鏈表中了。
            // 如果 FD 沒有在 nextsize 鏈表中
            if (FD->fd_nextsize == NULL) {                                      \
                // 如果 nextsize 串起來的雙鏈表只有 P 本身，那就直接拿走 P
                // 令 FD 爲 nextsize 串起來的
                if (P->fd_nextsize == P)                                      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;                      \
                else {                                                              \
                // 否則我們需要將 FD 插入到 nextsize 形成的雙鏈表中
                    FD->fd_nextsize = P->fd_nextsize;                              \
                    FD->bk_nextsize = P->bk_nextsize;                              \
                    P->fd_nextsize->bk_nextsize = FD;                              \
                    P->bk_nextsize->fd_nextsize = FD;                              \
                  }                                                              \
              } else {                                                              \
                // 如果在的話，直接拿走即可
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;                      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;                      \
              }                                                                      \
          }                                                                      \
      }                                                                              \
}
```

這裏我們以 small bin 的 unlink 爲例子介紹一下。對於 large bin 的 unlink，與其類似，只是多了一個nextsize 的處理。

![](./figure/unlink_smallbin_intro.png)

可以看出， **P 最後的 fd 和 bk 指針並沒有發生變化**，但是當我們去遍歷整個雙向鏈表時，已經遍歷不到對應的鏈表了。這一點沒有變化還是很有用處的，因爲我們有時候可以使用這個方法來泄漏地址

- libc 地址
    - P 位於雙向鏈表頭部，bk 泄漏
    - P 位於雙向鏈表尾部，fd 泄漏
    - 雙向鏈表只包含一個空閒 chunk 時，P 位於雙向鏈表中，fd 和 bk 均可以泄漏
- 泄漏堆地址，雙向鏈表包含多個空閒 chunk
    - P 位於雙向鏈表頭部，fd 泄漏
    - P 位於雙向鏈表中，fd 和 bk 均可以泄漏
    - P 位於雙向鏈表尾部，bk 泄漏

**注意**

- 這裏的頭部指的是 bin 的 fd 指向的 chunk，即雙向鏈表中最新加入的 chunk。
- 這裏的尾部指的是 bin 的 bk 指向的 chunk，即雙向鏈表中最先加入的 chunk。

同時，無論是對於 fd，bk 還是 fd_nextsize ，bk_nextsize，程序都會檢測 fd 和 bk 是否滿足對應的要求。

```c
// fd bk
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \

  // next_size related
              if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              \
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,                                      \
                               "corrupted double-linked list (not small)",    \
                               P, AV);
```

看起來似乎很正常。我們以 fd 和 bk 爲例，P 的 forward chunk 的 bk 很自然是 P ，同樣 P 的 backward chunk 的 fd 也很自然是 P 。如果沒有做相應的檢查的話，我們可以修改 P 的 fd 與 bk，從而可以很容易地達到任意地址寫的效果。關於更加詳細的例子，可以參見利用部分的 unlink 。

**注意：堆的第一個 chunk 所記錄的 prev_inuse 位默認爲1。**

## malloc_printerr

在 glibc malloc 時檢測到錯誤的時候，會調用 `malloc_printerr` 函數。

```cpp
static void malloc_printerr(const char *str) {
  __libc_message(do_abort, "%s\n", str);
  __builtin_unreachable();
}
```

主要會調用 `__libc_message` 來執行`abort` 函數，如下

```c
  if ((action & do_abort)) {
    if ((action & do_backtrace))
      BEFORE_ABORT(do_abort, written, fd);

    /* Kill the application.  */
    abort();
  }
```

在`abort` 函數裏，在 glibc 還是2.23 版本時，會 fflush stream。

```c
  /* Flush all streams.  We cannot close them now because the user
     might have registered a handler for SIGABRT.  */
  if (stage == 1)
    {
      ++stage;
      fflush (NULL);
    }
```

