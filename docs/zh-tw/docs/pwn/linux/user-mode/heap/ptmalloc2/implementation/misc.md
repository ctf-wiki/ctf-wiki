# 測試支持

下面的代碼用於支持測試，默認情況下 perturb_byte 是0。

```c
static int perturb_byte;

static void alloc_perturb(char *p, size_t n) {
    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte ^ 0xff, n);
}

static void free_perturb(char *p, size_t n) {
    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte, n);
}
```



