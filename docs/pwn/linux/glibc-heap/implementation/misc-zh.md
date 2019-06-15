[EN](./misc.md) | [ZH](./misc-zh.md)
# 测试支持

下面的代码用于支持测试，默认情况下 perturb_byte 是0。

```c
static int perturb_byte;

static void alloc_perturb(char *p, size_t n) {
    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte ^ 0xff, n);
}

static void free_perturb(char *p, size_t n) {
    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte, n);
}
```



