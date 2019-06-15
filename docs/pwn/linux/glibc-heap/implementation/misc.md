[EN](./misc.md) | [ZH](./misc-zh.md)
#测试支持


The following code is used to support testing. Perturb_byte is 0 by default.


```c

static int perturb_byte;



static void alloc_perturb(char *p, size_t n) {

    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte ^ 0xff, n);

}



static void free_perturb(char *p, size_t n) {

    if (__glibc_unlikely(perturb_byte)) memset(p, perturb_byte, n);

}

```






