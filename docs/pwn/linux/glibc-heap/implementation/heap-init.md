# 堆初始化

堆初始化是在用户第一次申请内存时执行 malloc_consolidate 再执行 malloc_init_state 实现的。这里不做过多讲解。可以参见 `malloc_state` 相关函数。