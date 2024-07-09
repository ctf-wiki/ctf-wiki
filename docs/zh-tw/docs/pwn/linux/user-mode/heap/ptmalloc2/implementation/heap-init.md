# 堆初始化

堆初始化是在用戶第一次申請內存時執行 malloc_consolidate 再執行 malloc_init_state 實現的。這裏不做過多講解。可以參見 `malloc_state` 相關函數。