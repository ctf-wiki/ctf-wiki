[EN](./heap-init.md) | [ZH](./heap-init-zh.md)
#堆 initialization


The heap initialization is performed by executing malloc_consolidate and then executing malloc_init_state when the user first requests memory. I won’t explain too much here. See the `malloc_state` correlation function.