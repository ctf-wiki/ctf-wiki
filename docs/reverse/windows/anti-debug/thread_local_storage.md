[EN](./thread_local_storage.md) | [ZH](./thread_local_storage-zh.md)
# Thread Local Storage(TLS)



Thread Local Storage (TLS) is used to initialize specific thread data before the thread starts, because each process contains at least 1 thread, which initializes the data before the main thread runs. Initialization can be done by specifying a copy that has been copied to dynamically allocated memory. The static buffer in the middle, and / or by executing the code in the callback function array to initialize the dynamic memory content. Often caused by the abuse of the callback function array.


At runtime, the contents of the TLS callback function array can be modified or added. The newly added or newly modified callback function will be called with the new address. There is no limit to the number of callback functions. The expansion of the array can be done with the following code:


`` `asm
l1: mov d [offset cbEnd], offset l2

right
l2: ...
```



When the callback at l1 returns, it will continue to call the callback function of l2.


> todo: continue to finish it




