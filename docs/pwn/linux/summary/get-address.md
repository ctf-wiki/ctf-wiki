[EN](./get-address.md) | [ZH](./get-address-zh.md)
# Get address


In the process of exploiting, we often need to get some variables, the address of the function, so that it can be further utilized. Here I will divide the methods for obtaining addresses into the following categories.


- Find the address directly, that is, we can directly see the address of the corresponding symbol by means of decompilation.
- Leak address, which requires us to leak the contents of some symbol pointers in the program by controlling the execution flow of the program to obtain the corresponding address.
- Speculative address, which we generally use here is based on the offset between the symbols in a segment is fixed, in order to infer the address of some new symbols.
- Guess the address, generally speaking, we need to guess the address of the corresponding symbol, which is often accompanied by violent enumeration.


The above methods are a kind of progressive consideration. We should maintain this way of thinking when obtaining the address of the relevant symbol.


In the above several ways, I think there are two main core ideas.


- Take full advantage of the nature of the code itself, such as the location of some code in the program is fixed, such as the location of the code segment when PIE is not turned on; for example, the last three bits of glibc are fixed.
- Take advantage of the nature of relative offsets. This is due to the fact that the memory that is currently loaded during program loading is a segment, so the relative offset is often fixed.


More specific, we can look at the following introduction.


## Directly looking for an address


The address of the relevant variable or function has been given in the program. At this time, we can use it directly.


This situation often applies when the program does not open PIE.


## Leak address


In the process of leaking addresses, we often need to find sensitive pointers that store either the address of the symbol we want or the address of the symbol we want.


Here are a few examples.


### Leaking variable pointer


such as


1. Leaking the header table pointers of various bins in the main arena, you may be able to get the address of a variable in the heap or glibc.


### leaking got table


Sometimes we don&#39;t have to know the address of a function directly. We can use the GOT table to jump to the address of the corresponding function. Of course, if we have to know the address of this function, we can use the output function such as write, puts and so on to output the corresponding content in the address of the GOT table (** premise that this function has been parsed once).


### ret2dl-resolve 



When the ELF file is dynamically linked, the got table uses the delay binding technique. When the libc function is called for the first time, the program calls the _dl_runtime_resolve function to resolve its address. Therefore, we can use the stack overflow to construct the ROP chain and forge the parsing of other functions (such as: system). This is also the technique we introduced in the advanced rop.


### /proc/self/maps



We can consider getting the base address associated with the program by reading the program&#39;s `/proc/self/maps`.


## Speculative address


In most cases, we can&#39;t directly get the address of the desired function, and often need to make some address speculation. As mentioned above, the emphasis here is on the idea that the offset between symbols is fixed.


### Stack Related



Regarding the address on the stack, in fact, most of the time we do not need a specific stack address, but we can guess the position of a variable on the stack relative to the EBP according to the addressing mode of the stack.


### Glibc Related



The main consideration here is how to find related functions in Glibc.


#### 有libc


At this time we need to consider using the same function as the base address of the function in libc. For example, we can leak the base address of libc in memory by the address of __libc_start_main.


**Note: Do not select a function with wapper, which will make the base address of the function incorrectly calculated. **


What are the common wapper functions? (To be added).


#### 无libc


In fact, the solution strategy for this situation is divided into two types.


- Find a way to get libc
- Find a way to get the corresponding address directly.


For the address that we want to leak, we simply need the corresponding content, so puts, write, printf can be.


- puts, printf will have \x00 truncation problem
- write can specify the length of the output.


Here are some corresponding methods


##### `pwnlib.dynelf`


The premise is that we can divulge the contents of any address.


- ** If you want to use the write function to leak, it is better to output some address content at a time, because we generally just continuously read the content to the high address, it is likely to cause the high address environment variable to be overwritten, which will lead to the shell. Can not start. **


##### libc database


```shell

#Update database
./get

# Add existing libc to the database
./add libc.so 

# Find all the libc's in the database that have the given names at the given addresses. 

./find function1 addr function2 addr

# Dump some useful offsets, given a libc ID. You can also provide your own names to dump.

./dump __libc_start_main_ret system dup2

```



Go to the libc database and find the corresponding libc with the same address that already appears. This is probably the same.


You can also use the following online website:


- [libcdb.com] (http://libcdb.com)
- [libc.blukat.me](https://libc.blukat.me)



** Of course, there are also https://github.com/lieanu/LibcSearcher mentioned above. **


### Heap related



Regarding the speculation of some addresses of the heap, this requires us to know in more detail how much memory is allocated in the heap, which block of the memory address is currently leaked, and then obtain the base address of the heap, and the relevant memory address in the heap.


## Guess the address


In some strange cases, we may be able to use the following


- Use some violent methods to get the address, such as 32-bit, the address randomization space is relatively small.
- When a program is specially deployed, the location where its different libraries are loaded may be special. We can try it locally and guess the situation at the remote.