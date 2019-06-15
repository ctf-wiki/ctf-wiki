[EN](./hijack-control-flow.md) | [ZH](./hijack-control-flow-zh.md)
# Control program execution flow


In the process of controlling the execution flow of the program, we can consider the following ways.


## Direct control EIP






## return address


That is, control the return address on the program stack.


## Jump pointer


Here we can consider the following way


- call 

- jmp


## function pointer


Common function pointers have


- vtable,  function table，如 IO_FILE 的 vtable，printf function table。

- hook pointers, such as `malloc_hook`, `free_hook`.
- acting


## Modify control flow related variables