[EN](./introduction.md) | [ZH](./introduction-zh.md)
# FILE结构


## FILE介绍

FILE在Linux系统的标准IO库中是用于描述文件的结构，称为文件流。
FILE结构在程序执行fopen等函数时会进行创建，并分配在堆中。我们常定义一个指向FILE结构的指针来接收这个返回值。

FILE结构定义在libio.h中，如下所示

```
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

进程中的FILE结构会通过_chain域彼此连接形成一个链表，链表头部用全局变量_IO_list_all表示，通过这个值我们可以遍历所有的FILE结构。

在标准I/O库中，每个程序启动时有三个文件流是自动打开的：stdin、stdout、stderr。因此在初始状态下，_IO_list_all指向了一个有这些文件流构成的链表，但是需要注意的是这三个文件流位于libc.so的数据段。而我们使用fopen创建的文件流是分配在堆内存上的。

我们可以在libc.so中找到stdin\stdout\stderr等符号，这些符号是指向FILE结构的指针，真正结构的符号是

```
_IO_2_1_stderr_
_IO_2_1_stdout_
_IO_2_1_stdin_
```


但是事实上_IO_FILE结构外包裹着另一种结构_IO_FILE_plus，其中包含了一个重要的指针vtable指向了一系列函数指针。

在libc2.23版本下，32位的vtable偏移为0x94，64位偏移为0xd8

```
struct _IO_FILE_plus
{
	_IO_FILE    file;
	IO_jump_t   *vtable;
}
```

vtable是IO_jump_t类型的指针，IO_jump_t中保存了一些函数指针，在后面我们会看到在一系列标准IO函数中会调用这些函数指针

```
void * funcs[] = {
   1 NULL, // "extra word"
   2 NULL, // DUMMY
   3 exit, // finish
   4 NULL, // overflow
   5 NULL, // underflow
   6 NULL, // uflow
   7 NULL, // pbackfail
   
   8 NULL, // xsputn  #printf
   9 NULL, // xsgetn
   10 NULL, // seekoff
   11 NULL, // seekpos
   12 NULL, // setbuf
   13 NULL, // sync
   14 NULL, // doallocate
   15 NULL, // read
   16 NULL, // write
   17 NULL, // seek
   18 pwn,  // close
   19 NULL, // stat
   20 NULL, // showmanyc
   21 NULL, // imbue
};
```



## fread

fread是标准IO库函数，作用是从文件流中读数据，函数原型如下

```
size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;
```

* buffer 存放读取数据的缓冲区。

* size：指定每个记录的长度。

* count： 指定记录的个数。

* stream：目标文件流。

* 返回值：返回读取到数据缓冲区中的记录个数

fread的代码位于/libio/iofread.c中，函数名为_IO_fread，但真正的功能实现在子函数_IO_sgetn中。

```
_IO_size_t
_IO_fread (buf, size, count, fp)
     void *buf;
     _IO_size_t size;
     _IO_size_t count;
     _IO_FILE *fp;
{
  ...
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  ...
}
```

在_IO_sgetn函数中会调用_IO_XSGETN，而_IO_XSGETN是_IO_FILE_plus.vtable中的函数指针，在调用这个函数时会首先取出vtable中的指针然后再进行调用。

```
_IO_size_t
_IO_sgetn (fp, data, n)
     _IO_FILE *fp;
     void *data;
     _IO_size_t n;
{
  return _IO_XSGETN (fp, data, n);
}
```

在默认情况下函数指针是指向_IO_file_xsgetn函数的，

```
  if (fp->_IO_buf_base
	      && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
	    {
	      if (__underflow (fp) == EOF)
		break;

	      continue;
	    }
```


## fwrite

fwrite同样是标准IO库函数，作用是向文件流写入数据，函数原型如下

```
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
```

* buffer:是一个指针，对fwrite来说，是要写入数据的地址;

* size:要写入内容的单字节数;

* count:要进行写入size字节的数据项的个数;

* stream:目标文件指针;

* 返回值：实际写入的数据项个数count。


fwrite的代码位于/libio/iofwrite.c中，函数名为_IO_fwrite。
在_IO_fwrite中主要是调用_IO_XSPUTN来实现写入的功能。

根据前面对_IO_FILE_plus的介绍，可知_IO_XSPUTN位于_IO_FILE_plus的vtable中，调用这个函数需要首先取出vtable中的指针，再跳过去进行调用。

```
written = _IO_sputn (fp, (const char *) buf, request);
```

在_IO_XSPUTN对应的默认函数_IO_new_file_xsputn中会调用同样位于vtable中的_IO_OVERFLOW

```
 /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
```


_IO_OVERFLOW默认对应的函数是_IO_new_file_overflow

```
if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
```
在_IO_new_file_overflow内部最终会调用系统接口write函数



## fopen

fopen在标准IO库中用于打开文件，函数原型如下

```   
FILE *fopen(char *filename, *type);
```

* filename:目标文件的路径

* type:打开方式的类型

* 返回值:返回一个文件指针

在fopen内部会创建FILE结构并进行一些初始化操作，下面来看一下这个过程

首先在fopen对应的函数__fopen_internal内部会调用malloc函数，分配FILE结构的空间。因此我们可以获知FILE结构是存储在堆上的

```
*new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
```

之后会为创建的FILE初始化vtable，并调用_IO_file_init进一步初始化操作
```
_IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
_IO_file_init (&new_f->fp);
```

在_IO_file_init函数的初始化操作中，会调用_IO_link_in把新分配的FILE链入_IO_list_all为起始的FILE链表中
```
void
_IO_link_in (fp)
     struct _IO_FILE_plus *fp;
{
    if ((fp->file._flags & _IO_LINKED) == 0)
    {
      fp->file._flags |= _IO_LINKED;
      fp->file._chain = (_IO_FILE *) _IO_list_all;
      _IO_list_all = fp;
      ++_IO_list_all_stamp;
    }
}
```

之后__fopen_internal函数会调用_IO_file_fopen函数打开目标文件，_IO_file_fopen会根据用户传入的打开模式进行打开操作，总之最后会调用到系统接口open函数，这里不再深入。
```
if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);
```

总结一下fopen的操作是

* 使用malloc分配FILE结构
* 设置FILE结构的vtable
* 初始化分配的FILE结构
* 将初始化的FILE结构链入FILE结构链表中
* 调用系统调用打开文件

## fclose

fclose是标准IO库中用于关闭已打开文件的函数，其作用与fopen相反。

```
int fclose(FILE *stream)
```
功能：关闭一个文件流，使用fclose就可以把缓冲区内最后剩余的数据输出到磁盘文件中，并释放文件指针和有关的缓冲区



fclose首先会调用_IO_unlink_it将指定的FILE从_chain链表中脱链

```
if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);
```

之后会调用_IO_file_close_it函数，_IO_file_close_it会调用系统接口close关闭文件

```
if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
```

最后调用vtable中的_IO_FINISH，其对应的是_IO_file_finish函数，其中会调用free函数释放之前分配的FILE结构

```
_IO_FINISH (fp);
```


## printf/puts

printf和puts是常用的输出函数，在printf的参数是以'\n'结束的纯字符串时，printf会被优化为puts函数并去除换行符。


puts在源码中实现的函数是_IO_puts，这个函数的操作与fwrite的流程大致相同，函数内部同样会调用vtable中的_IO_sputn，结果会执行_IO_new_file_xsputn，最后会调用到系统接口write函数。

printf的调用栈回溯如下，同样是通过_IO_file_xsputn实现

```
vfprintf+11
_IO_file_xsputn
_IO_file_overflow
funlockfile
_IO_file_write
write
```


