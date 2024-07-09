# FILE結構


## FILE介紹

FILE在Linux系統的標準IO庫中是用於描述文件的結構，稱爲文件流。
FILE結構在程序執行fopen等函數時會進行創建，並分配在堆中。我們常定義一個指向FILE結構的指針來接收這個返回值。

FILE結構定義在libio.h中，如下所示

```c
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
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;

  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};
```

進程中的FILE結構會通過_chain域彼此連接形成一個鏈表，鏈表頭部用全局變量_IO_list_all表示，通過這個值我們可以遍歷所有的FILE結構。

在標準I/O庫中，每個程序啓動時有三個文件流是自動打開的：stdin、stdout、stderr。因此在初始狀態下，_IO_list_all指向了一個有這些文件流構成的鏈表，但是需要注意的是這三個文件流位於libc.so的數據段。而我們使用fopen創建的文件流是分配在堆內存上的。

我們可以在libc.so中找到stdin\stdout\stderr等符號，這些符號是指向FILE結構的指針，真正結構的符號是

```
_IO_2_1_stderr_
_IO_2_1_stdout_
_IO_2_1_stdin_
```


但是事實上_IO_FILE結構外包裹着另一種結構_IO_FILE_plus，其中包含了一個重要的指針vtable指向了一系列函數指針。

在libc2.23版本下，32位的vtable偏移爲0x94，64位偏移爲0xd8

```
struct _IO_FILE_plus
{
	_IO_FILE    file;
	IO_jump_t   *vtable;
}
```

vtable是IO_jump_t類型的指針，IO_jump_t中保存了一些函數指針，在後面我們會看到在一系列標準IO函數中會調用這些函數指針

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

fread是標準IO庫函數，作用是從文件流中讀數據，函數原型如下

```
size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;
```

* buffer 存放讀取數據的緩衝區。

* size：指定每個記錄的長度。

* count： 指定記錄的個數。

* stream：目標文件流。

* 返回值：返回讀取到數據緩衝區中的記錄個數

fread的代碼位於/libio/iofread.c中，函數名爲_IO_fread，但真正的功能實現在子函數_IO_sgetn中。

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

在_IO_sgetn函數中會調用_IO_XSGETN，而_IO_XSGETN是_IO_FILE_plus.vtable中的函數指針，在調用這個函數時會首先取出vtable中的指針然後再進行調用。

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

在默認情況下函數指針是指向_IO_file_xsgetn函數的，

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

fwrite同樣是標準IO庫函數，作用是向文件流寫入數據，函數原型如下

```
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
```

* buffer:是一個指針，對fwrite來說，是要寫入數據的地址;

* size:要寫入內容的單字節數;

* count:要進行寫入size字節的數據項的個數;

* stream:目標文件指針;

* 返回值：實際寫入的數據項個數count。


fwrite的代碼位於/libio/iofwrite.c中，函數名爲_IO_fwrite。
在_IO_fwrite中主要是調用_IO_XSPUTN來實現寫入的功能。

根據前面對_IO_FILE_plus的介紹，可知_IO_XSPUTN位於_IO_FILE_plus的vtable中，調用這個函數需要首先取出vtable中的指針，再跳過去進行調用。

```
written = _IO_sputn (fp, (const char *) buf, request);
```

在_IO_XSPUTN對應的默認函數_IO_new_file_xsputn中會調用同樣位於vtable中的_IO_OVERFLOW

```
 /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
```


_IO_OVERFLOW默認對應的函數是_IO_new_file_overflow

```
if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
```
在_IO_new_file_overflow內部最終會調用系統接口write函數



## fopen

fopen在標準IO庫中用於打開文件，函數原型如下

```   
FILE *fopen(char *filename, *type);
```

* filename:目標文件的路徑

* type:打開方式的類型

* 返回值:返回一個文件指針

在fopen內部會創建FILE結構並進行一些初始化操作，下面來看一下這個過程

首先在fopen對應的函數__fopen_internal內部會調用malloc函數，分配FILE結構的空間。因此我們可以獲知FILE結構是存儲在堆上的

```
*new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));
```

之後會爲創建的FILE初始化vtable，並調用_IO_file_init進一步初始化操作
```
_IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
_IO_file_init (&new_f->fp);
```

在_IO_file_init函數的初始化操作中，會調用_IO_link_in把新分配的FILE鏈入_IO_list_all爲起始的FILE鏈表中
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

之後__fopen_internal函數會調用_IO_file_fopen函數打開目標文件，_IO_file_fopen會根據用戶傳入的打開模式進行打開操作，總之最後會調用到系統接口open函數，這裏不再深入。
```
if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);
```

總結一下fopen的操作是

* 使用malloc分配FILE結構
* 設置FILE結構的vtable
* 初始化分配的FILE結構
* 將初始化的FILE結構鏈入FILE結構鏈表中
* 調用系統調用打開文件

## fclose

fclose是標準IO庫中用於關閉已打開文件的函數，其作用與fopen相反。

```
int fclose(FILE *stream)
```
功能：關閉一個文件流，使用fclose就可以把緩衝區內最後剩餘的數據輸出到磁盤文件中，並釋放文件指針和有關的緩衝區



fclose首先會調用_IO_unlink_it將指定的FILE從_chain鏈表中脫鏈

```
if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);
```

之後會調用_IO_file_close_it函數，_IO_file_close_it會調用系統接口close關閉文件

```
if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
```

最後調用vtable中的_IO_FINISH，其對應的是_IO_file_finish函數，其中會調用free函數釋放之前分配的FILE結構

```
_IO_FINISH (fp);
```


## printf/puts

printf和puts是常用的輸出函數，在printf的參數是以'\n'結束的純字符串時，printf會被優化爲puts函數並去除換行符。


puts在源碼中實現的函數是_IO_puts，這個函數的操作與fwrite的流程大致相同，函數內部同樣會調用vtable中的_IO_sputn，結果會執行_IO_new_file_xsputn，最後會調用到系統接口write函數。

printf的調用棧回溯如下，同樣是通過_IO_file_xsputn實現

```
vfprintf+11
_IO_file_xsputn
_IO_file_overflow
funlockfile
_IO_file_write
write
```


