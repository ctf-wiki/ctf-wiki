[EN](./introduction.md) | [ZH](./introduction-zh.md)
# FILE结构




## FILE Introduction


FILE is a structure for describing files in a standard IO library of a Linux system, called a file stream.
The FILE structure is created when the program executes functions such as fopen and is allocated in the heap. We often define a pointer to the FILE structure to receive this return value.


The FILE structure is defined in libio.h as shown below


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



The FILE structure in the process will be connected to each other through the _chain field to form a linked list. The linked list header is represented by the global variable _IO_list_all. Through this value, we can traverse all the FILE structures.


In the standard I/O library, three file streams are automatically opened at the start of each program: stdin, stdout, stderr. So in the initial state, _IO_list_all points to a linked list of these file streams, but it should be noted that these three file streams are located in the data segment of libc.so. The file stream we created with fopen is allocated on the heap memory.


We can find stdin\stdout\stderr and other symbols in libc.so, these symbols are pointers to the FILE structure, the symbol of the real structure is


```

_IO_2_1_stderr_
_IO_2_1_stdout_
_IO_2_1_stdin_
```





But in fact the _IO_FILE structure is wrapped around another structure _IO_FILE_plus, which contains an important pointer vtable pointing to a series of function pointers.


In libc2.23, the 32-bit vtable offset is 0x94 and the 64-bit offset is 0xd8.


```

struct _IO_FILE_plus
{

_IO_FILE file;
	IO_jump_t   *vtable;

}

```



Vtable is a pointer of type IO_jump_t, and some function pointers are stored in IO_jump_t. Later we will see that these function pointers are called in a series of standard IO functions.


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

9 NULL, // xsgetn
10 NULL, // seekoff
   11 NULL, // seekpos

12 NULL, // setbuf
   13 NULL, // sync

14 NULL, // target location
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



Fread is a standard IO library function that reads data from a file stream. The function prototype is as follows


```

size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;

```



* buffer Holds the buffer for reading data.


* size: specifies the length of each record.


* count: Specifies the number of records.


* stream: the target file stream.

* Return value: Returns the number of records read into the data buffer


The code for fread is located in /libio/iofread.c and the function name is _IO_fread, but the real function is implemented in the subfunction _IO_sgetn.


```

_IO_size_t

_IO_fread (buf, size, count, fp)

     void *buf;

     _IO_size_t size;

     _IO_size_t count;

_IO_FILE * fp;
{

  ...

  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);

  ...

}

```



_IO_XSGETN is called in the _IO_sgetn function, and _IO_XSGETN is a function pointer in _IO_FILE_plus.vtable. When this function is called, the pointer in the vtable is first fetched and then called.


```

_IO_size_t

_IO_sgetn (fp, date, n)
_IO_FILE * fp;
     void *data;

     _IO_size_t n;

{

  return _IO_XSGETN (fp, data, n);

}

```



By default the function pointer points to the _IO_file_xsgetn function.


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



Fwrite is also a standard IO library function, the function is to write data to the file stream, the function prototype is as follows


```

size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);

```



* buffer: is a pointer, for fwrite, is the address to write data;


* size: the number of single bytes to write to the content;


* count: the number of data items to be written to size bytes;


* stream: target file pointer;


* Return value: count of the number of data items actually written.




The code for fwrite is located in /libio/iofwrite.c and the function name is _IO_fwrite.
In _IO_fwrite, _IO_XSPUTN is mainly called to implement the write function.


According to the introduction of _IO_FILE_plus, it can be seen that _IO_XSPUTN is located in the vtable of _IO_FILE_plus. To call this function, you need to first take out the pointer in the vtable and then jump over to make the call.


```

written = _IO_sputn (fp, (const char *) buf, request);

```



The _IO_OVERFLOW, also located in the vtable, is called in the default function _IO_new_file_xsputn corresponding to _IO_XSPUTN.


```

 /* Next flush the (full) buffer. */

      if (_IO_OVERFLOW (f, EOF) == EOF)

```





The default function of _IO_OVERFLOW is _IO_new_file_overflow


```

if (ch == EOF)

    return _IO_do_write (f, f->_IO_write_base,

			 f->_IO_write_ptr - f->_IO_write_base);

  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */

    if (_IO_do_flush (f) == EOF)

      return EOF;

```

The system interface write function will eventually be called inside _IO_new_file_overflow.






## fopen



Fopen is used to open files in the standard IO library. The function prototype is as follows


```   

FILE *fopen(char *filename, *type);

```



* filename: the path to the target file


* type: type of open method


* Return value: return a file pointer


Inside the fopen will create a FILE structure and perform some initialization operations, let&#39;s take a look at this process


First, the malloc function is called inside the fopen corresponding function __fopen_internal, and the space of the FILE structure is allocated. So we can know that the FILE structure is stored on the heap.


```

*new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

```



After that, the vtable will be initialized for the created FILE, and _IO_file_init will be called to further initialize the operation.
```

_IO_JUMPS (&new_f->fp) = &_IO_file_jumps;

_IO_file_init (&new_f->fp);

```



In the initialization operation of the _IO_file_init function, _IO_link_in is called to link the newly allocated FILE into _IO_list_all as the starting FILE list.
```

void

_IO_link_in (fp)     struct _IO_FILE_plus *fp;

{

    if ((fp->file._flags & _IO_LINKED) == 0)

    {

      fp->file._flags |= _IO_LINKED;

fp-&gt; file._chain = (_IO_FILE *) _IO_list_all;
      _IO_list_all = fp;

      ++_IO_list_all_stamp;

    }

}

```



After that, the __fopen_internal function will call the _IO_file_fopen function to open the target file. _IO_file_fopen will open according to the open mode passed by the user. In the end, it will call the system interface open function, which is not deepened here.
```

if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)

    return __fopen_maybe_mmap (&new_f->fp.file);

```



Summarize the operation of fopen is


* Use malloc to allocate FILE structure
* Set the vtable of the FILE structure
* Initialize the allocated FILE structure
* Link the initialized FILE structure into the FILE structure list
* Call system call to open file


## fclose



Fclose is a function in the standard IO library for closing open files, which is the opposite of fopen.


```

int fclose(FILE *stream)

```

Function: Close a file stream, use fclose to output the last remaining data in the buffer to the disk file, and release the file pointer and related buffer






Fclose will first call _IO_unlink_it to delink the specified FILE from the _chain list.


```

if (fp->_IO_file_flags & _IO_IS_FILEBUF)

_IO_un_link ((struct _IO_FILE_plus *) fp);
```



After that, the _IO_file_close_it function will be called, and _IO_file_close_it will call the system interface close to close the file.


```

if (fp->_IO_file_flags & _IO_IS_FILEBUF)

    status = _IO_file_close_it (fp);

```



Finally, the _IO_FINISH in the vtable is called, which corresponds to the _IO_file_finish function, which will call the free function to release the previously allocated FILE structure.


```

_IO_FINISH (fp);
```





## printf/puts



Printf and puts are commonly used output functions. When the printf argument is a pure string ending with &#39;\n&#39;, printf will be optimized to puts the function and remove the newline.




The function that puts implements in the source code is _IO_puts. The operation of this function is roughly the same as that of fwrite. The function also calls _IO_sputn in the vtable. The result is _IO_new_file_xsputn, and finally the system interface write function is called.


Printf&#39;s call stack traceback is as follows, also implemented by _IO_file_xsputn


```

vfprintf+11

_IO_file_xsputn
_IO_file_overflow

funlockfile

_IO_file_write

write

```




