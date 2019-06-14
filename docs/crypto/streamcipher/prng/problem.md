[EN](./problem.md) | [ZH](./problem-zh.md)
#题


## 2017 Tokyo Westerns CTF 3rd Backpacker's Problem



A cpp file is given in the title, which probably means the following


```

Given the integers a_1, a_2, ..., a_N, your task is to find a subsequence b of a

where b_1 + b_2 + ... + b_K = 0.



Input Format: N a_1 a_2 ... a_N

Answer Format: K b_1 b_2 ... b_K



Example Input:

4 -8 -2 3 5

Example Answer:

3 -8 3 5

```



It is a backpack problem. Among them, in this question, we need to solve 20 such backpack problems, the size of the backpack is 1 * 10 ~ 20 * 10 in order. The backpack problem of subset summation is an NPC problem, and the time complexity of the problem increases exponentially with the size of the backpack. The size of the backpack here is at most 200, and it is obviously impossible to use brute force.


**To be completed**


## references


-   https://github.com/r00ta/myWriteUps/tree/master/GoogleCTF/woodman

-   http://mslc.ctf.su/wp/google-ctf-woodman-crypto-100/