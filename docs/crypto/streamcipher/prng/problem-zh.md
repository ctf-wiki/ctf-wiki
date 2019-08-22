[EN](./problem.md) | [ZH](./problem-zh.md)
# 题目

## 2017 Tokyo Westerns CTF 3rd Backpacker's Problem

题目中给了一个 cpp 文件，大概意思如下

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

即是一个背包问题。其中，在本题中，我们需要解决 20 个这样的背包问题，背包大小依次是 1 * 10~20 * 10。而子集求和的背包问题是一个 NPC 问题，问题的时间复杂度随着随着背包大小而指数增长。这里背包的大小最大是200，显然不可能使用暴力破解的方式。

**待完成**

## 参考文献

-   https://github.com/r00ta/myWriteUps/tree/master/GoogleCTF/woodman
-   http://mslc.ctf.su/wp/google-ctf-woodman-crypto-100/