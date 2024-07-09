# 題目

## 2017 Tokyo Westerns CTF 3rd Backpacker's Problem

題目中給了一個 cpp 文件，大概意思如下

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

即是一個揹包問題。其中，在本題中，我們需要解決 20 個這樣的揹包問題，揹包大小依次是 1 * 10~20 * 10。而子集求和的揹包問題是一個 NPC 問題，問題的時間複雜度隨着隨着揹包大小而指數增長。這裏揹包的大小最大是200，顯然不可能使用暴力破解的方式。

**待完成**

## 參考文獻

-   https://github.com/r00ta/myWriteUps/tree/master/GoogleCTF/woodman
-   http://mslc.ctf.su/wp/google-ctf-woodman-crypto-100/