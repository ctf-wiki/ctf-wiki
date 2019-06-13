# 基本介绍

## 格定义

格是 m 维欧式空间 $R^m$ 的 n ($m\geq n$) 个线性无关向量$b_i(1\leq i \leq n)$ 的所有整系数的线性组合，即
$L(B)=\{\sum\limits_{i=1}^{n}x_ib_i:x_i \in Z,1\leq i \leq n\}$

这里 B 就是 n 个向量的集合，我们称

- 这 n 个向量是格 L 的一组基。
- 格 L 的秩为 n。
- 格 L 的位数为 m。

如果 m=n，那么我们称这个格式满秩的。

当然，也可以是其它群，不是 $R^m$。

## 格中若干基本定义

### successive minima

格是 m 维欧式空间 $R^m$ 的秩为 n 的格，那么 L 的连续最小长度(successive minima)为 $\lambda_1,...,\lambda_n \in R$，满足对于任意的 $1\leq i\leq n$，$\lambda_i$ 是满足格中 i 个线性无关的向量$v_i$， $||v_j||\leq \lambda_i,1\leq j\leq i$ 的最小值。

自然的 $\lambda_i \leq \lambda_j ,\forall i <j$。

## 格中计算困难性问题

**最短向量问题(Shortest Vector Problem，SVP)**：给定格 L 及其基向量 B ，找到格 L 中的非零向量 v 使得对于格中的任意其它非零向量 u，$||v|| \leq ||u||$。

**$\gamma$-近似最短向量问题(SVP-$\gamma$)**：给定格 L，找到格 L 中的非零向量 v 使得对于格中的任意其它非零向量 u，$||v|| \leq \gamma||u||$。

**连续最小长度问题(Successive Minima Problem, SMP)**:给定秩为 n 的格 L，找到格 L 中 n 个线性无关向量 $s_i$，满足 $\lambda_i(L)=||s_i||, 1\leq i \leq n$。

**最短线性无关向量问题(Shortest Independent Vector Problem, SIVP)**：给定一个秩为 n 的格 L，找到格 L 中 n 个线性无关向量 $s_i$，满足$||s_i|| \leq \lambda_n(L), 1\leq i \leq n$。

**唯一最短向量问题(Unique Shortest Vector Problem, uSVP-$\gamma$)**：给定格 L，满足 $ \lambda_2(L) > \gamma \lambda_1(L)$，找到该格的最短向量。

**最近向量问题(Closest Vector Problem，CVP)**：给定格 L和目标向量 $t\in R^m$，找到一个格中的非零向量 v，使得对于格中的任意非零向量 u，满足 $||v-t|| \leq ||u-t||$ 。



