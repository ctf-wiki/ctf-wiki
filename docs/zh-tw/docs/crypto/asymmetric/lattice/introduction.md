# 基本介紹

## 格定義

格是 m 維歐式空間 $R^m$ 的 n ($m\geq n$) 個線性無關向量$b_i(1\leq i \leq n)$ 的所有整係數的線性組合，即
$L(B)=\{\sum\limits_{i=1}^{n}x_ib_i:x_i \in Z,1\leq i \leq n\}$

這裏 B 就是 n 個向量的集合，我們稱

- 這 n 個向量是格 L 的一組基。
- 格 L 的秩爲 n。
- 格 L 的位數爲 m。

如果 m=n，那麼我們稱這個格式滿秩的。

當然，也可以是其它羣，不是 $R^m$。

## 格中若干基本定義

### successive minima

格是 m 維歐式空間 $R^m$ 的秩爲 n 的格，那麼 L 的連續最小長度(successive minima)爲 $\lambda_1,...,\lambda_n \in R$，滿足對於任意的 $1\leq i\leq n$，$\lambda_i$ 是滿足格中 i 個線性無關的向量$v_i$， $||v_j||\leq \lambda_i,1\leq j\leq i$ 的最小值。

自然的 $\lambda_i \leq \lambda_j ,\forall i <j$。

## 格中計算困難性問題

**最短向量問題(Shortest Vector Problem，SVP)**：給定格 L 及其基向量 B ，找到格 L 中的非零向量 v 使得對於格中的任意其它非零向量 u，$||v|| \leq ||u||$。

**$\gamma$-近似最短向量問題(SVP-$\gamma$)**：給定格 L，找到格 L 中的非零向量 v 使得對於格中的任意其它非零向量 u，$||v|| \leq \gamma||u||$。

**連續最小長度問題(Successive Minima Problem, SMP)**:給定秩爲 n 的格 L，找到格 L 中 n 個線性無關向量 $s_i$，滿足 $\lambda_i(L)=||s_i||, 1\leq i \leq n$。

**最短線性無關向量問題(Shortest Independent Vector Problem, SIVP)**：給定一個秩爲 n 的格 L，找到格 L 中 n 個線性無關向量 $s_i$，滿足$||s_i|| \leq \lambda_n(L), 1\leq i \leq n$。

**唯一最短向量問題(Unique Shortest Vector Problem, uSVP-$\gamma$)**：給定格 L，滿足 $ \lambda_2(L) > \gamma \lambda_1(L)$，找到該格的最短向量。

**最近向量問題(Closest Vector Problem，CVP)**：給定格 L和目標向量 $t\in R^m$，找到一個格中的非零向量 v，使得對於格中的任意非零向量 u，滿足 $||v-t|| \leq ||u-t||$ 。



