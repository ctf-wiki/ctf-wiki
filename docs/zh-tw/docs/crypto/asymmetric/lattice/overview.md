# 格概述

格在數學上至少有兩種含義

- 定義在非空有限集合上的偏序集合 L，滿足集合 L 中的任意元素 a，b，使得 a，b 在 L 中存在一個最大下界，和最小上界。具體參見https://en.wikipedia.org/wiki/Lattice_(order)。
- 羣論中的定義，是 $R^n$ 中的滿足某種性質的子集。當然，也可以是其它羣。

目前關於格方面的研究主要有以下幾大方向

1. 格中計算問題的困難性，即這些問題的計算複雜性，主要包括 
    1. SVP 問題
    2. CVP 問題
2. 如何求解格中的困難性問題，目前既有近似算法，也有一些精確性算法。
3. 基於格的密碼分析，即如何利用格理論分析一些已有的密碼學算法，目前有如下研究
    1. Knapsack cryptosystems
    2. DSA nonce biases
    3. Factoring RSA keys with bits known
    4. Small RSA private exponents
    5. Stereotyped messages with small RSA exponents
4. 如何基於格困難問題設計新的密碼體制，這也是後量子密碼時代的重要研究方向之一，目前有以下研究
    1. Fully homomorphic encryption
    2. The Goldreich–Goldwasser–Halevi (GGH) cryptosystem
    3. The NTRU cryptosystem
    4. The Ajtai–Dwork cryptosystem and the LWE cryptosystem

