# 格概述

格在数学上至少有两种含义

- 定义在非空有限集合上的偏序集合 L，满足集合 L 中的任意元素 a，b，使得 a，b 在 L 中存在一个最大下界，和最小上界。具体参见https://en.wikipedia.org/wiki/Lattice_(order)。
- 群论中的定义，是 $R^n$ 中的满足某种性质的子集。当然，也可以是其它群。

目前关于格方面的研究主要有以下几大方向

1. 格中计算问题的困难性，即这些问题的计算复杂性，主要包括 
    1. SVP 问题
    2. CVP 问题
2. 如何求解格中的困难性问题，目前既有近似算法，也有一些精确性算法。
3. 基于格的密码分析，即如何利用格理论分析一些已有的密码学算法，目前有如下研究
    1. Knapsack cryptosystems
    2. DSA nonce biases
    3. Factoring RSA keys with bits known
    4. Small RSA private exponents
    5. Stereotyped messages with small RSA exponents
4. 如何基于格困难问题设计新的密码体制，这也是后量子密码时代的重要研究方向之一，目前有以下研究
    1. Fully homomorphic encryption
    2. The Goldreich–Goldwasser–Halevi (GGH) cryptosystem
    3. The NTRU cryptosystem
    4. The Ajtai–Dwork cryptosystem and the LWE cryptosystem

