# basic introduction


## grid definition


The lattice is a linear combination of all integer coefficients of n ($m\geq n$) linearly independent vectors $b_i(1\leq i \leq n)$ of the m-dimensional European space $R^m$, ie
$L(B)=\{\sum\limits_{i=1}^{n}x_ib_i:x_i \in Z,1\leq i \leq n\}$



Here B is a collection of n vectors, we call


- These n vectors are a set of bases of the lattice L.
- The rank of the lattice L is n.
- The number of bits in L is m.


If m = n, then we call this format full rank.


Of course, it can be other groups, not $R^m$.


## A few basic definitions in the grid


### successive minimum


The grid is the lattice of the m-dimensional European space $R^m$ with rank n, then the continuous minimum length of L (successive minima) is $\lambda_1,...,\lambda_n \in R$, which satisfies for any $1\ Leq i\leq n$, $\lambda_i$ is the minimum value of the vector linearly independent vector $v_i$, $||v_j||\leq \lambda_i,1\leq j\leq i$ in the lattice.


Natural $\lambda_i \leq \lambda_j ,\forall i <j$。


## Calculating difficult problems in the grid


**Shortest Vector Problem (SVP)**: Given the lattice L and its base vector B, find the non-zero vector v in the lattice L such that for any other non-zero vector u in the lattice, $||v| | \leq ||u||$.


**$\gamma$-Approximate Shortest Vector Problem (SVP-$\gamma$)**: Given a fixed L, find the non-zero vector v in the lattice L such that for any other non-zero vector u in the lattice, $|| v|| \leq \gamma||u||$.


**Successive Minima Problem (SMP)**: Given a lattice L of rank n, find n linearly independent vectors $s_i$ in lattice L, satisfying $\lambda_i(L)=||s_i| |, 1\leq i \leq n$.


**Shortest Independent Vector Problem (SIVP)**: Given a lattice L of rank n, find n linear independent vectors $s_i$ in lattice L, satisfying $||s_i|| \leq \lambda_n(L), 1\leq i \leq n$.


**Unique Shortest Vector Problem (uSVP-$\gamma$)**: Given a fixed L, satisfying $ \lambda_2(L) &gt; \gamma \lambda_1(L)$, find the shortest vector of the cell.


**Closest Vector Problem (CVP)**: Given the lattice L and the target vector $t\in R^m$, find a non-zero vector v in a lattice such that for any non-zero vector u in the lattice , satisfy $||vt|| \leq ||ut||$.





