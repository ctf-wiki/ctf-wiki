# 题目

## 2017 Tokyo Westerns CTF 3rd Backpacker's Problem

题目中给了一个 cpp 文件

```cpp
#include <iostream>
#include <vector>
#include <cstdint>
#include <random>
#include <algorithm>
#include <signal.h>
#include <unistd.h>

typedef __int128 int128_t;

std::istream &operator>>(std::istream &is, int128_t &x) {
    std::string s;
    is >> s;
    bool neg = false;
    if (s.size() > 0 && s[0] == '-') {
        neg = true;
        s = s.substr(1);
    }
    x = 0;
    for (char t : s)
        x = x * 10 + t - '0';
    if (neg)
        x = -x;
    return is;
}

std::ostream &operator<<(std::ostream &os, int128_t x) {
    if (x < 0)
        return os << "-" << (-x);
    else if (x == 0)
        return os << "0";
    else {
        std::string s = "";
        while (x > 0) {
            s = static_cast<char>('0' + x % 10) + s;
            x /= 10;
        }
        return os << s;
    }
}

static std::mt19937 mt = std::mt19937(std::random_device()());
int128_t rand(int bits) {
    int128_t r = 0;
    for (int i = 0; i < bits; i += 32) {
        r = (r << 32) | mt();
        if (i + 32 > bits) {
            r >>= (i + 32 - bits);
        }
    }
    if (mt() & 1) {
        r = -r;
    }
    return r;
}

std::vector<int128_t> generate_problem(int problem_no) {
    int n = problem_no * 10;
    int m = n / 2;
    while (true) {
        std::vector<int128_t> ret;
        int128_t tmp = 0;
        for (int i = 0; i < m - 1; i++) {
            ret.push_back(rand(100));
            tmp -= ret.back();
        }
        if (tmp < 0 && ((-tmp) >> 100) > 0)
            continue;
        if (tmp > 0 && (tmp >> 100) > 0)
            continue;
        ret.push_back(tmp);
        for (int i = m; i < n; i++) {
            ret.push_back(rand(100));
        }
        std::sort(ret.begin(), ret.end());
        ret.erase(std::unique(ret.begin(), ret.end()), ret.end());
        return ret;
    }
}

const int P = 20;
const int TLE = 4;

void tle(int singals) {
    std::cout << "Time Limit Exceeded" << std::endl;
    std::exit(0);
}

bool check(bool condition) {
    if (!condition) {
        std::cout << "Wrong Answer" << std::endl;
        std::exit(0);
    }
    return true;
}

int main() {
    signal(SIGALRM, tle);
    std::cout << R"(--- Backpacker's Problem ---
Given the integers a_1, a_2, ..., a_N, your task is to find a subsequence b of a
where b_1 + b_2 + ... + b_K = 0.

Input Format: N a_1 a_2 ... a_N
Answer Format: K b_1 b_2 ... b_K

Example Input:
4 -8 -2 3 5
Example Answer:
3 -8 3 5
)" << std::endl;
    for (int problems = 1; problems <= P; problems++) {
        std::cout << "[Problem " << problems << "]" << std::endl;
        std::cout << "Input: " << std::endl;
        std::vector<int128_t> in = generate_problem(problems);
        std::cout << in.size();
        for (auto t : in)
            std::cout << " " << t;
        std::cout << std::endl;
        alarm(TLE);
        std::cout << "Your Answer: " << std::endl;
        int K;
        std::cin >> K;
        // Check Size
        check(K > 0 && K < static_cast<int>(in.size()));
        std::vector<int128_t> b(K);
        for (int i = 0; i < K; i++)
            std::cin >> b[i];
        alarm(0);
        // Check Subsequence
        check(std::is_sorted(b.begin(), b.end()));
        check(std::unique(b.begin(), b.end()) == b.end());
        check(std::remove_if(b.begin(), b.end(), [&](int128_t k) -> bool {
                  return !binary_search(in.begin(), in.end(), k);
              }) == b.end());
        // Check sum
        check(!std::accumulate(b.begin(), b.end(), 0));
    }
    // Give you the flag
    // std::cout << std::getenv("FLAG") << std::endl;
    std::cout << "flag{test}" << std::endl;
    return 0;
}
```

可以发现, 如算法竞赛题目一样给出题面和输入输出样例

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

即是一个背包问题。其中，在本题中，我们需要解决 $20$ 个这样的背包问题，背包大小依次是 1 * 10~20 * 10。而子集求和的背包问题是一个 NPC 问题，问题的时间复杂度随着随着背包大小而指数增长。这里背包的大小最大是 $200$，显然不可能使用暴力破解的方式

有两种解法，分治和格，这里我们讲

分治策略:

对于 $n > 20$ 的情况，将问题分解为前 $20$ 个元素和剩余元素的子集和问题，利用哈希表快速查找符合条件的子集

针对本题，在建表查表的过程中，有个小技巧是优先使用 `std::unordered_map` 而不是 `std::map`，性能会更好 (平均时间复杂度为 $O(1)$)

通过查找 `std::accumulate` 的文档，我们知道其 init 的类型决定了累加结果的类型。如果 init 是 int，那么累加结果也是 int；如果 init 是 double，那么累加结果也是 double。

而这里初始值为 `0`，那么其累加结果的空间只有 int 大小，那么我们在读取数据时只需要读低 $32$ bit 即可。

```cpp
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace std;

// 计算子集和的辅助函数
void find_subset_sum(const vector<unsigned int> &A, vector<int> &ans) {
    const int n = A.size();
    if (n <= 20) {
        // 如果 n <= 20，直接暴力枚举所有子集
        for (int b = 1; b < (1 << n); ++b) {
            unsigned int S = 0;
            for (int i = 0; i < n; ++i) {
                if (b >> i & 1) {
                    S += A[i];
                }
            }
            if (S == 0) {
                for (int i = 0; i < n; ++i) {
                    if (b >> i & 1) {
                        ans.push_back(i);
                    }
                }
                return;
            }
        }
    } else {
        // 如果 n > 20，使用分治策略
        unordered_map<unsigned int, int> M; // 存储前20个元素的子集和
        const int k = 20;                  // 分治的前20个元素

        // 枚举前20个元素的子集
        for (int b = 0; b < (1 << k); ++b) {
            unsigned int S = 0;
            for (int i = 0; i < k; ++i) {
                if (b >> i & 1) {
                    S += A[i];
                }
            }
            M[-S] = b; // 存储 -S 和对应的子集
        }

        // 枚举剩余元素的子集
        for (int b = 0;; ++b) {
            unsigned int S = 0;
            for (int i = k; i < n; ++i) {
                if (b >> (i - k) & 1) {
                    S += A[i];
                }
            }

            // 查找是否存在前20个元素的子集与当前子集的和为0
            if (auto it = M.find(S); it != M.end() && (b != 0 || it->second != 0)) {
                const int prefix_mask = it->second;
                for (int i = 0; i < k; ++i) {
                    if (prefix_mask >> i & 1) {
                        ans.push_back(i);
                    }
                }
                for (int i = k; i < n; ++i) {
                    if (b >> (i - k) & 1) {
                        ans.push_back(i);
                    }
                }
                return;
            }
        }
    }
}

int main() {
    int n;
    cin >> n;
    if (n <= 0) {
        cout << 0 << endl;
        return 0;
    }

    vector<unsigned int> A(n);
    for (unsigned int &a : A) {
        cin >> a;
    }

    vector<int> ans;
    find_subset_sum(A, ans);

    cout << ans.size();
    for (int a : ans) {
        cout << " " << a;
    }
    cout << endl;

    return 0;
}
```

单次询问我们已经解决了，使用 pwntools 更方便的为其赋予交互能力。

```python
# 像是 OI 的交互题
from pwn import context, process

# 连接到本地服务器
context.log_level = 'debug'  # 启用调试日志
io1 = process("/backpacker-server/server")

def readline():
    return io1.recvline().decode().strip()

# 读取前12行输出 (case)
for _ in range(12):
    readline()

# 处理接下来的20轮交互
for _ in range(20):
    readline()
    readline()
    input_list = readline()
    readline()

    # 处理输入数据
    input_list = list(map(int, input_list.split()))  # 将输入数据转换为整数列表

    # lambda 函数将列表中的每个元素与 0xffffffff 按位与
    # map 函数将 lambda 函数应用到列表中的每个元素
    # join 函数将列表中的元素连接成字符串，用空格分隔
    input_cut = " ".join(map(lambda x: str(x & 0xffffffff), input_list))
    print(f'input: {input_cut}')

    # 使用 pwntools 的 process 调用外部程序
    # 编译题目提供的 server.cpp 文件, 方便交互
    # g++ -std=c++11 server.cpp -o server
    io2 = process("./server")
    io2.sendline(input_cut.encode())
    input_solve = io2.recvline().decode().strip()

    input_solve = list(map(int, input_solve.split()))
    first_element = str(input_solve[0])
    
    remaining_elements = []
    for x in input_solve[1:]:
        element = str(input_list[x + 1])
        remaining_elements.append(element)
    
    input_solve = " ".join([first_element] + remaining_elements)
    io1.sendline(input_solve.encode())

    io2.close()

print(readline())

io1.close()
```


## 参考文献

-   https://github.com/r00ta/myWriteUps/tree/master/GoogleCTF/woodman
-   http://mslc.ctf.su/wp/google-ctf-woodman-crypto-100/
-   https://github.com/ymgve/ctf-writeups/tree/master/tokyowesterns2017/ppc-backpackers_problem
-   https://en.cppreference.com/w/cpp/algorithm/accumulate
-   https://qiita.com/kusano_k/items/b1fff79d535f4b26cdd0#backpackers-problem
