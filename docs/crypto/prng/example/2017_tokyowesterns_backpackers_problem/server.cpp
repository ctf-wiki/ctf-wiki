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
  if(s.size() > 0 && s[0] == '-') {
    neg = true; s = s.substr(1);
  }
  x = 0;
  for(char t: s) x = x * 10 + t - '0';
  if(neg) x = -x;
  return is;
}

std::ostream &operator<<(std::ostream &os, int128_t x) {
  if(x < 0) return os << "-" << (-x);
  else if(x == 0) return os << "0";
  else {
    std::string s = "";
    while(x > 0) {
      s = static_cast<char>('0' + x % 10) + s;
      x /= 10;
    }
    return os << s;
  }
}

static std::mt19937 mt = std::mt19937(std::random_device()());
int128_t rand(int bits) {
  int128_t r = 0;
  for(int i = 0; i < bits; i+= 32) {
    r = (r << 32) | mt();
    if(i + 32 > bits) {
      r >>= (i + 32 - bits);
    }
  }
  if(mt() & 1) {
    r = -r;
  }
  return r;
}

std::vector<int128_t> generate_problem(int problem_no) {
  int n = problem_no * 10;
  int m = n / 2;
  while(true) {
    std::vector<int128_t> ret;
    int128_t tmp = 0;
    for(int i = 0; i < m - 1; i++) {
      ret.push_back(rand(100));
      tmp -= ret.back();
    }
    if(tmp < 0 && ((-tmp) >> 100) > 0) continue;
    if(tmp > 0 && (tmp >> 100) > 0) continue;
    ret.push_back(tmp);
    for(int i = m; i < n; i++) {
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
  if(!condition) {
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
  for(int problems = 1; problems <= P; problems++) {
    std::cout << "[Problem " << problems << "]" << std::endl;
    std::cout << "Input: " << std::endl;
    std::vector<int128_t> in = generate_problem(problems);
    std::cout << in.size();
    for(auto t: in) std::cout << " " << t;
    std::cout << std::endl;
    alarm(TLE);
    std::cout << "Your Answer: " << std::endl;
    int K;
    std::cin >> K;
    // Check Size
    check(K > 0 && K < static_cast<int>(in.size()));
    std::vector<int128_t> b(K);
    for(int i = 0; i < K; i++) std::cin >> b[i];
    alarm(0);
    // Check Subsequence
    check(std::is_sorted(b.begin(), b.end()));
    check(std::unique(b.begin(), b.end()) == b.end());
    check(std::remove_if(b.begin(), b.end(), [&](int128_t k)->bool { return !binary_search(in.begin(), in.end(), k); }) == b.end());
    // Check sum
    check(!std::accumulate(b.begin(), b.end(), 0));
  }
  // Give you the flag
  std::cout << std::getenv("FLAG") << std::endl;
  return 0;
}
