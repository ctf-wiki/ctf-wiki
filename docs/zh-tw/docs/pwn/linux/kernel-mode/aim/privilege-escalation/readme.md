# Introduction

內核提權指的是普通用戶可以獲取到 root 用戶的權限，訪問原先受限的資源。這裏從兩種角度來考慮如何提權

- 改變自身：通過改變自身進程的權限，使其具有 root 權限。
- 改變別人：通過影響高權限進程的執行，使其完成我們想要的功能。

## 參考文獻

- https://en.wikipedia.org/wiki/Privilege_escalation

