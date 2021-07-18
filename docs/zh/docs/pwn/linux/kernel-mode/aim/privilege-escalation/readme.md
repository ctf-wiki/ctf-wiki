# Introduction

内核提权指的是普通用户可以获取到 root 用户的权限，访问原先受限的资源。这里从两种角度来考虑如何提权

- 改变自身：通过改变自身进程的权限，使其具有 root 权限。
- 改变别人：通过影响高权限进程的执行，使其完成我们想要的功能。

## 参考文献

- https://en.wikipedia.org/wiki/Privilege_escalation

