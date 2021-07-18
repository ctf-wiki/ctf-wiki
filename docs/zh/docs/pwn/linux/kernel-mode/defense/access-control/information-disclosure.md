# 信息泄漏

## dmesg_restrict

考虑到内核日志中可能会有一些地址信息或者敏感信息，研究者提出需要对内核日志的访问进行限制。

该选项用于控制是否可以使用 `dmesg` 来查看内核日志。当 `dmesg_restrict` 为 0 时，没有任何限制；当该选项为 1 时，只有具有 `CAP_SYSLOG` 权限的用户才可以通过 `dmesg` 命令来查看内核日志。

```
dmesg_restrict:

This toggle indicates whether unprivileged users are prevented
from using dmesg(8) to view messages from the kernel's log buffer.
When dmesg_restrict is set to (0) there are no restrictions. When
dmesg_restrict is set set to (1), users must have CAP_SYSLOG to use
dmesg(8).

The kernel config option CONFIG_SECURITY_DMESG_RESTRICT sets the
default value of dmesg_restrict.
```

## kptr_restrict

该选项用于控制在输出内核地址时施加的限制，主要限制以下接口

- 通过 /proc 获取的内核地址
- 通过其它接口（有待研究）获取的地址

具体输出的内容与该选项配置的值有关

- 0：默认情况下，没有任何限制。
- 1：使用 `％pK` 输出的内核指针地址将被替换为 0，除非用户具有 CAP_ SYSLOG 特权，并且 group id 和真正的 id 相等。
- 2：使用 `％pK` 输出的内核指针都将被替换为 0 ，即与权限无关。

```
kptr_restrict:

This toggle indicates whether restrictions are placed on
exposing kernel addresses via /proc and other interfaces.

When kptr_restrict is set to 0 (the default) the address is hashed before
printing. (This is the equivalent to %p.)

When kptr_restrict is set to (1), kernel pointers printed using the %pK
format specifier will be replaced with 0's unless the user has CAP_SYSLOG
and effective user and group ids are equal to the real ids. This is
because %pK checks are done at read() time rather than open() time, so
if permissions are elevated between the open() and the read() (e.g via
a setuid binary) then %pK will not leak kernel pointers to unprivileged
users. Note, this is a temporary solution only. The correct long-term
solution is to do the permission checks at open() time. Consider removing
world read permissions from files that use %pK, and using dmesg_restrict
to protect against uses of %pK in dmesg(8) if leaking kernel pointer
values to unprivileged users is a concern.

When kptr_restrict is set to (2), kernel pointers printed using
%pK will be replaced with 0's regardless of privileges.
```

当开启该保护后，攻击者就不能通过 `/proc/kallsyms` 来获取内核中某些敏感的地址了，如 commit_creds、prepare_kernel_cred。

## 参考

- https://blog.csdn.net/gatieme/article/details/78311841
