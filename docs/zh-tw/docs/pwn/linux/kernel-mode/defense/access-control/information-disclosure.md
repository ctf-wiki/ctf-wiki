# 信息泄漏

## dmesg_restrict

考慮到內核日誌中可能會有一些地址信息或者敏感信息，研究者提出需要對內核日誌的訪問進行限制。

該選項用於控制是否可以使用 `dmesg` 來查看內核日誌。當 `dmesg_restrict` 爲 0 時，沒有任何限制；當該選項爲 1 時，只有具有 `CAP_SYSLOG` 權限的用戶纔可以通過 `dmesg` 命令來查看內核日誌。

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

該選項用於控制在輸出內核地址時施加的限制，主要限制以下接口

- 通過 /proc 獲取的內核地址
- 通過其它接口（有待研究）獲取的地址

具體輸出的內容與該選項配置的值有關

- 0：默認情況下，沒有任何限制。
- 1：使用 `％pK` 輸出的內核指針地址將被替換爲 0，除非用戶具有 CAP_ SYSLOG 特權，並且 group id 和真正的 id 相等。
- 2：使用 `％pK` 輸出的內核指針都將被替換爲 0 ，即與權限無關。

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

當開啓該保護後，攻擊者就不能通過 `/proc/kallsyms` 來獲取內核中某些敏感的地址了，如 commit_creds、prepare_kernel_cred。

## 參考

- https://blog.csdn.net/gatieme/article/details/78311841
