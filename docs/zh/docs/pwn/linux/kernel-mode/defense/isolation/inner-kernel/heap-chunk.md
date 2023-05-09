# 内部隔离

## 堆块隔离

### GFP\_KERNEL & GFP\_KERNEL\_ACCOUNT 的隔离

`GFP_KERNEL` 与 `GFP_KERNEL_ACCOUNT`  是内核中最为常见与通用的分配 flag，常规情况下他们的分配都来自同一个 `kmem_cache` ——即通用的 `kmalloc-xx`。

在 5.9 版本之前`GFP_KERNEL` 与 `GFP_KERNEL_ACCOUNT` 存在隔离机制，在 [这个 commit](https://github.com/torvalds/linux/commit/10befea91b61c4e2c2d1df06a2e978d182fcf792) 中取消了隔离机制，自内核版本 5.14 起，在 [这个 commit](https://github.com/torvalds/linux/commit/494c1dfe855ec1f70f89552fce5eadf4a1717552) 当中又重新引入：

- 对于开启了 `CONFIG_MEMCG_KMEM` 编译选项的 kernel 而言（默认开启），其会为使用 `GFP_KERNEL_ACCOUNT` 进行分配的通用对象**创建一组独立的 `kmem_cache` ——名为 `kmalloc-cg-*`** ，从而导致使用这两种 flag 的 object 之间的隔离。

### SLAB_ACCOUNT

根据描述，如果在使用 `kmem_cache_create` 创建一个 cache 时，传递了 `SLAB_ACCOUNT` 标记，那么这个 cache 就会单独存在，不会与其它相同大小的 cache 合并。

```
Currently, if we want to account all objects of a particular kmem cache,
we have to pass __GFP_ACCOUNT to each kmem_cache_alloc call, which is
inconvenient. This patch introduces SLAB_ACCOUNT flag which if passed to
kmem_cache_create will force accounting for every allocation from this
cache even if __GFP_ACCOUNT is not passed.

This patch does not make any of the existing caches use this flag - it
will be done later in the series.

Note, a cache with SLAB_ACCOUNT cannot be merged with a cache w/o
SLAB_ACCOUNT, i.e. using this flag will probably reduce the number of
merged slabs even if kmem accounting is not used (only compiled in).
```

在早期，许多结构体（如 **cred 结构体**）对应的堆块并不单独存在，会和相同大小的堆块使用相同的 cache。在 Linux 4.5 版本引入了这个 flag 后，许多结构体就单独使用了自己的 cache。然而，根据上面的描述，这一特性似乎最初并不是为了安全性引入的。

```
Mark those kmem allocations that are known to be easily triggered from
userspace as __GFP_ACCOUNT/SLAB_ACCOUNT, which makes them accounted to
memcg.  For the list, see below:

 - threadinfo
 - task_struct
 - task_delay_info
 - pid
 - cred
 - mm_struct
 - vm_area_struct and vm_region (nommu)
 - anon_vma and anon_vma_chain
 - signal_struct
 - sighand_struct
 - fs_struct
 - files_struct
 - fdtable and fdtable->full_fds_bits
 - dentry and external_name
 - inode for all filesystems. This is the most tedious part, because
   most filesystems overwrite the alloc_inode method.

The list is far from complete, so feel free to add more objects.
Nevertheless, it should be close to "account everything" approach and
keep most workloads within bounds.  Malevolent users will be able to
breach the limit, but this was possible even with the former "account
everything" approach (simply because it did not account everything in
fact).
```

### 参考

- https://lore.kernel.org/patchwork/patch/616610/
- https://github.com/torvalds/linux/commit/5d097056c9a017a3b720849efb5432f37acabbac#diff-3cb5667a88a24e8d5abc7042f5c4193698d6b962157f637f9729e61198eec63a
- https://github.com/torvalds/linux/commit/230e9fc2860450fbb1f33bdcf9093d92d7d91f5b#diff-cc9aa90e094e6e0f47bd7300db4f33cf4366b98b55d8753744f31eb69c691016
- https://github.com/torvalds/linux/commit/10befea91b61c4e2c2d1df06a2e978d182fcf792
- https://github.com/torvalds/linux/commit/494c1dfe855ec1f70f89552fce5eadf4a1717552

