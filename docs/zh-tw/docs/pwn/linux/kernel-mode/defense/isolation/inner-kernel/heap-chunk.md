# 內部隔離

## 堆塊隔離

### GFP\_KERNEL & GFP\_KERNEL\_ACCOUNT 的隔離

`GFP_KERNEL` 與 `GFP_KERNEL_ACCOUNT`  是內核中最爲常見與通用的分配 flag，常規情況下他們的分配都來自同一個 `kmem_cache` ——即通用的 `kmalloc-xx`。

在 5.9 版本之前`GFP_KERNEL` 與 `GFP_KERNEL_ACCOUNT` 存在隔離機制，在 [這個 commit](https://github.com/torvalds/linux/commit/10befea91b61c4e2c2d1df06a2e978d182fcf792) 中取消了隔離機制，自內核版本 5.14 起，在 [這個 commit](https://github.com/torvalds/linux/commit/494c1dfe855ec1f70f89552fce5eadf4a1717552) 當中又重新引入：

- 對於開啓了 `CONFIG_MEMCG_KMEM` 編譯選項的 kernel 而言（默認開啓），其會爲使用 `GFP_KERNEL_ACCOUNT` 進行分配的通用對象**創建一組獨立的 `kmem_cache` ——名爲 `kmalloc-cg-*`** ，從而導致使用這兩種 flag 的 object 之間的隔離。

### SLAB_ACCOUNT

根據描述，如果在使用 `kmem_cache_create` 創建一個 cache 時，傳遞了 `SLAB_ACCOUNT` 標記，那麼這個 cache 就會單獨存在，不會與其它相同大小的 cache 合併。

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

在早期，許多結構體（如 **cred 結構體**）對應的堆塊並不單獨存在，會和相同大小的堆塊使用相同的 cache。在 Linux 4.5 版本引入了這個 flag 後，許多結構體就單獨使用了自己的 cache。然而，根據上面的描述，這一特性似乎最初並不是爲了安全性引入的。

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

### 參考

- https://lore.kernel.org/patchwork/patch/616610/
- https://github.com/torvalds/linux/commit/5d097056c9a017a3b720849efb5432f37acabbac#diff-3cb5667a88a24e8d5abc7042f5c4193698d6b962157f637f9729e61198eec63a
- https://github.com/torvalds/linux/commit/230e9fc2860450fbb1f33bdcf9093d92d7d91f5b#diff-cc9aa90e094e6e0f47bd7300db4f33cf4366b98b55d8753744f31eb69c691016
- https://github.com/torvalds/linux/commit/10befea91b61c4e2c2d1df06a2e978d182fcf792
- https://github.com/torvalds/linux/commit/494c1dfe855ec1f70f89552fce5eadf4a1717552

