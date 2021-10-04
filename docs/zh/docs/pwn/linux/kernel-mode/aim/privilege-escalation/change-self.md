# Change Self

内核会通过进程的 `task_struct` 结构体中的 cred 指针来索引 cred 结构体，然后根据 cred 的内容来判断一个进程拥有的权限，如果 cred 结构体成员中的 uid-fsgid 都为 0，那一般就会认为进程具有 root 权限。

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
  ...
}
```

因此，思路就比较直观了，我们可以通过以下方式来提权

- 直接修改 cred 结构体的内容
- 修改 task_struct 结构体中的 cred 指针指向一个满足要求的 cred

无论是哪一种方法，一般都分为两步：定位，修改。这就好比把大象放到冰箱里一样。

## 直接改 cred

### 定位具体位置

我们可以首先获取到 cred 的具体地址，然后修改 cred。

#### 定位

定位 cred 的具体地址有很多种方法，这里根据是否直接定位分为以下两种

##### 直接定位

cred 结构体的最前面记录了各种 id 信息，对于一个普通的进程而言，uid-fsgid 都是执行进程的用户的身份。因此我们可以通过扫描内存来定位 cred。

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
  ...
}
```

**在实际定位的过程中，我们可能会发现很多满足要求的 cred，这主要是因为 cred 结构体可能会被拷贝、释放。**一个很直观的想法是在定位的过程中，利用 usage 不为 0 来筛除掉一些 cred，但仍然会发现一些 usage 为 0 的 cred。这是因为 cred 从 usage 为 0， 到释放有一定的时间。此外，cred 是使用 rcu 延迟释放的。

##### 间接定位

###### task_struct

进程的 `task_struct` 结构体中会存放指向 cred 的指针，因此我们可以

1. 定位当前进程  `task_struct` 结构体的地址

2. 根据 cred 指针相对于 task_struct 结构体的偏移计算得出 `cred` 指针存储的地址

3. 获取 `cred` 具体的地址

###### comm

comm 用来标记可执行文件的名字，位于进程的 `task_struct` 结构体中。我们可以发现 comm 其实在 cred 的正下方，所以我们也可以先定位 comm ，然后定位 cred 的地址。

```c
	/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;

#ifdef CONFIG_KEYS
	/* Cached requested key. */
	struct key			*cached_requested_key;
#endif

	/*
	 * executable name, excluding path.
	 *
	 * - normally initialized setup_new_exec()
	 * - access it with [gs]et_task_comm()
	 * - lock it with task_lock()
	 */
	char				comm[TASK_COMM_LEN];
```

然而，在进程名字并不特殊的情况下，内核中可能会有多个同样的字符串，这会影响搜索的正确性与效率。因此，我们可以使用 prctl 设置进程的 comm 为一个特殊的字符串，然后再开始定位 comm。

#### 修改

在这种方法下，我们可以直接将 cred 中的 uid-fsgid 都修改为 0。当然修改的方式有很多种，比如说

- 在我们具有任意地址读写后，可以直接修改 cred。
- 在我们可以 ROP 执行代码后，可以利用 ROP gadget 修改 cred。

### 间接定位

虽然我们确实想要修改 cred 的内容，但是不一定非得知道 cred 的具体位置，我们只需要能够修改 cred 即可。

#### UAF 使用同样堆块

如果我们在进程初始化时能控制 cred 结构体的位置，并且我们可以在初始化后修改该部分的内容，那么我们就可以很容易地达到提权的目的。这里给出一个典型的例子

1. 申请一块与 cred 结构体大小一样的堆块
2. 释放该堆块
3. fork 出新进程，恰好使用刚刚释放的堆块
4. 此时，修改 cred 结构体特定内存，从而提权

非常有意思的是，在这个过程中，我们不需要任何的信息泄露。

## 修改 cred 指针

### 定位具体位置

在这种方式下，我们需要知道 cred 指针的具体地址。

#### 定位

##### 直接定位

显然，cred 指针并没有什么非常特殊的地方，所以很难通过直接定位的方式定位到 cred 指针。

##### 间接定位

###### task_struct

进程的 `task_struct` 结构体中会存放指向 cred 的指针，因此我们可以

1. 定位当前进程  `task_struct` 结构体的地址

2. 根据 cred 指针相对于 task_struct 结构体的偏移计算得出 `cred` 指针存储的地址

###### common

comm 用来标记可执行文件的名字，位于进程的 `task_struct` 结构体中。我们可以发现 comm 其实在 cred 指针的正下方，所以我们也可以先定位 comm ，然后定位 cred 指针的地址。

```c
	/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;

#ifdef CONFIG_KEYS
	/* Cached requested key. */
	struct key			*cached_requested_key;
#endif

	/*
	 * executable name, excluding path.
	 *
	 * - normally initialized setup_new_exec()
	 * - access it with [gs]et_task_comm()
	 * - lock it with task_lock()
	 */
	char				comm[TASK_COMM_LEN];
```

然而，在进程名字并不特殊的情况下，内核中可能会有多个同样的字符串，这会影响搜索的正确性与效率。因此，我们可以使用 prctl 设置进程的 comm 为一个特殊的字符串，然后再开始定位 comm。

#### 修改

在具体修改时，我们可以使用如下的两种方式

- 修改 cred 指针为内核镜像中已有的 init_cred 的地址。这种方法适合于我们能够直接修改 cred 指针以及知道 init_cred 地址的情况。
- 伪造一个 cred，然后修改 cred 指针指向该地址即可。这种方式比较麻烦，一般并不使用。

### 间接定位

#### commit_creds(prepare_kernel_cred(0))

我们还可以使用 commit_creds(prepare_kernel_cred(0)) 来进行提权，该方式会自动生成一个合法的 cred，并定位当前线程的 task_struct 的位置，然后修改它的 cred 为新的 cred。该方式比较适用于控制程序执行流后使用。

![72b919b7-87bb-4312-97ea-b59fe4690b2e](figure/elevation-of-privilege.png)

在整个过程中，我们并不知道 cred 指针的具体位置。
