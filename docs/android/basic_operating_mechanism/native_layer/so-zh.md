[EN](./so.md) | [ZH](./so-zh.md)
# so 介绍

## 基本介绍

- 为什么会用到 Shared Object(SO)
    - 开发效率
    - 快速移植
- so 的版本
    - 根据 CPU 平台有所不一样

## 加载方法

- System.loadLibrary
    - 如果加载的文件名是 xxx ，那么其实加载的是项目中 libs 目录下的 libxxx.so文件。
- System.load 
    - 对应 lib 的绝对路径。

主要使用第一种方式，第二种方式主要用于在插件中加载 so 文件。

## loadLibrary 加载流程

根据官方 API 介绍

> The call `System.loadLibrary(name)` is effectively equivalent to the call
>
> > ```
> >  Runtime.getRuntime().loadLibrary(name)
> > ```

可以看出该函数其实调用的是 Runtime.java（ `libcore/luni/src/main/java/java/lang/Runtime.java` ）中的函数 loadLibrary，继而会继续调用 loadLibrary 另一个重载函数，它包含两个参数

- libame，我们传入的库名字
- VMStack.getCallingClassLoader()，类加载器 ClassLoader，方便于去寻找相应的 library。

```java
    /**
     * Loads and links the library with the specified name. The mapping of the
     * specified library name to the full path for loading the library is
     * implementation-dependent.
     *
     * @param libName
     *            the name of the library to load.
     * @throws UnsatisfiedLinkError
     *             if the library can not be loaded.
     */
    public void loadLibrary(String libName) {
        loadLibrary(libName, VMStack.getCallingClassLoader());
    }
    /*
     * Searches for a library, then loads and links it without security checks.
     */
    void loadLibrary(String libraryName, ClassLoader loader) {
        if (loader != null) {
            String filename = loader.findLibrary(libraryName);
            if (filename == null) {
                throw new UnsatisfiedLinkError("Couldn't load " + libraryName +
                                               " from loader " + loader +
                                               ": findLibrary returned null");
            }
            String error = doLoad(filename, loader);
            if (error != null) {
                throw new UnsatisfiedLinkError(error);
            }
            return;
        }
        String filename = System.mapLibraryName(libraryName);
        List<String> candidates = new ArrayList<String>();
        String lastError = null;
        for (String directory : mLibPaths) {
            String candidate = directory + filename;
            candidates.add(candidate);
            if (IoUtils.canOpenReadOnly(candidate)) {
                String error = doLoad(candidate, loader);
                if (error == null) {
                    return; // We successfully loaded the library. Job done.
                }
                lastError = error;
            }
        }
        if (lastError != null) {
            throw new UnsatisfiedLinkError(lastError);
        }
        throw new UnsatisfiedLinkError("Library " + libraryName + " not found; tried " + candidates);
    }
```

可以看出，程序主要的功能正如注释所说

> Searches for a library, then loads and links it without security checks.

而其中所采用的加载函数是 doLoad 函数。在这里，我们先不继续分析，我们来看看 load 函数如何。

## load 加载流程

根据官方 API 说明，如下

> The call System.load(name) is effectively equivalent to the call:
>
>  ```java
> Runtime.getRuntime().load(name)
>  ```

其同样也是调用 Runtime.java 中的函数，如下

```java
    /**
     * Loads and links the dynamic library that is identified through the
     * specified path. This method is similar to {@link #loadLibrary(String)},
     * but it accepts a full path specification whereas {@code loadLibrary} just
     * accepts the name of the library to load.
     *
     * @param pathName
     *            the absolute (platform dependent) path to the library to load.
     * @throws UnsatisfiedLinkError
     *             if the library can not be loaded.
     */
    public void load(String pathName) {
        load(pathName, VMStack.getCallingClassLoader());
    }
    /*
     * Loads and links the given library without security checks.
     */
    void load(String pathName, ClassLoader loader) {
        if (pathName == null) {
            throw new NullPointerException("pathName == null");
        }
        String error = doLoad(pathName, loader);
        if (error != null) {
            throw new UnsatisfiedLinkError(error);
        }
    }
```

其同样也会调用load 的两个参数的重载函数，继而会调用doLoad函数。

**无论是上面的哪一种加载方法，最后都会调用Runtime.java中的doLoad函数。**

## 核心加载流程

### doLoad

下面我们来分析一下 doLoad 函数，如下

```java
    private String doLoad(String name, ClassLoader loader) {
        // Android apps are forked from the zygote, so they can't have a custom LD_LIBRARY_PATH,
        // which means that by default an app's shared library directory isn't on LD_LIBRARY_PATH.
        // The PathClassLoader set up by frameworks/base knows the appropriate path, so we can load
        // libraries with no dependencies just fine, but an app that has multiple libraries that
        // depend on each other needed to load them in most-dependent-first order.
        // We added API to Android's dynamic linker so we can update the library path used for
        // the currently-running process. We pull the desired path out of the ClassLoader here
        // and pass it to nativeLoad so that it can call the private dynamic linker API.
        // We didn't just change frameworks/base to update the LD_LIBRARY_PATH once at the
        // beginning because multiple apks can run in the same process and third party code can
        // use its own BaseDexClassLoader.
        // We didn't just add a dlopen_with_custom_LD_LIBRARY_PATH call because we wanted any
        // dlopen(3) calls made from a .so's JNI_OnLoad to work too.
        // So, find out what the native library search path is for the ClassLoader in question...
        String ldLibraryPath = null;
        if (loader != null && loader instanceof BaseDexClassLoader) {
            ldLibraryPath = ((BaseDexClassLoader) loader).getLdLibraryPath();
        }
        // nativeLoad should be synchronized so there's only one LD_LIBRARY_PATH in use regardless
        // of how many ClassLoaders are in the system, but dalvik doesn't support synchronized
        // internal natives.
        synchronized (this) {
            return nativeLoad(name, loader, ldLibraryPath);
        }
    }
```

虽然源代码很长，但是很多部分都是注释，也说明了为什么要使用这样的一个函数的原因，主要有以下原因

- Android App 都是由 zygote fork 生成的，因此他们的 LD_LIBRARY_PATH 就是 zygote 的LD_LIBRARY_PATH，这也说明 apk 中的 so 文件不在这个路径下。
- so 文件之间可能存在相互依赖，我们需要按照其按依赖关系的逆方向进行加载。

函数的基本思想就是找到库文件的路径，然后使用 synchronized 方式调用了 nativeLoad 函数。

### nativeload

而 nativeload 函数其实就是一个原生层的函数

```java
    // TODO: should be synchronized, but dalvik doesn't support synchronized internal natives.
    private static native String nativeLoad(String filename, ClassLoader loader,
            String ldLibraryPath);
```

相应的文件路径为 `dalvik/vm/native/java_lang_Runtime.cpp` ，具体的 nativeLoad 函数如下

```C
const DalvikNativeMethod dvm_java_lang_Runtime[] = {
    { "freeMemory",          "()J",
        Dalvik_java_lang_Runtime_freeMemory },
    { "gc",                 "()V",
        Dalvik_java_lang_Runtime_gc },
    { "maxMemory",          "()J",
        Dalvik_java_lang_Runtime_maxMemory },
    { "nativeExit",         "(I)V",
        Dalvik_java_lang_Runtime_nativeExit },
    { "nativeLoad",         "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/String;",
        Dalvik_java_lang_Runtime_nativeLoad },
    { "totalMemory",          "()J",
        Dalvik_java_lang_Runtime_totalMemory },
    { NULL, NULL, NULL },
};
```

可以看出在 native 层对应的函数是 Dalvik_java_lang_Runtime_nativeLoad，如下

```C++
/*
 * static String nativeLoad(String filename, ClassLoader loader, String ldLibraryPath)
 *
 * Load the specified full path as a dynamic library filled with
 * JNI-compatible methods. Returns null on success, or a failure
 * message on failure.
 */
static void Dalvik_java_lang_Runtime_nativeLoad(const u4* args,
    JValue* pResult)
{
    StringObject* fileNameObj = (StringObject*) args[0];
    Object* classLoader = (Object*) args[1];
    StringObject* ldLibraryPathObj = (StringObject*) args[2];

    assert(fileNameObj != NULL);
    char* fileName = dvmCreateCstrFromString(fileNameObj);

    if (ldLibraryPathObj != NULL) {
        char* ldLibraryPath = dvmCreateCstrFromString(ldLibraryPathObj);
        void* sym = dlsym(RTLD_DEFAULT, "android_update_LD_LIBRARY_PATH");
        if (sym != NULL) {
            typedef void (*Fn)(const char*);
            Fn android_update_LD_LIBRARY_PATH = reinterpret_cast<Fn>(sym);
            (*android_update_LD_LIBRARY_PATH)(ldLibraryPath);
        } else {
            ALOGE("android_update_LD_LIBRARY_PATH not found; .so dependencies will not work!");
        }
        free(ldLibraryPath);
    }

    StringObject* result = NULL;
    char* reason = NULL;
    bool success = dvmLoadNativeCode(fileName, classLoader, &reason);
    if (!success) {
        const char* msg = (reason != NULL) ? reason : "unknown failure";
        result = dvmCreateStringFromCstr(msg);
        dvmReleaseTrackedAlloc((Object*) result, NULL);
    }

    free(reason);
    free(fileName);
    RETURN_PTR(result);
}
```

根据注释，我们可以确定关键的代码在

```c++
    bool success = dvmLoadNativeCode(fileName, classLoader, &reason);
```

这一行执行后会告诉我们加载对应的 so 是否成功。

### dvmLoadNativeCode

其基本的代码如下，我们可以根据注释来简单判断一下该函数的功能：

-   程序根据指定的绝对路径加载相应的 native code，但是如果该 library 已经加载了，那么就不会再次进行加载。

此外，正如 JNI 中所说，我们不能将一个库加载到多个 class loader 中，也就是说，一个 library 只会和一个 class loader 关联。

函数的基本执行流程如下

1. 利用 findSharedLibEntry 判断是否已经加载了这个库，以及如果已经加载的话，是不是采用的是同一个class loader。

```c++
/*
 * Load native code from the specified absolute pathname.  Per the spec,
 * if we've already loaded a library with the specified pathname, we
 * return without doing anything.
 *
 * TODO? for better results we should absolutify the pathname.  For fully
 * correct results we should stat to get the inode and compare that.  The
 * existing implementation is fine so long as everybody is using
 * System.loadLibrary.
 *
 * The library will be associated with the specified class loader.  The JNI
 * spec says we can't load the same library into more than one class loader.
 *
 * Returns "true" on success. On failure, sets *detail to a
 * human-readable description of the error or NULL if no detail is
 * available; ownership of the string is transferred to the caller.
 */
bool dvmLoadNativeCode(const char* pathName, Object* classLoader,
        char** detail)
{
    SharedLib* pEntry;
    void* handle;
    bool verbose;

    /* reduce noise by not chattering about system libraries */
    verbose = !!strncmp(pathName, "/system", sizeof("/system")-1);
    verbose = verbose && !!strncmp(pathName, "/vendor", sizeof("/vendor")-1);

    if (verbose)
        ALOGD("Trying to load lib %s %p", pathName, classLoader);

    *detail = NULL;

    /*
     * See if we've already loaded it.  If we have, and the class loader
     * matches, return successfully without doing anything.
     */
    pEntry = findSharedLibEntry(pathName);
    if (pEntry != NULL) {
        if (pEntry->classLoader != classLoader) {
            ALOGW("Shared lib '%s' already opened by CL %p; can't open in %p",
                pathName, pEntry->classLoader, classLoader);
            return false;
        }
        if (verbose) {
            ALOGD("Shared lib '%s' already loaded in same CL %p",
                pathName, classLoader);
        }
        if (!checkOnLoadResult(pEntry))
            return false;
        return true;
    }



```

2. 如果没有加载的话，就会利用 dlopen 打开该共享库。

```c++
    /*
     * Open the shared library.  Because we're using a full path, the system
     * doesn't have to search through LD_LIBRARY_PATH.  (It may do so to
     * resolve this library's dependencies though.)
     *
     * Failures here are expected when java.library.path has several entries
     * and we have to hunt for the lib.
     *
     * The current version of the dynamic linker prints detailed information
     * about dlopen() failures.  Some things to check if the message is
     * cryptic:
     *   - make sure the library exists on the device
     *   - verify that the right path is being opened (the debug log message
     *     above can help with that)
     *   - check to see if the library is valid (e.g. not zero bytes long)
     *   - check config/prelink-linux-arm.map to ensure that the library
     *     is listed and is not being overrun by the previous entry (if
     *     loading suddenly stops working on a prelinked library, this is
     *     a good one to check)
     *   - write a trivial app that calls sleep() then dlopen(), attach
     *     to it with "strace -p <pid>" while it sleeps, and watch for
     *     attempts to open nonexistent dependent shared libs
     *
     * This can execute slowly for a large library on a busy system, so we
     * want to switch from RUNNING to VMWAIT while it executes.  This allows
     * the GC to ignore us.
     */
    Thread* self = dvmThreadSelf();
    ThreadStatus oldStatus = dvmChangeStatus(self, THREAD_VMWAIT);
    handle = dlopen(pathName, RTLD_LAZY);
    dvmChangeStatus(self, oldStatus);

    if (handle == NULL) {
        *detail = strdup(dlerror());
        ALOGE("dlopen(\"%s\") failed: %s", pathName, *detail);
        return false;
    }

```

其中的 dlopen 函数(`bionic/linker/dlfcn.cpp`)如下

```c++
void* dlopen(const char* filename, int flags) {
  ScopedPthreadMutexLocker locker(&gDlMutex);
  soinfo* result = do_dlopen(filename, flags);
  if (result == NULL) {
    __bionic_format_dlerror("dlopen failed", linker_get_error_buffer());
    return NULL;
  }
  return result;
}
```

其会调用 do_dlopen 函数(`bionic/linker/linker.cpp`)，如下

```c++
soinfo* do_dlopen(const char* name, int flags) {
  if ((flags & ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL)) != 0) {
    DL_ERR("invalid flags to dlopen: %x", flags);
    return NULL;
  }
  set_soinfo_pool_protection(PROT_READ | PROT_WRITE);
  soinfo* si = find_library(name);  //判断是否有这个库，有的话，需要完成初始化工作
  if (si != NULL) {
    si->CallConstructors();
  }
  set_soinfo_pool_protection(PROT_READ);
  return si;
}
```

在找到对应的库之后，会使用 `si->CallConstructors();`  来构造相关信息，如下

```c++
void soinfo::CallConstructors() {
  if (constructors_called) {
    return;
  }

  // We set constructors_called before actually calling the constructors, otherwise it doesn't
  // protect against recursive constructor calls. One simple example of constructor recursion
  // is the libc debug malloc, which is implemented in libc_malloc_debug_leak.so:
  // 1. The program depends on libc, so libc's constructor is called here.
  // 2. The libc constructor calls dlopen() to load libc_malloc_debug_leak.so.
  // 3. dlopen() calls the constructors on the newly created
  //    soinfo for libc_malloc_debug_leak.so.
  // 4. The debug .so depends on libc, so CallConstructors is
  //    called again with the libc soinfo. If it doesn't trigger the early-
  //    out above, the libc constructor will be called again (recursively!).
  constructors_called = true;

  if ((flags & FLAG_EXE) == 0 && preinit_array != NULL) {
    // The GNU dynamic linker silently ignores these, but we warn the developer.
    PRINT("\"%s\": ignoring %d-entry DT_PREINIT_ARRAY in shared library!",
          name, preinit_array_count);
  }

  if (dynamic != NULL) {
    for (Elf32_Dyn* d = dynamic; d->d_tag != DT_NULL; ++d) {
      if (d->d_tag == DT_NEEDED) {
        const char* library_name = strtab + d->d_un.d_val;
        TRACE("\"%s\": calling constructors in DT_NEEDED \"%s\"", name, library_name);
        find_loaded_library(library_name)->CallConstructors();  //判断库是否已经加载
      }
    }
  }

  TRACE("\"%s\": calling constructors", name);

  // DT_INIT should be called before DT_INIT_ARRAY if both are present.
  CallFunction("DT_INIT", init_func);
  CallArray("DT_INIT_ARRAY", init_array, init_array_count, false);
}
```

可以看出，正如注释所写的，如说 .init 函数与 init_array 存在的话，程序会依次调用 .init 函数与.init_array 中对应位置的代码。相关说明如下

```c++
#define DT_INIT		12	/* Address of initialization function */
#define DT_INIT_ARRAY	25	/* Address of initialization function array */
```

3. 建立一个打开的共享库的 entry，并试图其加入到对应的 list 中，方便管理。如果加入失败的话，就会对其进行释放。

```c++

    /* create a new entry */
    SharedLib* pNewEntry;
    pNewEntry = (SharedLib*) calloc(1, sizeof(SharedLib));
    pNewEntry->pathName = strdup(pathName);
    pNewEntry->handle = handle;
    pNewEntry->classLoader = classLoader;
    dvmInitMutex(&pNewEntry->onLoadLock);
    pthread_cond_init(&pNewEntry->onLoadCond, NULL);
    pNewEntry->onLoadThreadId = self->threadId;

    /* try to add it to the list */
    SharedLib* pActualEntry = addSharedLibEntry(pNewEntry);

    if (pNewEntry != pActualEntry) {
        ALOGI("WOW: we lost a race to add a shared lib (%s CL=%p)",
            pathName, classLoader);
        freeSharedLibEntry(pNewEntry);
        return checkOnLoadResult(pActualEntry);
    } 
```

4. 如果加载成功，就会利用 dlsym 来获取对应 so 文件中的 JNI_OnLoad 函数，如果存在该函数的话，就进行调用，否则，就会直接返回。

```c++
else {
        if (verbose)
            ALOGD("Added shared lib %s %p", pathName, classLoader);

        bool result = false;
        void* vonLoad;
        int version;

        vonLoad = dlsym(handle, "JNI_OnLoad");
        if (vonLoad == NULL) {
            ALOGD("No JNI_OnLoad found in %s %p, skipping init", pathName, classLoader);
            result = true;
        } else {
            /*
             * Call JNI_OnLoad.  We have to override the current class
             * loader, which will always be "null" since the stuff at the
             * top of the stack is around Runtime.loadLibrary().  (See
             * the comments in the JNI FindClass function.)
             */
            OnLoadFunc func = (OnLoadFunc)vonLoad;
            Object* prevOverride = self->classLoaderOverride;

            self->classLoaderOverride = classLoader;
            oldStatus = dvmChangeStatus(self, THREAD_NATIVE);
            if (gDvm.verboseJni) {
                ALOGI("[Calling JNI_OnLoad for \"%s\"]", pathName);
            }
            version = (*func)(gDvmJni.jniVm, NULL);
            dvmChangeStatus(self, oldStatus);
            self->classLoaderOverride = prevOverride;

            if (version == JNI_ERR) {
                *detail = strdup(StringPrintf("JNI_ERR returned from JNI_OnLoad in \"%s\"",
                                              pathName).c_str());
            } else if (dvmIsBadJniVersion(version)) {
                *detail = strdup(StringPrintf("Bad JNI version returned from JNI_OnLoad in \"%s\": %d",
                                              pathName, version).c_str());
                /*
                 * It's unwise to call dlclose() here, but we can mark it
                 * as bad and ensure that future load attempts will fail.
                 *
                 * We don't know how far JNI_OnLoad got, so there could
                 * be some partially-initialized stuff accessible through
                 * newly-registered native method calls.  We could try to
                 * unregister them, but that doesn't seem worthwhile.
                 */
            } else {
                result = true;
            }
            if (gDvm.verboseJni) {
                ALOGI("[Returned %s from JNI_OnLoad for \"%s\"]",
                      (result ? "successfully" : "failure"), pathName);
            }
        }

        if (result)
            pNewEntry->onLoadResult = kOnLoadOkay;
        else
            pNewEntry->onLoadResult = kOnLoadFailed;

        pNewEntry->onLoadThreadId = 0;

        /*
         * Broadcast a wakeup to anybody sleeping on the condition variable.
         */
        dvmLockMutex(&pNewEntry->onLoadLock);
        pthread_cond_broadcast(&pNewEntry->onLoadCond);
        dvmUnlockMutex(&pNewEntry->onLoadLock);
        return result;
    }
}
```

## 总结

这说明加载 .so 文件时，会按照执行如下顺序的函数（如果不存在的话，就会跳过）

- .init 函数
- .init_array 中的函数
- JNI_OnLoad 函数

