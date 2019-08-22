[EN](./so.md) | [ZH](./so-zh.md)
# so Introduction


## basic introduction


- Why use Shared Object(SO)
- Development efficiency
- Fast migration
- the version of so
- Different depending on the CPU platform


## Loading method


- System.loadLibrary

- If the loaded file name is xxx, then the libxxx.so file in the libs directory of the project is actually loaded.
- System.load 

- Corresponds to the absolute path of lib.


The first method is mainly used, and the second method is mainly used to load the so file in the plugin.


## loadLibrary Loading Process


According to the official API


> The call `System.loadLibrary(name)` is effectively equivalent to the call

>

> > ```

> >  Runtime.getRuntime().loadLibrary(name)

> > ```



It can be seen that the function actually calls the function loadLibrary in Runtime.java ( `libcore/luni/src/main/java/java/lang/Runtime.java` ), and then continues to call loadLibrary another overloaded function. Contains two parameters


- libame, the library name we passed in
- VMStack.getCallingClassLoader(), the class loader ClassLoader, is convenient for finding the corresponding library.


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



It can be seen that the main function of the program is as explained in the comments.


> Searches for a library, then loads and links it without security checks.



The load function used in it is the doLoad function. Here, let&#39;s not continue the analysis, let&#39;s take a look at the load function.


## load Loading process


According to the official API description, as follows


> The call System.load(name) is effectively equivalent to the call:

>

>  ```java

&gt; Runtime.getRuntime (). Load (name)
>  ```



It is also a function called Runtime.java, as follows


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



It also calls the overloaded function of the two parameters of load, which in turn calls the doLoad function.


** Regardless of which of the above loading methods, the doLoad function in Runtime.java will be called. **


## Core loading process


### doLoad



Let&#39;s analyze the doLoad function as follows


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



Although the source code is very long, many of them are comments, which explains why you should use such a function. The main reasons are as follows.


- Android apps are generated by zygote fork, so their LD_LIBRARY_PATH is zygote&#39;s LD_LIBRARY_PATH, which also means that the so files in apk are not in this path.
- There may be interdependencies between so files, we need to load them in the reverse direction of the dependencies.


The basic idea of a function is to find the path to the library file and then call the nativeLoad function using the synchronized method.


### nativeload



The nativeload function is actually a function of the native layer.


```java

    // TODO: should be synchronized, but dalvik doesn't support synchronized internal natives.

    private static native String nativeLoad(String filename, ClassLoader loader,

            String ldLibraryPath);

```



The corresponding file path is `dalvik/vm/native/java_lang_Runtime.cpp`, and the specific nativeLoad function is as follows


```C

const DalvikNativeMethod dvm_java_lang_Runtime[] = {

    { "freeMemory",          "()J",

        Dalvik_java_lang_Runtime_freeMemory },

{&quot;gc&quot;, &quot;() V&quot;,
        Dalvik_java_lang_Runtime_gc },

{&quot;maxMemory&quot;, &quot;() J&quot;,
Dalvik_java_lang_Runtime_maxMemory},
    { "nativeExit",         "(I)V",

        Dalvik_java_lang_Runtime_nativeExit },

    { "nativeLoad",         "(Ljava/lang/String;Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/String;",

        Dalvik_java_lang_Runtime_nativeLoad },

{&quot;totalMemory&quot;, &quot;() J&quot;,
        Dalvik_java_lang_Runtime_totalMemory },

{NULL, NULL, ZERO},
};

```



It can be seen that the function corresponding to the native layer is Dalvik_java_lang_Runtime_nativeLoad, as follows


```C++

/*

 * static String nativeLoad(String filename, ClassLoader loader, String ldLibraryPath)

 *

 * Load the specified full path as a dynamic library filled with

 * JNI-compatible methods. Returns null on success, or a failure

 * message on failure.

 */

static void Dalvik_java_lang_Runtime_nativeLoad(const u4* args,

JValue * Director)
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



According to the comments, we can determine the key code at


```c++

    bool success = dvmLoadNativeCode(fileName, classLoader, &reason);

```



After this line is executed, it will tell us whether the corresponding so is successful.


### dvmLoadNativeCode



The basic code is as follows, we can simply judge the function of the function according to the comments:


- The program loads the corresponding native code according to the specified absolute path, but if the library is already loaded, it will not be loaded again.


Also, as stated in JNI, we can&#39;t load a library into multiple class loaders, that is, a library will only be associated with a class loader.


The basic execution flow of the function is as follows


1. Use findSharedLibEntry to determine if the library has been loaded, and if it is already loaded, is the same class loader.


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

SharedLib * pEntry;
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

pEntry = findSharedLibEntry (pathName);
if (pEntry! = NULL) {
        if (pEntry->classLoader != classLoader) {

            ALOGW("Shared lib '%s' already opened by CL %p; can't open in %p",

                pathName, pEntry->classLoader, classLoader);

            return false;

        }

        if (verbose) {

            ALOGD("Shared lib '%s' already loaded in same CL %p",

                pathName, classLoader);

        }

if (! checkOnLoadResult (pEntry))
            return false;

        return true;

    }







```



2. If it is not loaded, it will open the shared library with dlopen.


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



The dlopen function (`bionic/linker/dlfcn.cpp`) is as follows


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



It will call the do_dlopen function (`bionic/linker/linker.cpp`) as follows


```c++

soinfo* do_dlopen(const char* name, int flags) {

  if ((flags & ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL)) != 0) {

    DL_ERR("invalid flags to dlopen: %x", flags);

    return NULL;

  }

  set_soinfo_pool_protection(PROT_READ | PROT_WRITE);

Soinfo* si = find_library(name); / / determine whether there is this library, if any, need to complete the initialization work
  if (si != NULL) {

yes-&gt; CallConstructors ();
  }

  set_soinfo_pool_protection(PROT_READ);

if they return;
}

```



After finding the corresponding library, `si-&gt;CallConstructors();` will be used to construct the relevant information, as follows


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

Find_loaded_library(library_name)-&gt;CallConstructors(); //Check if the library is loaded
      }

    }

  }



  TRACE("\"%s\": calling constructors", name);



  // DT_INIT should be called before DT_INIT_ARRAY if both are present.

  CallFunction("DT_INIT", init_func);

  CallArray("DT_INIT_ARRAY", init_array, init_array_count, false);

}

```



As you can see, as the comment says, if the .init function and init_array exist, the program will in turn call the code in the corresponding position in the .init function and .init_array. Related instructions are as follows


```c++

#define DT_INIT		12	/* Address of initialization function */

#define DT_INIT_ARRAY	25	/* Address of initialization function array */

```



3. Create an open shared library entry and try to add it to the corresponding list for easy management. If the join fails, it will be released.


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

SharedLib * pActualEntry = addSharedLibEntry (pNewEntry);


if (pNewEntry! = pActualEntry) {
        ALOGI("WOW: we lost a race to add a shared lib (%s CL=%p)",

            pathName, classLoader);

        freeSharedLibEntry(pNewEntry);

return checkOnLoadResult (pActualEntry);
    } 

```



4. If the loading is successful, dlsym will be used to get the JNI_OnLoad function in the corresponding so file. If the function exists, it will be called. Otherwise, it will return directly.


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



## to sum up


This means that when the .so file is loaded, it will follow the function in the following order (if it doesn&#39;t exist, it will be skipped)


- .init function
- Functions in .init_array
- JNI_OnLoad function

