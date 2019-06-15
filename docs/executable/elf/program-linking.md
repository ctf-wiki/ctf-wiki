[EN](./program-linking.md) | [ZH](./program-linking-zh.md)
---

typora-root-url: ../../../docs

---





#程序链接


## Static link


## Dynamic link


Dynamic linking is mainly to resolve variables or references to functions during program initialization or during program execution. Some sections and head elements in an ELF file are related to dynamic links. Dynamically linked models are defined and implemented by the operating system.


### Dynamic Linker



The dynamic linker can be used to help load the libraries needed by the application and parse the dynamic symbols (functions and global variables) exported by the library.


When using dynamic linking to construct a program, the link-editor adds an element of type PT_INTERP to the program&#39;s program header to tell the system to call the dynamic linker as a program interpreter.


&gt; It should be noted that different systems will be different for the dynamic linker provided by the system.


The executable and the dynamic linker work together to create a process image for the program, as detailed below:


1. Add the memory segment of the executable to the process image.
2. Add the memory segment of the shared object file to the process image.
3. Relocate the executable and shared object files.
4. If passed to the dynamic linker a file descriptor, close it.
5. Pass control to the program. This makes us feel as if the program got the execute permission directly from the executable.


The link editor also creates a variety of data to assist the dynamic linker in handling executables and shared object files, such as


- Sections of type SHT_DYNAMIC contain a variety of data, including information about other dynamic links at the beginning of this section.
- The section .hash of type SHT_HASH contains a symbol hash table.
- Sections .got and .plt of type SHT_PROGBITS contain two separate tables: global offset table, procedure linked table. The program uses the procedure link table to process the address independent code.


Because all UNIX System V imports basic system services from a shared object file, the dynamic linker participates in the execution of each TIS ELF-conforming program.


As stated in the program loading, the shared object file may occupy a different virtual address than that recorded in the program header. The dynamic linker relocates the memory image and updates the absolute address before the program takes control. If the shared object file is indeed loaded into the address specified in the program header, then the values of those absolute addresses will be correct. But usually, this will not happen.


If the process&#39;s environment has a non-null value called LD_BIND_NOW, then the dynamic linker performs all relocations when passing permissions to the program. For example, all values of the following environment variables specify this behavior.


- LD_BIND_NOW = 1

- LD_BIND_NOW = on

- LD_BIND_NOW = off



Otherwise, LD_BIND_NOW either does not exist in the current process environment or has a non-null value. The dynamic linker can delay the entry of the link table of the parsing process. This is actually the delay binding of the plt table, that is, when the program needs to use a certain symbol, then address resolution, which can reduce the load of symbol resolution and relocation.




### Function Address



The address reference of a function in the executable and the reference associated with it in the shared target may not be resolved to a value. The corresponding reference in the shared object file will be parsed by the dynamic linker to the virtual address corresponding to the function itself. The corresponding reference in the executable (from the shared object file) will be resolved by the link editor to the address in the entry for the corresponding function in the procedure link table.


In order to allow different function addresses to work as expected, if an executable file references a function defined in the shared object file, the link editor will put the process link table entry of the corresponding function into the symbol associated with it. In the table entry. The dynamic linker handles this symbol table item in a special way. If the dynamic linker is looking for a symbol and encounters a symbol in the executable file for a symbol table entry, it will follow the following rules:


1. If the `st_shndx` of the symbol table entry is not `SHN_UNDEF `, the dynamic linker will find the definition of this symbol and use its st_value as the address of the symbol.
2. If `st_shndx` is `SHN_UNDEF` and the symbol type is `STT_FUNC` and the `st_value` member is not 0, the dynamic linker will treat this entry as special and use the value of `st_value` as the symbol the address of.
3. Otherwise, the dynamic linker will assume that the symbols in the executable are undefined and continue processing.


Some relocations are related to the entries of the process linkage table. These entries are used for direct function calls, not for reference function addresses. These relocations are not handled as above because the dynamic linker must not be able to redirect process link table entries and point them to themselves.


### Shared Object Dependencies



When the link editor is processing an archive library, it extracts the library members and copies them into the output object file. This statically linked operation does not require dynamic connector participation during execution. The shared object file also provides the service, and the dynamic linker must attach the appropriate shared object file to the process image for easy execution. Therefore, executable files and shared object files specifically describe their dependencies.


When a dynamic linker creates a memory segment for an object file, the dependencies described in the DT_NEEDED entry give the service that depends on the file to support the program. The dynamic linker creates a complete process image by continually connecting the referenced shared object files (even if a shared object file is referenced multiple times, it will only be connected once by the dynamic linker) and their dependencies. When parsing symbol references, the dynamic linker uses BFS (broadness first search) to check the symbol table. That is, first, it checks the symbol table of the executable itself, and then checks the symbol table in the DT_NEEDED entry in order before continuing to view the next dependency, and so on. The shared object file must be readable by the program, and other permissions are not required.


The name in the dependency list is either a string in DT_SONAME or the pathname of the shared object file used to build the corresponding target file. For example, if a linker uses a shared object file with the DT_SONAME entry name lib1 and a shared object file with a path named /usr/lib/lib2, the executable will contain lib1 and /usr/ Lib/lib2 dependency list.


If a shared object file has one or more /, such as /usr/lib/lib2 or directory/file, the dynamic linker will use that string directly as the path name. If there is no / in the name, such as lib1, then the following three mechanisms give the order in which the shared object files are searched.


- First, the dynamic array tag DT_RPATH may give a string containing a series of directories separated by :. For example /home/dir/lib:/home/dir2/lib: Tell us to search in the `/home/dir/lib` directory first, then search in `/home/dir2/lib`, and finally search in the current directory.


- Second, the variable named LD_LIBRARY_PATH in the process environment variable contains a list of directories of the above mentioned format, and there may be one at the end; followed by another directory listing followed by another directory listing. Here is an example with the same effect as the first one.


  - LD_LIBRARY_PATH=/home/dir/lib:/home/dir2/lib:

  - LD_LIBRARY_PATH=/home/dir/lib;/home/dir2/lib:

  - LD_LIBRARY_PATH=/home/dir/lib:/home/dir2/lib:;



All directories in LD_LIBRARY_PATH will only be searched after searching for DT_RPATH. Although some programs (such as the link editor) are dealing; the list is different in the way it is, but the dynamic linker handles it in exactly the same way. In addition, the dynamic linker accepts the semicolon representation syntax, as described above. .


- Finally, if the above two directories cannot locate the desired library, the dynamic linker searches for libraries under the `/usr/lib` path.


note


&gt; ** For security purposes, for programs identified by `set-user` and `set-group`, the dynamic linker ignores search environment variables (eg `LD_LIBRARY_PATH`) and only searches for directories specified by `DT_RPATH` and `/usr/ Lib`. **