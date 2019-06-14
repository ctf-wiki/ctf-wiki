[EN](./get-shell.md) | [ZH](./get-shell-zh.md)
# shell Get a summary


## overview



The shell we get is generally in two forms.


- Directly interactive shell
- Bind the shell to the specified port of the specified ip


Here are a few common ways to get a shell.


## shellcode



When using shellcode to get a shell, the basic requirement is that we can place the shellcode in a ** writable executable memory area**. Therefore, when there is no memory area to write executable, we need to use the function `mprotect` to set the permissions of the relevant memory.


In addition, sometimes the characters in the shellcode must meet certain requirements, such as printable characters, letters, numbers, and so on.


## system



We usually execute functions such as system(&quot;/bin/sh&quot;), system(&#39;sh&#39;).


Here we mainly need to find some addresses, you can refer to the section for obtaining the address.


- the address of system
- &quot;/bin/sh&quot;, &quot;sh&quot; address
- binary is a string inside
- Consider personal reading the corresponding string
- libc actually has /bin/sh


When you get the shell in system, a very good advantage is that we only need to arrange one parameter. The disadvantage is that when we lay out the parameters, we may not be able to execute because the environment variables are destroyed.


## execve



Execute execve(&quot;/bin/sh&quot;, NULL, NULL).


When using `execve` to get a shell, the first few are consistent with system. But it has the advantage of being almost immune to environmental variables. But the downside is that we need to arrange three parameters.


In addition, we can also use one_gadget to get the shell in glibc.


## syscall



The system call number `__NR_execve` is 11 in IA-32 and 59 in x86-64.


Its advantage is that it is almost immune to environmental variables. However, we need to find a system call command like `syscall`.