[EN](./ld_preload.md) | [ZH](./ld_preload-zh.md)
## Principle


Under normal circumstances, Linux dynamic loader `ld-linux` (see man page ld-linux (8)) will search and load the shared link library file required by the program, and `LD_PRELOAD` is an optional environment variable, including One or more paths to the shared link library file. The loader will load the shared link library specified by `LD_PRELOAD` before the C language runtime, which is called preloading (`preload`).


Preloading means that its functions will be called before the function of the same name in other library files, so that the library functions can be blocked or replaced. The path of multiple shared link library files can be `colon` or `space. `To distinguish. Obviously not affected by `LD_PRELOAD`, only those statically linked programs.


Of course, to avoid malicious attacks, the loader will not be preloaded with `LD_PRELOAD` in the case of `ruid != euid`.


Read more: [https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html#ixzz569cbyze4](https://blog.fpmurphy.com/2012/09/all-about-ld_preload. Html#ixzz569cbyze4)


## Example


Let&#39;s take the 2014 `Hack In The Box Amsterdam: Bin 100` as an example. Download the topic: [hitb_bin100.elf](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/linux -re/2014_hitb/hitb_bin100.elf)


This is a 64-bit ELF file. The results are shown below:


![run.png](./figure/2014_hitb/run.png)



The program seems to be printing some sentences all the time. And there are no signs of stopping. Let&#39;s open it with IDA. First press `Shift+F12` to find the string.


![ida_strings.png](./figure/2014_hitb/ida_strings.png)



Obviously, apart from the sentences that have been printed, we found some interesting strings:


```

.rodata:0000000000400A53 00000006 C KEY:

.rodata:0000000000400A5F 0000001F C OK YOU WIN. HERE'S YOUR FLAG:

```



We came to the key code according to the cross-reference of `OK YOU WIN. HERE&#39;S YOUR FLAG: ` (I deleted some unnecessary code).


```  c

int __cdecl main(int argc, const char **argv, const char **envp)

{

  qmemcpy(v23, &unk_400A7E, sizeof(v23));

v3 = v22;
  for ( i = 9LL; i; --i )

  {

* (_DWORD *) v3 = 0;
v3 + = 4;
  }

  v20 = 0x31337;

  v21 = time(0LL);

  do

  {

    v11 = 0LL;

    do

    {

      v5 = 0LL;

      v6 = time(0LL);

Srand(233811181 - v21 + v6); // Initialize the random number seed
      v7 = v22[v11];

V22[v11] = rand() ^ v7; // pseudo-random number
      v8 = (&funny)[8 * v11];

      while ( v5 < strlen(v8) )

      {

v9 = v8 [v5];
        if ( (_BYTE)v9 == 105 )

        {

          v24[(signed int)v5] = 105;

        }

        else

        {

          if ( (_DWORD)v5 && v8[v5 - 1] != 32 )

V10 = __ctype_toupper_loc(); // uppercase
          else

V10 = __ctype_tolower_loc(); // lowercase
          v24[(signed int)v5] = (*v10)[v9];

        }

++ v5;
      }

      v24[(signed int)v5] = 0;

      ++v11;

__printf_chk(1LL, &quot;Uranium %80s uranium 玕n&quot;, v24); // garbled is actually a note
      sleep(1u);

    }

    while ( v11 != 36 );

--v20;
  }

  while ( v20 );

V13 = v22; // key is stored in the v22 array
  __printf_chk(1LL, "KEY: ", v12);

  do

  {

    v14 = (unsigned __int8)*v13++;

__printf_chk(1LL, &quot;%02x &quot;, v14); // output key
  }

  while ( v13 != v23 );

  v15 = 0LL;

  putchar(10);

  __printf_chk(1LL, "OK YOU WIN. HERE'S YOUR FLAG: ", v16);

  do

  {

V17 = v23[v15] ^ v22[v15]; // XOR with the value of key
++ v15;
Putchar(v17); // output flag
  }

  while ( v15 != 36 );

Putchar(10); // output line break
  result = 0;

  return result;

}

```



The whole code flow is mainly to continuously output the sentences in `funny`, output the `key` after satisfying the loop condition, and XOR the `flag` to get the value of `flag`.


But we can see that the number of times the whole loop is relatively small. So we can use some methods to make the loop faster. For example, I manually patch it, not let the program output the string (actually `printf `The time consumption is quite a lot.) The second is to use `LD_PRELOAD` to make the program&#39;s `sleep()` invalid. It can obviously save time.


The process of manual patching is relatively simple. We can find the code location and then modify it with some hex editors. Of course, we can also use `IDA` to do patch work.


`` `asm
.text:00000000004007B7                 call    ___printf_chk

.text:00000000004007BC                 xor     eax, eax

```



Point the cursor on `call ___printf_chk`, then select the menu `Edit-&gt;Patch Program-&gt;Assemble` (of course you can use other patch methods. The effect is the same). Then modify it to `nop(0x90)`, as follows Figure


![ida_patch.png](./figure/2014_hitb/ida_patch.png)



Modify the assembly code between `4007B7` and `4007BD` to `nop`. Then select the menu `Edit-&gt;Patch Program-&gt;Apply patches to input file`. Of course, it is best to make a backup (ie check) `Create a backup`), then click OK (I renamed to `patched.elf`, download link: [patched.elf](https://github.com/ctf-wiki/ctf-challenges/blob/ Master/reverse/linux-re/2014_hitb/patched.elf)).


![ida_apply.png](./figure/2014_hitb/ida_apply.png)



Now go to the `LD_PRELOAD` section. Here we simply write the c code, download link: [time.c](https://github.com/ctf-wiki/ctf-challenges/blob/master/reverse/linux-re/ 2014_hitb/time.c)


``` c

static int t = 0x31337;


void sleep(int sec) {

	t += sec;

}



int time() {

	return t;

}

```



Then use the command `gcc --shared time.c -o time.so` to generate the dynamic link file. Of course, the download link is also given: [time.so](https://github.com/ctf-wiki/ctf- Challenge/blob/master/reverse/linux-re/2014_hitb/time.so)


Then open the linux terminal and run the command: `LD_PRELOAD=./time.so ./patched.elf`


![LD_PRELOAD.png](./figure/2014_hitb/ld_preload.png)



After a while, you can hear the sound of the CPU running wildly, and then the flag will come out soon.