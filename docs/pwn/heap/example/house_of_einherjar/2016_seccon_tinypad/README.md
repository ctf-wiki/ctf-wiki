# tinypad

__keywords__: heap exploitation, glibc, Use After Free, malloc\_consolidate, poisoned NUL byte, House of Einherjar

## What's This?
This is the article for [CTF Advent Calendar 2016](http://www.adventar.org/calendars/1714).
"tinypad" was a pwnable challenge for SECCON 2016 Online CTF.  

## My Intended Solution
After an analysis, we can get two vulnerabilities, Use After Free(leak only) and Non-NUL terminated string.  
A fastbin-sized free()'d chunk and one smallbin-sized `malloc()` lead a fastbin into `unsorted_chunks` so we can leak the address of `main_arena` and calculate the address which is mapped the libc.   
Now, we can corrupt a chunk size by writing into Non-NULL terminated string but we are not able to use House of Force due to limited request size for an allocation. House of Einherjar is suitable in this case.   
We can forge the list of pads and get an arbitrary memory read and a partial write.   

It's enough to write up. See the detail in "exploit\_tinypad.py".  

## Other Solutions
There is another solution. [@Charo-IT solved by Poisoned NUL byte and House of Spirit(freeing a fake fastbin chunk)](https://gist.github.com/Charo-IT/c1931eb6a1b1bb80140d51822f4f4c51), perhaps I should not refer to "House of Einherjar" in the flag...
If you found a solution which is different from my one, tell me on [DM or reply](https://twitter.com/hhc0null/). :)

___Good pwn time,___  
@hhc0null

