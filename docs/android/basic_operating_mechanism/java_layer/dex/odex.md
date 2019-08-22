[EN](./odex.md) | [ZH](./odex-zh.md)
# ODEX file


## basic introduction


We know that the code for the java layer of the Android application is in the class.dex file of the apk file. In general, we get the dex file and parse it every time we start the program. Obviously, every time we do this, the efficiency will be lower. Android developers have come up with a way to optimize dex files when they are initially loaded, and generate an ODEX file, which is stored in the /data/dalvik-cache directory. When running this program again later, we only need to load the optimized ODEX file directly, eliminating the need to optimize each time. For the Android ROM&#39;s own app, it is directly converted to an odex file and stored in the same directory as the apk, so that when the phone is turned on every time, it will be much faster.


## basic structure


To be added.


##Generation process


To be added.






# 参考阅读


- Android software security and reverse analysis