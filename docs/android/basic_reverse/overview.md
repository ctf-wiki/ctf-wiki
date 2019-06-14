[EN](./overview.md) | [ZH](./overview-zh.md)
# Android Reverse Basic Introduction


First, we need to clarify the purpose of Android reverse: ** I want to analyze the function of the program**. Then we naturally have two aspects (methods and objects) that can be considered


- Analytical methods can be used in the following ways
- Static analysis, reverse the source code, then read the analysis
- Dynamic analysis, dynamic debugging of code, in general dynamic analysis is inseparable from static analysis.
- Analysis objects, generally have the following two types of objects
- java, layer code
- Native layer code


It is not difficult to see that in order to analyze Android applications, the basic knowledge of the Java layer and the knowledge of the native layer are still necessary.


Currently, Android reverse is mainly used in the following directions.


1. app security review
2. System vulnerability mining
3. Malicious code killing
4. Analysis of product technology principles in the same industry
5. Remove security mechanisms