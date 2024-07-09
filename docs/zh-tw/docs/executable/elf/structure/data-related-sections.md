# Data Related Sections

## .BSS Section

未初始化的全局變量對應的節。此節區不佔用 ELF 文件空間，但佔用程序的內存映像中的空間。當程序開始執行時，系統將把這些數據初始化爲 0。bss其實是block started by symbol 的簡寫。

## .data Section

這些節區包含初始化了的數據，會在程序的內存映像中出現。

## .rodata Section

這些節區包含只讀數據，這些數據通常參與進程映像的不可寫段。

