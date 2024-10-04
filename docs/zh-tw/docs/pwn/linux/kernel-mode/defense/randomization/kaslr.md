# KASLR

## 介紹

在開啓了 KASLR 的內核中，內核的代碼段基地址等地址會整體偏移。

## 發展歷史

TODO。

## 實現

TODO。

## 開啓與關閉

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `kaslr` 來開啓 KASLR。

如果是使用 qemu 啓動的內核，我們可以在 `-append` 選項中添加 `nokaslr` 來關閉 KASLR。

## Attack

通過泄漏內核某個段的地址，就可以得到這個段內的所有地址。比如當我們泄漏了內核的代碼段地址，就知道內核代碼段的所有地址。

## 參考

- https://outflux.net/slides/2013/lss/kaslr.pdf
- https://bneuburg.github.io/volatility/kaslr/2017/04/26/KASLR1.html

