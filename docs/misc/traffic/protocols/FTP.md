[EN](./FTP.md) | [ZH](./FTP-zh.md)
### FTP



`FTP` (File Transfer Protocol) is one of the protocols in the `TCP/IP` protocol suite. The `FTP` protocol consists of two components, one for the `FTP` server and the other for the `FTP` client. The `FTP` server is used to store files. Users can use the `FTP` client to access resources located on the `FTP` server via the `FTP` protocol. When developing a website, the web page or program is usually transferred to the `Web` server using the `FTP` protocol. In addition, because the `FTP` transmission efficiency is very high, this protocol is generally used when transferring large files on the network.


By default, the `FTP` protocol uses the `20` and `21` ports of the `TCP` port, where `20` is used to transfer data and `21` is used to transmit control information. However, whether to use `20` as the port for transmitting data is related to the transmission mode used by `FTP`. If the active mode is adopted, the data transmission port is `20`; if the passive mode is adopted, which port is ultimately used for the server side. Negotiate with the client to decide.