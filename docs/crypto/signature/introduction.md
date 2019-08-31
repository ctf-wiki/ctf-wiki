[EN](./introduction.md) | [ZH](./introduction-zh.md)
# digital signature


In daily life, when we participate in an event, we may need to sign in order to prove that we are indeed present, and to prevent the leader from knowing, you know. . . But in fact, this signature is easy to be forged, just ask someone to sign it, or find someone who will imitate someone else&#39;s handwriting to help sign it. In the computer world, we may need an electronic signature, because most of the time we use electronic files, what should we do at this time? Of course, we can still choose to use our own name. But there is another way, that is, using digital signatures, which are more difficult to forge and more trustworthy. The primary use of digital signatures is to ensure that the message does come from the person who claims to have generated the message.


Digital signatures are mainly used to sign digital messages in case of impersonation or falsification of messages, and can also be used for identity authentication of both parties.


Digital signatures rely on asymmetric cryptography because we have to make sure that one party can do something while the other party cannot do something like this. The basic principle is as follows


![](./figure/Digital_Signature_diagram.png)



Digital signatures should have the following characteristics:


(1) The signature is credible: anyone can verify the validity of the signature.


(2) Signatures are unforgeable: it is difficult for anyone else to falsify their signatures except for legitimate signers.


(3) Signatures are not reproducible: the signature of one message cannot be changed to the signature of another message by copying. If the signature of a message is copied from elsewhere, anyone can discover the inconsistency between the message and the signature, so that the signed message can be rejected.


(4) The signed message is immutable: the signed message cannot be tampered with. Once the signed message has been tampered with, anyone can discover the inconsistency between the message and the signature.


(5) The signature is non-repudiation: the signer cannot deny his signature afterwards.