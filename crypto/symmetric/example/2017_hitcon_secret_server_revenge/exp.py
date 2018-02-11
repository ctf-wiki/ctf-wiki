from pwn import *
import base64, time, random, string
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
#context.log_level = 'debug'

p = remote('127.0.0.1', 7777)


def strxor(str1, str2):
    return ''.join([chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(str1, str2)])


def pad(msg):
    pad_length = 16 - len(msg) % 16
    return msg + chr(pad_length) * pad_length


def unpad(msg):
    return msg[:-ord(msg[-1])]  # remove pad


def flipplain(oldplain, newplain, iv):
    """flip oldplain to new plain, return proper iv"""
    return strxor(strxor(oldplain, newplain), iv)


def bypassproof():
    p.recvuntil('SHA256(XXXX+')
    lastdata = p.recvuntil(')', drop=True)
    p.recvuntil(' == ')
    digest = p.recvuntil('\nGive me XXXX:', drop=True)

    def proof(s):
        return SHA256.new(s + lastdata).hexdigest() == digest

    data = pwnlib.util.iters.mbruteforce(
        proof, string.ascii_letters + string.digits, 4, method='fixed')
    p.sendline(data)


def sendmsg(iv, cipher):
    payload = iv + cipher
    payload = base64.b64encode(payload)
    p.sendline(payload)


def recvmsg():
    data = p.recvuntil("\n", drop=True)
    data = base64.b64decode(data)
    return data[:16], data[16:]


def getmd5enc(i, cipher_token, cipher_welcome, iv):
    """return encrypt( md5( token[:i+1] ) )"""
    ## keep iv[7:] do not change, so decrypt msg[7:] won't change
    get_md5_iv = flipplain("token: ".ljust(16, '\x00'), "get-md5".ljust(
        16, '\x00'), iv)
    payload = cipher_token
    ## calculate the proper last byte number
    last_byte_iv = flipplain(
        pad("Welcome!!"),
        "a" * 15 + chr(len(cipher_token) + 16 + 16 - (7 + i + 1)), iv)
    payload += last_byte_iv + cipher_welcome
    sendmsg(get_md5_iv, payload)
    return recvmsg()


def get_md5_token_indexi(iv_encrypt, cipher_welcome, cipher_token):
    md5_token_idxi = []
    for i in range(len(cipher_token) - 7):
        log.info("idx i: {}".format(i))
        _, md5_indexi = getmd5enc(i, cipher_token, cipher_welcome, iv_encrypt)
        assert (len(md5_indexi) == 32)
        # remove the last 16 byte for padding
        md5_token_idxi.append(md5_indexi[:16])
    return md5_token_idxi


def doin(unpadcipher, md5map, candidates, flag):
    if unpadcipher in md5map:
        lastbyte = md5map[unpadcipher]
    else:
        lastbyte = 0
    if flag == 0:
        lastbyte ^= 0x80
    newcandidates = []
    for x in candidates:
        for c in range(256):
            if MD5.new(x + chr(c)).digest()[-1] == chr(lastbyte):
                newcandidates.append(x + chr(c))
    candidates = newcandidates
    print candidates
    return candidates


def main():
    bypassproof()

    # result of encrypted Welcome!!
    iv_encrypt, cipher_welcome = recvmsg()
    log.info("cipher welcome is : " + cipher_welcome)

    # execute get-token
    get_token_iv = flipplain(pad("Welcome!!"), pad("get-token"), iv_encrypt)
    sendmsg(get_token_iv, cipher_welcome)
    _, cipher_token = recvmsg()
    token_len = len(cipher_token)
    log.info("cipher token is : " + cipher_token)

    # get command not found cipher
    sendmsg(iv_encrypt, cipher_welcome)
    _, cipher_notfound = recvmsg()

    # get encrypted(token[:i+1]),57 times
    md5_token_idx_list = get_md5_token_indexi(iv_encrypt, cipher_welcome,
                                              cipher_token)
    # get md5map for each unpadsize, 209-17 times
    # when upadsize>208, it will unpad ciphertoken
    # then we can reuse
    md5map = dict()
    for unpadsize in range(17, 209):
        log.info("get unpad size {} cipher".format(unpadsize))
        get_md5_iv = flipplain("token: ".ljust(16, '\x00'), "get-md5".ljust(
            16, '\x00'), iv_encrypt)
        ## padding 16*11 bytes
        padding = 16 * 11 * "a"
        ## calculate the proper last byte number, only change the last byte
        ## set last_byte_iv = iv_encrypted[:15] | proper byte
        last_byte_iv = flipplain(
            pad("Welcome!!"),
            pad("Welcome!!")[:15] + chr(unpadsize), iv_encrypt)
        cipher = cipher_token + padding + last_byte_iv + cipher_welcome
        sendmsg(get_md5_iv, cipher)
        _, unpadcipher = recvmsg()
        md5map[unpadcipher] = unpadsize

    # reuse encrypted(token[:i+1])
    for i in range(209, 256):
        target = md5_token_idx_list[56 - (i - 209)]
        md5map[target] = i

    candidates = [""]
    # get the byte token[i], only 56 byte
    for i in range(token_len - 7):
        log.info("get token[{}]".format(i))
        get_md5_iv = flipplain("token: ".ljust(16, '\x00'), "get-md5".ljust(
            16, '\x00'), iv_encrypt)
        ## padding 16*11 bytes
        padding = 16 * 11 * "a"
        cipher = cipher_token + padding + iv_encrypt + md5_token_idx_list[i]
        sendmsg(get_md5_iv, cipher)
        _, unpadcipher = recvmsg()
        # already in or md5[token[:i]][-1]='\x00'
        if unpadcipher in md5map or unpadcipher == cipher_notfound:
            candidates = doin(unpadcipher, md5map, candidates, 1)
        else:
            log.info("unpad size 1-16")
            # flip most significant bit of last byte to move it in a good range
            cipher = cipher[:-17] + strxor(cipher[-17], '\x80') + cipher[-16:]
            sendmsg(get_md5_iv, cipher)
            _, unpadcipher = recvmsg()
            if unpadcipher in md5map or unpadcipher == cipher_notfound:
                candidates = doin(unpadcipher, md5map, candidates, 0)
            else:
                log.info('oh my god,,,, it must be in...')
                exit()
    print len(candidates)
    # padding 0x01
    candidates = filter(lambda x: x[-1] == chr(0x01), candidates)
    # only 56 bytes
    candidates = [x[:-1] for x in candidates]
    print len(candidates)
    assert (len(candidates[0]) == 56)

    # check-token
    check_token_iv = flipplain(
        pad("Welcome!!"), pad("check-token"), iv_encrypt)
    sendmsg(check_token_iv, cipher_welcome)
    p.recvuntil("Give me the token!\n")
    p.sendline(base64.b64encode(candidates[0]))
    print p.recv()

    p.interactive()


if __name__ == "__main__":
    main()
