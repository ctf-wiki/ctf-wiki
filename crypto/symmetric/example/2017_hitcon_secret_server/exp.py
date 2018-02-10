#coding=utf-8
from pwn import *
import base64, time, random, string
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5
#context.log_level = 'debug'
if args['REMOTE']:
    p = remote('52.193.157.19', 9999)
else:
    p = remote('127.0.0.1', 7777)


def strxor(str1, str2):
    return ''.join([chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(str1, str2)])


def pad(msg):
    pad_length = 16 - len(msg) % 16
    return msg + chr(pad_length) * pad_length


def unpad(msg):
    return msg[:-ord(msg[-1])]  # 去掉pad


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
    p.recvuntil('Done!\n')


iv_encrypt = '2jpmLoSsOlQrqyqE'


def getmd5enc(i, cipher_flag, cipher_welcome):
    """return encrypt( md5( flag[7:7+i] ) )"""
    ## keep iv[7:] do not change, so decrypt won't change
    new_iv = flipplain("hitcon{".ljust(16, '\x00'), "get-md5".ljust(
        16, '\x00'), iv_encrypt)
    payload = new_iv + cipher_flag
    ## calculate the proper last byte number
    last_byte_iv = flipplain(
        pad("Welcome!!"),
        "a" * 15 + chr(len(cipher_flag) + 16 + 16 - (7 + i + 1)), iv_encrypt)
    payload += last_byte_iv + cipher_welcome
    p.sendline(base64.b64encode(payload))
    return p.recvuntil("\n", drop=True)


def main():
    bypassproof()

    # result of encrypted Welcome!!
    cipher = p.recvuntil('\n', drop=True)
    cipher_welcome = base64.b64decode(cipher)[16:]
    log.info("cipher welcome is : " + cipher_welcome)

    # execute get-flag
    get_flag_iv = flipplain(pad("Welcome!!"), pad("get-flag"), iv_encrypt)
    payload = base64.b64encode(get_flag_iv + cipher_welcome)
    p.sendline(payload)
    cipher = p.recvuntil('\n', drop=True)
    cipher_flag = base64.b64decode(cipher)[16:]
    flaglen = len(cipher_flag)
    log.info("cipher flag is : " + cipher_flag)

    # get command not found cipher
    p.sendline(base64.b64encode(iv_encrypt + cipher_welcome))
    cipher_notfound = p.recvuntil('\n', drop=True)

    flag = ""
    # brute force for every byte of flag
    for i in range(flaglen - 7):
        md5_indexi = getmd5enc(i, cipher_flag, cipher_welcome)
        md5_indexi = base64.b64decode(md5_indexi)[16:]
        log.info("get encrypt(md5(flag[7:7+i])): " + md5_indexi)
        for guess in range(256):
            # locally compute md5 hash
            guess_md5 = MD5.new(flag + chr(guess)).digest()
            # try to null out the md5 plaintext and execute a command
            payload = flipplain(guess_md5, 'get-time'.ljust(16, '\x01'),
                                iv_encrypt)
            payload += md5_indexi
            p.sendline(base64.b64encode(payload))
            res = p.recvuntil("\n", drop=True)
            # if we receive the block for 'command not found', the hash was wrong
            if res == cipher_notfound:
                print 'Guess {} is wrong.'.format(guess)
            # otherwise we correctly guessed the hash and the command was executed
            else:
                print 'Found!'
                flag += chr(guess)
                print 'Flag so far:', flag
                break


if __name__ == "__main__":
    main()
