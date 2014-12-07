from ocb.aes import AES
from ocb import OCB
from base64 import b64encode, b64decode
from Crypto import Random
import md5
import os
from pbkdf2 import PBKDF2 as pbkdf2

class Cipher:

    keySize = 32
    blockSize = 16

    @staticmethod
    def get_key():
        return b64encode(Random.get_random_bytes(Cipher.keySize))[:Cipher.keySize]

    @staticmethod
    def encrypt(text, secret):
        key = pbkdf2(secret, '').read(Cipher.keySize)
        plaintext = bytearray(text)
        header = bytearray('')
        aes = AES(Cipher.keySize * 8)
        ocb = OCB(aes)
        nonce = bytearray(Random.get_random_bytes(Cipher.blockSize))
        ocb.setKey(key)
        ocb.setNonce(nonce)
        (tag,ciphertext) = ocb.encrypt(plaintext, header)
        enc = b64encode(nonce + tag + ciphertext)
        return enc

    @staticmethod
    def decrypt(enc, secret):
        dec = b64decode(enc)
        nonce = bytearray(dec[:Cipher.blockSize])
        tag = bytearray(dec[Cipher.blockSize:Cipher.keySize])
        ciphertext = bytearray(dec[Cipher.keySize:])

        key = pbkdf2(secret, '').read(Cipher.keySize)
        aes = AES(Cipher.keySize * 8)
        ocb = OCB(aes)
        ocb.setKey(key)
        ocb.setNonce(nonce)
        kept_integrity, values = ocb.decrypt('', ciphertext, tag)
        if not kept_integrity:
            raise Exception('Ciphertext has been messed with!')
        return values.decode("utf-8")

def example_encryption():
    secret = 'this is a secret'
    encrypted = Cipher.encrypt('blah blah', secret)
    decrypted = Cipher.decrypt(encrypted, secret)
    return decrypted
#print example_encryption()

