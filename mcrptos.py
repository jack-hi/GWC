#!/usr/bin/python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
import hashlib

class AES128:
    padding = lambda t: \
        t + (AES.block_size-len(t)%AES.block_size)*bytes([AES.block_size-len(t)%AES.block_size])
    unpadding = lambda t: t[:-t[-1]]

    def __init__(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("AES key must be instance of bytes/bytearray.")
        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be instance of bytes/bytearray.")
        return self.cipher.encrypt(AES128.padding(data))

    def decrypt(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be instance of bytes/bytearray.")
        return AES128.unpadding(self.cipher.decrypt(data))

class MD5:
    def __init__(self):
        self.md5 = hashlib.new('md5')

    def digest(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be instance of bytes/bytearray.")
        self.md5.update(data)
        return self.md5.digest()




if __name__ == '__main__':
    key = b'1234567890123456'
    plain_text = bytes([0xAC, 0x01, 0x00, 0x12, 0x00, 0x88, 0x07, 0xE1, 0x09, 0x1C, 0x0A, 0x0F, 0x12, 0x7F, 0xCA])

    maes = AES128(key)
    mecr = maes.encrypt(plain_text)
    print(mecr)
    mdcr = maes.decrypt(mecr)
    print(mdcr)
    mm5 = MD5().digest(plain_text)
    print(len(mm5))
    print(mm5)


    import crc16

    # a = crc16._crc16.crc16xmodem(b'2')
    a = crc16.crc16xmodem(b'2')
    print(f'{a:x}')