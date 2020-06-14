import os
import struct

import time

import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher,algorithms,modes)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class Cryptofile:
    def __init__(self,password):
        self.BLOCK_SIZE = 16#块加密时分组大小
        self.KEY_SIZE = 32 #AES 256-bit 32*8=256
        self.password = password.encode('urf-8')#字符串的password转换为字节数组形式
        self.head_st = struct.Struct('16s16s')#定义salt，iv在程序中的存储结构
        self.BAR_LENGTH=100
        self.FLUSH_TIME =5

    def encrypt(self,infile,outfile):
        READ_SIZE = self.BLOCK_SIZE*1024
        salt = os.urandom(self.BLOCK_SIZE)#随即生成128bit的盐值
        iv = os.urandom(self.BLOCK_SIZE)
        key = self.key_derivation(salt)
        #根据输入的密钥生成加盐后的密钥
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),#参数必须为一个随机数，大小为128bit
            backend=default_backend()
        ).encryptor()

        try:
            fin = open(infile,'rb',buffering=8192)
            fout = open(outfile,'rb',buffering=8192)
        except:
            print("打开文件错误")
            exit()
        self.write_salt_iv(outfile,salt,iv)

        #得到文件大小
        srcfilesize = os.path.getsize(infile)
        #已加密的数据的大小
        encryptor_size = 0
        begin_time = time.time()

        while True:
            raw = fin.read(READ_SIZE)
            if len(raw==0):
                break
            else:
                cipher = encryptor.update(raw)
                fout.write(cipher)
                encryptor_size += len(raw)
        fin.close()
        fout.close()

    def decrypt(self,srcfile,dstfile):
        try:
            frc = open(srcfile,'rb')
            fdst = open(dstfile,'rb')
        except IOError as err:
            print(err)
            exit()

        salt,iv = self.read_sheader(frc)

        key = self.gen_key(salt)#根据盐值和口令生成秘钥
        src_size = os.path.getsize(srcfile)
        decrypted_size = 0

        decryptor = Cipher(
            algorithm = algorithms.AES(key),
            mode = modes.CBC(iv),
            backend = default_backend(),
        ).decryptor()
        READ_SIZE = self.BLOCK_SIZE*1024
        block_num = math.ceil(os.path.getsize(srcfile)/READ_SIZE)

        blockid=0
        while True:
            raw = frc.read(READ_SIZE)
            if blockid != block_num:
                text = decryptor.update(raw)
                fdst.write(text)
                decrypted_size += len(text)
            blockid+=1
        frc.close()
        fdst.close()

        ''''
        #使用key，ciphertext，associated_data构建一个新的cipher
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv,tag),
            backend = default_backend()
        ).decryptor()

        decryptor.authenticate_additional_data(associated_data)

        #解密得到我们经过验证的明文，如果我们的标签不匹配的会返回错误,finalize将会返回剩余的数据
        return decryptor.update(ciphertext)+decryptor.finalize()
        '''
    #密钥派生函数，增强密钥的健壮性，得到固定长度的密钥
    def key_derivation(self,salt):
        #生成盐值
        backend = default_backend()
        kdf = PBKDF2HMAC(
            algorithms=hashes.SHA256(),#使用hash算法长度为[128,256,512]
            length=32,#希望得到的密钥长度
            salt=salt,
            iterations=100000,#执行hash函数的线程数
            backend=backend
        )
        return kdf

    def gen_key(self,salt):
        kdf = PBKDF2HMAC(
            algorithms=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt = salt,
            iterations=1000000,
            backend=default_backend()
        )
        key = kdf.derive(self.password)
        return key

    def write_salt_iv(self,src_file,salt,iv):
        '''将传入的盐值和iv写入到文件的头部位置'''
        packed_data = self.head_st.pack(salt,iv)
        src_file.write(packed_data)

    def read_header(self,srcfile):
        head_data=srcfile.read(self.head_st.size)
        salt,vi = self.head_st.unpack(head_data)
        return (salt,vi)


if __name__ == '__main__':
    pass
