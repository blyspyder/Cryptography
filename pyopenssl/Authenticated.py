#encoding:utf-8
'''GCM模式的认证加密实现'''
import os
import sys
import cryptography
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ass = struct.Struct('16s')
#加密函数
#输入：需要加密的数据，关联数据，盐值，用户口令
def encrypto(srcfile,encryfile,aad,salt,password):
    with open(srcfile,'rb') as f:
        srcdata=f.read()
    #生成256位的秘钥
    key = gen_key(salt,password.encode())
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data=srcdata,associated_data=aad)
    with open(encryfile,'wb') as w:
        w.write(ct)
        w.write(salt)
        w.write(nonce)
    print('加密成功！')

#解密函数
def decrypto(srcfile,plainfile,aad,password):
    with open(srcfile,'rb') as f:
        data = f.read()
    srcdata = data[:-28]
    salt = data[-28:-12]
    nonce = data[-12:]

    #重新生成密钥
    key = gen_key(salt,password.encode())
    aesgem = AESGCM(key)
    try:
        plaintext = aesgem.decrypt(nonce,srcdata,aad)
        with open(plainfile,'wb') as w:
            w.write(plaintext)
        print('解密成功！')
    except cryptography.exceptions.InvalidTag as error:
        print(error)
        print('解密、认证失败')

#得到盐值
def getsalt():
    salt = os.urandom(16)
    return salt

#根据盐值和口令生成密钥，名钥长度为32byte
def gen_key(salt,password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),  # 使用一种hash算法，[128,256,512]等
        length=32,  # 生成的密钥长度(bytes)
        salt=salt,
        iterations=1000000,
        backend=openssl_backend
    )
    key = kdf.derive(password)
    return key

def menu():

    flag=sys.argv[1]#进行加密或者解密
    inputfile = sys.argv[2]
    #用户输入口令
    p = sys.argv[3]
    password = sys.argv[4]

    #得到16byte的盐值
    salt = getsalt()
    print('* * * * * * * * * * * * * * * * * * * * * * * * * *')
    print('* create by: 软件学院信息安全专业包聆言           *')
    print('* data:2018/12/23                                 *')
    print('* * * * * * * * * * * * * * * * * * * * * * * * * *')

    if flag=='-e':
        outputfile = inputfile.split('.')[0] + '.enc'
        associdata = ass.pack(outputfile.encode())  # 打包数据
        encrypto(inputfile,outputfile,associdata,salt,password)
    elif flag=='-d':
        outputfile = inputfile.split('.')[0] + '.dec'
        associdata = ass.pack(inputfile.encode())  # 打包数据
        decrypto(inputfile,outputfile,associdata,password)
    else:
        #根据inputfile在其后添加enc加密，dec为解密
        print('crypto -e/-d inputfile -p password')

if __name__ == '__main__':
    menu()
