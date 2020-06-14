#encoding:utf8
import getopt
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends.openssl import backend as openssl_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import  utils
from cryptography.hazmat.primitives.asymmetric import padding

#装载私钥
#输入：.pem私钥的路径
def keyload(privatekey):
    with open(privatekey,'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

#装载公钥文件
def pubkeyload(publickey):
    key_file = open(publickey, 'rb')
    key_data = key_file.read()
    key_file.close()

    public_key = serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )
    return public_key

#计算得到摘要值
#输入：源文件
#返回值：返回hash之后的结果
def caldigests(srcfile):
    # 得到digest
    digest = hashes.Hash(
        hashes.SHA256(),
        backend=default_backend()
    )
    with open(srcfile,"rb") as src_file:
        while True:
            data = src_file.read(2048)
            if not data:
                break
            else:
                digest.update(data)
        result_data = digest.finalize()#保存得到文件hash值最终将hash值保存到一个校验文件中
    src_file.close()
    return result_data

#对需要进行签名的数据签名
#对于文件签名可以得到文件的hash值
#输入：需要签名的文件
def Signing(private_key,srcfile):
    digest = caldigests(srcfile)#源文件的数字摘要
    chosen_hash = hashes.SHA256()
    #得到签名
    sig = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )
    return sig

#对签名的文件进行验证
#输入：需要验证的文件和公钥,以及得到的签名
def verification(srcfile,public_key,sig):
    chosn_hash = hashes.SHA256()
    digest = caldigests(srcfile)
    verify_ok=False
    try:
        public_key.verify(
            sig,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosn_hash)
        )
    except InvalidSignature:
        print('error')
    else:
        verify_ok=True
    return verify_ok

#得到盐值
def getsalt():
    salt = os.urandom(16)#16字节
    return salt

#根据盐值和口令生成密钥，名钥长度为32byte
def gen_key(salt,password):
    """
    :return key bytes[] 返回密钥的字节数组表示
    """
    # 使用PBKDF2进行键拉伸，增强密钥安全性，即使较短的口令也能生成足够强度的对称加密密钥，加入盐值，保证相同的口令能生成随机性较强的密钥
    # PBKDF内部使用HMAC对输入的密码和盐值进行处理，并迭代多次，派生出指定长度的密钥

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),  # 使用一种hash算法，[128,256,512]等
        length=32,  # 生成的密钥长度(bytes)
        salt=salt,
        iterations=1000000,
        backend=openssl_backend
    )
    key = kdf.derive(password)
    return key

def encrypt(salt,iv,password,data):
    key=gen_key(salt,password)
    encryptor = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    cipher = encryptor.update(data)
    return cipher

def decrypt(salt,iv,password,data):
    key = gen_key(salt, password)
    decrypto = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    text = decrypto.update(data)
    return text

def menu1():
    argv1 = sys.argv[1]
    if argv1=='-s':
        salt=getsalt()
        argv3 = sys.argv[3]
        argv5 = sys.argv[5]#需要签名的源文件
        password=sys.argv[7]
        private_key1 = keyload(argv3)
        iv = os.urandom(16)
        with open(argv5,'rb') as f:
            text = f.read()
        print(text)
        cipher=encrypt(salt,iv,password.encode(),text)

        sig = Signing(private_key1, argv5)
        filename = argv5
        outputfile = filename + '.enc'
        with open(outputfile, 'wb') as w:
            w.write(salt)
            w.write(iv)
            w.write(sig)
            w.write(cipher)
        print("签名成功,加密成功！")
        print(outputfile)
    elif argv1 == '-v':
        argv7 = sys.argv[7]
        argv3 = sys.argv[3]
        argv5 = sys.argv[5]
        public_key1 = pubkeyload(argv3)
        with open(argv5,'rb') as f:
            data = f.read()
        salt = data[:16]
        iv = data[16:32]
        sig = data[32:160]
        text =data[160:]
        flag = verification(argv5, public_key1, sig)
        filename = (argv3.split('.')[0])
        if flag:
            print('文件来自' + filename)
            plaintext = decrypt(salt,iv,argv7.encode(),text)
            dstfile = argv5+'.dec'
            with open(argv5,'rb') as w:
                w.write(plaintext)
        else:
            print('文件不是来自' + filename)
    else:
        print('签名：-s -e privatekeyfile -i srcfile -p password')
        print('认证：-v -c publicekeyfile -i srcfile -p password')

if __name__ == '__main__':
    menu1()

