import os
import sys
import time
import math
import msvcrt
import struct
import getopt
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import padding


class CryptoFile:
    def __init__(self,password):
        """
        :param password:String
        """
        self.BLOCK_SIZE = 16    # 块加密算法分组大小(bytes)
        self.KEY_SIZE = 32    #AES 256-bit
        self.password = password.encode('utf-8')    # 将字符串形式的password转为字节数组形式
        self.head_st = struct.Struct('16s16s')    #定义salt，iv在文件中存储结构
        self.BAR_LENGTH = 100
        self.FLUSH_TIME = 5

    def encryption(self,src,dst):
        salt = secrets.token_bytes(16)    #128-bit盐值，需要确保随机性。或使用salt = os.urandom(16)？     
        iv = secrets.token_bytes(self.BLOCK_SIZE)    #生成初始向量，用于块密码CBC加密模式
        key = self.gen_key(salt)
        READ_SIZE = self.BLOCK_SIZE * 1024    #单次读取文件块的大小，设置为加密块倍数，方便加密

        # 生成加密上下文实例，使用AES块加密算法，CBC加密模式
        encryptor = Cipher(
            algorithm = algorithms.AES(key),
            mode = modes.CBC(iv),
            backend = openssl_backend
        ).encryptor()

        #填充上下文实例，可以根据指定的块大小，对数据进行填充，填充内容为chr(N),N为指定块大小 - 数据块大小
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        try:
            fsrc = open(src,'rb',buffering = 8192)
            fdst = open(dst,'wb',buffering = 8192)
        except IOError as e:
            print(str(e))
            exit()

        self.write_header(fdst,salt,iv)    # 将盐值和随机向量写入加密后的文件中，解密时需要从文件中提取盐值和随机向量才能成功解密
        src_size = os.path.getsize(src)
        encrypted_size = 0
        begin_time = time.time()
        while True:
            raw = fsrc.read(READ_SIZE)    # 以字节形式读取原文件
            if len(raw) == 0:    # 返回字节数为0，说明读取到文件尾部，退出
                break
            if len(raw) == READ_SIZE:    # 对原文件分块加密后写入硬盘文件
                cipher = encryptor.update(raw)
                fdst.write(cipher)
                encrypted_size += READ_SIZE
                if time.time() - begin_time >= self.FLUSH_TIME:
                    self.progress_bar(src_size,encrypted_size)
                    begin_time = time.time()
            else:    # 对最后一块进行数据填充，以满足加密输入要求
                padded_raw = padder.update(raw)
                padded_raw += padder.finalize()
                cipher = encryptor.update(padded_raw)
                fdst.write(cipher)
                encrypted_size += len(raw)
                if time.time() - begin_time >= self.FLUSH_TIME:
                    self.progress_bar(src_size,encrypted_size)
                    begin_time = time.time()
                break
        fsrc.close()
        fdst.close()
        return (salt, iv)


    
    def decryption(self,src,dst):
        try:
            fsrc = open(src,'rb',buffering=8192)
            fdst = open(dst,'wb',buffering=8192)
        except IOError as err:
            print(err)
            exit()

        salt, iv = self.read_header(fsrc)    # 从文件头部读取加密后存入的盐值和随机向量
        key = self.gen_key(salt)    # 根据盐值和口令生成密钥
        src_size = os.path.getsize(src)
        decrypted_size = 0

        # 生成解密上下文实例，算法和模式需要与加密文件所使用的一致
        decryptor = Cipher(
            algorithm = algorithms.AES(key),
            mode = modes.CBC(iv),
            backend = openssl_backend
        ).decryptor()
        READ_SIZE = self.BLOCK_SIZE * 1024    #单次读取文件块的大小，设置为加密块倍数，方便加密
        block_num = math.ceil(os.path.getsize(src) / READ_SIZE)    # 计算文件以读取大小进行分块的块数量
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()    # 数据填充

        block_id = 1
        begin_time = time.time()
        while True:
            raw = fsrc.read(READ_SIZE)     # 以字节形式读取原文件
            if block_id != block_num:
                text = decryptor.update(raw)
                fdst.write(text)
                decrypted_size += len(raw)
                if time.time() - begin_time >= self.FLUSH_TIME:
                    self.progress_bar(src_size,decrypted_size)
                    begin_time = time.time()
            else:    # 当读取到最后一块时，可能该块是填充的数据，需要取出填充之前的原数据
                text = decryptor.update(raw)
                unpaded_data = unpadder.update(text)
                unpaded_data += unpadder.finalize()
                fdst.write(unpaded_data)
                decrypted_size += len(raw)
                if time.time() - begin_time >= self.FLUSH_TIME:
                    self.progress_bar(src_size,decrypted_size)
                    begin_time = time.time()
                break
            block_id += 1
        fsrc.close()
        fdst.close()

    def gen_key(self,salt):
        """
        :return key bytes[] 返回密钥的字节数组表示 
        """
        # 使用PBKDF2进行键拉伸，增强密钥安全性，即使较短的口令也能生成足够强度的对称加密密钥，加入盐值，保证相同的口令能生成随机性较强的密钥
        # PBKDF内部使用HMAC对输入的密码和盐值进行处理，并迭代多次，派生出指定长度的密钥
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA512(),    #使用一种hash算法，[128,256,512]等
            length = self.KEY_SIZE,    #生成的密钥长度(bytes)
            salt = salt,
            iterations = 1000000,
            backend = openssl_backend
        )
        key = kdf.derive(self.password)
        return key

    def write_header(self,src_file,salt,iv):
        """
        :src_file FILE
        :salt bytes[16]
        :iv bytes[16]
        将盐值和初始向量写入对应文件头部位置
        """
        packeted_data = self.head_st.pack(salt,iv)
        src_file.write(packeted_data)


    def read_header(self,src_file):
        """
        :src_file FILE 
        return (salt bytes[16], iv bytes[16])
        从指定文件头部读取盐值和初始向量
        """
        head_data = src_file.read(self.head_st.size)
        salt, iv = self.head_st.unpack(head_data)
        return (salt, iv)
        

    def progress_bar(self, total_size, change_size):
        hashes = "#" * int(float(change_size) / float(total_size) * self.BAR_LENGTH)  # 计算已经接收了的进度条长度
        spaces = " " * (self.BAR_LENGTH - len(hashes))  # 计算剩余进度条长度
        file_size_MB = total_size / 1024 / 1024 

        len_bar = hashes + spaces
        progress = float(change_size) / float(total_size) * 100

        # 小文件传输bug修正
        if len(len_bar) > 20:
            len_bar = '#' * 20
        if progress > 100:
            progress = 100

        sys.stdout.write(u"\r进度: [%s] %d%% 文件大小: %.2fMB" % (len_bar, progress, file_size_MB))

        return sys.stdout.flush()


def getpass(prompt = 'Password: ', hideChar = '*'):
        count = 0
        password = ''
        for char in prompt:
            msvcrt.putch(char.encode())# cuz password, be trouble
        while True:
            char = msvcrt.getch().decode()
            msvcrt.getch()
        
            if char == '\r' or char == '\n':
                break
        
            if char == '\003':
                raise KeyboardInterrupt # ctrl + c

            if char == '\b':
                count -= 1
                password = password[:-1]

                if count >= 0:
                    msvcrt.putch(b'\b')
                    msvcrt.putch(b' ')
                    msvcrt.putch(b'\b')
            
            else:
                if count < 0:
                    count = 0
                
                count += 1
                password += char
                msvcrt.putch(hideChar.encode())
            
        msvcrt.putch(b'\r')
        msvcrt.putch(b'\n')
    
        return "'%s'" % password if password != '' else "''"



def help():
    print("YMQM AES ENCRYPTION TOOL")
    print("Usage: python crypto.py -s src -t target -e encryption or -d decryption")
    exit()


def menu():
    short_opts = "-h-e-d-s:-t:-p:"
    try:
        opts, args = getopt.getopt(sys.argv[1:],short_opts)
    except getopt.GetoptError as err:
        print(str(err))
        help()

    do_enc = False
    do_dec = False
    src = ''
    dst = ''
    for opt_name, opt_value in opts:
        if opt_name in ('-h'):
            exit()
        elif opt_name in ('-s'):
            src = opt_value
        elif opt_name in ('-t'):
            dst = opt_value
        elif opt_name in ('-e'):
            do_enc = True
        elif opt_name in ('-d'):
            do_dec = True
    if do_dec:
        password =getpass()
        cf = CryptoFile(password)
        try:
            cf.decryption(src,dst)
        except Exception as err:
            print()
            print("[*] 解密失败")
            print(str(err))
            exit()
    elif do_enc:
        password =getpass()
        cf = CryptoFile(password)
        try:
            cf.encryption(src,dst)
        except Exception as err:
            print()
            print("[*] 加密失败")
            print(str(err))
            exit()
    else:
        print("[*]add - e or -d to do some work!")
        help()

if __name__ == "__main__":
    start_time = time.time()
    menu()
    t = round(time.time() - start_time,2)
    print("处理时间 %fs"  %t)