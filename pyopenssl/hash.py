import getopt
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import hashes, hmac
import algro
import os
import hmac

class M_digesrts:
    def __init__(self):
        self.BLOCK_SIZE = 2048 #处理大文件是每次读取的字节数
    #计算消息摘要，传入加密的文档

    # 得到盐值
    def getsalt(self):
        salt = os.urandom(16)#16字节盐值
        return salt

    # 根据盐值和口令生成密钥，名钥长度为32byte
    def gen_key(self,salt, password):
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

    #输入：需要获取摘要的源文件，algram算法
    def caldigests(self,srcfile,algram,password):

        # 得到digest,需要输入密钥
        digest = algro.gethash(algram,password)
        with open(srcfile,"rb") as src_file:
            while True:
                data = src_file.read(self.BLOCK_SIZE)
                if not data:
                    break
                else:
                    digest.update(data)
            result_data = digest.finalize()#保存得到文件hash值最终将hash值保存到一个校验文件中
        return result_data

    # 将得到的数字摘要写入相同目录下的文件中，摘要名命名为filenamedigest
    #输入：进行数字摘要的文件名和得到的hash值
    def writedigest(self,srcfile,digest,salt):
        #得到文件的目录名
        filebath = os.path.dirname(os.path.abspath(srcfile))
        filename = (srcfile.split('\\')[-1]).split('.')[0]
        outputfile = filebath+'\\'+filename+'.mac'
        try:
            f = open(outputfile,"wb")
        except IOError as error:
            print(error)
            exit()

        #讲得到摘要保存到文件中，盐值
        f.write(digest)
        f.write(salt)

    #需要验证的文件进行hash验证
    #input：需要验证的文件路径
    def check(self,digest,digestfile):
        try:
            #打开文件
            df=open(digestfile,'rb')
        except IOError as error:
            print(error)
            exit()
        srcdigest = df.read()[:-16]#读取摘要值
        if hmac.compare_digest(digest,srcdigest):
            return 1
        else:
            return 0

def menu():
    short_opts = "-h-c-d-i:-a:-f:-p:"#-h表示后没有参数-c表示校验,-d表示获取hash值,-i表示源文件路径，-f表示保存数字摘要的文件
    try:
        opts,args = getopt.getopt(sys.argv[1:],short_opts)
    except getopt.GetoptError as error:
        print(str(error))
        help()
    print('* * * * * * * * * * * * * * * * * * * * * * * * * *')
    print('* create by: 软件学院信息安全专业包聆言           *')
    print('* data:2018/12/23                                 *')
    print('* * * * * * * * * * * * * * * * * * * * * * * * * *')
    #保存输入的密码算法
    #获取摘要和进行校验的开关值
    do_enc=False
    do_che=False
    for opt_name,opt_value in opts:
        if opt_name in ('-h'):
            help()
        elif opt_name in ('-c'):
            do_che = True
        elif opt_name in ('-d'):
            do_enc = True
        elif opt_name in ('-a'):#用于接受需要选择的密码算法
            algram = opt_value
            if algram==-1:
                help()
                exit()
        elif opt_name in ('-p'):#接收密钥
            password = opt_value#用户输入的密钥
        elif opt_name in ('-i'):
            srcfile = opt_value
        elif opt_name in ('-f'):
            digestfile = opt_value

    di = M_digesrts()
    if do_enc:
        salt = di.getsalt()#生成盐值
        key = di.gen_key(salt,password.encode())#生成密钥
        try:
            digest=di.caldigests(srcfile,algram,key)
        except:
            print()
            print('获取摘要失败')
            exit()
        di.writedigest(srcfile,digest,salt)#将摘要和盐值
    elif do_che:
        fd = open(digestfile,'rb')
        data=fd.read()
        salt = data[-16:]
        key=di.gen_key(salt,password.encode())#重新生成密钥

        srcdigest = di.caldigests(srcfile,algram,key)#传入需要的验证的文件和相应的算法
        #根据上一个函数计算得到的值和保存摘要的文件对比验证数据是否被修改
        flag = di.check(srcdigest,digestfile)
        if flag:
            print('文件正确')
        else:
            print('文件被修改')
            exit()

def help():
    print()
    print('-a SHA256 -i srcfilename -c/d(验证或者获取摘要) -f 保存相应文件数字摘要的文件 -p 口令')
    exit()

if __name__ == '__main__':
    menu()

