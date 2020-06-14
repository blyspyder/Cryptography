#-*-coding:utf-8-*-
import getopt
import sys
import argparse

class ViEncrypto():
    def __init__(self,key):
        self.key = key

    def VigenereEncrypto (self,src) :#src表示需要加密的明文，key为秘钥
        ptLen = len(src)#明文长度
        keyLen =  len(self.key)
        quotient = ptLen // keyLen    #商
        remainder = ptLen % keyLen    #余
        out = ''
        self.key.lower()#将所有秘钥改为小写
        #循环处理明文，秘钥循环
        for i in range (0 , quotient) :
            for j in range (0 , keyLen) :
                if(src[i*keyLen+j].isalpha()):
                    if src[i*keyLen+j]>='a':
                        c = int(((ord(src[i * keyLen + j]) - ord('a')) + (ord(self.key[j]) - ord('a'))) % 26 + ord('a'))
                        out += chr (c)
                    else:
                        c = int(((ord(src[i * keyLen + j]) - ord('A')) + (ord(self.key[j]) - ord('a'))) % 26 + ord('A'))
                        out += chr(c)
                else:
                    out += src[i*keyLen+j]

        for i in range (0 , remainder) :
            if (src[quotient * keyLen + i].isalpha()):
                if src[quotient * keyLen + i] >= 'a':
                    c = int(((ord(src[quotient * keyLen + i]) - ord('a')) + (ord(self.key[j]) - ord('a'))) % 26 + ord('a'))
                    out += chr(c)
                else:
                    c = int(((ord(src[quotient * keyLen + i]) - ord('A')) + (ord(self.key[j]) - ord('a'))) % 26 + ord('A'))
                    out += chr(c)
            else:
                out += src[quotient * keyLen + i]
        out=self.change(out)#修改明文大小写后输出
        return out

    #解密函数
    def VigenereDecrypto (self,outputci) :
        output = self.change(outputci)
        ptLen = len (output)
        keyLen = len (self.key)
        quotient = ptLen // keyLen
        remainder = ptLen % keyLen
        inp = ""
        for i in range (0 , quotient) :
            for j in range (0 , keyLen) :
                if (output[i * keyLen + j].isalpha()):
                    if output[i * keyLen + j] >= 'a':
                        c=int(((ord(output[i*keyLen+j])-ord('a'))-(ord(self.key[j])-ord('a')))%26+ord('a'))
                        inp += chr (c)
                    else:
                        c = int(((ord(output[i * keyLen + j]) - ord('A')) - (ord(self.key[j]) - ord('a'))) % 26 + ord('A'))
                        inp += chr(c)
                else:
                    inp+=output[i*keyLen+j]

        for i in range (0 , remainder) :
            if (output[quotient * keyLen + i].isalpha()):
                if output[quotient * keyLen + i] >= 'a':
                    c = int(((ord(output[quotient * keyLen + i]) - ord('a')) - (ord(self.key[j]) - ord('a'))) % 26 + ord('a'))
                    inp += chr(c)
                else:
                    c = int(((ord(output[quotient * keyLen + i]) - ord('A')) - (ord(self.key[j]) - ord('a'))) % 26 + ord('A'))
                    inp += chr(c)
            else:
                inp+= output[quotient * keyLen + i]
        return inp

    def change(self,str):#将字符串中的大小写互换
        num = len(str)
        out=''
        for i in range(0,num):
            if 65<=ord(str[i])<=90:
                out+=str[i].lower()
            elif 97<=ord(str[i])<=122:
                out+=str[i].upper()
            else:
                out+=str[i]
        return out

def command():#使用命令行传输参数
    short_opts = "-h-e-d-p:-i:-o:"#h表示后面无参数，i:表示i后需要带参数，o:表示o后带参数
    try:
        opts,agrs = getopt.getopt(sys.argv[1:],short_opts)
    except getopt.GetoptError as err:
        print(str(err))
    infilname=''
    outfilename=''
    password=''
    do_enc = False
    do_dnc = False
    for opt_name,opt_value in opts:
        if opt_name in ('h'):
            help()
        elif opt_name in ('-e'):
            do_enc = True
        elif opt_name in ('-d'):
            do_dnc = True
        elif opt_name in ('-p'):
            password=opt_value
        elif opt_name in ('-i'):
            infilname = opt_value
        elif opt_name in ('-o'):
            outfilename = opt_value
    if do_enc:
            encodefile(password,infilname,outfilename)
    elif do_dnc:
            decodefile(password,infilname,outfilename)
    else:
        help()
        exit()

def help():
    print('参数设置 -e/d -p <password> -i <inputfilename> -o <outputfilename>')
    print('-e:表示加密文件')
    print('-d:表示解密文件')
    sys.exit()

def encodefile(key,inputfilename,outpufilename):#加密文件
    try:
        f = open(inputfilename, 'r')
        w = open(outpufilename, 'w')
    except IOError as error:
        print(error)
        exit()
    while True:
        block=f.read(len(key)*8)
        if not block:
            break
        else:
            Vi = ViEncrypto(key)
            cypth = Vi.VigenereEncrypto(block)
            w.write(cypth)
    f.close()
    w.close()

def decodefile(key,inputfilename,outpufilename):
    try:
        f = open(inputfilename, 'r')
        w = open(outpufilename, 'w')
    except IOError as error:
        print(error)
        exit()
    while True:
        block = f.read(len(key)*8)
        if not block:
            break
        else:
            Vi = ViEncrypto(key)
            decypth = Vi.VigenereDecrypto(block)
            w.write(decypth)
    f.close()
    w.close()

if __name__=='__main__':
    command()
