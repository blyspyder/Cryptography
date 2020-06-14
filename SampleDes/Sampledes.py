#encoding:utf8
import getopt
import struct
import sys
import binascii
import time


class SampleDes:
    def __init__(self,key):
        self.key = key
        self.P10 = [3,5,2,7,4,10,1,9,8,6]
        self.P8 = [6,3,7,4,8,5,10,9]
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_1 = [4, 1, 3, 5, 7, 2, 8, 6]
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]
        self.s0 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
        self.s1 = [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]
        self.P4 = [2,4,3,1]

    #加密函数
    #输入文件名
    def encryptor(self,srcfilepath,dstfilepath):
        #每次得到的秘钥相同
        key1,key2 = self.getdkey()
        try:
            f=open(srcfilepath,'rb')
            w=open(dstfilepath,'wb')
        except IOError as error:
            print(error)
            exit()
        while True:
            plaintext = f.read(1)
            if plaintext == b'':
                break
            plaintext = binascii.b2a_hex(plaintext)
            plaintext1 = bin(int(plaintext,16))[2:]
            if len(plaintext1) < 8:
                plaintext1 = '0' * (8 - len(plaintext1)) + plaintext1
            out=[]
            plaintext = self.pkey(plaintext1,self.IP)
            xre = self.fk(plaintext,key1)
            rsw=self.sw(xre)
            rfk = self.fk(rsw,key2)
            result=self.pkey(rfk,self.IP_1)
            print(result)
            out.append(int(result,2))
            print(out)
            w.write(bytearray(out))
        f.close()
        w.close()
        return result

    #解密得到明文
    #输入：一个8bit的密文，String形式
    def decryptor(self,srcfilepath,dstfilepath):
        key1,key2 = self.getdkey()#得到key1,key2
        try:
            f=open(srcfilepath,'rb')
            w=open(dstfilepath,'wb')
        except IOError as error:
            print(error)
            exit()
        while True:
            cipher = f.read(1)
            if cipher == b'':
                break
            cipher = binascii.b2a_hex(cipher)
            cipher1 = bin(int(cipher,16))[2:]
            if len(cipher1) < 8:
                cipher1 = '0' * (8 - len(cipher1)) + cipher1
            out=[]
            cip = self.pkey(cipher1,self.IP)#密文首先进行ip逆运算
            fk2 = self.fk(cip,key2)
            csw = self.sw(fk2)
            fk1 = self.fk(csw,key1)
            plaint = self.pkey(fk1,self.IP_1)
            out.append(int(plaint, 2))
            w.write(bytearray(out))
        f.close()
        w.close()
        return plaint

    def fk(self,plaintext,key):
        pl= plaintext[:4]  # 得到秘钥
        pr = plaintext[4:]
        last_ep = self.ep(pr)  # 对右边数据进行扩充
        s = self.xor(last_ep,key,8)
        rs0 = self.replacement(s[:4], self.s0)
        rs1 = self.replacement(s[4:], self.s1)
        rp4 = self.pkey(rs0 + rs1, self.P4)
        xre = self.xor(pl, rp4, 4)
        result = xre+pr
        return result

    #传入key之后经过运算得到k1,k2
    #输入秘钥string类型，长度为10bit
    def getdkey(self):
        key = self.pkey(self.key,self.P10)
        leftkey = key[:5]#得到左边秘钥
        rightkey = key[5:]#得到右边5位秘钥
        ls1keyl = leftkey[1:5]+leftkey[0]#循环左移一位
        ls1keyr = rightkey[1:5] + rightkey[0]
        key1 = self.pkey(ls1keyl+ls1keyr,self.P8)#得到秘钥1
        ls2keyl = ls1keyl[2:]+ls1keyl[:2]
        ls2keyr = ls1keyr[2:]+ls1keyr[:2]
        key2 = self.pkey(ls2keyl+ls2keyr,self.P8)
        return key1,key2
    '''
    def listtostr(self,src):
        str1=''
        for i in src:
            str1+=i
        return str1
    '''
    #传入秘钥进行P置换
    #输入：key和置换表
    def pkey(self,key,p):
        rkey = ''
        for i in p:
            rkey += key[i-1]
        return rkey

    #对右边明文进行扩充
    #4位扩充为8位
    #输入：8位明文，二进制形式
    def ep(self,plaintext):
        kuo = ''
        for i in self.EP:
            kuo += plaintext[i-1]
        return kuo

    #将明文进行IP置换分别返回左边和右边经过置换后的明文
    #输入：8为明文，二进制形式
    '''
    def cip(self,plaintext):
        pl = p[:4]
        pr = p[4:]
        return pl,pr
    '''
    #进行异或运算
    #n表示原文的长度
    def xor(self,s1,s2,n):
        s=''
        for i in range(n):
            if s1[i] != s2[i]:#不同为1相同为0
                s+='1'
            else:
                s+='0'
        return s

    #对高四位和低四位进行互换
    #传入8位的二进制文件
    def sw(self,src):
        result = ''
        result = src[4:]
        result += src[:4]
        return result

    #IP逆置换算法
    #传入八位二进制字符串
    def ipni(self,src):
        p=''
        for i in self.IP_1:
            p+= src[i]
        return p

    #进行s盒置换
    #输入s盒，需要置换的数
    def replacement(self,src,s):
        r=''
        hang = int(src[0])*2 + int(src[3])
        lie = int(src[1])*2 + int(src[2])
        result = bin(s[hang][lie])[2:]
        while len(result)<2:
            result = '0'+result
        return result

def menu():
    argv1=sys.argv[1]#-e
    argv2 = sys.argv[2]#key
    argv3= sys.argv[3]#i
    argv4=sys.argv[4]#o
    a = SampleDes(argv2)
    if argv1 =='-e':
        a.encryptor(argv3, argv4)
    elif argv1 == '-d':
        a.decryptor(argv3, argv4)
    else:
        print("input error")

def menu1():
    short_opts = "-h-e-d-k:-i:-o:"  # h表示后面无参数，i:表示i后需要带参数，o:表示o后带参数
    try:
        opts, agrs = getopt.getopt(sys.argv[1:], short_opts)
    except getopt.GetoptError as err:
        print(str(err))
    infilname = ''
    outfilename = ''
    key = ''
    # 加密解密标志位
    do_enc = False
    do_dnc = False
    for opt_name, opt_value in opts:  # 匹配
        if opt_name in ('h'):  # 命令行输入h时提示帮助
            help()
        elif opt_name in ('-e'):
            do_enc = True
        elif opt_name in ('-d'):
            do_dnc = True
        elif opt_name in ('-k'):
            key = opt_value
        elif opt_name in ('-i'):
            infilname = opt_value
        elif opt_name in ('-o'):
            outfilename = opt_value
    a=SampleDes(key)
    if do_enc:
        a.encryptor(infilname,outfilename)
    elif do_dnc:
        a.decryptor(infilname,outfilename)
    else:
        help()

if __name__ == '__main__':
    start = time.time()
    menu1()
    end = time.time()
    print(end-start)
