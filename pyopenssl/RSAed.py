from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#装载私钥
def loadprivatekey(key_file):
    with open(key_file,'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
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

#加密函数
def encrypto(publice_key,inputfile,outputfile):
    with open(inputfile,'rb') as f,open(outputfile,'wb') as w:
        message=f.read(1)
        ciphertext = publice_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        w.write(ciphertext)

#解密函数
def decrypto(private_key,inputfile,outputfile):
    with open(inputfile,'rb') as f, open(outputfile,'wb') as w:
        cipher = f.read(1)
        plaintext = private_key.decrypt(
            cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        w.write(plaintext)

if __name__ == '__main__':
    public1 = pubkeyload('/opt/testfile/bly_publice_key.pem')
    private1 = loadprivatekey('/opt/testfile/bly_private_key.pem')

    public2 = pubkeyload('/opt/testfile/public1.pem')
    private2 = loadprivatekey('/opt/testfile/private1.pem')

    #encrypto(public1,'/opt/testfile/1.txt','/opt/testfile/2.txt')
    #encrypto(public2,'/opt/testfile/2.txt','/opt/testfile/4.txt')
    decrypto(private1,'/opt/testfile/4.txt','/opt/testfile/3.txt')


