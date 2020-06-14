#encoding:utf8
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
def gethash(str,key):
    if str == 'SHA256':
        digest = hmac.HMAC(key,hashes.SHA256(),backend=default_backend())
    elif str=='SHA512':
        digest = hmac.HMAC(key,hashes.SHA512(),backend=default_backend())
    elif str=='SHA1':
        digest = hmac.HMAC(key,hashes.SHA1(),backend=default_backend())
    elif str=='MD5':
        digest = hmac.HMAC(key,hashes.MD5(),backend=default_backend())
    elif str=='SHA224':
        digest = hmac.HMAC(key,hashes.SHA224(),backend=default_backend())
    elif str=='SHA512':
        digest = hmac.HMAC(key,hashes.SHA512(),backend=default_backend())
    else:
        print('算法不正确')
        return -1
    return digest