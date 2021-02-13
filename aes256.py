import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher(object):

    def __init__(self, key: str):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, data_to_crypt: str) -> str:
        raw = pad(data_to_crypt.encode('utf-8'), self.bs)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        enc = base64.b64decode(encrypted_data)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        try:
            return unpad(cipher.decrypt(enc[AES.block_size:]), self.bs).decode('utf-8')
        except ValueError:
            return '[*] Key invalid'


if __name__ == '__main__':
    encrypt = AESCipher(key= 'test').encrypt(data_to_crypt= 'TOP SECRET ₪¡¢')
    print(encrypt)
    decrypt = AESCipher(key= 'test').decrypt(encrypted_data= encrypt)
    print(decrypt)