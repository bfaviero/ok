import base64
from Crypto.Cipher import AES
from Crypto import Random

class Cipher:
    def __init__(self, key=None):
        self.bs = 32
        if key:
            self.key = hashlib.sha256(key.encode()).digest()
        else:
            self.key = Random.get_random_bytes(32)

    def encrypt(self, content):
        content = content
        iv = Random.new().read(AES.block_size)
        aes = AES.new(self.key, AES.MODE_CFB, iv)
        return base64.b64encode(iv + aes.encrypt(content))

    def decrypt(self, content):
        enc = base64.b64decode(content)
        iv = enc[:AES.block_size]
        aes = AES.new(self.key, AES.MODE_CFB, iv)
        return aes.decrypt(enc[AES.block_size:]).decode('utf-8')
