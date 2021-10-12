import time
import os
from Cryptodome.Cipher import AES,PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from constants import AES_KEY, IV
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

class Util:
    
    @staticmethod
    def benchmark_time(func):
        start = time.time()
        func()
        end = time.time()
        print(f"Time elapsed: {end - start} ms")
        return end - start


class AESLib:
    @staticmethod
    def encrypt(filename):
        cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
        try:
            file = open(filename, 'rb')
            ct_bytes = cipher.encrypt(pad(file.read(), AES.block_size))
            file.close()
        except Exception as e:
            raise Exception('Error encrypting data')

        file = open("{}.b".format(filename), "wb")
        file.write(ct_bytes)
        file.close()


    @staticmethod
    def decrypt(filename):
        try:
            file = open(filename, 'rb')
            ct_bytes = file.read()
            file.close()
        except Exception as e:
            raise Exception('Error decrypting data')

        cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
        text = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        file = open(filename[:-2], "wb")
        file.write(text)
        file.close()
        os.remove(os.path.abspath(filename))

class RSALib:
    @staticmethod
    def generate_public_and_private_key(dir='.'):
        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open(f"{dir}/private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        public_key = key.publickey().export_key()
        file_out = open(f"{dir}/public.pem", "wb")
        file_out.write(public_key)
        file_out.close()

    def encrypt(self,public_key_dir):
        public_key = RSA.import_key(open(public_key_dir).read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_session_key = cipher_rsa.encrypt(AES_KEY)