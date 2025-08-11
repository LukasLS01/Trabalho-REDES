from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


class FerramentasCrypto:
    def encrypt(self, plain_text, key):
        
        cipher = AES.new(key, AES.MODE_CBC)
        
        padded_data = pad(plain_text.encode("utf-8"), AES.block_size)
                
        return cipher.iv, cipher.encrypt(padded_data)

    def decrypt(self, iv, enc_text, key):
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        
        decrypted_padded_data = cipher.decrypt(enc_text)
        
        return unpad(decrypted_padded_data, AES.block_size).decode("utf-8")