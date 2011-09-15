import json, M2Crypto
import getpass

def load_enc_conf(name):
    key = getpass.getpass("Enter the passphrase for %s:" %name)
    dec = M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=key, iv='\0' * 16, op=0, key_as_bytes=1)
    f = open(name, 'rb')
    encrypted = f.read()
    f.close()
    decrypted = dec.update(encrypted)
    decrypted = decrypted + dec.final()
    return json.loads(decrypted)
