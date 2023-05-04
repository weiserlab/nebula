# util.py
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS


PUBLIC_ECC_KEYFILE = 'jl-public-ecc.pem'
PRIVATE_ECC_KEYFILE = 'jl-private-ecc.pem'
AES_KEYFILE = 'jl-aes.key'


def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def decode_bytes(data: str) -> bytes:
    return base64.b64decode(data)


def gen_keys():
    key = ECC.generate(curve='secp256r1')
    with open(PUBLIC_ECC_KEYFILE, 'w') as f:
        f.write(key.public_key().export_key(format='PEM'))

    with open(PRIVATE_ECC_KEYFILE, 'w') as f:
        f.write(key.export_key(format='PEM'))

    with open(AES_KEYFILE, 'wb') as f:
        key = get_random_bytes(32)
        f.write(key)


def load_public_key():
    with open(PUBLIC_ECC_KEYFILE, 'r') as f:
        return ECC.import_key(f.read())


def load_private_key():
    with open(PRIVATE_ECC_KEYFILE, 'r') as f:
        return ECC.import_key(f.read())


def load_aes_key():
    with open(AES_KEYFILE, 'rb') as f:
        return f.read()


def hash(_data):
    hash_object = SHA256.new(data=_data)
    return hash_object.digest()


def sign(secretkey, message):
    h = SHA256.new(message)
    return DSS.new(secretkey, 'fips-186-3').sign(h)


def verify(publickey, message, signature):
    h = SHA256.new(message)
    try:
        verifier = DSS.new(publickey, 'fips-186-3')
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


def encrypt_aes(key, data):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag


def decrypt_aes(key, nonce, ciphertext, tag):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError):
        return None
