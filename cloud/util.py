# util.py
import base64
from Crypto.Hash import SHA256 # type: ignore
from Crypto.PublicKey import ECC # type: ignore
from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
from Crypto.Signature import DSS # type: ignore
import struct


PUBLIC_ECC_KEYFILE = 'appserver-public-ecc.pem'
PRIVATE_ECC_KEYFILE = 'appserver-private-ecc.pem'
AES_KEYFILE = 'appserver-aes.key'


def encode_bytes_b64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def decode_bytes_b64(data: str) -> bytes:
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


def gen_keypair(name):
    key = ECC.generate(curve='secp256r1')
    with open(name + '-public-ecc.pem', 'w') as f:
        f.write(key.public_key().export_key(format='PEM'))

    with open(name + '-private-ecc.pem', 'w') as f:
        f.write(key.export_key(format='PEM'))


def load_public_key(name=PUBLIC_ECC_KEYFILE):
    with open(name, 'r') as f:
        return ECC.import_key(f.read())


def load_private_key(name=PRIVATE_ECC_KEYFILE):
    with open(name, 'r') as f:
        return ECC.import_key(f.read())


def load_aes_key():
    with open(AES_KEYFILE, 'rb') as f:
        return f.read()


def hash_sha256(_data):
    hash_object = SHA256.new(data=_data)
    return hash_object.digest()


def sign_ecdsa(secretkey, message):
    h = SHA256.new(message)
    return DSS.new(secretkey, 'fips-186-3').sign(h)


def verify_ecdsa(publickey, message, signature):
    h = SHA256.new(message)
    try:
        verifier = DSS.new(publickey, 'fips-186-3')
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


def encrypt_aes(key, data) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    ct_bytes, tag_bytes = len(ciphertext), len(tag)
    return struct.pack(f'II12s{ct_bytes}s{tag_bytes}s', ct_bytes, tag_bytes, nonce, ciphertext, tag)


def decrypt_aes(key, encrypted_blob):
    ct_bytes, tag_bytes, nonce = struct.unpack_from('II12s', encrypted_blob, offset=0)
    ciphertext, tag = struct.unpack_from(f'{ct_bytes}s{tag_bytes}s', encrypted_blob, offset=(2*4 + 12))
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError):
        return None
