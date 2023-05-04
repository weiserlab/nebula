
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
import tokenlib
import base64


PUBLIC_ECC_KEYFILE = 'jl-public-ecc.pem'
PRIVATE_ECC_KEYFILE = 'jl-private-ecc.pem'
AES_KEYFILE = 'jl-aes.key'


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
        publickey.verify(h, signature)
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


def to_base64(data):
    return base64.b64encode(data).decode('utf-8')


def from_base64(data):
    return base64.b64decode(data)


if __name__ == '__main__':

    publickey = load_public_key()
    privatekey = load_private_key()
    aeskey = load_aes_key()

    payload = b'Fake payload yo'

    sensor_id = from_base64(
        'dPBDLvsxXTQ='
    )

    protocol_nonce = from_base64(
        '/lO7UPm3C9lJnewj+M3cJg=='
    )

    token = from_base64(
        '5Upp2zai1hr+b+bCLi23GOOhfz2grj+aXHm6+7m7u808a18V5R05TJFwquzr/kwrDq+GjVE7nMcXxZJnt1yJLQ=='
    )    
    print(len(token))

    # id length: 8 bytes
    # hash length: 32 bytes
    # sig length: 64 bytes
    predeliver_payload = from_base64(
        'dPBDLvsxXTTLcmT3kGYoH/Vn0TyhbH7h6MelL8huDhZGbvhUzx02hWCntgVLE5a7d6UoKgkRIDJKfgmIZ091y/i1ch5iOFArgwKAhqGLcW0LUV2pNDmttZb1p7o7gZUOlAaEtyadaUc='
    )

    '''
    mule_to_server_predeliver_payload = (
        sensor_id +
        hash(payload) +
        sign(privatekey, sensor_id + hash(payload))
    )

    print('signature length:', len(sign(privatekey, sensor_id + hash(payload))))
    print()

    print()
    print('Mule to server predeliver payload:')
    print('\t', to_base64(mule_to_server_predeliver_payload))
    print()

    print('sensor id:', to_base64(sensor_id))
    '''

    predeliver_response = from_base64(
        '/lO7UPm3C9lJnewj+M3cJstyZPeQZigf9WfRPKFsfuHox6UvyG4OFkZu+FTPHTaFYGjFcKglWhydSse0QBE954dVmm4k9QUiLk1pEJF0xrbYgi2eNTIGxxGTHdrFw38nYffvKjo3cvfNTYb2v9P67rzZlbp6u1bxwHTDx/lqEWQdP1WrX7ii6CWHe3vs1I9QsPNUbul5UglWq7IOmxZyHOQ9xY5B2+o5D89ZJK9TPR3HDqUuywSuB+kTgq5VJxmDysXcmOUxj1H5brbj'
    )

    '''
    # generate app server predeliver response
    app_server_sensor_id = predeliver_payload[:8]
    app_server_payload_hash = predeliver_payload[8:40]
    app_server_signature = predeliver_payload[40:]

    encrypted_token = encrypt_aes(aeskey, token)
    encrypted_token_bytes = encrypted_token[0] + encrypted_token[1] + encrypted_token[2]

    app_server_predeliver_response = (
        protocol_nonce +
        app_server_payload_hash +
        encrypted_token_bytes + 
        sign(privatekey, protocol_nonce + app_server_payload_hash + encrypted_token_bytes)
    )

    print('app server predeliver response:')
    print('\t', to_base64(app_server_predeliver_response))
    '''

    deliver_payload = from_base64(
        'dPBDLvsxXTRGYWtlIHBheWxvYWQgeW8='
    )

    '''
    deliver_payload = (
        sensor_id +
        payload
    )

    print('deliver payload:')
    print('\t', to_base64(deliver_payload))
    '''

    deliver_response = from_base64(
        '/lO7UPm3C9lJnewj+M3cJuVKads2otYa/m/mwi4ttxjjoX89oK4/mlx5uvu5u7vNPGtfFeUdOUyRcKrs6/5MKw6vho1RO5zHF8WSZ7dciS2AIOiMhdsm4qtDCrCVzH4PR4Z54PFU88F2bl9GZGQ6hzSCEdeCYBuTIBkdlCF5TovuNJA3ffNZd8Tle7irn15l'
    )

    '''
    app_server_deliver_response = (
        protocol_nonce +
        token +
        sign(privatekey, protocol_nonce + token)
    ) 

    print('app server deliver response:')
    print('\t', to_base64(app_server_deliver_response))
    '''

    complaint_token = from_base64(
        'Fi48X5Un37Yy1f3A8jRutx8ibiNO54g3rvxUykSRystMmz/c2FxRtGMlODXwDOE3Hx3ST8iHiJ30zS41xHjtfA=='
    )

    '''
    with open('complaints-keypair.bin', 'rb') as f:
        complaints_keypair = f.read()

    complaints_public_params = tokenlib.get_public_params(complaints_keypair)
    blinded_token = tokenlib.generate_token(complaints_public_params)
    complaint_token = tokenlib.unblind_token(blinded_token, tokenlib.sign_token(complaints_keypair, blinded_token))

    print('complaint token:') 
    print('\t', to_base64(complaint_token))
    '''

    complaint_send_with_data = from_base64(
        'Fi48X5Un37Yy1f3A8jRutx8ibiNO54g3rvxUykSRystMmz/c2FxRtGMlODXwDOE3Hx3ST8iHiJ30zS41xHjtfP5Tu1D5twvZSZ3sI/jN3CbLcmT3kGYoH/Vn0TyhbH7h6MelL8huDhZGbvhUzx02hVfNVrjBHbCQgmBSbhJDNizFUiBO7TgKnIV7knmcH0q/3mVNncmPjveNmVOz4nZkP4X2szvC+ETwjY4UmzWCXeu3kC+4Ap9BCJDS8SwsTge3X+V7NI6GiMucVtr6cSSgqQKLp2MdrHWQfD1tTQhDPWSGjyNmdcwvHnGK/HcxHNuzqnT+3X/8CQn/bA2AesPmu6Mm1PeYnz4d6NYACA=='
    )
    complaint_payload = from_base64(
        'RmFrZSBwYXlsb2FkIHlv'
    )

    complaint_send_with_token = from_base64(
        'Fi48X5Un37Yy1f3A8jRutx8ibiNO54g3rvxUykSRystMmz/c2FxRtGMlODXwDOE3Hx3ST8iHiJ30zS41xHjtfP5Tu1D5twvZSZ3sI/jN3CbLcmT3kGYoH/Vn0TyhbH7h6MelL8huDhZGbvhUzx02hdV7RvCcYRcXtkg/hgQtQ7KBUB6xUZb+Xvy0gbfYu3aeO6Bg+7ljRVNAmmsdZkvPtFkXDCKUAPeRV/z5tx9Nt7+f9TC4uYaEByEw/tcVZ2aejxiIp0gs3ttNnC7QWBZ/8AQIOK0SpDO0uKKGySiKH29R+jCxgo82fN4CidY6+JXNqJyHlYBvS+ZZooYZtTFny1yDq640KP5FgwJJf12655aCXCRTZFo9NxYtzU0z+MOXfounOuUFo2cpM01XroxDlyrVQDeWtZYguqytsdk9wLGD4V1tYz9hpu1AR24='
    )
    complaint_tokensig = from_base64(
        'rFg5wbTxUSphFKxoObJK0NcAb02W8SeO0ZmVFkSTVxukN16i3eTosA2Pp0gP5Lgy8Yp+5kYEK10UB0rRO+FMmQ=='
    )

    '''
    encrypted_token = encrypt_aes(aeskey, token)
    encrypted_token_bytes = encrypted_token[0] + encrypted_token[1] + encrypted_token[2]

    complaint_payload_with_sensor_data = (
        complaint_token +
        protocol_nonce +
        hash(payload) +
        encrypted_token_bytes +
        sign(privatekey, protocol_nonce + hash(payload) + encrypted_token_bytes)
    )

    print('complaint payload with sensor data:')
    print('\tcomplaint:', to_base64(complaint_payload_with_sensor_data))
    print('\tpayload:', to_base64(payload))

    complaint_payload_with_token = (
        complaint_token +
        protocol_nonce +
        hash(payload) +
        encrypted_token_bytes +
        sign(privatekey, protocol_nonce + hash(payload) + encrypted_token_bytes)
    )

    print('complaint payload with token:')
    print('\tcomplaint:', to_base64(complaint_payload_with_token))
    print('\ttokensig:', to_base64(sign(privatekey, protocol_nonce + hash(payload) + token)))
    '''

    blinded_token = from_base64(
        'oOI6NTDP78eok3967DLXkh0ShV5vnPoJN7N5Tx4+cV/AB2VTXBLsiJENQXx+uCtDjHb/F50J5QJHzm7UGFQBDw7PSPjiklmT7uXCJn+CaVSam5sAPTzm7/cPGjbfOvgBaqDXmUF06qcc2JG3xZsm3bQ9TTWib9bYWcFFiHh+kVTi8q4KarxOcaiEqWHFAFFfWOMLaqWC3Y22pllF4I0tdg=='
    )

    '''
    # get the public params from the server, this is a standin
    with open('complaint_keypair.bin', 'rb') as f:
        complaints_keypair = f.read()
    complaints_public_params = tokenlib.get_public_params(complaints_keypair)

    blinded_token = tokenlib.generate_token(complaints_public_params)

    print('blinded token:')
    print('\t', to_base64(blinded_token))
    '''

    '''
    # get the blinded token to the server to get signed
    signed_blinded_token = tokenlib.sign_token(complaints_keypair, blinded_token)

    # once returned, unblind to get new token
    signed_token_result = tokenlib.unblind_token(blinded_token, signed_blinded_token)
    '''

    