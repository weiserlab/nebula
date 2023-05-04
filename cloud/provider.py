# provider.py
import tokenlib
import util
import platform_db
import platform_tokendb
from Crypto.Random import get_random_bytes

# load keypair (generated with gen_keypair.py)
with open('keypair.bin', 'rb') as f:
    _keypair = f.read()

with open('complaint_keypair.bin', 'rb') as f:
    _complaint_keypair = f.read()

mule_db = platform_db.KeyValueDatabase()
token_db = platform_tokendb.StringSet()


def get_public_params(payload=None) -> str:
    return util.encode_bytes(tokenlib.get_public_params(_keypair))


def sign_tokens(payload) -> list[str]:

    decoded_tokens = [util.decode_bytes(token) for token in payload["blinded_tokens"]]
    signed_tokens = [tokenlib.sign_token(_keypair, token) for token in decoded_tokens]

    return [util.encode_bytes(token) for token in signed_tokens]


def redeem_tokens(payload) -> int:
    decoded_tokens = [util.decode_bytes(token) for token in payload["tokens"]]
    valid_tokens = [token for token in decoded_tokens if tokenlib.verify_token(_keypair, token)]
    num_unused = token_db.add_new_elements(valid_tokens)
    # mule_db.batch_increment_counts([('mule', num_unused)]) # Just a stripe call etc, irrelevant to design
    # We want to send the number of tokens that could be verified for signatures 
    return len(valid_tokens)


def query_provider(payload) -> dict:
    decoded_tokens = [util.decode_bytes(token) for token in payload["tokens"]]
    valid_tokens = [token for token in decoded_tokens if tokenlib.verify_token(_keypair, token)]

    invalid_tokens = [t for t in decoded_tokens if t not in valid_tokens]

    duplicate_tokens = []
    for t in valid_tokens:
        if token_db.add_new_elements([t]) == 0:
            duplicate_tokens.append(t)

    return {
        "invalid_tokens": [util.encode_bytes(t) for t in invalid_tokens],
        "duplicate_tokens": [util.encode_bytes(t) for t in duplicate_tokens]
    }


def complain(payload) -> str:

    complaint_token = util.decode_bytes(payload["complaint_token"])
    blinded_token = util.decode_bytes(payload["blinded_token"])

    complaint_bytes = util.decode_bytes(payload["complaint"])

    protocol_nonce_bytes = 16
    sha256_bytes = 32
    aes_nonce_bytes = 12
    aes_tag_bytes = 16
    token_bytes = 64
    sig_bytes = 64

    complaint = {
        "protocol_nonce": complaint_bytes[:protocol_nonce_bytes],
        "payload_hash": complaint_bytes[protocol_nonce_bytes:protocol_nonce_bytes+sha256_bytes],
        "aes_nonce": complaint_bytes[protocol_nonce_bytes+sha256_bytes:protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes],
        "encrypted_token": complaint_bytes[protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes:protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes+token_bytes],
        "aes_tag": complaint_bytes[protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes+token_bytes:protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes+token_bytes+aes_tag_bytes],
        "token_signature": complaint_bytes[protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes+token_bytes+aes_tag_bytes:protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes+token_bytes+aes_tag_bytes+sig_bytes]
    }
    
    signed_complaint_payload = complaint_bytes[:protocol_nonce_bytes+sha256_bytes+aes_nonce_bytes+token_bytes+aes_tag_bytes]

    sensor_payload = util.decode_bytes(payload["sensor_payload"]) if "sensor_payload" in payload else None
    finalized_token_signature = util.decode_bytes(payload["token_signature"]) if "token_signature" in payload else None

    # 1. verify complaint token
    is_good_token = tokenlib.verify_token(_complaint_keypair, complaint_token)

    # 2. verify the AS signature
    as_pk = util.load_public_key()
    is_correctly_signed = util.verify(as_pk, signed_complaint_payload, complaint["token_signature"])

    # 3. decrypt and verify the token
    symm_key = util.load_aes_key()
    decrypted_token = \
        util.decrypt_aes(symm_key, complaint["aes_nonce"], complaint["encrypted_token"], complaint["aes_tag"])
    # just get some token bytes for now
    decrypted_token = util.decode_bytes('5Upp2zai1hr+b+bCLi23GOOhfz2grj+aXHm6+7m7u808a18V5R05TJFwquzr/kwrDq+GjVE7nMcXxZJnt1yJLQ==')

    is_good_original_token = tokenlib.verify_token(_keypair, decrypted_token)

    if sensor_payload:
        does_hash_match = util.hash(sensor_payload) == complaint["payload_hash"]
    elif finalized_token_signature:
        sig_good = util.verify(as_pk, 
                               complaint["protocol_nonce"] + complaint["payload_hash"] + decrypted_token,
                               finalized_token_signature)

    # sign blinded token
    return util.encode_bytes(
        tokenlib.sign_token(_keypair, util.decode_bytes(payload["blinded_token"]))
    )


def get_complaint_public_params(payload=None) -> str:
    return util.encode_bytes(tokenlib.get_public_params(_complaint_keypair))