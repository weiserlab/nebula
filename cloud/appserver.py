# app.py
import json
import os
import requests
import tokenlib
import util


TOKEN_REQUEST_SIZE = 100


provider_url = os.environ.get("PROVIDER_URL") 
public_params = None
unused_tokens = []
payload_hashes = set()


def get_public_params() -> bytes:
    return requests.get(provider_url + "/public_params", verify=False).json()["result"]


# a function get_more_tokens that makes a GET request and atomically adds them to unused_tokens
def get_more_tokens(num_tokens: int) -> list[str]:

    global public_params

    # if we didn't query the app server for the public parameters yet, do so now
    if not public_params:
        public_params = get_public_params()

    blinded_tokens = [
        util.encode_bytes(tokenlib.generate_token(util.decode_bytes(public_params))) for _ in range(num_tokens)
    ]

    signed_tokens = [util.decode_bytes(t) for t in requests.post(
        provider_url + "/sign_tokens",
        verify=False,
        headers = {'Content-type': 'application/json'},
        data=json.dumps({"blinded_tokens": blinded_tokens})
    ).json()["result"]]

    return [
        util.encode_bytes(tokenlib.unblind_token(util.decode_bytes(b_token), s_token)) for b_token, s_token in \
            zip(blinded_tokens, signed_tokens)
    ]
    

def deliver(payload) -> str:

    global public_params
    global unused_tokens
    global provider_url

    # if unused_tokens is empty, get more tokens
    if len(unused_tokens) == 0:
        unused_tokens += get_more_tokens(TOKEN_REQUEST_SIZE)

    ret_token = util.decode_bytes(unused_tokens.pop())
    protocol_nonce_bytes = 16
    protocol_nonce = util.get_random_bytes(protocol_nonce_bytes)

    ret_sig = util.sign(util.load_private_key(), protocol_nonce + ret_token)
    
    return util.encode_bytes(protocol_nonce + ret_token + ret_sig)


def pre_deliver(payload) -> str:

    global public_params
    global unused_tokens
    global provider_url
    global payload_hashes

    payload_bytes = util.decode_bytes(payload["data"])

    protocol_nonce_bytes = 16
    sha256_bytes = 32

    sensor_id = payload_bytes[:16]
    payload_hash = payload_bytes[16:16+sha256_bytes]
    sig = payload_bytes[16+sha256_bytes:]

    is_in_set = payload_hash in payload_hashes

    protocol_nonce = util.get_random_bytes(protocol_nonce_bytes)
    
    if len(unused_tokens) == 0:
        unused_tokens += get_more_tokens(TOKEN_REQUEST_SIZE)

    aes_key = util.load_aes_key()
    token = util.decode_bytes(unused_tokens.pop())
    encrypted_token = util.encrypt_aes(aes_key, token)
    encrypted_token_bytes = encrypted_token[0] + encrypted_token[1] + encrypted_token[2]

    return_payload = protocol_nonce + payload_hash + encrypted_token_bytes
    return_sig = util.sign(util.load_private_key(), return_payload)

    return util.encode_bytes(return_payload + return_sig)
