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

    ret_token = unused_tokens.pop()
    return ret_token

def pre_deliver(payload) -> str:

    global public_params
    global unused_tokens
    global provider_url

    raise NotImplementedError