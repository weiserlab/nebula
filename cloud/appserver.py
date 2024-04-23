# app.py
import config
import json
import os
import requests
import tokenlib # type: ignore
import util
import payloads

# number of tokens to request from the provider at one time, increase if you're
# expecting a lot of traffic
TOKEN_REQUEST_SIZE = 10

# -- App Server State --
provider_url = os.environ.get('PROVIDER_URL') 
use_tls = os.environ.get('SERVER_TLS') == 'true'

# public parameters for token generation
public_params = None
# list of unused tokens to be handed out to mules
unused_tokens = []
# set of observed payload hashes
seen_hashes = set()
# map of sensor ID -> public ECDSA key. Here we just have one sensor with a known id-key pair
sensor_public_keys = {
    bytes.fromhex('ffffffffffffffffffffffffffffff01'): util.load_public_key('sensor-public-ecc.pem')
}
# map of pending data hashes -> [nonce, token] pairs
pending_deliveries = {}


def get_public_params() -> bytes:
    return payloads.PublicParams.deserialize(
        requests.get(provider_url + '/public_params', verify=use_tls).content
    )


# ALGORITHM 1: TOKEN PURCHASE
# make a request to provider for more tokens
def get_more_tokens(num_tokens: int) -> list[bytes]:

    global public_params

    # if we didn't query the app server for the public parameters yet, do so now
    if not public_params:
        public_params = get_public_params()

    blinded_tokens = [tokenlib.generate_token(public_params) for _ in range(num_tokens)]
    blinded_token_bytes = payloads.TokenList.serialize(blinded_tokens)
    signed_tokens = payloads.TokenList.deserialize(
        requests.post(
            provider_url + '/sign_tokens',
            verify=use_tls,
            headers = {'Content-type': 'application/octet-stream'},
            data=blinded_token_bytes
        ).content
    )

    return [tokenlib.unblind_token(b_token, s_token) for b_token, s_token in zip(blinded_tokens, signed_tokens)]


# ALGORITHM 2(a): PAYLOAD DELIVERY (HASH PAYLOAD)
def deliver_hash_payload(payload) -> str:

    global unused_tokens
    global provider_url
    global seen_hashes 
    global sensor_public_keys
    global pending_deliveries

    p_hash, sig_hash = payloads.SignedHashPayload.deserialize(payload)
    sensor_id, data_hash = payloads.HashPayload.deserialize(p_hash)
    print(f'data_hash: {util.encode_bytes_b64(data_hash)}')

    # if the payload hash is already in the set of payload hashes, abort by returning nothing
    if data_hash in seen_hashes:
        print(f'Payload hash already seen: {util.encode_bytes_b64(data_hash)}')
        return None

    # verify the signature, abort if it fails
    if sensor_id not in sensor_public_keys:
        print(f'Unknown sensor ID: {sensor_id}')
        return None
        
    if not util.verify_ecdsa(sensor_public_keys[sensor_id], p_hash, sig_hash):
        print(f'Invalid signature for sensor ID: {sensor_id}')
        return None

    # generate random nonce and get an unused token
    protocol_nonce = util.get_random_bytes(config.DELIVER_NONCE_BYTES)
    if len(unused_tokens) == 0:
        unused_tokens += get_more_tokens(TOKEN_REQUEST_SIZE)
    token = unused_tokens.pop()

    pending_deliveries[data_hash] = [protocol_nonce, token]

    aes_key = util.load_aes_key()
    encrypted_token = util.encrypt_aes(aes_key, token)

    payload = payloads.PredeliveryPayload.serialize(protocol_nonce, data_hash, encrypted_token)
    sig = util.sign_ecdsa(util.load_private_key(), payload)
    return payloads.SignedPredeliveryPayload.serialize(
        payload, sig
    )


# ALGORITHM 2(b) PAYLOAD DELIVERY (DATA PAYLOAD) 
def deliver_data(payload) -> str:

    global pending_deliveries

    # Yay! We can do something with the data now!
    data = payloads.Data.deserialize(payload)

    # hash the data payload and check if it's in the set of pending payload hashes
    data_hash = util.hash_sha256(data)
    if data_hash not in pending_deliveries:
        print(f'Unknown data hash: {util.encode_bytes_b64(data_hash)}')
        return None
    
    # get the nonce and token from the pending deliveries
    nonce, token = pending_deliveries[data_hash]
    del pending_deliveries[data_hash]

    token_payload = payloads.TokenPayload.serialize(nonce, token, data_hash)
    return payloads.SignedTokenPayload.serialize(
        token_payload, util.sign_ecdsa(util.load_private_key(), token_payload)
    )


# ALGORITHM 4(c): RECEIVE COMPLAINT DATA
def deliver_complaint_data(payload) -> bool: 
    # Yay! We can do something with the complaint data now!
    complaint_data = payloads.Data.serialize(payload)
    return b''
