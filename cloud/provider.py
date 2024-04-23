# provider.py
import config
import tokenlib # type: ignore
import util
import platform_db
import platform_tokendb
import requests
import json
from Crypto.Random import get_random_bytes # type: ignore
import payloads
import os

# load keypair (generated with gen_keypair.py)
with open('keypair.bin', 'rb') as f:
    _keypair = f.read()

with open('complaint_keypair.bin', 'rb') as f:
    _complaint_keypair = f.read()

# -- Provider State --
use_tls = os.environ.get('SERVER_TLS') == 'true'
# map of known appserver id -> {'public_key': <>, 'url': <>}
appservers = {
    (0).to_bytes(16, 'big'): {
        'public_key': util.load_public_key('jl-public-ecc.pem'),
        'url': 'http://appserver:8080'
    }
}
# database of redeemed token counts per-mule
mule_db = platform_db.KeyValueDatabase()
# database of per-mule duplicate tokens
mule_duplicate_db = {}
# database of already-redeemed delivery tokens
token_db = platform_tokendb.StringSet()
# database of already-redeemed complaint tokens
complaint_token_db = platform_tokendb.StringSet()
# database of duplicates with filed complaints
complaint_duplicate_token_db = platform_tokendb.StringSet()


# ALGORITHM 1(a) TOKEN PURCHASE (PUBLIC PARAMS)
def get_public_params(payload=None) -> bytes:
    return payloads.PublicParams.serialize(
        tokenlib.get_public_params(_keypair)
    )


# ALGORITHM 1(b) TOKEN PURCHASE (SIGN TOKENS)
def sign_tokens(payload) -> bytes:
    print('sign tokens', payload)
    blinded_tokens = payloads.TokenList.deserialize(payload)
    return payloads.TokenList.serialize([
        tokenlib.sign_token(_keypair, token) for token in blinded_tokens
    ])


# ALGORITHM 3: TOKEN REDEMPTION
def redeem_tokens(payload) -> bytes:

    global token_db
    global mule_db
    global mule_duplicate_db

    mule_id, token_bytes = payloads.TokenRedemptionPayload.deserialize(payload)
    decoded_tokens = payloads.TokenList.deserialize(token_bytes)

    valid_tokens = []
    invalid_tokens = []
    for token in decoded_tokens:
        if tokenlib.verify_token(_keypair, token):
            valid_tokens.append(token)
        else:
            invalid_tokens.append(token)

    duplicate_mule_list = token_db.add_new_elements(valid_tokens, [mule_id] * len(valid_tokens))
    duplicate_tokens = 0
    for token, previous_mule_id in zip(valid_tokens, duplicate_mule_list):
        if previous_mule_id == None:
            continue

        mule_duplicate_db[previous_mule_id] = mule_duplicate_db.get(previous_mule_id, []) + [token]
        mule_db.increment_count(previous_mule_id, -1)

        mule_duplicate_db[mule_id] = mule_duplicate_db.get(mule_id, []) + [token]
        duplicate_tokens += 1

    num_successfully_redeemed = len(valid_tokens) - duplicate_tokens
    mule_db.increment_count(mule_id, num_successfully_redeemed)

    return payloads.TokenList.serialize(invalid_tokens)


# ALGORITHM 4(a): COMPLAINT (PUBLIC PARAMS)
def get_complaint_public_params(payload=None) -> bytes:
    return payloads.PublicParams.serialize(
        tokenlib.get_public_params(_complaint_keypair)
    )


# ALGORITHM 4(b): COMPLAINT (COMPLAIN)
def complain(payload) -> bytes:

    global appservers
    global complaint_token_db
    global token_db
    global complaint_duplicate_token_db

    complaint_token, blinded_token, appserver_id, complaint_type, complaint = \
        payloads.ComplaintPayload.deserialize(payload)

    if appserver_id not in appservers:
        print('Unknown appserver ID')
        return None

    # verify complaint token
    if not tokenlib.verify_token(_complaint_keypair, complaint_token):
        print('Complaint token failed to verify')
        return None

    # check if the complaint token has been used before
    if complaint_token_db.add_if_not_exists(complaint_token) is not None:
        print('Complaint token already used')
        return None

    if complaint_type == 0:
        signed_predeliver_payload, signed_token_payload = \
            payloads.IncorrectComplaintRecord.deserialize(complaint)
    elif complaint_type == 1:
        signed_predeliver_payload, data = \
            payloads.MissingComplaintRecord.deserialize(complaint)
    else:
        print('Invalid complaint type')
        return None

    pre_payload, pre_signature = payloads.SignedPredeliveryPayload.deserialize(signed_predeliver_payload)
    if not util.verify_ecdsa(appservers[appserver_id]['public_key'], pre_payload, pre_signature):
        print('Invalid predelivery signature')
        return None

    _, data_hash, encrypted_token = payloads.PredeliveryPayload.deserialize(pre_payload)
    decrypted_token = util.decrypt_aes(
        util.load_aes_key(),
        encrypted_token
    )
    if not tokenlib.verify_token(_keypair, decrypted_token):
        # if the token fails to verify after the signature worked, then the appserver is at fault
        # send a new token
        return tokenlib.sign_token(_keypair, blinded_token)
    
    # invalidate the token
    already_used = token_db.add_if_not_exists(decrypted_token)
    if already_used:
        print('Token already used, don\'t allow another token to be issued')
        return None

    if complaint_type == 0:
        # check the token signature
        token_payload, token_signature = payloads.SignedTokenPayload.deserialize(signed_token_payload)
        if not util.verify_ecdsa(appservers[appserver_id]['public_key'], token_payload, token_signature):
            print('Invalid token payload signature')
            return None

        _, token, data_hash = payloads.TokenPayload.deserialize(token_payload)

        # check the actual token
        if decrypted_token != token or not tokenlib.verify_token(_keypair, token):
            # app server gave a bad token, return a new one
            return tokenlib.sign_token(_keypair, blinded_token)
        
        # if the token was ok but it's a duplicate, then the first complaint wins
        already_complained = complaint_duplicate_token_db.add_if_not_exists(token)
        if already_complained:
            return b'' # don't return an error, but don't return a new token either
        
    else: # complaint_type == 1

        if data_hash != util.hash_sha256(data):
            print('Data hash mismatch')
            return None

        # send data to AS
        print('Sending data to appserver at ', appservers[appserver_id]['url'] + '/deliver_data')
        requests.post(
            appservers[appserver_id]['url'] + '/deliver_complaint_data',
            verify=use_tls,
            headers = {'Content-Type': 'application/octet-stream'},
            data=data
        )

    # sign and return a blinded token
    return tokenlib.sign_token(_keypair, blinded_token)


# ALGORITHM 5: NEW EPOCH
def new_epoch(payload):

    global mule_duplicate_db

    mule_id, blinded_token_bytes = payloads.NewEpochRequest.deserialize(payload)
    blinded_tokens = payloads.TokenList.deserialize(blinded_token_bytes)

    signed_tokens = [tokenlib.sign_token(_complaint_keypair, b_t) for b_t in blinded_tokens]
    signed_token_bytes = payloads.TokenList.serialize(signed_tokens)

    duplicate_tokens = mule_duplicate_db.get(mule_id, [])
    duplicate_token_bytes = payloads.TokenList.serialize(duplicate_tokens)

    return payloads.NewEpochResponse.serialize(signed_token_bytes, duplicate_token_bytes)

