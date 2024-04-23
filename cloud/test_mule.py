
import argparse
import requests
import util
import json
import struct
import payloads
import tokenlib # type: ignore

def check_servers(provider_url, appserver_url):

    # Check provider
    try:
        response = requests.get(provider_url + '/')
        if response.status_code != 200:
            print(f'  Provider not up, got status code {response.status_code}')
            return False
    except Exception as e:
        print(f'  Error checking provider: {e}')
        return False

    # Check app server
    try:
        response = requests.get(appserver_url + '/')
        if response.status_code != 200:
            print(f'  App server not up, got status code {response.status_code}')
            return False
    except Exception as e:
        print(f'  Error checking app server: {e}')
        return False

    return True


def get_public_params(provider_url):
    try:
        response = requests.get(provider_url + '/public_params')
        if response.status_code != 200:
            print(f'  Error getting public params, got status code {response.status_code}')
            return None
        return response.content
    except Exception as e:
        print(f'  Error getting public params: {e}')
        return None


def get_complaint_public_params(provider_url):
    try:
        response = requests.get(provider_url + '/complaint_public_params')
        if response.status_code != 200:
            print(f'  Error getting complaint public params, got status code {response.status_code}')
            return None
        return response.content
    except Exception as e:
        print(f'  Error getting complaint public params: {e}')
        return None


def deliver_payload(_provider_url, appserver_url):

    try: 
        sensor_id = 0xffffffffffffffffffffffffffffff01
        sensor_id_bytes = sensor_id.to_bytes(16, 'big')
        print(f'  Using sensor ID: {sensor_id_bytes}\n')
        sensor_private_key = util.load_private_key('sensor-private-ecc.pem')

        # generate 512 random bytes
        data = util.get_random_bytes(512)
        data_hash = util.hash_sha256(data)

        hash_payload = payloads.HashPayload.serialize(sensor_id_bytes, data_hash)
        signed_hash_payload = payloads.SignedHashPayload.serialize(
            hash_payload,
            util.sign_ecdsa(sensor_private_key, hash_payload)
        )

        # send to the app server
        response = requests.post(appserver_url + '/deliver_hash',
                    verify = False,
                    headers = {'Content-Type': 'application/octet-stream'},
                    data = signed_hash_payload
        )
        if response.status_code != 200:
            print(f'  Error delivering hash payload, got status code {response.status_code}')
            return False, None
        
        response_bytes = response.content
        predelivery_payload, predelivery_signature = payloads.SignedPredeliveryPayload.deserialize(response_bytes)

        print(f'  Predelivery payload! {util.encode_bytes_b64(predelivery_payload)}')
        print(f'  Predelivery sig: {util.encode_bytes_b64(predelivery_signature)}')

        if not util.verify_ecdsa(
                util.load_public_key('jl-public-ecc.pem'),
                predelivery_payload,
                predelivery_signature):
            print(f'  Error verifying predelivery signature')
            return False, None

        pre_nonce, pre_hash, pre_enc_token = payloads.PredeliveryPayload.deserialize(predelivery_payload)
        if pre_hash != data_hash:
            print(f'  Error checking predelivery hash ({pre_hash} != {data_hash})')
            return False, None

        # send data to app server
        data_payload = payloads.Data.serialize(data)
        response = requests.post(appserver_url + '/deliver_data',
                    verify = False,
                    headers = {'Content-Type': 'application/octet-stream'},
                    data = data
        )
        if response.status_code != 200:
            print(f'  Error delivering data, got status code {response.status_code}')
            return False, None

        token_payload, token_signature = payloads.SignedTokenPayload.deserialize(response.content)
        if not util.verify_ecdsa(
                util.load_public_key('jl-public-ecc.pem'),
                token_payload,
                token_signature):
            print(f'  Error verifying token signature')
            return False, None

        token_nonce, token_token, token_data_hash = payloads.TokenPayload.deserialize(token_payload)

        if token_nonce != pre_nonce:
            print(f'  Error checking token nonce ({token_nonce} != {pre_nonce})')
            return False, None

        if token_data_hash != pre_hash:
            print(f'  Error checking token data hash ({token_data_hash} != {pre_hash})')
            return False, None
        
        print(f'  Token get! {util.encode_bytes_b64(token_token)}\n')

    except Exception as e:
        print(f'  Error delivering payload: {e}')
        return False, None

    return True, token_token


def redeem_token(provider_url, appserver_url, token):

    token_bytes = payloads.TokenList.serialize([token])
    redeem_bytes = payloads.TokenRedemptionPayload.serialize(util.get_random_bytes(16), token_bytes)

    response = requests.post(provider_url + '/redeem_tokens',
                    verify = False,
                    headers = {'Content-Type': 'application/octet-stream'},
                    data = redeem_bytes
    )
    if response.status_code != 200:
        print(f'  Error redeeming token, got status code {response.status_code}')
        return False

    response_bytes = response.content
    invalid_tokens = payloads.TokenList.deserialize(response_bytes)

    print(f'  Provider response: invalid tokens (empty is good): {invalid_tokens}')
    return True


def complain_deliver(_provider_url, appserver_url):

    try: 
        sensor_id = 0xffffffffffffffffffffffffffffff01
        sensor_id_bytes = sensor_id.to_bytes(16, 'big')
        print(f'  Using sensor ID: {sensor_id_bytes}\n')
        sensor_private_key = util.load_private_key('sensor-private-ecc.pem')

        # get some complaint tokens
        complaint_pp = get_complaint_public_params(_provider_url)
        blinded_tokens = [tokenlib.generate_token(complaint_pp) for _ in range(3)]

        new_epoch_payload = payloads.NewEpochRequest.serialize(sensor_id_bytes, payloads.TokenList.serialize(blinded_tokens))
        response = requests.post(_provider_url + '/new_epoch',
                    verify = False,
                    headers = {'Content-Type': 'application/octet-stream'},
                    data = new_epoch_payload)
        if response.status_code != 200:
            print(f'  Error getting complaint tokens, got status code {response.status_code}')
            return False, None

        complaint_bytes, dup_bytes = payloads.NewEpochResponse.deserialize(response.content)
        signed_tokens = payloads.TokenList.deserialize(complaint_bytes)
        complaint_tokens = [tokenlib.unblind_token(b_t, s_t) for b_t, s_t in zip(blinded_tokens, signed_tokens)]

        # generate 512 random bytes
        data = util.get_random_bytes(512)
        data_hash = util.hash_sha256(data)

        hash_payload = payloads.HashPayload.serialize(sensor_id_bytes, data_hash)
        signed_hash_payload = payloads.SignedHashPayload.serialize(
            hash_payload,
            util.sign_ecdsa(sensor_private_key, hash_payload)
        )

        # send to the app server
        response = requests.post(appserver_url + '/deliver_hash',
                    verify = False,
                    headers = {'Content-Type': 'application/octet-stream'},
                    data = signed_hash_payload
        )
        if response.status_code != 200:
            print(f'  Error delivering hash payload, got status code {response.status_code}')
            return False, None
        
        response_bytes = response.content
        predelivery_payload, predelivery_signature = payloads.SignedPredeliveryPayload.deserialize(response_bytes)

        print(f'  Predelivery payload! {util.encode_bytes_b64(predelivery_payload)}')
        print(f'  Predelivery sig: {util.encode_bytes_b64(predelivery_signature)}')

        if not util.verify_ecdsa(
                util.load_public_key('jl-public-ecc.pem'),
                predelivery_payload,
                predelivery_signature):
            print(f'  Error verifying predelivery signature')
            return False, None

        pre_nonce, pre_hash, pre_enc_token = payloads.PredeliveryPayload.deserialize(predelivery_payload)
        if pre_hash != data_hash:
            print(f'  Error checking predelivery hash ({pre_hash} != {data_hash})')
            return False, None

        # instead of delivering, complain
        pp = get_public_params(_provider_url)
        new_blinded_token = tokenlib.generate_token(pp)

        complaint = payloads.MissingComplaintRecord.serialize(response_bytes, data)
        complaint_bytes = payloads.ComplaintPayload.serialize(complaint_tokens[0], new_blinded_token, (0).to_bytes(16, 'big'), (1).to_bytes(1, 'big'), complaint)
        response = requests.post(_provider_url + '/complain',
                    verify = False,
                    headers = {'Content-Type': 'application/octet-stream'},
                    data = complaint_bytes)

        if response.status_code != 200:
            print(f'  Error complaining, got status code {response.status_code}')
            return False, None
        new_signed_token = response.content
        new_token = tokenlib.unblind_token(new_blinded_token, new_signed_token)

    except Exception as e:
        print(f'  Error delivering payload: {e}')
        return False, None

    return True, new_token


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test mule for running against local provider/app server docker containers')
    parser.add_argument('--provider', help="Provider url", default='http://localhost:8000')
    parser.add_argument('--appserver', help="App server url", default='http://localhost:8080')
    args = parser.parse_args()

    print('\n== Test Mule ==\n')
    print('checking provider and app server are up...')
    servers_up = check_servers(args.provider, args.appserver)
    if not servers_up:
        print('failed :(, exiting...')
        exit(1)
    else:
        print('done!')

    print('getting public parameters from provider...')
    result = get_public_params(args.provider)
    if result is None:
        print('failed :(, exiting...')
        exit(1)
    else:
        print('done!')

    print('getting complaint public parameters from provider...')
    result = get_complaint_public_params(args.provider)
    if result is None:
        print('failed :(, exiting...')
        exit(1)
    else:
        print('done!')

    print('generating payload and attempting delivery...')
    success, token = deliver_payload(args.provider, args.appserver)
    if not success:
        print('failed :(, exiting...')
        exit(1)
    else:
        print('done!') 

    print('attempting to redeem token...')
    success = redeem_token(args.provider, args.appserver, token)
    if not success:
        print('failed :(, exiting...')
        exit(1)
    else:
        print('done!')

    print('complaining about delivery...')
    success, new_token = complain_deliver(args.provider, args.appserver)
    if not success:
        print('failed :(, exiting...')
        exit(1)
    else:
        print('done!')

    print('attempting to redeem new token...')
    success = redeem_token(args.provider, args.appserver, new_token)
    if not success:
        print('failed :(, exiting...')
        exit(1)
    else:
        print('done!')

    print('\n')

