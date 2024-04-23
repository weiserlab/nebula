
import struct


SHA256_BYTES = 32
SIGNATURE_BYTES = 64
SENSOR_ID_BYTES = 16


class PublicParams:

    # this payload is a passthrough since there's a single bytes object
    @staticmethod
    def serialize(public_params: bytes) -> bytes:
        return public_params
    
    @staticmethod
    def deserialize(response_body: bytes) -> bytes:
        return response_body


class TokenList:

    # assumes that they all have the same size
    @staticmethod
    def serialize(tokens: list[bytes]) -> bytes:
        token_len = 0 if len(tokens) == 0 else len(tokens[0])
        concat_tokens = b''.join(tokens)
        return struct.pack(f'I{len(concat_tokens)}s', token_len, concat_tokens)
    
    @staticmethod
    def deserialize(response_body: bytes) -> list[bytes]:
        tokens = []
        token_bytes = struct.unpack_from('I', response_body, offset=0)[0]

        idx = 4
        while idx < len(response_body):
            tokens.append(response_body[idx:idx + token_bytes])
            idx += token_bytes

        return tokens


# P_hash = [id_s, H(d)]
class HashPayload:

    @staticmethod
    def serialize(sensor_id, data_hash) -> bytes:
        return struct.pack('16s32s', sensor_id, data_hash)
    
    # returns (sensor_id, payload_hash, payload_sig)
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        return struct.unpack('16s32s', response_body)


class SignedHashPayload:

    @staticmethod
    def serialize(hash_payload, signature) -> bytes:
        return struct.pack('48s64s', hash_payload, signature)
    
    # results (hash_payload, signature)
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        return struct.unpack('48s64s', response_body)


class PredeliveryPayload:

    @staticmethod
    def serialize(protocol_nonce, data_hash, encrypted_token) -> bytes:
        return b''.join([
            struct.pack('16s32s', protocol_nonce, data_hash),
            encrypted_token
        ])
    
    # returns (protocol_nonce, data_hash, encrypted_token)
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes, bytes]:
        protocol_nonce, data_hash = struct.unpack_from('16s32s', response_body, offset=0)
        encrypted_token = response_body[48:]
        return protocol_nonce, data_hash, encrypted_token


class SignedPredeliveryPayload:

    @staticmethod
    def serialize(predelivery_payload, signature) -> bytes:
        return b''.join([
            predelivery_payload,
            signature
        ])
    
    # returns (predelivery_payload, signature)
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        return response_body[:-SIGNATURE_BYTES], response_body[-SIGNATURE_BYTES:]
    

class Data:

    @staticmethod
    def serialize(data: bytes) -> bytes:
        return data
    
    @staticmethod
    def deserialize(response_body: bytes) -> bytes:
        return response_body

    
class TokenPayload:

    @staticmethod
    def serialize(protocol_nonce, token, data_hash) -> bytes:
        return struct.pack('16s64s32s', protocol_nonce, token, data_hash)
    
    # returns (protocol_nonce, token, data_hash)
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes, bytes]:
        return struct.unpack('16s64s32s', response_body)


class SignedTokenPayload:

    @staticmethod
    def serialize(token_payload, signature) -> bytes:
        return b''.join([
            token_payload,
            signature
        ])
    
    # returns (token_payload, signature)
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        return response_body[:-SIGNATURE_BYTES], response_body[-SIGNATURE_BYTES:]


class TokenRedemptionPayload:

    @staticmethod
    def serialize(mule_id, token_bytes) -> bytes:
        return b''.join([
            mule_id,
            token_bytes
        ])
    
    # returns (mule_id, list[tokens])
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes,  bytes]:

        mule_id = response_body[:16]
        token_bytes = response_body[16:]

        return mule_id, token_bytes


class ComplaintPayload:

    @staticmethod
    def serialize(complaint_token, blinded_token, appserver_id, complaint_record_type, complaint_record) -> bytes:
        return struct.pack(f'64s160s16sc{len(complaint_record)}s',
                           complaint_token, blinded_token, appserver_id, complaint_record_type, complaint_record)
    
    # returns (complaint_token, blinded_token, appserver_id, complaint_record_type, complaint_record)
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes, bytes, int, bytes]:
        complaint_token, blinded_token, appserver_id, complaint_record_type = \
            struct.unpack_from('64s160s16sc', response_body[:241], offset=0)
        complaint_record = response_body[241:]
        return complaint_token, blinded_token, appserver_id, int.from_bytes(complaint_record_type, 'big'), complaint_record


class IncorrectComplaintRecord:
    
    @staticmethod
    def serialize(signed_pre_payload, signed_token_payload) -> bytes:
        pre_bytes = len(signed_pre_payload)
        token_bytes = len(signed_token_payload)

        return struct.pack(f'I{pre_bytes}s{len(signed_token_payload)}s',
                           pre_bytes, signed_pre_payload, signed_token_payload)
    
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        pre_bytes = struct.unpack('I', response_body[:4])
        signed_pre_payload = response_body[4:4 + pre_bytes]
        signed_token_payload = response_body[4 + pre_bytes:]
        return signed_pre_payload, signed_token_payload


class MissingComplaintRecord:

    @staticmethod
    def serialize(signed_pre_payload, data) -> bytes:
        pre_bytes = len(signed_pre_payload)
        return struct.pack(f'I{pre_bytes}s{len(data)}s',
                           pre_bytes, signed_pre_payload, data)
    
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        pre_bytes = struct.unpack('I', response_body[:4])[0]
        signed_pre_payload = response_body[4:4 + pre_bytes]
        data = response_body[4 + pre_bytes:]
        return signed_pre_payload, data


class NewEpochRequest:
    
    @staticmethod
    def serialize(mule_id, complaint_token_bytes) -> bytes:
        return mule_id + complaint_token_bytes
    
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        return response_body[:16], response_body[16:]


class NewEpochResponse:

    @staticmethod
    def serialize(complaint_token_bytes, duplicate_token_bytes) -> bytes:
        return struct.pack(f'II{len(complaint_token_bytes)}s{len(duplicate_token_bytes)}s',
                           len(complaint_token_bytes), len(duplicate_token_bytes),
                           complaint_token_bytes, duplicate_token_bytes)
    
    @staticmethod
    def deserialize(response_body: bytes) -> tuple[bytes, bytes]:
        complaint_token_bytes_len, duplicate_token_bytes_len = struct.unpack('II', response_body[:8])
        return response_body[8:8 + complaint_token_bytes_len], response_body[8 + complaint_token_bytes_len:]