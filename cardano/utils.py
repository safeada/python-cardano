import hashlib
import cbor

def hash_serialized(s):
    return hashlib.blake2b(s, digest_size=32).digest()

def hash_data(v):
    return hash_serialized(cbor.dumps(v))
