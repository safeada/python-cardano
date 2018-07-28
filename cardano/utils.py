import hashlib
import cbor

from .constants import SECURITY_PARAMETER_K

def hash_serialized(s):
    return hashlib.blake2b(s, digest_size=32).digest()

def hash_data(v):
    return hash_serialized(cbor.dumps(v))

def flatten_slotid(slot):
    epoch, idx = slot
    return epoch * SECURITY_PARAMETER_K * 10 + (idx or 0)
