import hashlib
import time
import cbor

from . import config

def hash_serialized(s):
    return hashlib.blake2b(s, digest_size=32).digest()

def hash_data(v):
    return hash_serialized(cbor.dumps(v))

def flatten_slotid(slot):
    epoch, idx = slot
    return epoch * config.SECURITY_PARAMETER_K * 10 + (idx or 0)

def unflatten_slotid(n):
    return divmod(n, config.SECURITY_PARAMETER_K * 10)

def get_current_slot():
    n = (int(time.time()) - config.START_TIME) // config.SLOT_DURATION
    return unflatten_slotid(n)
