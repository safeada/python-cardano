import hashlib
import time
import cbor

from .constants import SECURITY_PARAMETER_K, START_TIME, SLOT_DURATION

def hash_serialized(s):
    return hashlib.blake2b(s, digest_size=32).digest()

def hash_data(v):
    return hash_serialized(cbor.dumps(v))

def flatten_slotid(slot):
    epoch, idx = slot
    return epoch * SECURITY_PARAMETER_K * 10 + (idx or 0)

def unflatten_slotid(n):
    return divmod(n, SECURITY_PARAMETER_K * 10)

def get_current_slot():
    n = (int(time.time()) - START_TIME) // SLOT_DURATION
    return unflatten_slotid(n)
