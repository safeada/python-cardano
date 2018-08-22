import hashlib
import time
import cbor
import getpass

from . import config
from . import cbits


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
    n = (int(time.time()) - config.START_TIME) // (config.SLOT_DURATION / 1000)
    return unflatten_slotid(n)


def input_passphase():
    passphase = getpass.getpass('Input passphase:').encode()
    if passphase:
        return hashlib.blake2b(passphase, digest_size=32).digest()
    return passphase


SIGN_TAGS = {
    'test': b'\x00',
    'tx': b'\x01',
    'redeem_tx': b'\x02',
    'vss_cert': b'\x03',
    'us_proposal': b'\x04',
    'commitment': b'\x05',
    'us_vote': b'\x06',
    'mainblock': b'\x07',
    'mainblock_light': b'\x08',
    'mainblock_heavy': b'\x09',
    'proxy_sk': b'\x0a',
}


def sign_tag(tag):
    if tag is None:
        return b''
    elif tag == 'test':
        return b'\x00'
    else:
        return SIGN_TAGS[tag] + cbor.dumps(config.PROTOCOL_MAGIC)


def sign(tag, sk, data):
    msg = sign_tag(tag) + cbor.dumps(data)
    return cbits.encrypted_sign(sk, b'', msg)


def verify(tag, pk, sig, data):
    msg = sign_tag(tag) + cbor.dumps(data)
    return cbits.verify(pk, msg, sig)
