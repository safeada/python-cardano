'''
Crypto primitives of Cardano HD wallet and addresses.

All secret keys in memory are encrypted by passphase.

sk: secret key 32bit
pk: public key 32bit
chaincode: 32bit
xpub: pk + chaincode 64bit
xpriv: 64bit + xpub
hdpassphase: passphase derive from root xpub used to encrypt address payload
'''
import binascii
import hashlib  # Python >= 3.6
import hmac
import struct

from mnemonic import Mnemonic
import cbor
import pbkdf2
import base58
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305

from . import cbits
from .utils import hash_serialized, hash_data

FIRST_HARDEN_INDEX = 2147483648

def mnemonic_to_seed(words, lang='english'):
    return hash_data(bytes(Mnemonic(lang).to_entropy(words)))

def gen_root_xpriv(seed, passphase):
    seed = cbor.dumps(seed)
    for i in range(1, 1000):
        I = hmac.new(seed, b'Root Seed Chain %d' % i, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        result = cbits.encrypted_from_secret(passphase, Il, Ir)
        if result:
            return result
    else:
        print('generate failed')

def xpriv_to_xpub(xpriv):
    return xpriv[64:]

def derive_hdpassphase(xpub):
    return pbkdf2.PBKDF2(xpub, 'address-hashing', iterations=500, digestmodule=hashlib.sha512).read(32)

def pack_addr_payload(path, hdpass):
    'packHDAddressAttr'
    plaintext = cbor.dumps(cbor.VarList(path))
    return bytes(CHACHA20_POLY1305(hdpass, 'python').seal(b'serokellfore', plaintext, b''))

def unpack_addr_payload(ciphertext, hdpass):
    plaintext = CHACHA20_POLY1305(hdpass, 'python').open(b'serokellfore', ciphertext, b'')
    if plaintext:
        return cbor.loads(bytes(plaintext))

def root_addr(xpub):
    'Address\', assuming BootstrapEra'
    return [
        0,              # addrType
        [ 0, xpub ],    # addrSpendingData
        {} # attrAttributes
    ]

def hd_addr(xpub, derive_path, hdpass):
    'Address\', assuming BootstrapEra'
    return [
        0,              # addrType
        [ 0, xpub ],    # addrSpendingData
        {1: cbor.dumps(pack_addr_payload(derive_path, hdpass))} # attrAttributes
    ]

def addr_hash(addr):
    'hash method for address is different.'
    return hashlib.blake2b(hashlib.sha3_256(cbor.dumps(addr)).digest(), digest_size=28).digest()

def encode_with_crc(v):
    s = cbor.dumps(v)
    return cbor.dumps([
        cbor.Tag(24, s),
        binascii.crc32(s)
    ])

def encode_addr(addr):
    h = addr_hash(addr)
    bs = encode_with_crc([
        h,
        addr[2],
        addr[0]
    ])
    return base58.b58encode(bs)

def addr_hash_short(addr):
    'Shorten hash result to 20 bytes.'
    return hashlib.blake2b(hashlib.sha3_256(cbor.dumps(addr)).digest(), digest_size=20).digest()

def encode_with_crc_short(v):
    'Remove a level of cbor overhead.'
    s = cbor.dumps(v)
    # the prefix byte is for backward compatibility, old address always start with 0x82.
    return b'\x00' + s + struct.pack('<I', binascii.crc32(s))

def encode_addr_short(addr):
    addr[2].pop(1, None) # Don't encode derive path in address.
    h = addr_hash_short(addr)
    bs = encode_with_crc_short([
        h,
        addr[2],
        addr[0]
    ])
    return base58.b58encode(bs)

def decode_addr(s):
    s = base58.b58decode(s)
    if s[0] == 0:
        # version byte for new encoding.
        crc32, = struct.unpack('<I', s[-4:])
        s = s[1:-4]
    else:
        # old normal address.
        tag, crc32 = cbor.loads(s)
        s = tag.value
    assert binascii.crc32(s) == crc32, 'crc32 checksum don\'t match.'
    return cbor.loads(s)

def derive_address(xpriv, passphase, path):
    hdpass = derive_hdpassphase(xpriv_to_xpub(xpriv))
    for idx in path:
        xpriv = cbits.encrypted_derive_private(
            xpriv, passphase, idx, cbits.DERIVATION_V1
        )
    return hd_addr(xpriv_to_xpub(xpriv), path, hdpass)

def get_derive_path(addr, hdpass):
    'Get derive path from lagacy address.'
    _, attrs, _ = decode_addr(addr)
    payload = attrs.get(1)
    if payload:
        return unpack_addr_payload(cbor.loads(payload), hdpass)

def recover_from_blocks(blocks, hdpass):
    addrs = {} # addr -> derive path
    for blk in blocks:
        for tx in blk.transactions():
            for out in tx.outputs:
                addr = base58.b58encode(out.addr)
                path = get_derive_path(addr, hdpass)
                if path:
                    print('found', addr)
                    addrs[out.addr] = path
    return addrs

def recover_from_storage(store, hdpass):
    return recover_from_blocks(store.blocks_rev(), hdpass)

def test_encode_address(words, passphase):
    root_xpriv = gen_root_xpriv(mnemonic_to_seed(words), passphase)
    print('wallet id', encode_addr(root_addr(xpriv_to_xpub(root_xpriv))).decode())
    print('wallet id[short]', encode_addr_short(root_addr(xpriv_to_xpub(root_xpriv))).decode())
    addr = encode_addr(derive_address(root_xpriv, passphase, [FIRST_HARDEN_INDEX, FIRST_HARDEN_INDEX]))
    print('first address', addr.decode())
    addr_short = encode_addr_short(derive_address(root_xpriv, passphase, [FIRST_HARDEN_INDEX, FIRST_HARDEN_INDEX]))
    print('first address[short]', addr_short.decode())
    print('decode', decode_addr(addr))
    print('decode[short]', decode_addr(addr_short))

    hdpass = derive_hdpassphase(xpriv_to_xpub(root_xpriv))
    print('decrypte derive path', get_derive_path(addr, hdpass))

def test_recover(words, passphase):
    from .storage import Storage
    store = Storage('./test_db')

    root_xpriv = gen_root_xpriv(mnemonic_to_seed(words), passphase)
    hdpass = derive_hdpassphase(xpriv_to_xpub(root_xpriv))
    print(recover_from_storage(store, hdpass))

if __name__ == '__main__':
    import getpass
    passphase = getpass.getpass('Input passphase:').encode()
    words = 'ring crime symptom enough erupt lady behave ramp apart settle citizen junk'
    test_encode_address(words, passphase)
