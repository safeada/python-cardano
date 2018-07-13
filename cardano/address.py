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

FIRST_HARDEN_INDEX = 2147483648
def generate_pk(seed, passphase):
    for i in range(1, 1000):
        I = hmac.new(seed, b'Root Seed Chain %d' % i, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        ext = hashlib.sha512(Il).digest()
        ext = bytearray(ext)
        ext[0] &= 248
        ext[31] &= 127
        ext[31] |= 64
        if ext[31] & 0x20 != 0:
            continue
        return cbits.encrypted_from_secret(passphase, Il, Ir)
    else:
        print('generate failed')

def derive_hdpassphase(xpub):
    return pbkdf2.PBKDF2(xpub, 'address-hashing', iterations=500, digestmodule=hashlib.sha512).read(32)

def xpriv_to_xpub(xpriv):
    return xpriv[64:]

def pack_addr_payload(hdpass, path):
    'packHDAddressAttr'
    # manually construct variable length list encoding.
    plaintext = cbor.dumps(cbor.VarList(path))
    return bytes(CHACHA20_POLY1305(hdpass, 'python').seal(b"serokellfore", plaintext, b''))

def root_addr(xpub):
    # Address', assuming BootstrapEra
    return [
        0,              # addrType
        [ 0, xpub ],    # addrSpendingData
        {} # attrAttributes
    ]

def hd_addr(xpub, derive_path, hdpass):
    # Address', assuming BootstrapEra
    return [
        0,              # addrType
        [ 0, xpub ],    # addrSpendingData
        {1: cbor.dumps(pack_addr_payload(hdpass, derive_path))} # attrAttributes
    ]

def addr_hash(addr):
    return hashlib.blake2b(hashlib.sha3_256(cbor.dumps(addr)).digest(), digest_size=28).digest()

def encode_with_crc(v):
    s = cbor.dumps(v)
    return cbor.dumps([
        cbor.Tag(24, s),
        binascii.crc32(s)
    ])

def addr_hash2(addr):
    return hashlib.blake2b(hashlib.sha3_256(cbor.dumps(addr)).digest(), digest_size=20).digest()

def encode_with_crc2(v):
    s = cbor.dumps(v)
    # the prefix byte is for backward compatibility, old address always start with 0x82.
    return b'\x00' + s + struct.pack('<I', binascii.crc32(s))

def encode_addr(addr):
    h = addr_hash(addr)
    bs = encode_with_crc([
        h,
        addr[2],
        addr[0]
    ])
    return base58.b58encode(bs)

def encode_addr2(addr):
    addr[2] = {}    # don't need any attributes in bootstrap era.
    h = addr_hash2(addr)
    bs = encode_with_crc2([
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

def derive_address(xpriv, passphase, account_index, address_index):
    account_xpriv = cbits.encrypted_derive_private(
        xpriv, passphase, account_index, cbits.DERIVATION_V1
    )
    hdpass = derive_hdpassphase(xpriv_to_xpub(xpriv))
    key = cbits.encrypted_derive_private(
        account_xpriv, passphase, address_index, cbits.DERIVATION_V1
    )
    return hd_addr(xpriv_to_xpub(key), [account_index, address_index], hdpass)

def test(words, passphase):
    entropy = Mnemonic('english').to_entropy(words)
    sseed = cbor.dumps(hashlib.blake2b(cbor.dumps(bytes(entropy)), digest_size=32).digest())
    root_xpriv = generate_pk(sseed, passphase) # pk + chain code
    hdpass = derive_hdpassphase(xpriv_to_xpub(root_xpriv))
    print('wallet id', encode_addr(root_addr(xpriv_to_xpub(root_xpriv))).decode())
    print('experimental wallet id', encode_addr2(root_addr(xpriv_to_xpub(root_xpriv))).decode())
    print('first address', encode_addr(derive_address(root_xpriv, passphase, FIRST_HARDEN_INDEX, FIRST_HARDEN_INDEX)).decode())
    print('experimental first address', encode_addr2(derive_address(root_xpriv, passphase, FIRST_HARDEN_INDEX, FIRST_HARDEN_INDEX)).decode())
    print('decode',
    decode_addr('DdzFFzCqrhsx32JQQd7rKh85WTW8DqEghedsHB9Jv5Z86xKiuFFq9qcHWSyjo9bJwZgaHQoEbzdV1jSHPb1J6EQPHPx933dwHkv6aazr'),
    decode_addr('12MLxfn92bNZvqMcKo3iG7LQ1X1WqooMgadk6cor'))

if __name__ == '__main__':
    test('ring crime symptom enough erupt lady behave ramp apart settle citizen junk', b'123456')
