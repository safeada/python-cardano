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
from collections import namedtuple

from mnemonic import Mnemonic
import cbor
import pbkdf2
import base58

from . import cbits
from .utils import hash_data
from .constants import FIRST_HARDEN_INDEX


def mnemonic_to_seed(words, lang='english'):
    return hash_data(bytes(Mnemonic(lang).to_entropy(words)))


def gen_root_xpriv(seed, passphase):
    seed = cbor.dumps(seed)
    for i in range(1, 1000):
        buf = hmac.new(seed, b'Root Seed Chain %d' % i, hashlib.sha512).digest()
        buf_l, buf_r = buf[:32], buf[32:]
        result = cbits.encrypted_from_secret(passphase, buf_l, buf_r)
        if result:
            return result


def xpriv_to_xpub(xpriv):
    return xpriv[64:]


def derive_hdpassphase(xpub):
    return pbkdf2.PBKDF2(xpub, 'address-hashing',
                         iterations=500, digestmodule=hashlib.sha512).read(32)


def pack_addr_payload(path, hdpass):
    'packHDAddressAttr'
    plaintext = cbor.dumps(cbor.VarList(path))
    return cbits.encrypt_chachapoly(b'serokellfore', hdpass, b'', plaintext)


def unpack_addr_payload(ciphertext, hdpass):
    plaintext = cbits.decrypt_chachapoly(b'serokellfore', hdpass, b'', ciphertext)
    if plaintext:
        return cbor.loads(plaintext)


def addr_hash(addr):
    'hash method for address is different.'
    return hashlib.blake2b(hashlib.sha3_256(cbor.dumps(addr, sort_keys=True)).digest(),
                           digest_size=28).digest()


def encode_with_crc(v):
    s = cbor.dumps(v, sort_keys=True)
    return cbor.dumps([
        cbor.Tag(24, s),
        binascii.crc32(s)
    ])


def addr_hash_short(addr):
    'Shorten hash result to 20 bytes.'
    return hashlib.blake2b(hashlib.sha3_256(cbor.dumps(addr, sort_keys=True)).digest(),
                           digest_size=20).digest()


def encode_with_crc_short(v):
    'Remove a level of cbor overhead.'
    s = cbor.dumps(v, sort_keys=True)
    # the prefix byte is for backward compatibility, old address always start with 0x82.
    return b'\x00' + s + struct.pack('<I', binascii.crc32(s))


def encode_addr_short(addr):
    return encode_with_crc_short([
        addr_hash_short(addr),
        addr.attrs,
        addr.type
    ])


RawAddressContent = namedtuple('RawAddressContent', 'type spending attrs')
RawAddress = namedtuple('RawAddress', 'hash attrs type')


class Address(RawAddress):
    def encode(self):
        return encode_with_crc(self)

    def encode_base58(self):
        return base58.b58encode(self.encode())

    @classmethod
    def decode(cls, s):
        if s[0] == 0:
            # version byte for new encoding.
            crc32, = struct.unpack('<I', s[-4:])
            s = s[1:-4]
        else:
            # old normal address.
            tag, crc32 = cbor.loads(s)
            s = tag.value
        assert binascii.crc32(s) == crc32, 'crc32 checksum don\'t match.'
        return cls(*cbor.loads(s))

    @classmethod
    def decode_base58(cls, s):
        return cls.decode(base58.b58decode(s))

    def verify_pubkey(self, xpub):
        if self.type != 0:
            return False
        confirm = AddressContent(0, [0, xpub], self.attrs)
        return confirm.address().hash == self.hash

    def verify_script(self, script):
        # TODO
        pass

    def get_derive_path(self, hdpass):
        'Get derive path from lagacy address.'
        payload = self.attrs.get(1)
        if payload:
            return unpack_addr_payload(cbor.loads(payload), hdpass)


class AddressContent(RawAddressContent):
    @staticmethod
    def pubkey(xpub, attrs=None):
        return AddressContent(
            0, [0, xpub], attrs or {}
        )

    @staticmethod
    def pubkey_lagacy(xpub, derive_path, hdpass, attrs=None):
        return AddressContent(
            0,            # addrType
            [0, xpub],    # addrSpendingData
            {1: cbor.dumps(pack_addr_payload(derive_path, hdpass)), **(attrs or {})}
        )

    @staticmethod
    def redeem(pk):
        return AddressContent(
            2,          # RedeemASD
            [2, pk],
            {}
        )

    @staticmethod
    def script(s):
        # TODO
        pass

    def address(self):
        return Address(
            addr_hash(self),
            self.attrs,
            self.type
        )


def derive_key(xpriv, passphase, path, derivation_schema):
    for idx in path:
        xpriv = cbits.encrypted_derive_private(
            xpriv, passphase, idx, derivation_schema
        )
    return xpriv


def derive_key_public(xpub, path, derivation_schema):
    for idx in path:
        xpub = cbits.encrypted_derive_public(xpub, idx, derivation_schema)
    return xpub


def derive_address_lagacy(xpriv, passphase, path, derivation_schema):
    hdpass = derive_hdpassphase(xpriv_to_xpub(xpriv))
    xpriv = derive_key(xpriv, passphase, path, derivation_schema)
    return AddressContent.pubkey_lagacy(xpriv_to_xpub(xpriv), path, hdpass)


def recover_addresses_lagacy(store, hdpass):
    result = set()
    for addr in store.iter_addresses():
        if Address.decode(addr).get_derive_path(hdpass):
            result.add(addr)
    return result


def test_encode_address(root_xpriv, passphase):
    addr = AddressContent.pubkey(xpriv_to_xpub(root_xpriv))
    print('wallet id', addr.address().encode_base58().decode())
    # print('wallet id[short]', base58.b58encode(encode_addr_short(addr)).decode())
    path = [FIRST_HARDEN_INDEX, FIRST_HARDEN_INDEX]
    addr = derive_address_lagacy(root_xpriv, passphase, path, cbits.DERIVATION_V1)
    print('first address', addr.address().encode_base58().decode())
    addr = derive_address_lagacy(root_xpriv, passphase, path, cbits.DERIVATION_V1)
    # print('first address[short]', base58.b58encode(encode_addr_short(addr)).decode())
    print('decode', Address.decode(addr.address().encode()))
    # print('decode[short]', Address.decode(encode_addr_short(addr)))

    hdpass = derive_hdpassphase(xpriv_to_xpub(root_xpriv))
    print('decrypte derive path', addr.address().get_derive_path(hdpass))


if __name__ == '__main__':
    from .utils import input_passphase
    passphase = input_passphase()
    words = 'ring crime symptom enough erupt lady behave ramp apart settle citizen junk'
    root_xpriv = gen_root_xpriv(mnemonic_to_seed(words), passphase)
    # test_encode_address(root_xpriv, passphase)

    from .storage import Storage
    hdpass = derive_hdpassphase(xpriv_to_xpub(root_xpriv))
    for addr in recover_addresses_lagacy(Storage('test_db'), hdpass):
        print(base58.b58encode(addr).decode())
