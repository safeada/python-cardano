'''
Main data structures of blockchain.

Rather than fully decode the data into python object, we access the required fields from cbor data.
It's more efficient this way at most scenario.

We also try to cache raw data, to prevent re-serialization.
'''
from collections import namedtuple
import hashlib
import binascii
import base58
import cbor
from .utils import hash_serialized, hash_data

class DecodedBlockHeader(object):
    def __init__(self, data, raw=None):
        self.data = data
        self._raw = raw

    def hash(self):
        return hash_serialized(self.raw())

    def prev_header(self):
        return self.data[1][1]

    def slot(self):
        '''
        (epoch, slotid)

        slotid: None means genesis block.
        '''
        if self.is_genesis():
            epoch = self.data[1][3][0]
            slotid = None
        else:
            epoch, slotid = self.data[1][3][0]
        return epoch, slotid

    def is_genesis(self):
        return self.data[0] == 0

    def raw(self):
        return self._raw or cbor.dumps(self.data)

class DecodedTransaction(object):
    def __init__(self, data, raw=None):
        self.data = data
        self._raw = raw

    def hash(self):
        return hash_serialized(self.raw())

    def tx(self):
        from .wallet import Tx, TxIn, TxOut
        inputs = set(TxIn(*cbor.loads(item.value)) for tag, item in self.data[0] if tag == 0)
        outputs = [TxOut(cbor.dumps(addr), c) for addr, c in self.data[1]]
        return Tx(self.txid(), inputs, outputs)

    def txid(self):
        return hash_data(self.data)

    def raw(self):
        return self._raw or cbor.dumps(self.data)

class DecodedBlock(object):
    def __init__(self, data, raw=None):
        self.data = data
        self._raw = raw

    def header(self):
        return DecodedBlockHeader([self.data[0], self.data[1][0]])

    def is_genesis(self):
        return self.data[0] == 0

    def transactions(self):
        if self.is_genesis():
            return []
        else:
            # GenericBlock -> MainBody -> [(Tx, TxWitness)]
            return [DecodedTransaction(tx) for tx, _ in self.data[1][1][0]]

    def txs(self):
        'Transaction list in wallet Tx format.'
        return map(lambda t: t.tx(), self.transactions())

    def raw(self):
        return self._raw or cbor.dumps(self.data)
