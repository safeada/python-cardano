import hashlib
import binascii
import base58
import cbor

def default_hash(v):
    return hashlib.blake2b(cbor.dumps(v), digest_size=32).digest()

class DecodedBlockHeader(object):
    def __init__(self, data, raw=None):
        self.data = data
        self._raw = raw

    def hash(self):
        return default_hash(self.data)

    def prev_header(self):
        return self.data[1][1]

    def slot(self):
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
        self.raw = raw

    @property
    def txid(self):
        return default_hash(self.data)

    @property
    def inputs(self):
        # filter TxInUtxo
        return set(tuple(cbor.loads(item.value)) for tag, item in self.data[0] if tag == 0)

    @property
    def outputs(self):
        return [(cbor.dumps(addr), c) for addr, c in self.data[1]]

    def raw(self):
        return self._raw or cbor.dumps(self.data)

    def __str__(self):
        inputs = ', '.join('(%s, %d)' % (binascii.hexlify(txid).decode(), ix) for txid, ix in self.inputs)
        outputs = ', '.join('(%s, %d)' % (base58.b58encode(addr).decode(), c) for addr, c in self.outputs)
        return 'txid: %s, inputs: [%s], outputs: [%s]' % (
                binascii.hexlify(self.txid).decode(),
                inputs, outputs)

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

    def raw(self):
        return self._raw or cbor.dumps(self.data)
