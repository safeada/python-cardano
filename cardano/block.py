'''
Main data structures of blockchain.

Rather than fully decode the data into python object,
we access the required fields from cbor data.
It's more efficient this way at most scenario.

We also try to cache raw data, to prevent re-serialization.
'''
import cbor
from .utils import hash_serialized, hash_data


class DecodedBase(object):
    def __init__(self, data, raw=None, hash=None):
        self.data = data
        self._raw = raw
        self._hash = hash

    @classmethod
    def from_raw(cls, raw, hash=None):
        return cls(cbor.loads(raw), raw, hash)

    def raw(self):
        return self._raw or cbor.dumps(self.data)

    def hash(self):
        return self._hash or hash_serialized(self.raw())


class DecodedBlockHeader(DecodedBase):
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

    def difficulty(self):
        if self.is_genesis():
            n, = self.data[1][3][1]
        else:
            n, = self.data[1][3][2]
        return n


class DecodedTransaction(DecodedBase):
    def tx(self):
        from .wallet import Tx, TxIn, TxOut
        inputs = set(TxIn(*cbor.loads(item.value))
                     for tag, item in self.data[0]
                     if tag == 0)
        outputs = [TxOut(cbor.dumps(addr), c) for addr, c in self.data[1]]
        return Tx(self.txid(), inputs, outputs)

    def txid(self):
        return hash_data(self.data)


class DecodedBlock(DecodedBase):
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
        'Transaction list in wallet format.'
        return map(lambda t: t.tx(), self.transactions())

    def utxos(self):
        'Set of inputs spent, and UTxO created.'
        from .wallet import TxIn
        txins = set()
        utxo = {}
        # Process in reversed order, so we can remote inputs spent by current block.
        for t in reversed(self.transactions()):
            tx = t.tx()
            for idx, txout in enumerate(tx.outputs):
                # new utxo
                txin = TxIn(tx.txid, idx)
                if txin not in txins:
                    utxo[txin] = txout
            for txin in tx.inputs:
                txins.add(txin)
        return txins, utxo
