'''
Main data structures of blockchain.

Rather than fully decode the data into python object,
we access the required fields from cbor data.
It's more efficient this way at most scenario.

We also try to cache raw data, to prevent re-serialization.
'''
import cbor
from .utils import hash_serialized, hash_data
from .address import addr_hash
from . import config


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
        if not self._hash:
            self._hash = hash_serialized(self.raw())
        return self._hash


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

    def tx_count(self):
        if not self.is_genesis():
            return self.data[1][2][0][0]

    def protocol_magic(self):
        return self.data[1][0]

    def leader_key(self):
        assert not self.is_genesis()
        return self.data[1][3][1]

    def unknowns(self):
        return self.data[1][4][2]


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
        assert not self.is_genesis()
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
        # Process in reversed order, so we can remove inputs spent by current block.
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

    def unknowns(self):
        return self.data[1][2][0]

    def leaders(self):
        assert self.is_genesis()
        return self.data[1][1]


class VerifyException(Exception):
    pass


def verify_header(
        hdr,
        protocol_magic,
        header_no_unknown=False,
        prev_header=None,
        current_slot=None,
        leaders=None,
        max_header_size=None):
    if hdr.protocol_magic() != config.PROTOCOL_MAGIC:
        raise VerifyException('protocol magic')

    if prev_header is not None:
        if hdr.prev_header() != prev_header.hash():
            raise VerifyException('prev header hash')
        if hdr.difficulty() != prev_header.difficulty() + (0 if hdr.is_genesis() else 1):
            raise VerifyException('prev header difficulty')
        if hdr.slot() <= prev_header.slot():
            raise VerifyException('prev header slot')
        if not hdr.is_genesis() and hdr.slot()[0] != prev_header.slot()[0]:
            raise VerifyException('prev header epoch')

    if current_slot is not None and hdr.slot() > current_slot:
        raise VerifyException('slot in future')

    if leaders is not None and not hdr.is_genesis() and \
            leaders[hdr.slot()[1]] != addr_hash(hdr.leader_key()):
        raise VerifyException('leader')

    if header_no_unknown and hdr.unknowns():
        raise VerifyException('extra header data')


def verify_block(
        blk,
        protocol_magic,
        max_block_size=None,
        body_no_unknown=False,
        **kwargs):
    verify_header(blk.header(), protocol_magic, **kwargs)

    if max_block_size is not None and len(blk.raw()) > max_block_size:
        raise VerifyException('block size')

    if body_no_unknown and blk.unknowns():
        raise VerifyException('extra block data')


def verify_blocks(blks):
    pass


if __name__ == '__main__':
    from .storage import Storage
    from .utils import get_current_slot
    store = Storage('test_db')
    hdr = store.tip()
    blk = store.block(hdr)
    prev_header = store.blockheader(blk.header().prev_header())
    print(hdr.slot())
    genesis = store.genesis_block(hdr.slot()[0])
    print(genesis.leaders())
    print(blk.unknowns(), hdr.unknowns())
    verify_block(blk, config.PROTOCOL_MAGIC,
                 max_block_size=config.MAX_BLOCK_SIZE,
                 body_no_unknown=True,
                 header_no_unknown=True,
                 current_slot=get_current_slot(),
                 prev_header=prev_header,
                 leaders=genesis.leaders())
