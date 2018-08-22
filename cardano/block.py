'''
Main data structures of blockchain.

Rather than fully decode the data into python object,
we access the required fields from cbor data.
It's more efficient this way at most scenario.

We also try to cache raw data, to prevent re-serialization.
'''
import cbor
import base64
import binascii
import itertools
from collections import defaultdict
from .utils import hash_serialized, hash_data, verify
from .address import Address, AddressContent
from .random import Random
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
        if not self._raw:
            self._raw = cbor.dumps(self.data)
        return self._raw

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
    @classmethod
    def build(cls, inputs, outputs, attrs=None):
        '''
        inputs: [(txid, ix)]
        outputs: [(address, n)]
        '''
        data = (
            cbor.VarList([  # inputs
                (0, cbor.Tag(24, cbor.dumps((txid, ix))))
                for txid, ix in inputs
            ]),
            cbor.VarList([  # outputs
                (cbor.loads(Address.decode_base58(addr).encode()), c)
                for addr, c in outputs
            ]),
            attrs or {}  # attrs
        )
        return cls(data)

    def tx(self):
        from .wallet import Tx
        return Tx(self.hash(), self.inputs(), self.outputs())

    def inputs(self):
        from .wallet import TxIn
        return set(TxIn(*cbor.loads(item.value))
                   for tag, item in self.data[0]
                   if tag == 0)

    def outputs(self):
        from .wallet import TxOut
        return [TxOut(cbor.dumps(addr), c)
                for addr, c in self.data[1]]


class DecodedTxAux(DecodedBase):
    '(Tx, TxWitness)'
    @classmethod
    def build(cls, tx, witnesses):
        '''
        witnesses: [(pubkey, signature)]
        '''
        assert len(tx.inputs()) == len(witnesses)
        return cls((
            tx.data,
            [(0, cbor.Tag(24, cbor.dumps((pk, sig))))
             for pk, sig in witnesses]
        ))

    def transaction(self):
        return DecodedTransaction(self.data[0])

    def verify(self, undo):
        '''
        undo: [TxOut]
        '''
        for txin, wit, out in itertools.zip_longest(
                self.transaction().inputs(),
                self.data[1],
                undo):
            if wit[0] != 0:
                print('only support pubkey witness')
                return False
            pk, sig = cbor.loads(wit[1].value)
            if not out:
                return False
            addr = Address.decode(out.addr)
            if not addr.verify_pubkey(pk):
                return False
            if not verify('tx', pk, sig, hash_data(self.data[0])):
                print('sig verify fail')
                return False
        return True


class DecodedBlock(DecodedBase):
    def header(self):
        return DecodedBlockHeader([self.data[0], self.data[1][0]])

    def is_genesis(self):
        return self.data[0] == 0

    def transactions(self):
        assert not self.is_genesis()
        # GenericBlock -> MainBody -> [(Tx, TxWitness)]
        return [DecodedTransaction(tx) for tx, _ in self.data[1][1][0]]

    def txaux(self):
        assert not self.is_genesis()
        # GenericBlock -> MainBody -> [(Tx, TxWitness)]
        return [DecodedTxAux(data) for data in self.data[1][1][0]]

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


def genesis_block(prev_header, epoch, leaders):
    'create genesis block'
    return DecodedBlock([
        0,
        [[
            config.PROTOCOL_MAGIC,
            prev_header.hash(),
            hash_data(leaders),
            [epoch, prev_header.difficulty()],
            {}
        ], leaders],
        {}
    ])


def avvm_pk(s):
    s = s.replace('_', '/').replace('-', '+')
    s = base64.b64decode(s)
    assert len(s) == 32
    return s


def genesis_balances():
    return [(AddressContent.redeem(avvm_pk(k)).address(), int(v))
            for k, v in config.GENESIS['avvmDistr'].items()] + \
        [(Address.decode_base58(k), int(v))
         for k, v in config.GENESIS['nonAvvmBalances'].items()]


def bootstrap_distr(c):
    # bootstrap
    stakeholders = config.GENESIS['bootStakeholders']
    sum_weight = sum(stakeholders.values())
    result = []
    if c < sum_weight:
        for holder, weight in stakeholders.items():
            result.append((binascii.unhexlify(holder), min(c, weight)))
            c -= weight
            if c < 0:
                break
    else:
        d, m = divmod(c, sum_weight)
        stakes = [weight * d for _, weight in stakeholders.items()]
        if m > 0:
            ix = Random(hash_data(m)).number(len(stakeholders))
            stakes[ix] += m
        result = zip(map(binascii.unhexlify, stakeholders.keys()), stakes)

    return result


def addr_stakes(addr, c):
    dist = addr.attrs.get(0)
    if dist is None:
        return bootstrap_distr(c)
    else:
        # TODO
        assert False


def genesis_stakes():
    stakes = defaultdict(int)
    for addr, c in genesis_balances():
        for holder, n in addr_stakes(addr, c):
            stakes[holder] += n
    return stakes


def fts(slotcount, seed, coinsum, stakelist):
    'if stakelist is consistant with coinsum, no exception'
    assert coinsum > 0

    # generate coin indexes.
    rnd = Random(seed)
    indices = [(slot, rnd.number(coinsum)) for slot in range(slotcount)]
    indices.sort(key=lambda t: t[1])  # sort by coin index

    leaders = []
    it = iter(stakelist)
    current_holder, upper_range = next(it)
    for slot, idx in indices:
        while True:
            if idx <= upper_range:
                leaders.append((slot, current_holder))
                break

            current_holder, c = next(it)
            upper_range += c

    assert len(leaders) == slotcount
    leaders.sort(key=lambda t: t[0])  # sort by slot index
    return [leader for _, leader in leaders]


def genesis_block0():
    'create the first genesis block from config.'
    stakes = genesis_stakes().items()
    # TODO cardano-sl used HM.toList to sort genesis stakes, so...
    leaders = fts(
        config.GENESIS['protocolConsts']['k'] * 10,
        config.GENESIS['ftsSeed'].encode(),
        sum(n for _, n in stakes),
        stakes,
    )
    return DecodedBlock([
        0,
        [[
            config.PROTOCOL_MAGIC,
            config.GENESIS_HASH,
            hash_data(leaders),
            [0, 0],
            {}
        ], leaders],
        {}
    ])


if __name__ == '__main__':
    config.use('mainnet')
    blk = genesis_block0()
    leaders = blk.leaders()

    from cardano.storage import Storage
    store = Storage('test_db')
    db_leaders = store.genesis_block(0).leaders()

    # compare with official result.
    for i in range(10):
        print(leaders[i], db_leaders[i])
