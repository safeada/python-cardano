'''
Implement wallet logic following the formal wallet specification.
'''

import operator
from collections import namedtuple
from recordclass import recordclass

# Basic Model.


Tx = namedtuple('Tx', 'txid inputs outputs')
TxIn = namedtuple('TxIn', 'txid ix')
TxOut = namedtuple('TxOut', 'addr c')
# UTxO :: Map TxIn TxOut

def dependent_on(tx2, tx1):
    'Check if tx2 is dependent on tx1'
    return any(lambda txin: txin.txid == tx1.txid, tx2.inputs)

def filter_ins(fn, utxo):
    return {txin:txout for txin, txout in utxo.items() if fn(txin)}

def filter_outs(fn, utxo):
    return {txin:txout for txin, txout in utxo.items() if fn(txout)}

def balance(utxo):
    return sum(txout.c for txout in utxo.values())

def dom(utxo):
    return set(utxo.keys())

# Txs :: List(Tx)
def txins(txs):
    return reduce(operator.or_, (tx.inputs for tx in txs))

def txouts(txs):
    return {(tx.txid, ix): txout for ix, txout in enumerate(tx.outputs) for tx in txs}

def new_utxo(txs):
    'new utxo added by these transactions.'
    txins_ = txins(txs)
    return filter_ins(lambda txin: txin in txins_, txouts(txs))

class Wallet(object):
    def __init__(self, addrs):
        self.addrs = set(addrs)
        self.utxo = {}
        self.pending = []

    def ours_utxo(self, utxo):
        'filter utxo belongs to us.'
        return filter_outs(lambda txout: txout.addr in self.addrs, utxo)

    def change(self, txs):
        'return change UTxOs from transactions.'
        return self.ours_utxo(txouts(txs))

    def available_utxo(self):
        'available utxo'
        txins_ = txins(self.pending)
        return filter_ins(lambda txin: txin not in txins_, self.utxo)

    def total_utxo(self):
        'total utxo'
        return self.available_utxo() | self.change(self.pending)

    def available_balance(self):
        return balance(self.available_utxo())

    def total_balance(self):
        return balance(self.total_utxo())

    def apply_block(self, txs):
        assert dom(txouts(txs)) & dom(self.utxo) == set(), 'precondition doesn\'t meet'
        txins_ = txins(txs)
        self.utxo = filter_ins(lambda txin: txin not in txins_, self.utxo | self.change(txs))
        self.pending = [tx for tx in self.pending if tx.inputs & txins_ == set()]

    def new_pending(self, tx):
        assert tx.inputs.issubset(dom(self.available_utxo())), 'precondition doesn\'t meet.'
        self.pending.append(tx)

    # Invariants
    def invariant_3_4(self):
        assert txins(self.pending).issubset(dom(self.utxo)), 'invariant 3.4 doesn\'t hold'

    def invariant_3_5(self):
        assert all(txout.addr in self.addrs for txout in self.utxo.values()), 'invariant 3.5 doesn\'t hold'

    def invariant_3_6(self):
        assert dom(self.change(self.pending)) & dom(self.available_utxo()) == set(), 'invariant 3.6 doesn\'t hold'

    def check_invariants(self):
        invariants = [
            self.invariant_3_4,
            self.invariant_3_5,
            self.invariant_3_6,
        ]
        for inv in invariants:
            inv()

if __name__ == '__main__':
    # Test with local database.
    import cbor, binascii
    from .storage import Storage
    store = Storage('test_db', True)
    hdr = store.blockheader(store.tip())
    while hdr:
        blk = store.block(hdr)
        for tx in blk.transactions():
            print(tx)

        hdr = store.blockheader(hdr.prev_header())