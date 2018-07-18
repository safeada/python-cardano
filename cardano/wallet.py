'''
Implement wallet logic following the formal wallet specification.
'''

import operator
from collections import namedtuple

# Basic Model.

Tx = namedtuple('Tx', 'txid inputs outputs')
TxIn = namedtuple('TxIn', 'txid ix')
TxOut = namedtuple('TxOut', 'addr c')
# UTxO :: Map TxIn TxOut

def dependent_on(tx2, tx1):
    'Check if tx2 is dependent on tx1'
    return any(lambda txin: txin.txid == tx1.txid, tx2.inputs)

#def filter_ins(fn, utxo):
#    return {txin:txout for txin, txout in utxo.items() if fn(txin)}

def filter_outs(fn, utxo):
    return {txin:txout for txin, txout in utxo.items() if fn(txout)}

def constraint_txins(txins, utxo):
    # More efficient than filter_ins
    return {txin: utxo[txin] for txin in txins if txin in utxo}

def exclude_txins_inplace(txins, utxo):
    # More efficient than filter_ins
    for txin in txins:
        utxo.pop(txin, None)
    return utxo

def balance(utxo):
    return sum(txout.c for txout in utxo.values())

def dom(utxo):
    return set(utxo.keys())

# Txs :: List(Tx)
def txins(txs):
    result = set()
    for tx in txs:
        result |= tx.inputs
    return result

def txouts(txs):
    return {(tx.txid, ix): txout for tx in txs for ix, txout in enumerate(tx.outputs)}

def new_utxo(txs):
    'new utxo added by these transactions.'
    return exclude_txins_inplace(txins(txs), txouts(txs))

class Wallet(object):
    def __init__(self, addrs):
        self.addrs = set(addrs)
        self.utxo = {}
        self.pending = []
        self._utxo_balance = 0

    def ours_utxo(self, utxo):
        'filter utxo belongs to us.'
        # TODO efficiency
        return filter_outs(lambda txout: txout.addr in self.addrs, utxo)

    def change(self, txs):
        'return change UTxOs from transactions.'
        return self.ours_utxo(txouts(txs))

    def available_utxo(self):
        'available utxo'
        utxo = self.utxo.copy()
        return exclude_txins_inplace(txins(self.pending), utxo)

    def total_utxo(self):
        'total utxo'
        return {**self.available_utxo(), **self.change(self.pending)}

    def available_balance(self):
        return self._utxo_balance - balance(constraint_txins(txins(self.pending), self.utxo))

    def total_balance(self):
        return self.available_balance() + balance(self.change(self.pending))

    def apply_block(self, txs):
        txouts_ = txouts(txs)
        txins_ = txins(txs)
        assert dom(txouts_) & dom(self.utxo) == set(), 'precondition doesn\'t meet'

        # add new utxo.
        utxo_new = self.ours_utxo(txouts_)
        self.utxo.update(utxo_new)
        utxo_spent = constraint_txins(txins_, self.utxo)
        # remove spent utxo inplace.
        exclude_txins_inplace(txins_, self.utxo)
        self._utxo_balance += balance(utxo_new) - balance(utxo_spent)

        self.pending = filter(lambda tx: tx.inputs & txins_ == set, self.pending)

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

    def invariant_balance_cache(self):
        assert self._utxo_balance == balance(self.utxo), 'balance cache broken.'
        assert self.available_balance() == balance(self.available_utxo()), 'available balance is wrong'
        assert self.total_balance() == balance(self.total_utxo()), 'total balance is wrong'

    def check_invariants(self):
        invariants = [
            self.invariant_3_4,
            self.invariant_3_5,
            self.invariant_3_6,
            self.invariant_balance_cache,
        ]
        for inv in invariants:
            inv()

if __name__ == '__main__':
    # Test with local database.
    import cbor, binascii
    import random
    from .storage import Storage
    store = Storage('test_db', readonly=True)
    def random_addresses(threshold):
        addrs = set()
        for blk in store.blocks():
            for tx in blk.transactions():
                for txout in tx.outputs:
                    if random.random() < 0.1:
                        addrs.add(txout.addr)
                        if len(addrs) > threshold:
                            return addrs

    print('Collect random addresses to test.')
    w = Wallet(random_addresses(10000))
    print('Apply blocks')
    b = w.available_balance()
    for blk in store.blocks():
        txs = blk.transactions()
        if txs:
            w.apply_block(txs)
            w.check_invariants()
            n = w.available_balance()
            if n != b:
                b = n
                print('balance changed', b)
