'''
* Use rocksdb as cardano-sl did.
* Store each epoch in seperate db.
    'b/' + hash -> block data
    'u/' + hash -> undo data
    g -> hash of genesis block of epoch.
* Main database:
  * 'c/tip' -> hash
  * 'b/' + hash -> BlockHeader
  * 'e/fl/' + hash -> hash of next block.
  * 'ut/t/' + txIn -> TxOut
  * 's/' + stake holder id
  * 's/ftssum'
  * 'a/' + addr -> 1 # address discovery.

Sync
----

* get headers from storage current tip to network tip.
* download blocks and save to db.

'''
import os

import cbor
import rocksdb

from .block import DecodedBlock, DecodedBlockHeader
from . import config


def iter_prefix(db, prefix):
    it = db.iteritems()
    it.seek(prefix)
    for k, v in it:
        if not k.startswith(prefix):
            break
        yield k, v


def remove_prefix(db, prefix):
    batch = rocksdb.WriteBatch()
    for k, _ in iter_prefix(db, prefix):
        batch.delete(k)
    db.write(batch)


class Storage(object):
    def __init__(self, root_path, readonly=False):
        print('create storage at', root_path)
        if not os.path.exists(root_path):
            os.makedirs(root_path)
        self._root_path = root_path
        opt = rocksdb.Options(create_if_missing=True)
        self.db = rocksdb.DB(os.path.join(self._root_path, 'db'), opt, readonly)
        self._tip = None  # cache current tip header in memory.

        # cache recent used epoch db.
        self._current_epoch_db = None
        self._current_epoch = None

    def epoch_db_path(self, epoch):
        return os.path.join(self._root_path, 'epoch%d' % epoch)

    def open_epoch_db(self, epoch, readonly=False):
        if epoch != self._current_epoch:
            self._current_epoch = epoch
            self._current_epoch_db = rocksdb.DB(
                self.epoch_db_path(epoch),
                rocksdb.Options(create_if_missing=True),
                readonly
            )
        return self._current_epoch_db

    def load_tip(self):
        h = self.db.get(b'c/tip')
        if h:
            return self.blockheader(h)

    def tip(self):
        if not self._tip:
            self._tip = self.load_tip()
        return self._tip

    def set_tip(self, hdr, batch=None):
        self._tip = hdr
        (batch or self.db).put(b'c/tip', hdr.hash())

    def blockheader(self, h):
        buf = self.db.get(b'b/' + h)
        if buf:
            return DecodedBlockHeader.from_raw(buf, h)

    def raw_block(self, hdr):
        db = self.open_epoch_db(hdr.slot()[0], readonly=True)
        buf = db.get(b'b/' + hdr.hash())
        if buf:
            return buf

    def block(self, hdr):
        raw = self.raw_block(hdr)
        if raw:
            return DecodedBlock.from_raw(raw)

    def undos(self, hdr):
        db = self.open_epoch_db(hdr.slot()[0], readonly=True)
        buf = db.get(b'u/' + hdr.hash())
        if buf:
            return cbor.loads(buf)

    def genesis_block(self, epoch):
        db = self.open_epoch_db(epoch, readonly=True)
        h = db.get(b'g')
        assert h, 'epoch not exist: %d' % epoch
        return DecodedBlock.from_raw(db.get(h))

    def blocks_rev(self, start_hash=None):
        'Iterate blocks backwardly.'
        current_hash = start_hash or self.tip().hash()
        current_epoch = self.blockheader(current_hash).slot()[0]
        current_epoch_db = self.open_epoch_db(current_epoch, readonly=True)
        while True:
            raw = current_epoch_db.get(b'b/' + current_hash)
            if not raw:
                # try decrease epoch id.
                current_epoch -= 1
                if current_epoch < 0:
                    break
                current_epoch_db = self.open_epoch_db(current_epoch, readonly=True)
                continue

            blk = DecodedBlock(cbor.loads(raw), raw)
            yield blk
            current_hash = blk.header().prev_header()

    def blocks(self, start_hash=None):
        'Iterate blocks forwardly.'
        if start_hash:
            current_epoch, _ = DecodedBlockHeader(
                cbor.loads(self.db.get(b'b/' + start_hash))
            ).slot()
        else:
            start_hash = config.GENESIS_BLOCK_HASH
            current_epoch = 0

        current_epoch_db = self.open_epoch_db(current_epoch, readonly=True)
        current_hash = start_hash
        raw = current_epoch_db.get(b'b/' + current_hash)
        yield DecodedBlock(cbor.loads(raw), raw)
        while True:
            current_hash = self.db.get(b'e/fl/' + current_hash)
            if not current_hash:
                return

            raw = current_epoch_db.get(b'b/' + current_hash)
            if raw:
                yield DecodedBlock(cbor.loads(raw), raw)
                continue

            # try increase epoch number.
            current_epoch += 1
            current_epoch_db = self.open_epoch_db(current_epoch, readonly=True)
            if not current_epoch_db:
                return
            raw = current_epoch_db.get(b'b/' + current_hash)
            if not raw:
                return

            yield DecodedBlock(cbor.loads(raw), raw)

    def blockheaders_rev(self, start=None):
        'Iterate block header backwardly.'
        current_hash = start or self.tip().hash()
        while True:
            raw = self.db.get(b'b/' + current_hash)
            if not raw:
                break
            hdr = DecodedBlockHeader(cbor.loads(raw), raw)
            yield hdr
            current_hash = hdr.prev_header()

    def blockheaders(self, start=None):
        current_hash = start or config.GENESIS_BLOCK_HASH
        while True:
            raw = self.db.get(b'b/' + current_hash)
            yield DecodedBlockHeader.from_raw(raw, current_hash)
            current_hash = self.db.get(b'e/fl/' + current_hash)
            if not current_hash:
                break

    def iter_header_hash(self, start=None):
        current_hash = start or config.GENESIS_BLOCK_HASH
        while True:
            yield current_hash
            current_hash = self.db.get(b'e/fl/' + current_hash)
            if not current_hash:
                break

    def blockheaders_noorder(self):
        'Iterate block header in rocksdb order, fastest.'
        return map(
            lambda t: DecodedBlockHeader.from_raw(t[1], t[0][2:]),
            iter_prefix(self.db, b'b/')
        )

    def append_block(self, block):
        hdr = block.header()
        batch = rocksdb.WriteBatch()

        # check prev_hash
        tip = self.tip()
        if tip:
            assert hdr.prev_header() == tip.hash(), 'invalid block.'

        h = hdr.hash()
        batch.put(b'b/' + h, hdr.raw())
        batch.put(b'e/fl/' + hdr.prev_header(), h)
        undos = None
        if not block.is_genesis():
            undos = self._get_block_undos(block)
            self.utxo_apply_block(block, batch)
            for tx in block.transactions():
                for out in tx.outputs():
                    batch.put(b'a/' + out.addr, b'')
        self.set_tip(hdr, batch)
        self.db.write(batch)

        # write body
        epoch, _ = hdr.slot()
        db = self.open_epoch_db(epoch, readonly=False)
        batch = rocksdb.WriteBatch()
        if hdr.is_genesis():
            assert not db.get(b'g')
            batch.put(b'g', h)
        else:
            batch.put(b'u/' + h, cbor.dumps(undos))
        batch.put(b'b/' + h, block.raw())
        db.write(batch)

    def _get_block_undos(self, block):
        return [[self.get_output(txin) for txin in tx.inputs()]
                for tx in block.transactions()]

    def utxo_apply_block(self, block, batch):
        txins, utxo = block.utxos()
        for txin in txins:
            batch.delete(b'ut/t/' + cbor.dumps(txin))
        for txin, txout in utxo.items():
            batch.put(b'ut/t/' + cbor.dumps(txin), cbor.dumps(txout))

    def iter_utxo(self):
        from .wallet import TxIn, TxOut
        prefix = b'ut/t/'
        for k, v in iter_prefix(self.db, prefix):
            yield TxIn(*cbor.loads(k[len(prefix):])), TxOut(*cbor.loads(v))

    def iter_addresses(self):
        it = self.db.iterkeys()
        it.seek(b'a/')
        for k in it:
            if not k.startswith(b'a/'):
                break
            yield k[2:]

    def get_output(self, txin):
        data = self.db.get(b'ut/t/' + cbor.dumps(txin))
        if data:
            return cbor.loads(data)


def hash_range(store, hstart, hstop, depth_limit):
    if hstart == hstop:
        assert depth_limit > 0
        yield hstart
        return
    start = store.blockheader(hstart)
    stop = store.blockheader(hstop)
    assert start and stop
    assert stop.diffculty() > start.diffculty()
    assert stop.diffculty() - start.diffculty() < depth_limit
    for h in store.iter_header_hash(start):
        yield h
        if h == stop:
            break


def fetch_raw_blocks(store, hstart, hstop):
    '''
    '''
    for h in hash_range(store,
                        hstart,
                        hstop,
                        config.CHAIN['block']['recoveryHeadersMessage']):
        yield store.raw_block(store.blockheader(h))

def stream_raw_blocks(store, hstart):
    for h in store.iter_header_hash(hstart):
        yield store.raw_block(store.blockheader(h))
