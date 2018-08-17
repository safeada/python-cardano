'''
* Use rocksdb as cardano-sl did.
* Store each epoch in seperate db.
    hash -> block data
    genesis -> hash of genesis block of epoch.
* Main database:
  * 'c/tip' -> hash
  * 'b/' + hash -> BlockHeader
  * 'e/fl/' + hash -> hash of next block.
  * 'ut/t/' + txIn -> TxOut
  * 's/' + stake holder id
  * 's/ftssum'

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

    def tip(self):
        if not self._tip:
            h = self.db.get(b'c/tip')
            if h:
                self._tip = self.blockheader(h)
        return self._tip

    def set_tip(self, hdr, batch=None):
        self._tip = hdr
        (batch or self.db).put(b'c/tip', hdr.hash())

    def blockheader(self, h):
        buf = self.db.get(b'b/' + h)
        if buf:
            return DecodedBlockHeader.from_raw(buf, h)

    def block(self, hdr):
        db = self.open_epoch_db(hdr.slot()[0], readonly=True)
        buf = db.get(hdr.hash())
        if buf:
            return DecodedBlock(cbor.loads(buf), buf)

    def genesis_block(self, epoch):
        db = self.open_epoch_db(epoch, readonly=True)
        h = db.get(b'genesis')
        assert h, 'epoch not exist: %d' % epoch
        return DecodedBlock.from_raw(db.get(h))

    def blocks_rev(self, start_hash=None):
        'Iterate blocks backwardly.'
        current_hash = start_hash or self.tip().hash()
        current_epoch = self.blockheader(current_hash).slot()[0]
        current_epoch_db = self.open_epoch_db(current_epoch, readonly=True)
        while True:
            raw = current_epoch_db.get(current_hash)
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
            start_hash = config.MAINCHAIN_GENESIS
            current_epoch = 0

        current_epoch_db = self.open_epoch_db(current_epoch, readonly=True)
        current_hash = start_hash
        raw = current_epoch_db.get(current_hash)
        yield DecodedBlock(cbor.loads(raw), raw)
        while True:
            current_hash = self.db.get(b'e/fl/' + current_hash)
            if not current_hash:
                return

            raw = current_epoch_db.get(current_hash)
            if raw:
                yield DecodedBlock(cbor.loads(raw), raw)
                continue

            # try increase epoch number.
            current_epoch += 1
            current_epoch_db = self.open_epoch_db(current_epoch, readonly=True)
            if not current_epoch_db:
                return
            raw = current_epoch_db.get(current_hash)
            if not raw:
                return

            yield DecodedBlock(cbor.loads(raw), raw)

    def blockheaders_rev(self):
        'Iterate block header backwardly.'
        current_hash = self.tip().hash()
        while True:
            raw = self.db.get(b'b/' + current_hash)
            if not raw:
                break
            hdr = DecodedBlockHeader(cbor.loads(raw), raw)
            yield hdr
            current_hash = hdr.prev_header()

    def blockheaders(self):
        current_hash = config.MAINCHAIN_GENESIS
        while True:
            raw = self.db.get(b'b/' + current_hash)
            yield DecodedBlockHeader.from_raw(raw, current_hash)
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
        if not block.is_genesis():
            self.utxo_apply_block(block, batch)
        self.set_tip(hdr, batch)
        self.db.write(batch)

        # write body
        epoch, _ = hdr.slot()
        db = self.open_epoch_db(epoch, readonly=False)
        if hdr.is_genesis():
            assert not db.get(b'genesis')
            db.put(b'genesis', h)
        db.put(h, block.raw())

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
