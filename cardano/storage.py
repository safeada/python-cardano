'''
* Use rocksdb as cardano-sl did.
* Store each epoch in seperate db.
    hash -> block data
    genesis -> hash of genesis block of epoch.
    tip -> hash of last block of epoch.
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
import binascii
import itertools

import cbor
import rocksdb

from .block import DecodedBlock, DecodedBlockHeader

class Storage(object):
    def __init__(self, root_path, readonly=False):
        self._root_path = root_path
        self.db = rocksdb.DB(os.path.join(self._root_path, 'db'), rocksdb.Options(create_if_missing=True), readonly)
        self._tip = None # cache current tip in memory.

    def epoch_db_path(self, epoch):
        return os.path.join(self._root_path, 'epoch%d'%epoch)

    def open_epoch_db(self, epoch, readonly=False):
        return rocksdb.DB(self.epoch_db_path(epoch), rocksdb.Options(create_if_missing=True), readonly)

    def tip(self):
        if not self._tip:
            self._tip = self.db.get(b'c/tip')
        return self._tip

    def set_tip(self, s):
        self._tip = s
        self.db.put(b'c/tip', s)

    def genesis_block_hash(self):
        return self.open_epoch_db(0).get(b'genesis')

    def blockheader(self, hash):
        buf = self.db.get(b'b/'+hash)
        if buf:
            return DecodedBlockHeader(cbor.loads(buf), buf)

    def block(self, hdr):
        db = self.open_epoch_db(hdr.slot()[0], readonly=True)
        buf = db.get(hdr.hash())
        if buf:
            return DecodedBlock(cbor.loads(buf), buf)

    def blocks_rev(self, start_hash=None):
        'Iterate blocks backwardly.'
        current_hash = start_hash or self.tip()
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
            current_epoch, _ = DecodedBlockHeader(cbor.loads(self.db.get(b'b/'+start_hash))).slot()
        else:
            start_hash = self.genesis_block_hash()
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
        current_hash = self.tip()
        while True:
            raw = self.db.get(b'b/'+current_hash)
            if not raw:
                break
            hdr = DecodedBlockHeader(cbor.loads(raw), raw)
            yield hdr
            current_hash = hdr.prev_header()

    def blockheaders(self):
        current_hash = self.genesis_block_hash()
        while True:
            raw = self.db.get(b'b/'+current_hash)
            yield DecodedBlockHeader(cbor.loads(raw), raw)
            current_hash = self.db.get(b'e/fl/'+current_hash)
            if not current_hash:
                break

    def blockheaders_noorder(self):
        'Iterate block header in rocksdb order, fastest.'
        it = self.db.iteritems()
        it.seek(b'b/')
        for k, raw in it:
            if not k.startswith(b'b/'):
                break
            yield DecodedBlockHeader(cbor.loads(raw), raw)

    def append_block(self, block):
        hdr = block.header()

        # check prev_hash
        tip = self.tip()
        if tip:
            assert hdr.prev_header() == tip, 'invalid block.'

        hash = hdr.hash()
        self.db.put(b'b/' + hash, hdr.raw())
        self.db.put(b'e/fl/' + hdr.prev_header(), hash)
        self.set_tip(hash)
