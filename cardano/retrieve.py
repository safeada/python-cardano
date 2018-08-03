import binascii

import gevent.queue
import gevent.event

from .storage import Storage
from .transport import Transport
from .node import default_node, Message
from .utils import flatten_slotid, get_current_slot

def classify_new_header(tip_header, header):
    current_slot = get_current_slot()
    hdr_slot = header.slot()
    #if hdr_slot[1] == None:
    #    # genesis block
    #    print('new header is genesis block')
    #    return # useless
    if hdr_slot > current_slot:
        print('new header is for future slot')
        return # future slot
    if hdr_slot <= tip_header.slot():
        print('new header slot not advanced than tip')
        return

    if header.prev_header() == tip_header.hash():
        # TODO verify new header
        return True # is's a continuation
    else:
        # check difficulty
        if header.difficulty() > tip_header.difficulty():
            # longer alternative chain.
            return False

class BlockRetriever(object):
    def __init__(self, store, node):
        self.store = store
        self.node = node

        # retrieval task queue
        self.queue = gevent.queue.Queue(16)
        # recovery signal
        self._recovery = None

        self.event = gevent.event.Event()

        self.last_known_header = None

    def __call__(self):
        while True:
            self.event.wait()
            self.event.clear()

            while not self.queue.empty():
                addr, header = self.queue.get(False)
                self._handle_retrieval_task(addr, header)

            if self._recovery:
                self._handle_recovery_task(*self._recovery)

    def add_retrieval_task(self, addr, header):
        print('add retrieval task', header.difficulty())
        self._update_last_known_header(header)
        self.queue.put((addr, header))
        self.event.set()

    def recovering(self):
        return bool(self._recovery)

    def trigger_recovery(self, addr):
        'trigger recovery actively by requesting tip'
        print('recovery triggered.')
        w = self.node.worker(Message.GetHeaders, addr)
        self.add_retrieval_task(addr, w.tip())

    def status(self):
        'syncing: return sync progress; not syncing: return None'
        if self._recovery:
            local = self.store.blockheader(self.store.tip()).difficulty()
            net = self.last_known_header.difficulty()
            return local / net

    def _set_recovery_task(self, addr, header):
        if self._recovery:
            _, old_hdr = self._recovery
            if header.difficulty() <= old_hdr.difficulty():
                # no need to update
                return

        if not self._recovery:
            print('start recovery', header.difficulty())
        else:
            print('update recovery target', header.difficulty())

        self._recovery = (addr, header)
        self.event.set()

    def _handle_recovery_task(self, addr, header):
        tip_header = self.store.blockheader(self.store.tip())
        # TODO proper checkpoints
        self._stream_blocks(addr, [tip_header.hash()], header.hash())

    def _handle_retrieval_task(self, addr, header):
        tip_header = self.store.blockheader(self.store.tip())
        result = classify_new_header(tip_header, header)
        if result == True:
            # continuation, get a single block.
            self._single_block(addr, header.hash())
        elif result == False:
            # alternative, enter recovery mode.
            self._set_recovery_task(addr, header)

    def _handle_blocks(self, blocks):
        if self._recovery:
            _, header = self._recovery
            target_difficulty = header.difficulty()
            if any(blk.header().difficulty() >= target_difficulty for blk in blocks):
                print('exit recovering')
                self._recovery = None

        for blk in blocks:
            self.store.append_block(blk)

    def _batch_blocks(self, addr, checkpoints, head):
        # TODO classify headers
        print('request batch blocks')
        w_headers = self.node.worker(Message.GetHeaders, addr)
        headers = w_headers(checkpoints, head)
        print('got headers', len(headers))
        if not headers:
            return
        w_blocks = self.node.worker(Message.GetBlocks, addr)
        blocks = list(w_blocks(headers[-1].hash(), headers[0].hash()))
        print('got blocks', len(blocks))
        self._handle_blocks(blocks)

    def _stream_blocks(self, addr, checkpoints, head):
        # get blocks [tip] header
        worker = self.node.worker(Message.Stream, addr)
        if worker:
            # stream mode
            pass
        else:
            self._batch_blocks(addr, checkpoints, head)

    def _single_block(self, addr, h):
        print('request single block')
        w = self.node.worker(Message.GetBlocks, addr)
        blk = next(w(h, h))
        self._handle_blocks([blk])

    def _update_last_known_header(self, header):
        # update last known header
        if not self.last_known_header or header.difficulty() > self.last_known_header.difficulty():
            self.last_known_header = header
