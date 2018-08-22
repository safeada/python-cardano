'''
Logic includes workers and listeners.
'''
import binascii
import random
import time
import math
import traceback

import gevent
import cbor
from orderedset import OrderedSet

from .block import DecodedBlockHeader, DecodedBlock
from .node import Node, Worker, Message
from .utils import get_current_slot, flatten_slotid
from . import config


# Workers
class GetHeaders(Worker):
    message_type = Message.GetHeaders

    def __call__(self, from_, to):
        self.conv.send(cbor.dumps([cbor.VarList(from_), [to] if to else []]))
        tag, data = cbor.loads(self.conv.receive())  # sum type MsgHeaders
        if tag == 1:  # NoHeaders
            return []
        return [DecodedBlockHeader(item) for item in data]

    def tip(self):
        return self([], None)[0]


class GetBlocks(Worker):
    message_type = Message.GetBlocks

    def __call__(self, from_, to):
        self.conv.send(cbor.dumps([from_, to]))
        while True:
            buf = self.conv.receive()
            if not buf:
                # closed by remote.
                break
            tag, data = cbor.loads(buf)  # \x82, \x00, block_raw_data
            if tag == 0:  # MsgBlock
                yield DecodedBlock(data, buf[2:])

    def one(self, h):
        return next(self(h, h))


class StreamBlocks(Worker):
    message_type = Message.Stream

    def __init__(self, *args, **kwargs):
        super(StreamBlocks, self).__init__(*args, **kwargs)
        self._ended = False

    @property
    def ended(self):
        return self._ended

    def start(self, from_, to, n):
        self._ended = False
        self.conv.send(cbor.dumps([
            0,
            [cbor.VarList(from_), to, n]
        ]))
        yield from self._receive_stream(n)

    def update(self, n):
        assert not self._ended
        self.conv.send(cbor.dumps([
            1,
            [n]
        ]))
        yield from self._receive_stream(n)

    def _receive_stream(self, n):
        for i in range(n):
            buf = self.conv.receive()
            if not buf:
                # closed by remote.
                self._ended = True
                print('connection closed')
                break
            tag, data = cbor.loads(buf)  # \x82, \x00, block_raw_data
            if tag != 0:
                self._ended = True
                print('stream ended', tag, data)
                break
            yield DecodedBlock(data, buf[2:])


class Subscribe(Worker):
    message_type = Message.Subscribe

    def __call__(self):
        # instance Bi MsgSubscribe
        self.conv.send(cbor.dumps(42))

    def keepalive(self):
        while True:
            gevent.sleep(config.SLOT_DURATION / 1000)
            # keep alive
            self.conv.send(cbor.dumps(43))


class Subscribe1(Worker):
    message_type = Message.Subscribe1

    def __call__(self):
        # instance Bi MsgSubscribe1
        self.conv.send(cbor.dumps(42))


# Listeners
def handle_get_headers(node, conv):
    'Peer wants some block headers from us.'
    while True:
        data = conv.receive()
        if not data:
            print('remote closed')
            break
        print('request', cbor.loads(data))
        conv.send(cbor.dumps([0, []]))  # NoHeaders


def handle_get_blocks(node, conv):
    'Peer wants some blocks from us.'
    data = cbor.loads(conv.receive())
    print('request', data)
    conv.send(cbor.dumps([1, 0]))  # NoBlock


def handle_stream_start(node, conv):
    'Peer wants to stream some blocks from us.'
    pass


def handle_headers(node, conv):
    'Peer has a block header for us (yes, singular only).'
    data = conv.receive()
    if not data:
        print('remote closed')
        return
    tag, headers = cbor.loads(data)
    assert tag == 0 and len(headers) == 1, 'invalid header message'
    header = DecodedBlockHeader(headers[0])
    print('got new block header', binascii.hexlify(header.hash()).decode())

    if not getattr(node, 'retriever', None):
        # it's just a demo node.
        return

    node.retriever.add_retrieval_task(conv.addr, header)


def inv_worker(conv, key, value):
    '''
    Inv/Req/Data/Res

    send (Left (InvMsg key))                       listener (Either InvMsg DataMsg)
    Either ReqMsg ResMsg <- recv
    case
        (ReqMsg (Just key)) ->
           send (Right (DataMsg data))
           Either ReqMsg ResMsg <- recv
           case
             ResMsg -> return ResMsg
             ReqMsg -> error
        (ReqMsg Nothing) -> pass
        ResMsg -> error
    '''
    print('send inv key', key)
    conv.send(cbor.dumps([0, key]))  # Left (InvMsg key)
    (tag, req) = cbor.loads(conv.receive())
    assert tag == 0, 'should be ReqMsg'
    if req:
        assert cbor.dumps(req[0]) == cbor.dumps(key)
        conv.send(cbor.dumps([1, value]))  # Right (DataMsg value)
        (tag, res) = cbor.loads(conv.receive())
        assert tag == 1, 'should be ResMsg'
        return res


class TxInvWorker(Worker):
    message_type = Message.TxInvData

    def __call__(self, key, value):
        return inv_worker(self.conv, key, value)


workers = [
    GetHeaders,
    GetBlocks,
    StreamBlocks,
    Subscribe,
    Subscribe1,
    TxInvWorker,
]


listeners = {
    Message.GetHeaders: handle_get_headers,
    Message.GetBlocks: handle_get_blocks,
    Message.Stream: handle_stream_start,
    Message.Headers: handle_headers,
}


def retry_duration(duration):
    slot = config.SLOT_DURATION / 1000
    return math.floor(slot / 2 ** (duration / slot))


class LogicNode(Node):
    def __init__(self, ep, store):
        super(LogicNode, self).__init__(ep, workers, listeners)
        self.store = store

        # start worker threads
        self._parent_thread = gevent.getcurrent()

        # block retriever
        from .retrieve import BlockRetriever
        self.retriever = BlockRetriever(self.store, self)
        self.retriever_thread = gevent.spawn(self.retriever)
        self.retriever_thread.link(self._handle_worker_exit)

        # recover trigger
        self.trigger_recovery_thread = gevent.spawn(
            self._trigger_recovery_worker,
            config.SECURITY_PARAMETER_K * 2
        )
        self.trigger_recovery_thread.link(self._handle_worker_exit)

        # dns subscribe worker
        self._peers = gevent.event.AsyncResult()  # set of peer addresses
        self.subscribe_thread = gevent.spawn(self._subscribe, [config.CLUSTER_ADDR])
        self.subscribe_thread.link(self._handle_worker_exit)

    def _handle_worker_exit(self, t):
        print('worker thread exit unexpected')
        gevent.kill(self._parent_thread)

    def _trigger_recovery(self):
        'trigger recovery actively by requesting tip'
        print('recovery triggered.')
        for addr in list(self._peers.get()):  # use list to iterating a copy.
            try:
                header = self.worker(Message.GetHeaders, addr).tip()
            except Exception as e:
                traceback.print_exc()
                print('get tip failed', str(e))
            else:
                self.retriever.add_retrieval_task(addr, header)

    def _trigger_recovery_worker(self, lag_behind):
        while True:
            triggered = False
            slot_diff = 0
            if not self.retriever.recovering():
                cur_slot = get_current_slot()
                tip = self.store.tip()
                tip_slot = tip.slot() if tip else (0, 0)
                slot_diff = flatten_slotid(cur_slot) - flatten_slotid(tip_slot)
                if slot_diff >= lag_behind:
                    # need to recovery.
                    self._trigger_recovery()
                    triggered = True
                elif slot_diff < 0:
                    print('tip slot is in future.')

            if not triggered:
                # random
                if random.random() < 0.004 and slot_diff >= 5:
                    self._trigger_recovery()
                    triggered = True

            gevent.sleep(20 if triggered else 1, True)

    def _subscribe(self, domains):
        from .peers import resolve_loop
        for addr in resolve_loop(domains):
            start = time.time()

            if not self._peers.ready():
                self._peers.set(OrderedSet([addr]))
            else:
                self._peers.get().add(addr)

            try:
                print('subscribing to', addr.decode())
                w = self.worker(Message.Subscribe, addr)
                w()
                w.keepalive()
            except Exception as e:
                traceback.print_exc()
                print('subscribtion failed:' + str(e))
                # remove peers
                self._peers.get().remove(addr)

            gevent.sleep(retry_duration(time.time() - start))


if __name__ == '__main__':
    config.use('mainnet')
    from .transport import Transport
    from .storage import Storage
    from .utils import hash_data
    from .address import AddressContent
    from .block import DecodedTransaction, DecodedTxAux

    txid = hash_data(b'')
    pk = bytes(64)
    sig = bytes(64)
    addr = AddressContent.pubkey(pk).address().encode_base58()
    tx = DecodedTransaction.build(
        [(txid, 0)],
        [(addr, 100)],
    )
    txaux = DecodedTxAux.build(tx, [(pk, sig)])

    node = LogicNode(Transport().endpoint(), Storage('./test_db'))
    peer = node._peers.get()[0]
    worker = node.worker(Message.TxInvData, peer)
    key, success = worker(tx.hash(), txaux.data)
    assert key == tx.hash()
    print('success', success)
