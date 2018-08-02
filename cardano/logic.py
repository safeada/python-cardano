'''
Logic includes workers and listeners.
'''
import binascii

import gevent
import cbor

from .block import DecodedBlockHeader, DecodedBlock
from .node import Node, Worker, Message
from .utils import get_current_slot
from .config import SLOT_DURATION

# Workers
class GetHeaders(Worker):
    message_type = Message.GetHeaders

    def __call__(self, from_, to):
        self.conv.send(cbor.dumps([cbor.VarList(from_), [to] if to else []]))
        tag, data = cbor.loads(self.conv.receive()) # sum type MsgHeaders
        if tag == 1: # NoHeaders
            return []
        return [DecodedBlockHeader(item) for item in data]

class GetBlocks(Worker):
    message_type = Message.GetBlocks

    def __call__(self, from_, to):
        self.conv.send(cbor.dumps([from_, to]))
        while True:
            buf = self.conv.receive()
            if not buf:
                # closed by remote.
                break
            tag, data = cbor.loads(buf) # \x82, \x00, block_raw_data
            if tag == 0: # MsgBlock
                yield DecodedBlock(data, buf[2:])

class StreamBlocks(Worker):
    message_type = Message.Stream

    def start(self, from_, to, n):
        self.conv.send(cbor.dumps([
            0,
            [0, cbor.VarList(from_), to, n]
        ]))
        yield from self._receive_stream()

    def update(self, n):
        self.conv.send(cbor.dumps([
            1,
            [0, n]
        ]))
        yield from self._receive_stream()

    def _receive_stream(self):
        while True:
            buf = self.conv.receive()
            if not buf:
                # closed by remote.
                print('connection closed')
                break
            tag, data = cbor.loads(buf) # \x82, \x00, block_raw_data
            if tag != 0:
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
            gevent.sleep(SLOT_DURATION)
            # keep alive
            self.conv.send(cbor.dumps(43))

class Subscribe1(Worker):
    message_type = Message.Subscribe1

    def __call__(self):
        # instance Bi MsgSubscribe1
        self.conv.send(cbor.dumps(42))

workers = [
    GetHeaders,
    GetBlocks,
    StreamBlocks,
    Subscribe,
    Subscribe1,
]

# Listeners
def handle_get_headers(node, conv):
    'Peer wants some block headers from us.'
    while True:
        data = conv.receive()
        if not data:
            print('remote closed')
            break
        print('request', cbor.loads(data))
        conv.send(cbor.dumps([0, []])) # NoHeaders

def handle_get_blocks(node, conv):
    'Peer wants some blocks from us.'
    data = cbor.loads(conv.receive())
    print('request', data)
    conv.send(cbor.dumps([1])) # NoBlock

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
    assert tag==0 and len(headers) == 1, 'invalid header message'
    header = DecodedBlockHeader(headers[0])
    print('got block header', binascii.hexlify(header.hash()))

    if not getattr(node, 'retriever', None):
        # it's just a demo node.
        return

    node.retriever.add_retrieval_task(conv.addr, header)

listeners = {
    Message.GetHeaders: handle_get_headers,
    #Message.GetBlocks: handle_get_blocks,
    #Message.Stream: handle_stream_start,
    Message.Headers: handle_headers,
}

class LogicNode(Node):
    def __init__(self, ep, store):
        super(LogicNode, self).__init__(ep, workers, listeners)
        self.store = store

        # start worker threads
        from .retrieve import BlockRetriever
        self.retriever = BlockRetriever(self.store, self)
        self.retriever_thread = gevent.spawn(self.retriever)

if __name__ == '__main__':
    from .transport import Transport
    from .storage import Storage
    from .config import MAINCHAIN_ADDR
    print('connecting')
    node = LogicNode(Transport().endpoint(), Storage('./test_db'))
    w = node.worker(Message.Subscribe, MAINCHAIN_ADDR)
    print('subscribe')
    w()
    w.keepalive()
