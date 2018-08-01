'''
Logic includes workers and listeners.
'''
import binascii

import gevent
import cbor

from .block import DecodedBlockHeader, DecodedBlock
from .node import Worker, Message
from .utils import get_current_slot

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
        while True:
            gevent.sleep(20)
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
# listeners
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

def classify_new_header(tip_header, hdr):
    current_slot = get_current_slot()
    hdr_slot = hdr.slot()
    if hdr_slot[1] == None:
        # genesis block
        print('new header is genesis block')
        return # useless
    if hdr_slot > current_slot:
        print('new header is for future slot')
        return # future slot
    if hdr_slot <= tip_header:
        print('new header slot smaller then tip')

    if hdr_slot.prev_header() == tip_header.hash():
        # TODO verify
        return True # means is's a continue.
    else:
        # check difficulty
        if hdr_slot.difficulty() > tip_header.difficulty():
            # longer alternative chain.
            return False

def handle_headers(node, conv):
    'Peer has a block header for us (yes, singular only).'
    data = conv.receive()
    if not data:
        print('remote closed')
        return
    tag, headers = cbor.loads(data)
    assert tag==0 and len(headers) == 1, 'invalid header message'
    hdr = DecodedBlockHeader(headers[0])
    print('got block header', binascii.hexlify(hdr.hash()))

    # need to send to block retrieve logic.
    #store = node.resource.storage
    #tip_header = store.blockheader(store.tip())
    #classify_new_header(tip_header, hdr)

listeners = {
    Message.GetHeaders: handle_get_headers,
    #Message.GetBlocks: handle_get_blocks,
    #Message.Stream: handle_stream_start,
    Message.Headers: handle_headers,
}

# tests
def poll_tip(addr):
    node = default_node(Transport().endpoint())
    headers_client = node.worker(Message.GetHeaders, addr)
    current = None
    while True:
        # get tip
        tip = headers_client([], None)[0]
        h = tip.hash()
        if h != current:
            for b in node.worker(Message.GetBlocks, addr)(current or h, h):
                hdr = b.header()
                h = hdr.hash()
                if h == current:
                    continue
                print('new block', hdr.slot())
                txs = b.transactions()
                if txs:
                    print('transactions:')
                    for tx in txs:
                        print(binascii.hexlify(tx.hash()).decode())
                else:
                    print('no transactions')
            current = h

        gevent.sleep(20)

def get_all_headers(addr, genesis):
    node = Node(Transport().endpoint())

    headers_client = node.client(addr, GetHeaders)
    tip = headers_client([], None)[0]

    current = None
    print('tip', binascii.hexlify(tip.hash()), binascii.hexlify(tip.prev_header()))
    headers = headers_client([genesis], tip.hash())
    print('validate headers')
    for hdr in headers:
        print(binascii.hexlify(hdr.hash()), binascii.hexlify(hdr.prev_header()))
        if current:
            assert hdr.hash() == current, 'invalid chain'
            current = hdr.prev_header()
    assert current == genesis

def test_stream_block(addr, genesis):
    node = Node(Transport().endpoint())
    tip = node.client(addr, GetHeaders)([], None)[0]
    client = node.client(addr, StreamBlocks)
    assert client, 'Peer don\'t support stream blocks.'
    for blk in client.start([genesis], tip.hash(), 10):
        print(blk.header().slot())

