'''
Support bidirectional conversation on unidirectional lightweight connections.
'''
import sys
import random
import struct
import binascii
import enum

import cbor
import gevent
import gevent.event

from .transport import Transport, ControlHeader, Event
from .block import DecodedBlockHeader, DecodedBlock

PROTOCOL_MAGIC = 764824073

class Message(enum.IntEnum):
    Void = 0
    GetHeaders = 4
    Headers = 5
    GetBlocks = 6
    Block = 7
    Subscribe1 = 13
    Subscribe = 14
    Stream = 15
    StreamBlock = 16

DEFAULT_PEER_DATA = [
    PROTOCOL_MAGIC, # protocol magic.
    [0,1,0],   # version
    { # in handlers
        Message.GetHeaders:     [0, cbor.Tag(24, cbor.dumps(Message.Headers))],
        Message.Headers:        [0, cbor.Tag(24, cbor.dumps(Message.GetHeaders))],
        Message.GetBlocks:      [0, cbor.Tag(24, cbor.dumps(Message.Block))],
        0x22:  [0, cbor.Tag(24, cbor.dumps(0x5e))],
        0x25:  [0, cbor.Tag(24, cbor.dumps(0x5e))],
        0x2b:  [0, cbor.Tag(24, cbor.dumps(0x5d))],
        0x31:  [0, cbor.Tag(24, cbor.dumps(0x5c))],
        0x37:  [0, cbor.Tag(24, cbor.dumps(0x62))],
        0x3d:  [0, cbor.Tag(24, cbor.dumps(0x61))],
        0x43:  [0, cbor.Tag(24, cbor.dumps(0x60))],
        0x49:  [0, cbor.Tag(24, cbor.dumps(0x5f))],
        0x53:  [0, cbor.Tag(24, cbor.dumps(0x00))],
        0x5c:  [0, cbor.Tag(24, cbor.dumps(0x31))],
        0x5d:  [0, cbor.Tag(24, cbor.dumps(0x2b))],
        0x5e:  [0, cbor.Tag(24, cbor.dumps(0x25))],
        0x5f:  [0, cbor.Tag(24, cbor.dumps(0x49))],
        0x60:  [0, cbor.Tag(24, cbor.dumps(0x43))],
        0x61:  [0, cbor.Tag(24, cbor.dumps(0x3d))],
        0x62:  [0, cbor.Tag(24, cbor.dumps(0x37))],
    },
    { # out handlers
        Message.GetHeaders:     [0, cbor.Tag(24, cbor.dumps(Message.Headers))],
        Message.Headers:        [0, cbor.Tag(24, cbor.dumps(Message.GetHeaders))],
        Message.GetBlocks:      [0, cbor.Tag(24, cbor.dumps(Message.Block))],
        0x0d:  [0, cbor.Tag(24, cbor.dumps(0x00))],
        0x0e:  [0, cbor.Tag(24, cbor.dumps(0x00))],
        0x25:  [0, cbor.Tag(24, cbor.dumps(0x5e))],
        0x2b:  [0, cbor.Tag(24, cbor.dumps(0x5d))],
        0x31:  [0, cbor.Tag(24, cbor.dumps(0x5c))],
        0x37:  [0, cbor.Tag(24, cbor.dumps(0x62))],
        0x3d:  [0, cbor.Tag(24, cbor.dumps(0x61))],
        0x43:  [0, cbor.Tag(24, cbor.dumps(0x60))],
        0x49:  [0, cbor.Tag(24, cbor.dumps(0x5f))],
        0x53:  [0, cbor.Tag(24, cbor.dumps(0x00))],
    },
]

class Conversation(object):
    'Bidirectional connection.'
    def __init__(self, id, conn):
        self._id = id
        self._conn = conn # client unidirectional lightweight connection.
        self._queue = gevent.queue.Queue(maxsize=128)
        self._evt_handshake = gevent.event.Event()

    def __gc__(self):
        self.close()

    @property
    def id(self):
        return self._id

    def send(self, data):
        self._conn.send(data)

    def receive(self, *args):
        o = self._queue.get(*args)
        if o != StopIteration:
            return o

        # closed.
        self._queue = None

    def closed(self):
        return self._conn.alive

    def close(self):
        'close by us.'
        self._conn.close()

    def on_close(self):
        'close by remote.'
        if self._conn.alive:
            self._conn.close()
        self._queue.put(StopIteration)

class Node(object):
    def __init__(self, ep):
        self._endpoint = ep
        self._peer_sending = {} # addr -> state (None | done | evt)
        self._peer_received = {} # addr -> state

        self._conversations = {} # (nonce, addr) -> Conversation
        self._server_conns = {} # connid -> None | nonce

        self._next_nonce = random.randint(0, sys.maxsize)

        self._dispatcher_thread = gevent.spawn(self.dispatcher)

    def gen_next_nonce(self):
        n = self._next_nonce
        self._next_nonce = (self._next_nonce + 1) % sys.maxsize
        return n

    def connect(self, addr):
        conn = self._endpoint.connect(addr)

        # Waiting for peer data to be transmitted.
        st = self._peer_sending.get(addr)
        if st == 'done':
            pass # already done.
        elif st == None:
            # transmit and notify pending connections.
            evt = gevent.event.Event()
            self._peer_sending[addr] = evt
            conn.send(cbor.dumps(DEFAULT_PEER_DATA, True))
            self._peer_sending[addr] = 'done'
            evt.set()
        else:
            assert isinstance(st, gevent.event.Event), 'invalid state: ' + str(st)
            st.wait() # wait for peer data transmiting.

        nonce = self.gen_next_nonce()
        conn.send(b'S' + struct.pack('>Q', nonce))
        conv = Conversation((nonce, addr), conn)
        self._conversations[(nonce, addr)] = conv
        conv._evt_handshake.wait()
        return conv

    def dispatcher(self):
        ep = self._endpoint
        while True:
            ev = ep.receive()
            tp = type(ev)
            if tp == Event.ConnectionOpened:
                assert ev.connid not in self._server_conns, 'duplicate connection id.'
                # TODO waiting for peer data.
                self._server_conns[ev.connid] = (None, ev.addr)
            elif tp == Event.Received:
                nonce, addr = self._server_conns[ev.connid]
                if addr not in self._peer_received:
                    # not received peerdata yet, assuming this is it.
                    self._peer_received[addr] = cbor.loads(ev.data)
                    continue
                if nonce == None:
                    assert ev.data[:1] == b'A', 'dont support listeners yet.'
                    nonce = struct.unpack('>Q', ev.data[1:])[0]
                    self._server_conns[ev.connid] = (nonce, addr)
                    self._conversations[(nonce, addr)]._evt_handshake.set()
                else:
                    # normal data.
                    self._conversations[(nonce, addr)]._queue.put(ev.data)
            elif tp == Event.ConnectionClosed:
                nonce, addr = self._server_conns.pop(ev.connid)
                conv = self._conversations.pop((nonce, addr))
                conv.on_close()
            else:
                print('unhandled event', ev)

class Worker(object):
    def __init__(self, node, addr):
        conv = node.connect(addr)
        self.conv = conv
        conv.send(cbor.dumps(self.message_type))

    def close(self):
        self.conv.close()

class GetHeaders(Worker):
    message_type = Message.GetHeaders

    def __call__(self, from_, to):
        self.conv.send(cbor.dumps([cbor.VarList(from_), [to] if to else []]))
        tag, data = cbor.loads(self.conv.receive()) # sum type MsgHeaders
        assert tag == 0, 'no headers'
        return [DecodedBlockHeader(item) for item in data]

class GetBlocks(Worker):
    message_type = Message.GetBlocks

    def __call__(self, from_, to):
        self.conv.send(cbor.dumps([from_, to]))
        result = []
        while True:
            buf = self.conv.receive()
            if not buf:
                # closed by remote.
                break
            tag, data = cbor.loads(buf) # \x82, \x00, block_raw_data
            if tag == 0: # MsgBlock
                result.append(DecodedBlock(data, buf[2:]))
        return result

def poll_tip(addr):
    node = Node(Transport().endpoint())

    headers_worker = GetHeaders(node, addr)
    current = None
    while True:
        # get tip
        tip = headers_worker([], None)[0]
        h = tip.hash()
        if h != current:
            for b in GetBlocks(node, addr)(current or h, h):
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

    headers_worker = GetHeaders(node, addr)
    tip = headers_worker([], None)[0]

    print('tip', binascii.hexlify(tip.hash()), binascii.hexlify(tip.prev_header()))
    headers = headers_worker([genesis], tip.hash())
    print('validate headers')
    current = None
    for hdr in headers:
        print(binascii.hexlify(hdr.hash()), binascii.hexlify(hdr.prev_header()))
        if current:
            assert hdr.hash() == current, 'invalid chain'
            current = hdr.prev_header()
    assert current == genesis

if __name__ == '__main__':
    addr = 'relays.cardano-mainnet.iohk.io:3000:0'
    poll_tip(addr)

    #genesis = binascii.unhexlify(b'89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4'),
    #get_all_headers(addr, genesis)
