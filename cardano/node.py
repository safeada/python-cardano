'''
Support bidirectional conversation on unidirectional lightweight connections.
'''
import sys
import random
import struct

import cbor
import gevent
import gevent.event

from .transport import Transport, ControlHeader, Event

DEFAULT_PEER_DATA = [
    764824073, # protocol magic.
    [0,1,0],   # version
    {
        0x04:  [0, cbor.Tag(24, cbor.dumps(0x05))],
        0x05:  [0, cbor.Tag(24, cbor.dumps(0x04))],
        0x06:  [0, cbor.Tag(24, cbor.dumps(0x07))],
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
    {
        0x04:  [0, cbor.Tag(24, cbor.dumps(0x05))],
        0x05:  [0, cbor.Tag(24, cbor.dumps(0x04))],
        0x06:  [0, cbor.Tag(24, cbor.dumps(0x07))],
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

MAX_INT32 = 2**31

class Conversation(object):
    'Bidirectional connection.'
    def __init__(self, id, conn):
        self._id = id
        self._conn = conn # client unidirectional lightweight connection.
        self._queue = gevent.queue.Queue(maxsize=128)
        self._evt_handshake = gevent.event.Event()

    @property
    def id(self):
        return self._id

    def send(self, data):
        self._conn.send(data)

    def receive(self, *args):
        return self._queue.get(*args)

    def close(self):
        pass

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
                    assert ev.data[:1] == b'A', 'dont support server function.'
                    nonce = struct.unpack('>Q', ev.data[1:])[0]
                    self._server_conns[ev.connid] = (nonce, addr)
                    self._conversations[(nonce, addr)]._evt_handshake.set()
                else:
                    # normal data.
                    self._conversations[(nonce, addr)]._queue.put(ev.data)
            else:
                print('unhandled event', ev)

def get_tip(conv):
    # send get_tip message
    conv.send(b'\x04')
    conv.send(
        b'\x82' +               # [
        b'\x9f\xff' +           # [] variable length.
        b'\x80'                 # []
    )
    return cbor.loads(conv.receive())

if __name__ == '__main__':
    node = Node(Transport().endpoint())
    print('connect')
    conv = node.connect('relays.cardano-mainnet.iohk.io:3000:0')
    print('get tip', get_tip(conv))
