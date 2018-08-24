'''
Support bidirectional conversation on unidirectional lightweight connections.
'''
import sys
import random
import struct
import enum

import cbor
import gevent
import gevent.event

from .transport import Event, RemoteEndPoint
from . import config


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
    TxInvData = 37      # InvOrData (Tagged TxMsgContents TxId) TxMsgContents
    TxReqRes = 94       # ReqOrRes (Tagged TxMsgContents TxId)


MessageSndRcv = {
    Message.GetHeaders: Message.Headers,
    Message.Headers: Message.GetHeaders,
    Message.GetBlocks: Message.Block,
    Message.Stream: Message.StreamBlock,
    Message.TxInvData: Message.TxReqRes,
    Message.TxReqRes: Message.TxInvData,
    Message.Subscribe: Message.Void,
    Message.Subscribe1: Message.Void,
}


def make_peer_data(workers, listeners):
    peer_data = [config.PROTOCOL_MAGIC, [0, 1, 0], {}, {}]
    for cls in workers:
        peer_data[3][cls.message_type] = [
            0,
            cbor.Tag(24, cbor.dumps(MessageSndRcv[cls.message_type]))]
    for msgtype in listeners.keys():
        peer_data[2][msgtype] = [0, cbor.Tag(24, cbor.dumps(MessageSndRcv[msgtype]))]
    return peer_data


class Conversation(object):
    'Bidirectional connection.'
    def __init__(self, node, conn, queue, addr):
        self._node = node
        self._conn = conn    # sending side.
        self._queue = queue  # receive message.
        self._addr = addr    # remote address.

    def __gc__(self):
        self.close()

    @property
    def peer_data(self):
        return self._node._peer_received[self._addr][0]

    @property
    def addr(self):
        return self._addr

    def send(self, data):
        self._conn.send(data)

    def receive(self, *args, **kwargs):
        o = self._queue.get(*args, **kwargs)
        if o == StopIteration:
            # closed by remote
            if self._conn.alive:
                self.close()
            self._queue = None
        else:
            return o

    def closed(self):
        return not self._conn.alive

    def close(self):
        'close our end.'
        if self.closed():
            return
        self._conn.close()
        remote = self._node._endpoint.valid_state._remotes[self._addr]
        if isinstance(remote.state, RemoteEndPoint.Closing) or \
                remote.valid_state.outgoing == 0:
            self._node._peer_sending.pop(self._addr)


class Node(object):
    def __init__(self, ep, workers, listeners):
        self._endpoint = ep
        self._workers = {cls.message_type: cls for cls in workers}
        self._listeners = listeners
        self._peer_data = make_peer_data(workers, listeners)

        # The first connect request send peer data, other concurrent requests need to wait
        # addr -> state (None | 'done' | Event)
        self._peer_sending = {}
        # Received peer_data, addr -> (peer_data, set of connid)
        self._peer_received = {}

        # Address of incoming connections, connid -> addr
        self._incoming_addr = {}
        # Incoming connections in handshaking, connid -> nonce
        self._incoming_nonce = {}
        # All incoming message queues, connid -> Queue
        self._incoming_queues = {}

        # Connector wait for message receive queue, (nonce, addr) -> AsyncResult
        self._wait_for_queue = {}

        self._next_nonce = random.randint(0, sys.maxsize)
        self._dispatcher_thread = gevent.spawn(self.dispatcher)

    @property
    def endpoint(self):
        return self._endpoint

    def gen_next_nonce(self):
        n = self._next_nonce
        self._next_nonce = (self._next_nonce + 1) % sys.maxsize
        return n

    def _connect_peer(self, addr):
        conn = self._endpoint.connect(addr)

        # Waiting for peer data to be transmitted.
        st = self._peer_sending.get(addr)
        if st == 'done':
            pass  # already done.
        elif st is None:
            # transmit and notify pending connections.
            print('sending our peer data')
            evt = gevent.event.Event()
            self._peer_sending[addr] = evt
            conn.send(cbor.dumps(self._peer_data, sort_keys=True))
            self._peer_sending[addr] = 'done'
            evt.set()
        else:
            assert isinstance(st, gevent.event.Event), 'invalid state: ' + str(st)
            st.wait()  # wait for peer data transmiting.
        return conn

    def connect(self, addr):
        conn = self._connect_peer(addr)

        # start handshake
        nonce = self.gen_next_nonce()
        conn.send(b'S' + struct.pack('>Q', nonce))

        # wait for ack and receiving queue.
        evt = gevent.event.AsyncResult()
        self._wait_for_queue[(nonce, addr)] = evt
        queue = evt.get()
        return Conversation(self, conn, queue, addr)

    def dispatcher(self):
        ep = self._endpoint
        while True:
            ev = ep.receive()
            tp = type(ev)
            if tp == Event.ConnectionOpened:
                assert ev.connid not in self._incoming_addr, 'duplicate connection id.'
                self._incoming_addr[ev.connid] = ev.addr
                if ev.addr in self._peer_received:
                    self._peer_received[ev.addr][1].add(ev.connid)
            elif tp == Event.Received:
                addr = self._incoming_addr[ev.connid]
                if addr not in self._peer_received:
                    # not received peerdata yet, assuming this is it.
                    print('received remote peer data')
                    self._peer_received[addr] = (cbor.loads(ev.data), set([ev.connid]))
                    continue

                nonce = self._incoming_nonce.get(ev.connid)
                if nonce is None:
                    direction = ev.data[:1]
                    nonce = struct.unpack('>Q', ev.data[1:])[0]
                    self._incoming_nonce[ev.connid] = nonce

                    queue = gevent.queue.Queue(32)
                    self._incoming_queues[ev.connid] = queue

                    if direction == b'A':
                        self._wait_for_queue.pop((nonce, addr)).set(queue)
                    elif direction == b'S':
                        gevent.spawn(self._handle_incoming, addr, nonce, queue)
                    else:
                        assert False, 'invalid request message.'
                else:
                    # normal data.
                    self._incoming_queues[ev.connid].put(ev.data)
            elif tp == Event.ConnectionClosed:
                addr = self._incoming_addr.pop(ev.connid)
                _, connset = self._peer_received[addr]
                connset.remove(ev.connid)
                if not connset:
                    self._peer_received.pop(addr)

                self._incoming_nonce.pop(ev.connid, None)
                queue = self._incoming_queues.pop(ev.connid, None)
                if queue:
                    # close the queue.
                    queue.put(StopIteration)
            else:
                print('unhandled event', ev)

    def _handle_incoming(self, addr, nonce, queue):
        # Will use the exist tcp connection.
        conn = self._connect_peer(addr)
        conn.send(b'A' + struct.pack('>Q', nonce))
        conv = Conversation(self, conn, queue, addr)

        # run listener.
        try:
            result = queue.get()
            if result != StopIteration:
                msgcode = cbor.loads(result)
                self._listeners[msgcode](self, conv)
        finally:
            conv.close()

    def worker(self, msgtype, addr):
        cls = self._workers[msgtype]
        assert cls.message_type == msgtype
        conv = self.connect(addr)
        if msgtype not in conv.peer_data[2]:
            # print('Remote peer don\'t support this message type.')
            return

        conv.send(cbor.dumps(msgtype))
        return cls(conv)


class Worker(object):
    def __init__(self, conv):
        self.conv = conv

    def close(self):
        self.conv.close()


def default_node(ep):
    from .logic import workers, listeners
    return Node(ep, workers, listeners)


if __name__ == '__main__':
    config.use('mainnet')
    from .transport import Transport
    node = default_node(Transport().endpoint())
    worker = node.worker(Message.Subscribe, config.CLUSTER_ADDR)
    # send subscribe
    worker()
    # keepalive loop
    worker.keepalive()
