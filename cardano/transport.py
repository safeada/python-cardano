import os
import socket
from datetime import datetime
from typing import NamedTuple

import bitstruct
import cbor2

from .utils import recv_exact, send_many

HDR = bitstruct.compile("u32u1u15u16")


class Header(NamedTuple):
    time: int
    mode: bool
    mini_protocol_id: int
    length: int


def now_micros():
    return int(datetime.now().timestamp() * (10 ** 6)) & 0xFFFFFFFF


def test():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(os.environ["CARDANO_NODE_SOCKET_PATH"])
    # propose
    msg = cbor2.dumps([0, {5: [42, False]}])
    hdr = Header(
        time=now_micros(),
        mode=0,
        mini_protocol_id=0,  # handshake protocol id
        length=len(msg),
    )
    raw = HDR.pack(*hdr)
    print("sent", len(msg) + 8)
    send_many(sock, raw, msg)
    print("recv")
    raw = recv_exact(sock, 8)
    hdr = Header(*HDR.unpack(raw))
    print("recv header", hdr)
    msg = cbor2.loads(recv_exact(sock, hdr.length))
    print("recv msg", msg)


if __name__ == "__main__":
    test()
