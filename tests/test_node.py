import gevent
from cardano.transport import Transport
from cardano.node import default_node, Message


def test_simple():
    t1 = Transport(('127.0.0.1', 3000))
    t2 = Transport(('127.0.0.1', 3001))

    n1 = default_node(t1.endpoint())
    n2 = default_node(t2.endpoint())

    worker = n1.worker(Message.GetBlocks, n2.endpoint.addr)
    print(list(worker(b'test', b'test')))
    worker.close()

    print('second try')
    worker = n1.worker(Message.GetBlocks, n2.endpoint.addr)
    print(list(worker(b'test', b'test')))
    worker.close()

    t1.close()
    t2.close()


if __name__ == '__main__':
    test_simple()
    gevent.sleep(0.1)
