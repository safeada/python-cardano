import gevent
from cardano.node import Transport, default_node, Message

def test_simple():
    n1 = default_node(Transport(('127.0.0.1', 3000)).endpoint())
    n2 = default_node(Transport(('127.0.0.1', 3001)).endpoint())

    worker = n1.worker(Message.GetHeaders, n2.endpoint.addr)
    print(worker([], None))
    worker.close()
    gevent.sleep(1)

if __name__ == '__main__':
    test_simple()
