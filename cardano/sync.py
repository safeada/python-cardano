import binascii

from .storage import Storage
from .transport import Transport
from .node import Node, GetHeaders, GetBlocks

def sync(store, node, addr, genesis):
    headers_worker = GetHeaders(node, addr)

    current_epoch = 0
    current_epoch_db = None

    print('get tip')
    hdr = next(headers_worker([], None))
    network_tip = hdr.hash()

    while True:
        local_tip = store.tip() or genesis

        print('get headers')
        hdrs = list(headers_worker([local_tip], network_tip))
        print('get blocks')
        blocks = list(GetBlocks(node, addr)(hdrs[-1].hash(), hdrs[0].hash()))
        assert blocks[0].header().prev_header() == local_tip, 'validate fail.'

        print('store blocks')
        for blk in blocks:
            hdr = blk.header()
            epoch, slotid = hdr.slot()
            hash = hdr.hash()
            if not current_epoch_db or epoch != current_epoch:
                current_epoch = epoch
                current_epoch_db = store.open_epoch_db(epoch)
            current_epoch_db.put(hash, blk.raw())
            if slotid == None:
                # is genesis
                print('set genesis', current_epoch)
                current_epoch_db.put(b'genesis', hash)
            store.append_block(blk)
        print('finish', blk.header().slot())

if __name__ == '__main__':
    store = Storage('./test_db')
    node = Node(Transport().endpoint())
    genesis = binascii.unhexlify(b'89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4')
    try:
        sync(store, node, 'relays.cardano-mainnet.iohk.io:3000:0', genesis)
    finally:
        store = None
        import gc
        gc.collect()
