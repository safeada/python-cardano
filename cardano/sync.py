import binascii

from .storage import Storage
from .transport import Transport
from .node import Node, GetHeaders, GetBlocks

def sync(store, node, addr, genesis, genesis_prev):
    headers_worker = node.client(addr, GetHeaders)

    current_epoch = 0
    current_epoch_db = None

    print('get tip')
    hdr = headers_worker([], None)[0]
    network_tip = hdr.hash()

    while True:
        local_tip = store.tip()
        if not local_tip:
            # get genesis block.
            blk = node.client(addr, GetBlocks)(genesis, genesis)[0]
            assert blk.header().prev_header() == genesis_prev and blk.header().slot() == (0, None), 'invalid genesis block.'
            assert current_epoch_db == None, 'impossible'
            current_epoch_db = store.open_epoch_db(0)
            current_epoch_db.put(b'genesis', blk.header().hash())
            current_epoch_db.put(blk.header().hash(), blk.raw())
            current_epoch_db.put(b'tip', blk.header().hash())
            store.append_block(blk)
            continue

        if local_tip == network_tip:
            print('sync finished')
            break

        print('get headers')
        hdrs = list(headers_worker([local_tip], network_tip))
        print('get blocks')
        blocks = list(node.client(addr, GetBlocks)(hdrs[-1].hash(), hdrs[0].hash()))
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
            current_epoch_db.put(b'tip', hash) # update tip
            if slotid == None:
                # is genesis
                print('set genesis', current_epoch)
                current_epoch_db.put(b'genesis', hash)
            store.append_block(blk)
        print('finish', blk.header().slot())

if __name__ == '__main__':
    import sys
    store = Storage(sys.argv[1])
    node = Node(Transport().endpoint())
    genesis = binascii.unhexlify(b'89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4')
    genesis_prev = binascii.unhexlify(b'5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb')
    try:
        sync(store, node, 'relays.cardano-mainnet.iohk.io:3000:0', genesis, genesis_prev)
    finally:
        store = None
        import gc
        gc.collect()
