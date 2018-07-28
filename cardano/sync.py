import binascii

from .storage import Storage
from .transport import Transport
from .node import default_node, Message
from .utils import flatten_slotid

def sync(store, node, addr, genesis, genesis_prev):
    headers_worker = node.worker(Message.GetHeaders, addr)

    current_epoch = 0
    current_epoch_db = None

    network_tip_header = headers_worker([], None)[0]
    network_tip = network_tip_header.hash()

    local_tip = store.tip()
    if not local_tip:
        # Empty database, init genesis block.
        blk = node.worker(Message.GetBlocks, addr)(genesis, genesis)[0]
        assert blk.header().prev_header() == genesis_prev and blk.header().slot() == (0, None), 'invalid genesis block.'
        assert current_epoch_db == None, 'impossible'
        current_epoch_db = store.open_epoch_db(0)
        current_epoch_db.put(b'genesis', blk.header().hash())
        current_epoch_db.put(blk.header().hash(), blk.raw())
        store.append_block(blk)
        local_tip_header = blk.header()
    else:
        local_tip_header = store.blockheader(local_tip)

    if local_tip == network_tip:
        print('Already synced.')
        return

    start_slotid = flatten_slotid(local_tip_header.slot())
    end_slotid = flatten_slotid(network_tip_header.slot())
    print('from', start_slotid, 'to', end_slotid)
    print('%.02f%%' % (start_slotid * 100 / end_slotid), end='\r')
    while True:
        local_tip = store.tip()
        if local_tip == network_tip:
            break

        hdrs = list(headers_worker([local_tip], network_tip))
        blocks = node.worker(Message.GetBlocks, addr)(hdrs[-1].hash(), hdrs[0].hash())
        for blk in blocks:
            hdr = blk.header()
            epoch, idx = hdr.slot()
            hash = hdr.hash()
            if not current_epoch_db or epoch != current_epoch:
                current_epoch = epoch
                current_epoch_db = store.open_epoch_db(epoch)
            current_epoch_db.put(hash, blk.raw())
            current_epoch_db.put(b'tip', hash) # update tip
            if idx == None:
                # genesis block
                current_epoch_db.put(b'genesis', hash)
            store.append_block(blk)

            current_slotid = flatten_slotid(hdr.slot())
            progress = current_slotid * 100 / end_slotid
            print('%.02f%%' % progress, end='\r')

    print('\nSync finished', blk.header().slot())

if __name__ == '__main__':
    import sys
    store = Storage(sys.argv[1])
    node = default_node(Transport().endpoint())
    genesis = binascii.unhexlify(b'89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4')
    genesis_prev = binascii.unhexlify(b'5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb')
    try:
        sync(store, node, 'relays.cardano-mainnet.iohk.io:3000:0', genesis, genesis_prev)
    finally:
        store = None
        import gc
        gc.collect()
