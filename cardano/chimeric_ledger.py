import hashlib
from typing import Hashable, NamedTuple, Union, List, Dict
from dataclasses import dataclass, field
from collections import defaultdict

'''
Proof-of-Concept implementation of merging utxo and account model.
'''

Address = Hashable
TxId = Hashable
ContractCode = bytes


class UTxOInput(NamedTuple):
    txid: TxId
    index: int


class RedeemInput(NamedTuple):
    addr: Address
    value: int


Input = Union[UTxOInput, RedeemInput]


class UTxOOutput(NamedTuple):
    addr: Address
    value: int


class DepositOutput(NamedTuple):
    addr: Address
    value: int
    data: bytes = None


Output = Union[UTxOOutput, DepositOutput]


class Tx(NamedTuple):
    txid: TxId
    inputs: List[Input]
    outputs: List[Output]


UTxO = Dict[UTxOInput, UTxOOutput]


class TxValidationError(Exception):
    pass


@dataclass
class State:
    utxo: UTxO = field(default_factory=dict)
    balances: Dict[Address, int] = field(default_factory=lambda: defaultdict(int))
    contracts: Dict[Address, ContractCode] = field(default_factory=dict)
    storages: Dict[Address, dict] = field(default_factory=lambda: defaultdict(dict))
    receipts: Dict[TxId, list] = field(default_factory=lambda: defaultdict(list))
    nonces: Dict[Address, int] = field(default_factory=lambda: defaultdict(int))

    def gen_contract_addr(self, sender):
        nonce = self.nonces[sender]
        self.nonces[sender] = nonce + 1
        h = hash((sender, nonce)).to_bytes(8, 'big', signed=True)
        return hashlib.sha224(h).hexdigest()

    def validate_tx(self, tx: Tx):
        input_sum = 0
        for input in tx.inputs:
            if isinstance(input, UTxOInput):
                try:
                    input_sum += self.utxo[input].value
                except KeyError:
                    raise TxValidationError('utxo input not exist.')
            elif isinstance(input, RedeemInput):
                if input.value > self.balances.get(input.addr, 0):
                    raise TxValidationError('redeem input not enough balance.')
                input_sum += input.value
            else:
                raise TxValidationError('unknown input type: {0}'.format(type(input)))

        if sum(output.value for output in tx.outputs) > input_sum:
            raise TxValidationError('output value is bigger than input')

    def apply_tx(self, tx: Tx, validate: bool=True):
        if validate:
            self.validate_tx(tx)

        sender: Address = None
        for input in tx.inputs:
            if isinstance(input, UTxOInput):
                sender = self.utxo.pop(input).addr
            elif isinstance(input, RedeemInput):
                assert self.balances.get(input.addr, 0) >= input.value
                self.balances[input.addr] -= input.value
                sender = input.addr
            else:
                raise NotImplemented

        for index, output in enumerate(tx.outputs):
            if isinstance(output, UTxOOutput):
                self.utxo[UTxOInput(tx.txid, index)] = output
            elif isinstance(output, DepositOutput):
                if not output.addr:
                    # contract creation.
                    addr = self.gen_contract_addr(sender)
                    self.contracts[addr] = output.data
                    self.receipts[tx.txid].append(('create contract', addr))
                else:
                    if output.addr in self.contracts:
                        # contract execution.
                        self.execute_contract(output, tx)
                    else:
                        self.balances[output.addr] += output.value
            else:
                raise NotImplemented(type(output))

    def rollback_tx(self, tx: Tx, undo):
        # TODO
        pass

    def get_balance(self, addr: Address):
        return self.balances.get(addr, 0) + \
            sum(output.value
                for output in self.utxo.values()
                if output.addr == addr)

    def execute_contract(self, output, tx):
        code = self.contracts[output.addr]
        print('execute contract', code, output.value, output.data)


if __name__ == '__main__':
    genesis_tx = Tx(b'genesis',
                    [],
                    [UTxOOutput(b'addr1', 100),
                     UTxOOutput(b'addr2', 100)])
    s = State()
    s.apply_tx(genesis_tx, False)
    assert s.get_balance(b'addr1') == 100
    s.apply_tx(Tx(b'tx1',
                  [UTxOInput(b'genesis', 1)],
                  [DepositOutput(b'addr1', 100)]))
    assert s.get_balance(b'addr1') == 200

    # create contract
    s.apply_tx(Tx(b'tx2',
                  [RedeemInput(b'addr1', 10)],
                  [DepositOutput(None, 10, 'contract1')]))
    contract = s.receipts[b'tx2'][0][1]
    print('contract created', contract)

    s.apply_tx(Tx(b'tx3',
                  [RedeemInput(b'addr1', 10)],
                  [DepositOutput(contract, 10, 'call signature')]))
