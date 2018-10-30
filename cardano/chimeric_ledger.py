from typing import NamedTuple, Union, List, Dict
from dataclasses import dataclass, field
from collections import defaultdict


Address = bytes
TxId = bytes

UTxOInput = NamedTuple('UTxOInput', [('txid', TxId), ('index', int)])
RedeemInput = NamedTuple('RedeemInput', [('addr', Address), ('value', int)])
Input = Union[UTxOInput, RedeemInput]

UTxOOutput = NamedTuple('UTxOOutput', [('addr', Address), ('value', int)])
DepositOutput = NamedTuple('DepositOutput', [('addr', Address), ('value', int)])
Output = Union[UTxOOutput, DepositOutput]

Tx = NamedTuple('Tx', [('txid', TxId),
                       ('inputs', List[Input]),
                       ('outputs', List[Output])])
UTxO = Dict[UTxOInput, UTxOOutput]


class TxValidationError(Exception):
    pass


@dataclass
class State:
    utxo: UTxO = field(default_factory=dict)
    balances: Dict[Address, int] = field(default_factory=lambda: defaultdict(int))

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
                input_sum += self.balances[input.addr]
            else:
                raise TxValidationError('unknown input type: {0}'.format(type(input)))

        if sum(output.value for output in tx.outputs) > input_sum:
            raise TxValidationError('output value is bigger than input')

    def process_tx(self, tx: Tx, validate: bool=False):
        if validate:
            self.validate_tx(tx)

        for input in tx.inputs:
            if isinstance(input, UTxOInput):
                del self.utxo[input]
            elif isinstance(input, RedeemInput):
                assert self.balances.get(input.addr, 0) >= input.value
                self.balances[input.addr] -= input.value
            else:
                raise NotImplemented

        for index, output in enumerate(tx.outputs):
            if isinstance(output, UTxOOutput):
                self.utxo[UTxOInput(tx.txid, index)] = output
            elif isinstance(output, DepositOutput):
                self.balances[output.addr] += output.value
            else:
                raise NotImplemented(type(output))

    def get_balance(self, addr: Address):
        return self.balances.get(addr, 0) + \
            sum(output.value
                for output in self.utxo.values()
                if output.addr == addr)


if __name__ == '__main__':
    genesis_tx = Tx(b'genesis',
                    [],
                    [UTxOOutput(b'addr1', 100),
                     UTxOOutput(b'addr2', 100)])
    s = State()
    s.process_tx(genesis_tx, False)
    assert s.get_balance(b'addr1') == 100
    s.process_tx(Tx(b'tx1',
                    [UTxOInput(b'genesis', 1)],
                    [DepositOutput(b'addr1', 100)]))
    assert s.get_balance(b'addr1') == 200
