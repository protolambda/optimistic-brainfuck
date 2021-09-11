from enum import IntEnum
from typing import TypeVar, Type, Callable
from remerkleable.complex import Container, List
from remerkleable.basic import uint64, uint32, uint8
from remerkleable.bitfields import Bitlist
from remerkleable.byte_arrays import ByteVector


class Address(ByteVector[20]):
    pass


# Brainfuck rules in rollup TLDR:
#
# bits  brainfuck   meaning
# 000   > 	        Move the pointer to the right
# 001   < 	        Move the pointer to the left
# 010   + 	        Increment the memory cell at the pointer
# 011   - 	        Decrement the memory cell at the pointer
# 100   . 	        Output the character signified by the cell at the pointer
# 101   , 	        Input a character and store it in the cell at the pointer
# 110   [ 	        Jump past the matching ] if the cell at the pointer is 0
# 111   ] 	        Jump back to the matching [ if the cell at the pointer is nonzero
#
# State:
#   - There are 256 brainfuck contract slots
#   - Contracts can only be created via a L1 deposit, with a fee
#   - Memory cells and pointer are persisted per contract, essentially cheap and easy to navigate storage
#   - Regular transactions are input data to the contract specified by the transaction, it's up to the contract to read and process it
#   - The l1 sender is always put in the first 20 input bytes, so the contract can trust the user
#   - Contract program counter always starts at 0
#   - Execution stops as soon as the contract outputs a 0 (success, changes are persisted) or a 1 (reverts to pre-state memory and ptr).
#     Other outputs are ignored (todo: can use this instead to implement log events).
#
# Gas: a transaction gets 1000 + 128 times the gas of its payload length, to loop around and stuff.
# 1 gas is 1 brainfuck opcode. No gas is returned on exit.
# TODO: can we afford this in terms of DoS?

GAS_FREE_STIPEND = 1000
L1_CALLDATA_TO_L2_GAS_MULTIPLIER = 128

# 64 KiB per transaction
MAX_CODE_SIZE = 64 * 1024

# Note: we fail transactions that go out of bounds, we do not wrap around
# 128 KiB memory per transaction
MAX_CELL_COUNT = 128 * 1024

# 64 KiB per payload
MAX_PAYLOAD_DATA = 64 * 1024

# maximum amount of yet unmatched '[' at any time
MAX_STACK_DEPTH = 1024

MAX_CONTRACTS = 256

brainfuck_chars = ['>', '<', '+', '-', '.', ',', '[', ']']

class ExitCodes(IntEnum):
    OK = 0
    StackOverflow = 1
    StackUnderflow = 2
    NegativePtr = 3
    PtrTooHigh = 4
    OutOfGas = 5


class OpCode(IntEnum):
    MOVE_RIGHT = 0b000
    MOVE_LEFT = 0b001
    INCR_CELL = 0b010
    DECR_CELL = 0b011
    GET_CELL = 0b100
    PUT_CELL = 0b101
    JUMP_COND = 0b110
    JUMP_BACK = 0b111

    def character(self) -> str:
        return brainfuck_chars[self]

    def __str__(self):
        return self.character()


V = TypeVar('V')


# 3 bits per brainfuck opcode, utilize all that data!
class Code(Bitlist[MAX_CODE_SIZE]):
    @classmethod
    def from_pretty_str(cls: Type[V], v: str) -> V:
        ops = [brainfuck_chars.index(c) for c in v]
        bits = []
        for op in ops:
            for j in range(2, -1, -1):
                bits.append(op & (1 << j) != 0)
        return cls(bits)

    def to_pretty_str(self) -> str:
        bits = list(self)  # faster
        ops = [((int(bits[j]) << 2) | (int(bits[j+1]) << 1) | int(bits[j+2])) for j in range(0, len(bits), 3)]
        return ''.join(brainfuck_chars[op] for op in ops)

    def op_count(self) -> uint32:
        return len(self) // 3

    def get_op(self, i: uint32) -> OpCode:
        i *= 3
        a, b, c = self[i], self[i + 1], self[i + 2]
        op = (int(a) << 2) | (int(b) << 1) | int(c)
        return OpCode(op)


class Cells(List[uint8, MAX_CELL_COUNT]):
    pass


class PayloadData(List[uint8, MAX_PAYLOAD_DATA]):
    pass


class Contract(Container):
    code: Code
    cells: Cells
    ptr: uint32
    # the pc is always reset to 0 in each transaction


class Step(Container):
    # a transaction spends gas, to constrain computation (infinite loops)
    # gas is "free", just based on L1 calldata cost
    gas: uint64

    # Program counter, pointing to current op code
    pc: uint32
    # keeps track of the pc of every past opening bracket '[', to return to later
    stack: List[uint32, MAX_STACK_DEPTH]
    # any opcode, except [ and ] is ignored until this indent is back to 0
    indent: uint32

    contract: Contract

    input_read: uint32
    input_data: PayloadData

    result_code: uint8


def parse_tx(contract: Contract, sender: Address, payload: bytes) -> Step:
    gas = uint64(GAS_FREE_STIPEND + len(payload) * L1_CALLDATA_TO_L2_GAS_MULTIPLIER)
    return Step(
        gas=gas,
        pc=0,
        stack=[],
        contract=contract,
        input_read=0,
        input_data=PayloadData(list(sender)+list(payload)),
        result_code=0xff,  # unused value to start with, either 0 or 1 at the end
    )


def next_step(last: Step) -> Step:
    next = last.copy()
    pc = last.pc

    size = last.contract.code.op_count()
    if pc >= size:
        next.result_code = ExitCodes.OK
        return next

    # count 1 gas for this operation
    if last.gas == 0:
        next.result_code = ExitCodes.OutOfGas
        return next

    next.gas -= 1

    # run the operation
    op = last.contract.code.get_op(pc)

    # print("----")
    # print("op", op)
    # print("ptr", last.contract.ptr)
    # print("stack", list(last.stack))
    # print("cells", list(last.contract.cells))
    # print("indent", last.indent)

    if last.indent > 0:
        if op == OpCode.JUMP_COND:
            if last.indent > MAX_STACK_DEPTH:
                next.result_code = ExitCodes.StackOverflow
                return next
            next.indent += 1
            next.pc += 1
            return next
        elif op == OpCode.JUMP_BACK:
            next.indent -= 1
            next.pc += 1
            return next
        else:
            next.pc += 1
            return next

    if op == OpCode.MOVE_RIGHT:
        if last.contract.ptr < MAX_CELL_COUNT - 1:
            if last.contract.ptr + 1 >= len(last.contract.cells):  # dynamically grow the cells data
                next.contract.cells.append(uint8(0))
            next.contract.ptr += 1
            next.pc += 1
            return next
        else:
            next.result_code = ExitCodes.PtrTooHigh
            return next
    elif op == OpCode.MOVE_LEFT:
        if last.contract.ptr != 0:
            next.contract.ptr -= 1
            next.pc += 1
            return next
        else:
            next.result_code = ExitCodes.NegativePtr
            return next
    elif op == OpCode.INCR_CELL:
        cell_value = last.contract.cells[last.contract.ptr]
        next.contract.cells[last.contract.ptr] = (int(cell_value) + 1) % 256  # we want over/underflow here
        next.pc += 1
        return next
    elif op == OpCode.DECR_CELL:
        cell_value = last.contract.cells[last.contract.ptr]
        next.contract.cells[last.contract.ptr] = (int(cell_value) + 256 - 1) % 256  # we want over/underflow here
        next.pc += 1
        return next
    elif op == OpCode.GET_CELL:
        cell_value = last.contract.cells[last.contract.ptr]
        if cell_value == 0 or cell_value == 1:
            next.result_code = cell_value
            return next
        else:
            # ignore the value, continue
            next.pc += 1
            return next
    elif op == OpCode.PUT_CELL:
        if last.input_read < len(last.input_data):
            new_cell_value = last.input_data[last.input_read]
        else:
            new_cell_value = 0
        next.contract.cells[last.contract.ptr] = new_cell_value
        next.input_read += 1
        next.pc += 1
        return next
    elif op == OpCode.JUMP_COND:
        cell_value = last.contract.cells[last.contract.ptr]
        if cell_value == 0:
            # we want to skip to matching ], we do this by tracking indentation
            next.pc += 1
            next.indent += 1
            return next
        else:
            if len(last.stack) == MAX_STACK_DEPTH:
                next.result_code = ExitCodes.StackOverflow
                return next
            next.stack.append(pc)
            next.pc += 1
            return next
    elif op == OpCode.JUMP_BACK:
        if len(last.stack) == 0:
            next.result_code = ExitCodes.StackUnderflow
            return next
        back_pc = last.stack[len(last.stack) - 1]
        next.stack.pop()
        next.pc = back_pc
        return next
    else:
        raise Exception(f"opcode parsing broken, unrecognized op: {op}")
