import click
from typing import TextIO
from .node_shim import ShimNode
from .brainfuck import Step, next_step, parse_tx, Address, Contract, uint8, Code
from remerkleable.tree import PairNode, RootNode, Node
import json
import sys


def encode_hex(v: bytes) -> str:
    return '0x' + v.hex()


def decode_hex(v: str) -> bytes:
    if v.startswith('0x'):
        v = v[2:]
    return bytes.fromhex(v)


@click.group()
def cli():
    """Optimistic Brainfuck - experiment to run brainfuck on an optimistic rollup on ethereum
    Contribute here: https://github.com/protolambda/optimistic-brainfuck
    """


# TODO: when to shut down the tracer, just in case of unexpected loop?
SANITY_LIMIT = 10000

# Enables us to save the contract with brainfuck characters, instead of more compressed form
def contract_parse_code(obj):
    obj['code'] = Code.from_pretty_str(obj['code']).to_obj()
    return obj

def contract_pretty_code(obj):
    obj['code'] = Code.from_obj(obj['code']).to_pretty_str()
    return obj


@cli.command()
@click.argument('state', type=click.File('wt'))
def init_state(state: TextIO):
    """Initialize STATE

    STATE path to world state, will be JSON
    """
    state.write(json.dumps({
        'contracts': {},  # 256 contract slots, starting with none
    }))


@cli.command()
@click.argument('input', type=click.File('rt'))
@click.argument('output', type=click.File('wt'))
@click.argument('sender', type=click.STRING)
@click.argument('tx', type=click.STRING)
def transition(input: TextIO, output: TextIO, sender: str, tx: str):
    """Transition full transaction TX, read INPUT state and write OUTPUT state

    INPUT file/input to current brainfuck world state, encoded in JSON

    OUTPUT where the updated state is written to

    SENDER sender address, 32 bytes, hex encoded and 0x prefix

    TX brainfuck tx payload
    """
    click.echo("decoding transaction: "+tx)
    tx_bytes = decode_hex(tx)

    state_parsed = json.loads(input.read())

    def get_contract(i: uint8) -> Contract:
        return Contract.from_obj(contract_parse_code(state_parsed['contracts'][str(i)]))

    click.echo("loading first step...")
    contract_id, step = parse_tx(Address(decode_hex(sender)), tx_bytes, get_contract)
    click.echo("selected brainfuck contract %d" % contract_id)

    click.echo("updating state by just generating and applying all fraud proof steps...")
    n = 0
    while True:
        click.echo("\rProcessing step %d" % n, nl=False)
        n += 1
        if n >= SANITY_LIMIT:
            raise Exception("Oh no! So many steps! What happened?")

        step = next_step(step)
        if step.result_code != 0xff:  # have we finished yet?
            break
    print()  # new line after \r loop

    if step.result_code == 0:
        click.echo("success transaction")
        # success, write back new contract state
        state_parsed['contracts'][str(contract_id)] = contract_pretty_code(step.contract.to_obj())
        output.write(json.dumps(state_parsed))
    else:
        click.echo("failed transaction, no state changes")


@cli.command()
@click.argument('state', type=click.File('rt'))
@click.argument('tx', type=click.STRING)
@click.argument('output', type=click.File('wt'))
def gen(output: TextIO, state: TextIO, tx: str):
    """Generate a fraud proof for the given transaction TX, applied on top of STATE

    STATE file/input to current brainfuck world state, encoded in JSON.

    TX brainfuck tx payload
    """

    click.echo("decoding transaction: "+tx)
    if tx.startswith("0x"):
        tx = tx[2:]
    tx_bytes = bytes.fromhex(tx)

    state_parsed = json.loads(state.read())

    def get_contract(i: uint8) -> Contract:
        return Contract.from_obj(contract_parse_code(state_parsed['contracts'][str(i)]))

    click.echo("loading first step...")
    contract_id, init_step = parse_tx(Address(tx_bytes[:20]), tx_bytes[20:], get_contract)

    click.echo("selected brainfuck contract %d" % contract_id)

    steps = [init_step]
    access_trace = []

    def reset_shims():
        for step in steps:
            backing: ShimNode = step.get_backing()
            backing.reset_shim()

    def capture_access(last: Step):
        shim: ShimNode = last.get_backing()
        access_list = list(shim.get_touched_gindices(g=1))
        access_trace.append(access_list)

    click.echo("running step by step proof generator...")
    n = 0
    while True:
        click.echo("\rProcessing step %d" % n, nl=False)
        n += 1

        if n >= SANITY_LIMIT:
            raise Exception("Oh no! So many steps! What happened?")

        reset_shims()
        last = steps[-1]
        next = next_step(last)
        capture_access(last)
        steps.append(next)
        if next.result_code != 0xff:  # have we finished yet?
            break
    print()  # new line after \r loop

    binary_nodes = dict()

    def store_tree(b: PairNode):
        left, right = b.get_left(), b.get_right()
        # The merkle-roots are cached, this is fine
        binary_nodes[encode_hex(b.merkle_root())] = [encode_hex(left.merkle_root()), encode_hex(right.merkle_root())]
        if not left.is_leaf():
            store_tree(left)
        if not right.is_leaf():
            store_tree(right)

    output.write(json.dumps({
        'nodes': binary_nodes,
        'step_roots': [encode_hex(step.hash_tree_root()) for step in steps],
        'access': [
            # not that this array is 1 shorter, the last step (post output) has no access data
            [encode_hex(gi.to_bytes(length=32, byteorder='big')) for gi in acc_li] for acc_li in access_trace
        ],
    }))

    click.echo("done!")


@cli.command()
@click.argument('input', type=click.File('rt'))
@click.argument('step', type=click.INT)
@click.argument('output', type=click.File('wt'))
def step_witness(input: TextIO, step: int, output: TextIO):
    """Compute the witness data for a single step by index, using the full trace witness"""
    obj = json.loads(input.read())

    nodes = obj['nodes']

    def retrieve_node_by_gindex(i: int, root: str) -> str:
        if i == 1:
            return root

        pivot = 1 << (i.bit_length() - 1)
        go_right = i & pivot != 0
        # mask out the top bit, and set the new top bit
        child = (i | pivot) - (pivot << 1)
        left, right = nodes[root]
        if go_right:
            return retrieve_node_by_gindex(child, right)
        else:
            return retrieve_node_by_gindex(child, left)

    root = obj['step_roots'][step]

    contents = {g: retrieve_node_by_gindex(int.from_bytes(bytes.fromhex(g[2:]), byteorder='big'), root)
                for g in obj['access'][step]}

    output.write(json.dumps({
        'node_by_gindex': contents,
        'root': obj['step_roots'][step],
        'step': step,
    }))


@cli.command()
@click.argument('input', type=click.File('rt'))
@click.argument('claimed_post_root', type=click.STRING)
def verify(input: TextIO, claimed_post_root: str):
    """Verify the execution of a step
    \f
    by providing the witness data and computing the step output

    CLAIMED_POST_ROOT   hex encoded, 0x prefixed, root of contract state
       that is expected after progressing one step further
    """
    obj = json.loads(input.read())

    click.echo('parsing fraud proof')

    # parse all gindices and node contents
    node_by_gindex = {
        int.from_bytes(decode_hex(g), byteorder='big'): decode_hex(node) for g, node in obj['node_by_gindex'].items()
    }

    # Take all those witness nodes by their position, and construct a tree that we can use as backing.
    # Any other node
    def construct_backing(g: int) -> Node:
        if g > 2**60:
            raise Exception("didn't expect backing branches this deep! witness data must be missing")
        if g not in node_by_gindex:
            left = construct_backing(g*2)
            right = construct_backing(g*2+1)
            return PairNode(left, right)
        else:
            return RootNode(node_by_gindex[g])

    # start at the root, find all sub-node
    partial_backing = construct_backing(1)

    click.echo('verifying fraud proof')

    pre = Step.view_from_backing(partial_backing)
    post = next_step(pre)

    expected_root = decode_hex(claimed_post_root)
    if post.result_code == 0:
        # success, state may have changed, check it
        got_root = post.contract.hash_tree_root()
        click.echo("transaction was effective, post contract root: "+encode_hex(got_root))

    else:
        # no success, check that we were expecting the pre-state root as output (i.e. no changes)
        got_root = post.contract.hash_tree_root()
        click.echo("transaction reverted, expecting pre-state contract root,"
                   " to indicate no change was made: "+encode_hex(got_root))
    if got_root != expected_root:
        click.echo("root did not match, fraud detected!")
        sys.exit(1)
    else:
        click.echo("root matches, no fraud")
        sys.exit(0)


if __name__ == '__main__':
    cli()
