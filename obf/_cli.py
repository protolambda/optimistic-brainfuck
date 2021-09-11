import click
from typing import TextIO
from .node_shim import ShimNode
from .brainfuck import Step, next_step, parse_tx, Address, Contract, ExitCodes, Code
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
        "contracts": {
            "0": {
                "code": ",,,,,,,,,,,,,,,,,,,,,[>+++++++<-]",  # skips the 20 byte address, and then multiplies the first input byte with 7, and stores result in second cell
                "ptr": 0,
                "cells": [0]
            }
        },  # 256 contract slots, starting with none
    }, indent='  '))


@cli.command()
@click.argument('input', type=click.File('rt'))
@click.argument('output', type=click.File('wt'))
@click.argument('sender', type=click.STRING)
@click.argument('contract', type=click.INT)
@click.argument('tx', type=click.STRING)
def transition(input: TextIO, output: TextIO, sender: str, contract: int, tx: str):
    """Transition full transaction TX, read INPUT state and write OUTPUT state

    INPUT file/input to current brainfuck world state, encoded in JSON

    OUTPUT where the updated state is written to

    SENDER sender address, 20 bytes, hex encoded and 0x prefix

    CONTRACT the ID (one byte) to call

    TX brainfuck tx payload
    """
    click.echo("decoding transaction: "+tx)
    tx_bytes = decode_hex(tx)

    state_parsed = json.loads(input.read())

    contract_inst = Contract.from_obj(contract_parse_code(state_parsed['contracts'][str(contract)]))

    click.echo("loading first step...")
    step = parse_tx(contract_inst, Address(decode_hex(sender)), tx_bytes)
    click.echo("selected brainfuck contract %d" % contract)

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
        state_parsed['contracts'][str(contract)] = contract_pretty_code(step.contract.to_obj())
        output.write(json.dumps(state_parsed, indent='  '))
    else:
        click.echo(f"failed transaction, no state changes, exit code: {str(ExitCodes(step.result_code))}")


@cli.command()
@click.argument('state', type=click.File('rt'))
@click.argument('output', type=click.File('wt'))
@click.argument('sender', type=click.STRING)
@click.argument('contract', type=click.INT)
@click.argument('tx', type=click.STRING)
def gen(state: TextIO, output: TextIO, sender: str, contract: int, tx: str):
    """Generate a fraud proof for the given transaction TX, applied on top of STATE

    STATE file/input to current brainfuck world state, encoded in JSON.

    OUTPUT the file/output to write the proof to.

    SENDER sender address, 20 bytes, hex encoded and 0x prefix

    CONTRACT the ID (one byte) to call

    TX brainfuck tx payload
    """

    click.echo("decoding transaction: "+tx)
    if tx.startswith("0x"):
        tx = tx[2:]
    tx_bytes = bytes.fromhex(tx)

    state_parsed = json.loads(state.read())

    contract_inst = Contract.from_obj(contract_parse_code(state_parsed['contracts'][str(contract)]))

    click.echo("loading first step...")
    init_step = parse_tx(contract_inst, Address(decode_hex(sender)), tx_bytes)

    click.echo("selected brainfuck contract %d" % contract)

    steps = [Step(backing=ShimNode.shim(init_step.get_backing()))]
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
        steps.append(Step(backing=ShimNode.shim(next.get_backing())))
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

    # store all data relevant to all steps
    for step in steps:
        store_tree(step.get_backing())

    output.write(json.dumps({
        'nodes': binary_nodes,
        'step_roots': [encode_hex(step.hash_tree_root()) for step in steps],
        'access': [
            # not that this array is 1 shorter, the last step (post output) has no access data
            [encode_hex(gi.to_bytes(length=32, byteorder='big')) for gi in acc_li] for acc_li in access_trace
        ],
    }, indent='  '))

    click.echo("done!")


@cli.command()
@click.argument('input', type=click.File('rt'))
@click.argument('output', type=click.File('wt'))
@click.argument('step', type=click.INT)
def step_witness(input: TextIO, output: TextIO, step: int):
    """Compute the witness data for a single step by index, using the full trace witness.

    INPUT File/input to read fraud proof from.

    OUTPUT File/output to write witness of selected step to.

    STEP index of step to generate witness data for.
    """
    obj = json.loads(input.read())

    nodes = obj['nodes']

    def retrieve_node_by_gindex(i: int, root: str) -> str:
        if i == 1:
            return root

        if root not in nodes:
            raise Exception("this should be 1")

        pivot = 1 << (i.bit_length() - 2)
        go_right = i & pivot != 0
        # mask out the top bit, and set the new top bit
        child = (i | pivot) - (pivot << 1)
        left, right = nodes[root]
        if go_right:
            return retrieve_node_by_gindex(child, right)
        else:
            return retrieve_node_by_gindex(child, left)

    pre_root = obj['step_roots'][step]
    post_root = obj['step_roots'][step+1]

    contents = {g: retrieve_node_by_gindex(int.from_bytes(decode_hex(g), byteorder='big'), pre_root)
                for g in obj['access'][step]}

    output.write(json.dumps({
        'node_by_gindex': contents,
        'pre_root': pre_root,
        'post_root': post_root,
        'step': step,
    }, indent='  '))


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
    if post.result_code == 0 or post.result_code == 0xff:
        # success, state may have changed, check it
        got_root = post.hash_tree_root()
        click.echo("transaction was effective, post contract root: "+encode_hex(got_root))
    else:
        # no success, check that we were expecting the pre-state root as output (i.e. no changes)
        got_root = post.hash_tree_root()
        click.echo(f"transaction reverted ({str(ExitCodes(post.result_code))}), expecting pre-state contract root,"
                   " to indicate no change was made: "+encode_hex(got_root))
    if got_root != expected_root:
        click.echo("root did not match, fraud detected!")
        sys.exit(1)
    else:
        click.echo("root matches, no fraud")
        sys.exit(0)


if __name__ == '__main__':
    cli()
