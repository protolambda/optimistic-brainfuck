# Optimistic Brainfuck

Ever wanted to run [Brainfuck](https://esolangs.org/wiki/Brainfuck) on ethereum? Don't ask, now you can! And at a fraction of the cost, thanks to optimistic rollup tech!

If you can plug in Brainfuck, you can plug in **anything**. [EVM is a work in progress](https://github.com/protolambda/macula).


```shell
# create a state with example contract
obf init-state state.json
```
Output:
```json
{
  "contracts": {
    "0": {
      "code": ",,,,,,,,,,,,,,,,,,,,,[>+++++++<-]",
      "ptr": 0,
      "cells": [
        0
      ]
    }
  }
}
```
This is a simple contract that skips over the standard sender address data (first 20 bytes), and multiplies the first byte with 7.


```shell
# call the default 0 contract with some input data, and a dummy 0xaa.... address
obf transition state.json state_out.json '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 0 '0x03'
```

This produces `state_out.json`:
```json
{
  "contracts": {
    "0": {
      "code": ",,,,,,,,,,,,,,,,,,,,,[>+++++++<-]",
      "cells": [
        0,
        21
      ],
      "ptr": 0
    }
  }
}
```

Now say some malicious sequencer committed to a different state of this contract, what happens?
1. Any honest user sees the mismatch with their local transition
2. Generate a fraud proof witness
3. They open a challenge on-chain
4. They do an interactive game to find the first differing step
5. They extract the witness for this particular step from the fraud proof data
6. They submit it, to finish the on-chain work, showing that indeed the sequencer was claiming a different result 
   than could be computed with a tiny step on-chain, on top of the previous undisputed step (base case is just loading the transaction into a step).
 
Generate a fraud proof:
```shell
obf gen state.json proof.json '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 0 '0x03'
```

Output:
```json
{
   "nodes": { /* key -> [left node, right node] */},
   "step_roots": [ /* merkle roots of each step, as well as the final output, to play dispute game on */],
   "access": [ /* per step, a list of 32-byte encoded generalized indices, to point which nodes are relevant to the step */]
}
```

Build a witness for a specific step, e.g. step 53:
```shell
step-witness proof.json step53.json 53
```

```json
{
  "node_by_gindex": {
    "0x0000000000000000000000000000000000000000000000000000000000000008": "0x0000000000000433000000000000000000000000000000000000000000000000",
     "0x0000000000000000000000000000000000000000000000000000000000000009": "0x0000001d00000000000000000000000000000000000000000000000000000000",
    // some more gindex -> value nodes
  },
  "pre_root": "0x3ea782a870598661a410b833761ab5483002362cc4ce077ab96bf5e038be394a",
  "post_root": "0x438d23b78af4c6701d00630bb716c6dfdab5390ce0a5425fe5419f0cd0242184",
  "step": 53
}
```

And now the last part: format the witness as a call to the L1 executor contract, to finish the game with.
This prototype does not have a solidity implementation of the verification (yet? next project maybe), but it does have a python one:
```shell
obf verify step53.json "0x438d23b78af4c6701d00630bb716c6dfdab5390ce0a5425fe5419f0cd0242184"
```
```
parsing fraud proof
verifying fraud proof
transaction was effective, post contract root: 0x438d23b78af4c6701d00630bb716c6dfdab5390ce0a5425fe5419f0cd0242184
root matches, no fraud
```

Or with a slightly different root (thus wrong, like a malicous actor might try):
```shell
obf verify step53.json "0x438d23b78af4c6701d00630bb716c6dfdab5390ce0a5425fe5419f0cd0242183"
```
```
parsing fraud proof
verifying fraud proof
transaction was effective, post contract root: 0x438d23b78af4c6701d00630bb716c6dfdab5390ce0a5425fe5419f0cd0242184
root did not match, fraud detected!
```

## License

MIT, see [`LICENSE`](./LICENSE) file.
