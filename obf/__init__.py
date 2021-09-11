try:
    from Crypto.Hash import keccak

    def keccak_256(x): return keccak.new(digest_bits=256, data=x).digest()
except ImportError:
    import sha3 as _sha3

    def keccak_256(x): return _sha3.keccak_256(x).digest()

import remerkleable.settings as remerkleable_settings


def merkle_hash(left: bytes, right: bytes) -> bytes:
    return keccak_256(left + right)


# The EVM is big-endian, it will be easier to implement a verifier in the EVM if we use big-endian integers,
# even though SSZ spec is little-endian.
remerkleable_settings.ENDIANNESS = 'big'

# Keccak-256 is cheaper in the EVM than calling a sha-256 precompile.
remerkleable_settings.merkle_hash = merkle_hash

# re-initialize the zero-hashes we use to pad list trees, to use the new hash func
remerkleable_settings.init_zero_hashes()


