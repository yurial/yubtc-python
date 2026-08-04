
def keccak256(data: bytes) -> bytes:
    from sha3 import keccak_256
    return keccak_256(data).digest()


def sha256(data: bytes) -> bytes:
    from hashlib import sha256
    return sha256(data).digest()


def ripemd160(data: bytes) -> bytes:
    import hashlib
    return hashlib.new('ripemd160', data).digest()


def blake2b256(data: bytes) -> bytes:
    from hashlib import blake2b
    return blake2b(data, digest_size=32).digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))
