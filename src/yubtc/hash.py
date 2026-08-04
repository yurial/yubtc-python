
def keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def sha256(data: bytes) -> bytes:
    from Crypto.Hash import SHA256
    return SHA256.new(data).digest()


def ripemd160(data: bytes) -> bytes:
    from Crypto.Hash import RIPEMD160
    return RIPEMD160.new(data).digest()


def blake2b256(data: bytes) -> bytes:
    from Crypto.Hash import BLAKE2b
    h = BLAKE2b.new(digest_bytes=32)
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))
