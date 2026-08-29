
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


def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    """BIP-340/341 tagged hash: `sha256(sha256(tag) || sha256(tag) || msg)`.

    Shared by the Taproot address derivation (`TapTweak`) and the
    BIP-341 signature digest (`TapSighash`). Mirrors
    `yubtc core/src/misc.rs::tagged_hash` bit-for-bit.
    """
    tag_hash = sha256(tag)
    return sha256(tag_hash + tag_hash + msg)
