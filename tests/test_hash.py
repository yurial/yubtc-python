"""Known-answer tests for the hash primitives.

These lock the exact bytes each function produces. crypto.py derives private
keys from them, so a silent change here would move every address the wallet
has ever generated -- which is precisely the risk when a hash dependency is
swapped out.

Vectors are the published ones: FIPS 180-4 for SHA-256, the reference RIPEMD-160
and BLAKE2 test suites, and the standard Keccak-256 values.
"""
import pytest

from yubtc.hash import sha256, keccak256, ripemd160, blake2b256, hash160

EMPTY = b''
ABC = b'abc'


@pytest.mark.parametrize('func, message, expected', [
    (sha256, EMPTY, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    (sha256, ABC, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),

    (keccak256, EMPTY, 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
    (keccak256, ABC, '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),

    (ripemd160, EMPTY, '9c1185a5c5e9fc54612808977ee8f548b2258d31'),
    (ripemd160, ABC, '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'),

    # blake2b256() is BLAKE2b truncated to 32 bytes -- see test_blake2b256_matches_hashlib.
    (blake2b256, EMPTY, '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'),
    (blake2b256, ABC, 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'),

    # hash160 = ripemd160(sha256(x)), the standard Bitcoin construction.
    (hash160, EMPTY, 'b472a266d0bd89c13706a4132ccfb16f7c3b9fcb'),
    (hash160, ABC, 'bb1be98c142444d7a56aa3981c3942a978e4dc33'),
])
def test_known_answer(func, message, expected):
    assert func(message).hex() == expected


@pytest.mark.parametrize('func, size', [
    (sha256, 32), (keccak256, 32), (blake2b256, 32), (ripemd160, 20), (hash160, 20),
])
def test_digest_size(func, size):
    assert len(func(EMPTY)) == size
    assert len(func(b'x' * 1000)) == size


def test_keccak256_is_not_nist_sha3():
    """Guard against 'simplifying' keccak256 to hashlib.sha3_256.

    Keccak and the final NIST SHA-3 differ in their padding, so the two produce
    different digests. Swapping one for the other would change every derived
    key while still looking like a reasonable cleanup.
    """
    import hashlib
    assert keccak256(ABC) != hashlib.sha3_256(ABC).digest()


def test_blake2b256_matches_hashlib():
    """Pin blake2b256() to hashlib.blake2b(digest_size=32).

    BLAKE2b is parameterised: a different digest_size, key, or person string
    produces a different output. This test stops a future refactor from
    drifting away from the exact configuration the wallet relies on.
    """
    import hashlib
    assert blake2b256(ABC) == hashlib.blake2b(ABC, digest_size=32).digest()


def test_hash160_is_ripemd160_of_sha256():
    for message in (EMPTY, ABC, b'\x00' * 32, bytes(range(256))):
        assert hash160(message) == ripemd160(sha256(message))
