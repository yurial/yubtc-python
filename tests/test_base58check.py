"""Tests for base58check.py.

Encode/decode cycles over a stable external library (base58), so the
bulk of these are known-answer tests pinned to hand-computed values
rather than the encode/decode functions themselves.

The local countLeadingZeroes / countLeadingOnes helpers are now
correct (compare bytes-iter-ints to 0 / ord('1')). Even before the
fix they were dead code: base58.b58encode / b58decode already
preserve leading zeros / '1's, so the round-trip tests below would
have passed either way.
"""
import pytest


# ---------------------------------------------------------------------------
# KAT vectors for the encode side. Computed once and pinned.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('payload, expected', [
    (b'', b'3QJmnh'),
    (b'\x00', b'1Wh4bh'),
    (b'\x00\x00', b'112edB6q'),
    (b'\x00\x00\x00\x00\x00', b'1111146Q4wc'),
    (b'hello', b'2L5B5yqsVG8Vt'),
    (b'\x00\x01\x02hello', b'1FX2wksLr1nSBug'),
    (b'\x01\x02\x03\x04', b'An6Ui6sE1F'),
    (bytes(range(32)), b'16qJFWMMHFy3xDdLmvUeyc2S6FrWRhJP51HsvDYdz9d1FsYG'),
    (b'\xff' * 32, b'2wkBET2rRgE8pahuaczxKbmv7ciehqsne57F9gtzf1PVZS9BEY'),
    # The 20-byte P2PKH payload (without the 0x00 prefix) used by yuBTC.
    (bytes.fromhex('e96b5b4561e70170c16f51ca30a9429e3bede977'),
     b'NHD3xcMHK7QW1bPQq1J5SCb6cpbNzC4wo'),
    # Full P2PKH payload (with the 0x00 prefix) -- the form wallet addresses take.
    (bytes.fromhex('00e96b5b4561e70170c16f51ca30a9429e3bede977'),
     b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'),
])
def test_base58CheckEncode_known_answers(payload, expected):
    from yubtc.base58check import base58CheckEncode
    assert base58CheckEncode(payload) == expected


# ---------------------------------------------------------------------------
# KAT vectors for the decode side: same vectors reversed.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('encoded, expected', [
    (b'3QJmnh', b''),
    (b'1Wh4bh', b'\x00'),
    (b'112edB6q', b'\x00\x00'),
    (b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k',
     bytes.fromhex('00e96b5b4561e70170c16f51ca30a9429e3bede977')),
    (b'16qJFWMMHFy3xDdLmvUeyc2S6FrWRhJP51HsvDYdz9d1FsYG', bytes(range(32))),
])
def test_base58CheckDecode_known_answers(encoded, expected):
    from yubtc.base58check import base58CheckDecode
    assert base58CheckDecode(encoded) == expected


# ---------------------------------------------------------------------------
# Round-trip: anything that encodes must decode back to the same bytes.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('payload', [
    b'',
    b'\x00',
    b'\x00' * 21,
    b'\x00\x01\x02hello',
    b'hello',
    bytes(range(32)),
    b'\xff' * 32,
    b'\x00\xff\x00\xff',
    bytes(range(256)),
])
def test_roundtrip(payload):
    from yubtc.base58check import base58CheckEncode, base58CheckDecode
    assert base58CheckDecode(base58CheckEncode(payload)) == payload


# ---------------------------------------------------------------------------
# Leading-zero preservation: this is the bug surfacing point.
#
# The `countLeadingZeroes` helper inside `base58CheckEncode` is broken
# (int compared to str), but the underlying `b58encode` already maps
# 0x00 bytes to '1' characters. The decode side mirrors with `b58decode`.
# These tests pin the actual -- correct -- behaviour.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('payload, leading_ones', [
    (b'\x00' * 1, 1),
    (b'\x00' * 2, 2),
    (b'\x00' * 5, 5),
    (b'\x00' * 21, 21),
    (b'\x00' * 21 + b'\x01', 21),
    # A payload with no leading zeros encodes to something that does
    # not start with '1'.
    (b'hello', 0),
])
def test_encode_prefix_consistent_with_leading_zero_count(payload, leading_ones):
    from yubtc.base58check import base58CheckEncode
    encoded = base58CheckEncode(payload)
    # Count leading '1' chars.
    n = 0
    for c in encoded:
        if c == ord('1'):
            n += 1
        else:
            break
    assert n == leading_ones


def test_decode_roundtrip_with_many_leading_zeros():
    """The decode side must reconstruct the leading zero bytes for the
    checksum to match. If `b58decode` failed to introduce them, the
    checksum verification would reject the payload."""
    from yubtc.base58check import base58CheckEncode, base58CheckDecode
    payload = b'\x00' * 21 + b'\x01'
    encoded = base58CheckEncode(payload)
    assert base58CheckDecode(encoded) == payload


# ---------------------------------------------------------------------------
# Error path: tampering with the checksum must raise.
# ---------------------------------------------------------------------------

def test_decode_rejects_tampered_checksum():
    from yubtc.base58check import base58CheckDecode
    # Encode a payload, then mutate the last character of the base58 string.
    # The base58 alphabet is carefully chosen so any single-char change
    # produces a different but still-decodable string -- so the checksum
    # check is the only thing that catches the tampering.
    encoded = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    # Flip the last char to a different valid base58 character.
    tampered = encoded[:-1] + (b'L' if encoded[-1:] != b'L' else b'K')
    assert tampered != encoded
    with pytest.raises(ValueError, match='invalid checksum'):
        base58CheckDecode(tampered)


def test_decode_accepts_p2pkh_address_prefix_byte():
    """Integration with the wider wallet: the first byte of the decoded
    payload is the address family prefix (0x00 for P2PKH mainnet)."""
    from yubtc.base58check import base58CheckDecode
    decoded = base58CheckDecode(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert decoded[0] == 0x00
    assert len(decoded) == 21  # 1 prefix byte + 20-byte hash


# ---------------------------------------------------------------------------
# Empty / minimal inputs.
# ---------------------------------------------------------------------------

def test_encode_then_decode_empty_payload():
    from yubtc.base58check import base58CheckEncode, base58CheckDecode
    assert base58CheckDecode(base58CheckEncode(b'')) == b''


def test_encode_output_is_bytes():
    """base58CheckEncode returns bytes, not str."""
    from yubtc.base58check import base58CheckEncode
    assert isinstance(base58CheckEncode(b'hello'), bytes)
