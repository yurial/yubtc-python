"""Tests for bech32.py: the BIP-173/BIP-350 codec.

Pinned against the official BIP-173 valid/invalid string lists and the
BIP-350 bech32m additions. A codec drift here silently mangles every
address the wallet ever prints, so the vectors are the contract.
"""
import pytest

from yubtc.bech32 import (BECH32, BECH32M, BECH32M_CONST, BECH32_MAX_LEN,
                          Bech32InvalidCharacter, Bech32InvalidChecksum,
                          Bech32InvalidDataValue, Bech32InvalidStructure,
                          Bech32MixedCase, Bech32TooLong, bytes_to_5bit,
                          decode, encode, five_bit_to_bytes)

# Official BIP-173 valid generic bech32 strings.
BIP173_VALID = [
    'A12UEL5L',
    'a12uel5l',
    'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
    'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
    '11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j',
    'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w',
    '?1ezyfcl',
]

# Official BIP-350 valid generic bech32m strings.
BIP350_VALID = [
    'A1LQFN3A',
    'a1lqfn3a',
    'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
    'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
    '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
    'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
    '?1v759aa',
]


@pytest.mark.parametrize('s', BIP173_VALID)
def test_bip173_valid_strings_decode_as_bech32(s):
    hrp, encoding, _data = decode(s=s)
    assert encoding == BECH32
    # The decoded HRP is always lowercase.
    assert hrp == hrp.lower()


@pytest.mark.parametrize('s', BIP350_VALID)
def test_bip350_valid_strings_decode_as_bech32m(s):
    hrp, encoding, _data = decode(s=s)
    assert encoding == BECH32M
    assert hrp == hrp.lower()


def test_encode_reproduces_bip173_generic_strings():
    # "A12UEL5L" / "a12uel5l" are hrp "a" with an empty payload;
    # "?1ezyfcl" is hrp "?" with an empty payload.
    cases = [
        ('a', 'a12uel5l'),
        ('?', '?1ezyfcl'),
        ('split', 'split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w'),
        ('abcdef', 'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw'),
    ]
    for hrp, expected in cases:
        decoded_hrp, encoding, data = decode(s=expected)
        assert decoded_hrp == hrp
        assert encoding == BECH32
        assert encode(hrp=hrp, encoding=BECH32, data=data) == expected


def test_encode_reproduces_bip350_generic_strings():
    cases = [
        ('a', 'a1lqfn3a'),
        ('?', '?1v759aa'),
        ('abcdef', 'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx'),
    ]
    for hrp, expected in cases:
        decoded_hrp, encoding, data = decode(s=expected)
        assert decoded_hrp == hrp
        assert encoding == BECH32M
        assert encode(hrp=hrp, encoding=BECH32M, data=data) == expected


def test_bip173_invalid_strings_are_rejected():
    # HRP character out of range (space = 0x20).
    with pytest.raises(Bech32InvalidCharacter, match="' '"):
        decode(s=' 1nwldj5')
    # HRP character out of range (U+00FF > 126).
    with pytest.raises(Bech32InvalidCharacter):
        decode(s='ÿ1axkwrx')
    # Overall max length exceeded (91 chars).
    too_long = 'a' * 85 + '1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqq'
    assert len(too_long) > BECH32_MAX_LEN
    with pytest.raises(Bech32TooLong):
        decode(s=too_long)
    # No separator character.
    with pytest.raises(Bech32InvalidStructure):
        decode(s='pzry9x0s0muk')
    # Empty HRP.
    with pytest.raises(Bech32InvalidStructure):
        decode(s='1pzry9x0s0muk')
    # Invalid data character ('b' is excluded from the charset).
    with pytest.raises(Bech32InvalidCharacter, match="'b'"):
        decode(s='x1b4n0q5v')
    # Too short checksum (data part < 6 chars).
    with pytest.raises(Bech32InvalidStructure):
        decode(s='li1dgmt3')
    # Checksum calculated with the uppercase form of the HRP:
    # passes the case check (all uppercase), then fails the bech32
    # checksum after lowercasing.
    with pytest.raises(Bech32InvalidChecksum):
        decode(s='A1G7SGD8')
    # Empty HRP (separator at position 0).
    with pytest.raises(Bech32InvalidStructure):
        decode(s='10a06t8')
    with pytest.raises(Bech32InvalidStructure):
        decode(s='1qzzfhee')


def test_bip350_invalid_strings_are_rejected():
    # Invalid data character.
    with pytest.raises(Bech32InvalidCharacter, match="'b'"):
        decode(s='y1b0jsk6g')
    with pytest.raises(Bech32InvalidCharacter, match="'i'"):
        decode(s='lt1igcx5c0')
    # Too short checksum.
    with pytest.raises(Bech32InvalidStructure):
        decode(s='in1muywd')
    # Invalid character in checksum.
    with pytest.raises(Bech32InvalidCharacter, match="'i'"):
        decode(s='mm1crxm3i')
    with pytest.raises(Bech32InvalidCharacter, match="'o'"):
        decode(s='au1s5cgom')
    # Checksum calculated with the uppercase form of the HRP.
    with pytest.raises(Bech32InvalidChecksum):
        decode(s='M1VUXWEZ')
    # Empty HRP.
    with pytest.raises(Bech32InvalidStructure):
        decode(s='16plkw9')
    with pytest.raises(Bech32InvalidStructure):
        decode(s='1p2gdwpf')


def test_mixed_case_is_rejected():
    # From the BIP-173 segwit list: mixed case MUST be rejected at the
    # codec level, before any address semantics.
    with pytest.raises(Bech32MixedCase):
        decode(s='tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7')
    # Minimal mixed-case probe on a generic string.
    with pytest.raises(Bech32MixedCase):
        decode(s='a12Uel5L')


def test_checksum_constants_match_bips():
    from yubtc.bech32 import _CHECKSUM_CONST
    assert _CHECKSUM_CONST[BECH32] == 1
    assert _CHECKSUM_CONST[BECH32M] == BECH32M_CONST
    assert BECH32M_CONST == 0x2bc830a3


def test_encode_rejects_out_of_range_data_values():
    with pytest.raises(Bech32InvalidDataValue, match='out of 5-bit range'):
        encode(hrp='bc', encoding=BECH32, data=bytes([32]))
    with pytest.raises(Bech32InvalidDataValue):
        encode(hrp='bc', encoding=BECH32M, data=bytes([255]))


def test_encode_rejects_result_longer_than_90():
    # 83-char HRP is the BIP-173 HRP max; with the separator and
    # 6 checksum chars any non-empty payload breaches 90.
    with pytest.raises(Bech32TooLong):
        encode(hrp='a' * 83, encoding=BECH32, data=bytes([0]))


def test_bytes_to_5bit_official_example():
    # The canonical P2WPKH program 751e76e8...bd6 from BIP-173 encodes
    # to the data part of bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    # (version 0 + payload). It is hash160 of the BIP-173 example
    # pubkey 0279BE66...798 (the generator's compressed form).
    program = bytes.fromhex('751e76e8199196d4549' + '41c45d1b3a323f1433bd6')
    _hrp, _encoding, data = decode(s='BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4')
    assert data[0] == 0  # witness version 0
    assert bytes_to_5bit(data=program) == data[1:]


def test_five_bit_to_bytes_round_trips_bytes_to_5bit():
    payload = bytes(range(256))
    grouped = bytes_to_5bit(data=payload)
    assert five_bit_to_bytes(data=grouped) == payload
    # Empty payload round-trips to empty.
    assert five_bit_to_bytes(data=bytes_to_5bit(data=b'')) == b''


def test_five_bit_to_bytes_rejects_bad_padding():
    # More than 4 bits of padding: 6 values = 30 bits -> 3 bytes
    # + 6 leftover bits.
    assert five_bit_to_bytes(data=bytes([31, 31, 31, 31, 31, 0])) is None
    # Exactly 5 leftover bits is still "more than 4".
    assert five_bit_to_bytes(data=bytes([7])) is None
    # Non-zero padding: [25, 25] = 11001 11001 -> byte 206 with
    # 2 leftover bits "01" != 0.
    assert five_bit_to_bytes(data=bytes([25, 25])) is None
    # Same prefix with zero padding decodes fine.
    assert five_bit_to_bytes(data=bytes([24, 24])) == bytes([198])
    # ...and 25 one-bits + one zero value = 3 bytes + 1 zero bit.
    assert five_bit_to_bytes(data=bytes([31, 31, 31, 31, 0])) == bytes([255, 255, 240])
    # Value out of 5-bit range.
    assert five_bit_to_bytes(data=bytes([32])) is None
