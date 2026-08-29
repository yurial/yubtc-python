"""Bech32 / Bech32m codec (BIP-173 / BIP-350).

Pure-Python mirror of `yubtc core/src/bech32.rs` (Phase 13). The
algorithms are the reference ones from the BIPs: the BCH checksum
polymod over GF(2^5) with generator constants
`0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3`, and the
HRP expansion (high bits of each character, a zero separator, then the
low 5 bits).

The codec is the generic BIP-173/350 string format (arbitrary HRP +
5-bit data values). The SegWit-address layer on top of it -- witness
version/program validation, the `bc` HRP, bech32-vs-bech32m selection
-- lives in `yubtc.crypto.decode_segwit_addr`.

Checksum constants: `1` for bech32 (BIP-173) and `0x2bc830a3` for
bech32m (BIP-350). Encoders always emit lowercase; decoders accept
all-lowercase and all-uppercase input and reject mixed case (BIP-173
MUST).

Every malformed input is rejected with a typed `Bech32Error`
subclass; nothing here panics or returns garbage.
"""

from yubtc.util import NotNone, require_kwargs_only

# The BIP-173 character set (GF(2^5) alphabet, in encoding order).
CHARSET = b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

# Bech32m checksum constant (BIP-350). Bech32 uses `1`.
BECH32M_CONST = 0x2bc830a3

# Maximum total length of a bech32 string (BIP-173).
BECH32_MAX_LEN = 90

# Which checksum specification a string satisfies (mirrors
# `bech32.rs::Encoding`). The values are the `Encoding::as_str` names.
BECH32 = 'bech32'  # BIP-173 -- checksum constant 1; witness v0.
BECH32M = 'bech32m'  # BIP-350 -- checksum constant 0x2bc830a3; witness v1+.

_CHECKSUM_CONST = {
    BECH32: 1,
    BECH32M: BECH32M_CONST,
}

# Generator polynomial of the BCH checksum (BIP-173).
_GEN = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)


class Bech32Error(ValueError):
    """Base class for typed bech32 failures (mirrors
    `yubtc core/src/bech32.rs::Bech32Error`)."""


class Bech32TooLong(Bech32Error):
    """The string exceeded 90 characters (BIP-173 overall max length)."""


class Bech32InvalidCharacter(Bech32Error):
    """A character outside the US-ASCII printable range [33, 126] or
    outside the data-part charset was encountered."""

    def __init__(self, char):
        self.char = char
        super().__init__(f'invalid bech32 character {char!r}')


class Bech32MixedCase(Bech32Error):
    """Some characters are lowercase and some are uppercase (BIP-173
    decoders MUST reject mixed case)."""


class Bech32InvalidStructure(Bech32Error):
    """The string is structurally malformed: no `1` separator, empty
    HRP, or a data part shorter than the 6-character checksum."""


class Bech32InvalidChecksum(Bech32Error):
    """Neither the bech32 (`1`) nor the bech32m (`0x2bc830a3`)
    checksum matches."""


class Bech32InvalidDataValue(Bech32Error):
    """An encoder-side data value is not a 5-bit number (>= 32)."""

    def __init__(self, value):
        self.value = value
        super().__init__(f'bech32 data value {value} out of 5-bit range')


def polymod(values):
    """BCH checksum generator from BIP-173."""
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i, g in enumerate(_GEN):
            if (b >> i) & 1:
                chk ^= g
    return chk


def hrp_expand(hrp):
    """HRP expansion from BIP-173: high bits of each character, a zero
    separator, then the low 5 bits of each character."""
    data = bytes(hrp, 'ascii')
    return [b >> 5 for b in data] + [0] + [b & 31 for b in data]


@require_kwargs_only
def encode(hrp: str = NotNone, encoding: str = NotNone, data: bytes = NotNone) -> str:
    """Encode `data` (5-bit values, checksum excluded) with `hrp` under
    the given `encoding` (`bech32` or `bech32m`).

    Contract (mirrors `bech32.rs::encode`):
    - every value in `data` must be < 32, otherwise
      `Bech32InvalidDataValue`;
    - returns `Bech32TooLong` when the result would exceed 90
      characters (BIP-173);
    - the output is always lowercase (BIP-173 encoder MUST).
    The HRP is not re-validated: all production callers pass the
    constant `"bc"`.
    """
    data = bytes(data)
    for v in data:
        if v > 31:
            raise Bech32InvalidDataValue(v)
    values = hrp_expand(hrp) + list(data) + [0] * 6
    checksum = polymod(values) ^ _CHECKSUM_CONST[encoding]
    out = hrp + '1'
    out += bytes(CHARSET[v] for v in data).decode('ascii')
    for i in range(5, -1, -1):
        out += chr(CHARSET[(checksum >> (5 * i)) & 31])
    if len(out) > BECH32_MAX_LEN:
        raise Bech32TooLong(f'bech32 string longer than {BECH32_MAX_LEN} characters')
    return out


@require_kwargs_only
def decode(s: str = NotNone) -> tuple:
    """Decode a bech32/bech32m string into `(hrp, encoding, data)`.

    Contract (mirrors `bech32.rs::decode`):
    - mixed-case input is rejected with `Bech32MixedCase` (BIP-173
      MUST); all-lowercase and all-uppercase are accepted and the
      returned `hrp` is always lowercase;
    - the returned `data` excludes the 6-character checksum; it MAY be
      empty (a pure-checksum payload is valid generic bech32);
    - the returned `encoding` tells which checksum constant the string
      satisfies; the SegWit layer enforces the v0->bech32 /
      v1+->bech32m correspondence (BIP-350 rule 2).
    """
    if len(s) > BECH32_MAX_LEN:
        raise Bech32TooLong(f'bech32 string longer than {BECH32_MAX_LEN} characters')
    # Every character must be US-ASCII printable [33, 126] (BIP-173
    # HRP and data-part validity). Checked before case handling.
    for c in s:
        if not 33 <= ord(c) <= 126:
            raise Bech32InvalidCharacter(c)
    has_lower = any(c.islower() for c in s)
    has_upper = any(c.isupper() for c in s)
    if has_lower and has_upper:
        raise Bech32MixedCase('mixed-case bech32 string')
    s = s.lower()

    # The LAST '1' is the separator (BIP-173 allows '1' inside the
    # HRP; the final one delimits the data part).
    pos = s.rfind('1')
    # `pos == 0` -> empty HRP; `pos + 7 > len(s)` -> data part shorter
    # than the 6-character checksum.
    if pos <= 0 or pos + 7 > len(s):
        raise Bech32InvalidStructure('malformed bech32 structure')
    hrp = s[:pos]
    data_part = s[pos + 1:]

    values = []
    for c in data_part:
        idx = CHARSET.find(ord(c))
        if idx < 0:
            raise Bech32InvalidCharacter(c)
        values.append(idx)

    # The checksum characters are still part of `values` here -- the
    # polymod runs over the HRP expansion plus the full data part and
    # must land on one of the two checksum constants.
    chk = polymod(hrp_expand(hrp) + values)
    if chk == 1:
        encoding = BECH32
    elif chk == BECH32M_CONST:
        encoding = BECH32M
    else:
        raise Bech32InvalidChecksum('bech32 checksum mismatch')
    return hrp, encoding, bytes(values[:-6])


@require_kwargs_only
def bytes_to_5bit(data: bytes = NotNone) -> bytes:
    """Re-group arbitrary bytes into 5-bit values, zero-padding the
    final group (the 8->5 direction of BIP-173 convertbits with
    `pad=True`). Infallible."""
    acc = 0
    bits = 0
    out = bytearray()
    for b in bytes(data):
        acc = ((acc << 8) | b) & 0xfff
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits > 0:
        out.append((acc << (5 - bits)) & 31)
    return bytes(out)


@require_kwargs_only
def five_bit_to_bytes(data: bytes = NotNone):
    """Re-group 5-bit values back into bytes (the 5->8 direction of
    BIP-173 convertbits with `pad=False`).

    Strict per BIP-173: any value >= 32, more than 4 bits of trailing
    padding, or non-zero padding bits yield `None` (mirrors the Rust
    `Option<Vec<u8>>`; the SegWit layer maps `None` to
    `SegWitInvalidStructure`).
    """
    acc = 0
    bits = 0
    out = bytearray()
    for v in bytes(data):
        if v > 31:
            return None
        acc = ((acc << 5) | v) & 0xfff
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)
    # An incomplete trailing group must be at most 4 bits AND zero.
    if bits >= 5:
        return None
    if bits > 0 and acc & ((1 << bits) - 1):
        return None
    return bytes(out)
