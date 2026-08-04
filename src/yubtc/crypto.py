from typing import Optional, TYPE_CHECKING

from yubtc.fwd import TAddress, TNonce, TSatoshi, TSeed

if TYPE_CHECKING:
    from yubtc.script import CScript

SUFFIX_PRIVKEY_COMPRESSED = 0x01
PREFIX_P2PKH = 0x00  # Publick Key Hash
PREFIX_PUBKEY_EVEN = 0x02
PREFIX_PUBKEY_ODD = 0x03
PREFIX_PUBKEY_FULL = 0x04
PREFIX_P2SH = 0x05  # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch07.asciidoc#pay-to-script-hash-p2sh
PREFIX_TESTNET_P2PKH = 0x6F
PREFIX_TESTNEY_P2SH = 0xc4
PREFIX_PRIVKEY = 0x80
PREFIX_ENCPRIVKEY = 0x0142  # BIP-38
PREFIX_EXTPUBKEY = 0x0488B21E  # BIP-32
# TODO: SEGWIT https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch07.asciidoc#segregated-witness


def str2bytes(s: str) -> bytes:
    return s.encode('latin-1')


def bytes2str(b: bytes) -> str:
    return ''.join(map(chr, b))


def str2list(s: str) -> list:
    return [c for c in s]


def seed2bin(*args, seed: Optional[TSeed] = None, nonce: Optional[TNonce] = None) -> bytes:
    if args:
        raise Exception('only kwargs allowed')
    if seed is None:
        raise Exception('seed not set')
    if nonce is None:
        raise Exception('nonce not set')
    from yubtc.hash import sha256, keccak256, blake2b256
    from struct import pack
    data = pack(">L", nonce) + str2bytes(seed)
    return sha256(keccak256(blake2b256(data)))


def bin2privkey(data: bytes) -> bytes:
    privkey = bytearray(data)
    """
    Clamping the lower bits ensures the key is a multiple of the cofactor.
    This is done to prevent small subgroup attacks.
    Clamping the (second most) upper bit to one is done because certain
    implementations of the Montgomery Ladder don't correctly handle this
    bit being zero.
    """
    privkey[0] &= 248
    privkey[31] &= 127
    privkey[31] |= 64
    return bytes(privkey)


def seed2privkey(*args, seed: Optional[TSeed] = None, nonce: Optional[TNonce] = None) -> bytes:
    if args:
        raise Exception('only kwargs allowed')
    if seed is None:
        raise Exception('seed not set')
    if nonce is None:
        raise Exception('nonce not set')
    return bin2privkey(seed2bin(seed=seed, nonce=nonce))


def privkey2privwif(*args, privkey: Optional[bytes] = None, compressed: Optional[bool] = None) -> str:
    if args:
        raise Exception('only kwargs allowed')
    if privkey is None:
        raise Exception('privkey not set')
    if compressed is None:
        raise Exception('compressed not set')
    from yubtc.base58check import base58CheckEncode
    if compressed:
        # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
        privkey += bytes([SUFFIX_PRIVKEY_COMPRESSED])
    return base58CheckEncode(bytes([PREFIX_PRIVKEY]) + privkey)


def privwif2privkey(privwif: str) -> tuple:
    from yubtc.base58check import base58CheckDecode
    privkey = base58CheckDecode(privwif)
    if privkey[0] != PREFIX_PRIVKEY:
        raise Exception('prefix missmatch')
    else:
        privkey = privkey[1:]
    if len(privkey) == 33 and privkey[-1] == SUFFIX_PRIVKEY_COMPRESSED:
        return (privkey[:-1], True)  # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return (privkey, False)


def privkey2pubkey(privkey: bytes) -> bytes:
    from coincurve import PrivateKey
    sk = PrivateKey(privkey)
    # coincurve's uncompressed form is 65 bytes with the 0x04 prefix; strip it
    # so callers receive the 64-byte (X || Y) form the rest of the wallet expects.
    return sk.public_key.format(compressed=False)[1:]


def sign_hash(*args, privkey: Optional[bytes] = None, datahash: Optional[bytes] = None) -> bytes:
    if args:
        raise Exception('only kwargs allowed')
    if privkey is None:
        raise Exception('privkey not set')
    if datahash is None:
        raise Exception('datahash not set')
    from coincurve import PrivateKey
    sk = PrivateKey(privkey)
    # hasher=None: sign the 32-byte digest directly. libsecp256k1 already
    # produces DER-encoded, low-s signatures by default.
    return sk.sign(datahash, hasher=None)


def sign_data(*args, privkey: Optional[bytes] = None, data: Optional[bytes] = None) -> bytes:
    if args:
        raise Exception('only kwargs allowed')
    if privkey is None:
        raise Exception('privkey not set')
    if data is None:
        raise Exception('data not set')
    from yubtc.hash import sha256
    datahash = sha256(sha256(data))
    return sign_hash(privkey=privkey, datahash=datahash)


def pubkey2pubwif(*args, pubkey: Optional[bytes] = None, compressed: Optional[bool] = None) -> bytes:
    if args:
        raise Exception('only kwargs allowed')
    if pubkey is None:
        raise Exception('pubkey not set')
    if compressed is None:
        raise Exception('compressed not set')
    if not compressed:
        return bytes([PREFIX_PUBKEY_FULL]) + pubkey
    x, y = pubkey[:32], pubkey[32:]
    prefix = PREFIX_PUBKEY_EVEN if (y[-1] % 2) == 0 else PREFIX_PUBKEY_ODD
    return bytes([prefix]) + x


def pubkey2addr(*args, pubkey: Optional[bytes] = None, compressed: Optional[bool] = None) -> bytes:
    if args:
        raise Exception('only kwargs allowed')
    if pubkey is None:
        raise Exception('pubkey not set')
    if compressed is None:
        raise Exception('compressed not set')
    from yubtc.base58check import base58CheckEncode
    from yubtc.hash import hash160
    pubwif = pubkey2pubwif(pubkey=pubkey, compressed=compressed)
    return base58CheckEncode(bytes([PREFIX_P2PKH]) + hash160(pubwif))


def privkey2addr(*args, privkey: Optional[bytes] = None, compressed: Optional[bool] = None) -> bytes:
    if args:
        raise Exception('only kwargs allowed')
    if privkey is None:
        raise Exception('privkey not set')
    if compressed is None:
        raise Exception('compressed not set')
    return pubkey2addr(pubkey=privkey2pubkey(privkey), compressed=compressed)


"""
>>> p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
>>> x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
>>> y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
>>> (x ** 3 + 7) % p == y**2 % p
"""


def make_lock_script(address: TAddress) -> 'CScript':
    from yubtc.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL
    from yubtc.crypto import PREFIX_P2PKH, PREFIX_P2SH
    from yubtc.misc import unpack_address
    prefix, dsthash = unpack_address(address)
    if prefix == PREFIX_P2PKH:
        return CScript([OP_DUP, OP_HASH160, dsthash, OP_EQUALVERIFY, OP_CHECKSIG])
    elif prefix == PREFIX_P2SH:
        return CScript([OP_HASH160, dsthash, OP_EQUAL])
    else:
        raise Exception('address not supported')


def make_vout(*args, src: Optional[TAddress] = None, dst: Optional[TAddress] = None,
              in_amount: Optional[TSatoshi] = None, amount: Optional[TSatoshi] = None,
              fee: Optional[TSatoshi] = None) -> tuple:
    if args:
        raise Exception('only kwargs allowed')
    if src is None:
        raise Exception('src not set')
    if dst is None:
        raise Exception('dst not set')
    if in_amount is None:
        raise Exception('in_amount not set')
    if fee is None:
        raise Exception('fee not set')
    from yubtc.transaction import COut
    vout_script = make_lock_script(dst)
    if amount is None or (amount + fee == in_amount):
        amount = in_amount - fee
        return [COut(amount=amount, script=vout_script)], 0, amount
    else:
        cashback = in_amount - amount - fee
        cashback_lock_script = make_lock_script(src)
        return [COut(amount=cashback, script=cashback_lock_script), COut(
            amount=amount, script=vout_script)], cashback, amount
