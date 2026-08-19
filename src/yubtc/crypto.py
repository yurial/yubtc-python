from typing import NamedTuple, TYPE_CHECKING

from coincurve import PrivateKey

from yubtc.fwd import TAddress, TNonce, TSatoshi, TSeed, TPassphrase
from yubtc.util import NotNone, require_kwargs_only

if TYPE_CHECKING:
    from yubtc.script import CScript

SUFFIX_PRIVKEY_COMPRESSED = 0x01
PREFIX_P2PKH = 0x00  # Public Key Hash
PREFIX_PUBKEY = 0x02  # Compressed pubkey prefix; the low bit signals parity of y.
PREFIX_P2SH = 0x05  # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch07.asciidoc#pay-to-script-hash-p2sh
PREFIX_TESTNET_P2PKH = 0x6F
PREFIX_TESTNET_P2SH = 0xc4
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


@require_kwargs_only
def seed2bin(seed: TSeed = NotNone,
             nonce: TNonce = NotNone,
             passphrase: TPassphrase = None) -> bytes:
    """KDF: turn `(seed, nonce, passphrase)` into a 32-byte secret.

    Two derivations, gated on the passphrase:

    - **Empty passphrase** (the default, and what every pre-passphrase
      caller passes): the legacy `blake2b → keccak → sha256` cascade
      over `nonce ‖ seed`. The output is bit-for-bit identical to the
      pre-passphrase code path, so a wallet that has been around since
      before passphrase support still opens.

    - **Non-empty passphrase**: BIP-39 + BIP-32 + BIP-44. The mnemonic
      and passphrase are NFKD-normalized and UTF-8-encoded, then
      stretched through standard PBKDF2-HMAC-SHA512 (salt
      `b'mnemonic' + passphrase`, 2048 iter, 64 bytes) to produce the
      BIP-39 seed. The BIP-32 master is derived from that seed, and the
      final 32-byte key is the hardened-walked leaf at
      `m/44'/0'/0'/0/<nonce>` -- the BIP-44 receiving-chain path. Any
      BIP-44 wallet (Trezor, Ledger, Electrum, ...) with the same
      mnemonic and passphrase will arrive at the same key for the same
      nonce -- addresses line up bit-for-bit.

    The PBKDF2 stretch is the only thing between an attacker with a
    stolen mnemonic and the passphrase-derived funds. 2048 iterations
    is the BIP-39 default; raising it would slow *every* derivation
    and is not done here.
    """
    from hashlib import pbkdf2_hmac
    from yubtc.hash import sha256, keccak256, blake2b256
    from struct import pack
    if not passphrase:
        # Backward-compatible path: existing wallets and tests keep
        # producing the same bytes they always did. The branch is gated
        # on the *string* being empty, not on the seed -- a seed of ""
        # is rejected by `TPrivKey` / `Wallet` higher up.
        data = pack(">L", nonce) + str2bytes(seed)
        return sha256(keccak256(blake2b256(data)))
    # BIP-39 → BIP-32 → BIP-44 path. yubtc walks the main receiving
    # chain only (m/44'/0'/0'/0/<nonce>); cashback lands on the next
    # unused index of the same chain, not on a separate change chain.
    # Walking the full tree would be O(N×M) on every scan, which is
    # incompatible with the wallet's no-storage, rescan-every-run model.
    import unicodedata
    from yubtc.bip32 import master_from_seed, derive_path
    seed_bytes = unicodedata.normalize('NFKD', seed).encode('utf-8')
    pass_bytes = unicodedata.normalize('NFKD', passphrase).encode('utf-8')
    stretched = pbkdf2_hmac(
        'sha512',
        seed_bytes,
        b'mnemonic' + pass_bytes,
        2048,
        dklen=64,
    )
    master_priv, master_chain = master_from_seed(seed=stretched)
    path = "m/44'/0'/0'/0/{nonce}".format(nonce=nonce)
    child_priv, _ = derive_path(master_priv=master_priv, master_chain=master_chain, path=path)
    return child_priv


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


@require_kwargs_only
def seed2privkey(seed: TSeed = NotNone,
                 nonce: TNonce = NotNone,
                 passphrase: TPassphrase = '') -> PrivateKey:
    """Derive the signing key from (seed, nonce, passphrase).

    Clamp policy (decision C1): the X25519-style clamp applies ONLY
    to the legacy yubtc cascade branch (empty passphrase), keeping
    bit-for-bit parity with pre-passphrase yubtc wallets. The
    BIP-39-compatible branch (non-empty passphrase) feeds the raw
    32-byte BIP-44 leaf to secp256k1 verbatim, so addresses match
    what Trezor/Ledger/Electrum derive for the same
    (mnemonic, passphrase). Mirrors the Rust port's
    `seed2privkey_with_kdf`.
    """
    raw = seed2bin(seed=seed, nonce=nonce, passphrase=passphrase)
    if passphrase:
        return PrivateKey(raw)
    return PrivateKey(bin2privkey(raw))


@require_kwargs_only
def privkey2privwif(privkey: PrivateKey = NotNone) -> str:
    from yubtc.base58check import base58CheckEncode
    # https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#comp_priv
    return base58CheckEncode(
        bytes([PREFIX_PRIVKEY]) + privkey.secret + bytes([SUFFIX_PRIVKEY_COMPRESSED]))


def privwif2privkey(privwif: str) -> PrivateKey:
    from yubtc.base58check import base58CheckDecode
    decoded = base58CheckDecode(privwif)
    if decoded[0] != PREFIX_PRIVKEY:
        raise ValueError('prefix mismatch')
    body = decoded[1:]
    # Compressed WIFs are 33 bytes with the 0x01 suffix; uncompressed WIFs
    # are 32 bytes. Only compressed is supported.
    if len(body) != 33 or body[-1] != SUFFIX_PRIVKEY_COMPRESSED:
        raise ValueError('uncompressed wif not supported')
    return PrivateKey(body[:-1])


def privkey2pubkey(privkey: PrivateKey) -> bytes:
    # 33-byte compressed form: PREFIX_PUBKEY || X. The low bit of the prefix
    # carries the parity of y, so the receiving side can recover the full
    # point on the curve from X alone.
    return privkey.public_key.format(compressed=True)


@require_kwargs_only
def sign_hash(privkey: PrivateKey = NotNone, datahash: bytes = NotNone) -> bytes:
    # hasher=None: sign the 32-byte digest directly. libsecp256k1 already
    # produces DER-encoded, low-s signatures by default.
    return privkey.sign(datahash, hasher=None)


@require_kwargs_only
def sign_data(privkey: PrivateKey = NotNone, data: bytes = NotNone) -> bytes:
    from yubtc.hash import sha256
    # Bitcoin transaction-hash: double-SHA256, then ECDSA.
    return privkey.sign(sha256(sha256(data)), hasher=None)


@require_kwargs_only
def pubkey2addr(pubkey: bytes = NotNone) -> bytes:
    from yubtc.base58check import base58CheckEncode
    from yubtc.hash import hash160
    return base58CheckEncode(bytes([PREFIX_P2PKH]) + hash160(pubkey))


@require_kwargs_only
def privkey2addr(privkey: PrivateKey = NotNone) -> bytes:
    return pubkey2addr(pubkey=privkey2pubkey(privkey))


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
        raise ValueError('address not supported')


class VoutResult(NamedTuple):
    """Output of `make_vout`: the vout list plus the satoshi amounts.

    `cashback` is 0 in the drain branch (no change output) and the
    genuine cashback value otherwise. `amount` is what leaves the wallet
    for `dst` (the requested amount, or the drained input minus fee in
    drain mode).
    """
    vout: list
    cashback: TSatoshi
    amount: TSatoshi


@require_kwargs_only
def make_vout(src: TAddress = NotNone, dst: TAddress = NotNone,
              in_amount: TSatoshi = NotNone, amount: TSatoshi = None,
              fee: TSatoshi = NotNone) -> VoutResult:
    from yubtc.transaction import COut
    if in_amount < fee:
        # Drain (`amount is None`) lands in the branch below and would
        # compute `amount = in_amount - fee < 0`. Bail out with a message
        # that names both numbers so the operator can see the gap.
        raise ValueError('input does not cover fee')
    if amount is not None and amount + fee > in_amount:
        # Non-drain branch: this is the check that keeps cashback from
        # going negative. The drain branch is gated by the check above.
        raise ValueError('amount + fee exceeds input')
    vout_script = make_lock_script(dst)
    if amount is None or (amount + fee == in_amount):
        amount = in_amount - fee
        return VoutResult(vout=[COut(amount=amount, script=vout_script)],
                          cashback=0, amount=amount)
    else:
        cashback = in_amount - amount - fee
        cashback_lock_script = make_lock_script(src)
        return VoutResult(
            vout=[COut(amount=cashback, script=cashback_lock_script),
                  COut(amount=amount, script=vout_script)],
            cashback=cashback, amount=amount)
