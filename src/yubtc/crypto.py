from typing import NamedTuple, TYPE_CHECKING

from coincurve import PrivateKey

from yubtc.fwd import TAddress, TNonce, TSatoshi, TSeed, TPassphrase, AddrType
from yubtc.util import NotNone, OPTIONAL, require_kwargs_only

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

# --- SegWit / Taproot address constants (Phase 13) --------------------

# Mainnet bech32/bech32m human-readable part (BIP-173/350). Testnet
# (`tb`) is out of scope and rejected on decode. Mirrors
# `address.rs::HRP_MAINNET`.
HRP_MAINNET = 'bc'

# BIP-32 purpose coordinate per address type for BIP-39-compatible
# derivation (spec: pbkdf2 -> m/44' legacy, m/84' native (BIP-84),
# m/86' taproot (BIP-86)). The non-BIP-32 KDFs do not use this table:
# for them the address type is a re-encoding of the same key
# (variant A, spec ОВ-2).
_BIP32_PURPOSE = {
    AddrType.LEGACY: 44,
    AddrType.NATIVE: 84,
    AddrType.TAPROOT: 86,
}

# --- KDF selection (mirrors yubtc core/src/kdf.rs::KdfAlgo) ----------
#
# Four KDFs, one derivation shape for the three passphrase modes:
# stretch the mnemonic to 64 bytes, then take the BIP-44
# receiving-chain leaf at m/44'/0'/0'/0/<nonce>. Only the stretch
# differs, so `nonce` stays meaningful in every mode and one expensive
# stretch per wallet buys cheap BIP-32 walks per address.

KDF_YUBTC = 'yubtc'  # legacy cascade -- empty passphrase only
KDF_PBKDF2 = 'pbkdf2'  # BIP-39 compatible; default for non-empty passphrase
KDF_ARGON2ID = 'argon2id'  # Argon2id stretch, then BIP-44 walk
KDF_SCRYPT = 'scrypt'  # scrypt stretch, then BIP-44 walk
_KDF_ALGOS = (KDF_YUBTC, KDF_PBKDF2, KDF_ARGON2ID, KDF_SCRYPT)

# Frozen KDF parameters (mirrors kdf.rs). Changing any of these changes
# every key the affected KDF has ever produced -- no existing wallet
# would open again.
STRETCH_LEN = 64  # BIP-32 master-key construction expects 64 bytes
ARGON2_SALT_TAG = b'yubtc-argon2id-v1\x00'
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 4
SCRYPT_SALT_TAG = b'yubtc-scrypt-v2\x00'
SCRYPT_LOG_N = 15  # N = 2^15
SCRYPT_R = 16  # r=16 -> 128 * r * N = 64 MiB
SCRYPT_P = 1
# hashlib.scrypt forwards `maxmem` to OpenSSL, whose default cap
# (32 MiB) is below the 64 MiB this frozen KDF legitimately needs.
# 2x headroom over 128 * r * N; the cap never changes the output bytes.
_SCRYPT_MAXMEM = 2 * 128 * SCRYPT_R * (1 << SCRYPT_LOG_N)


class KdfError(ValueError):
    """Base class for typed KDF failures (mirrors
    `yubtc core/src/kdf.rs::KdfError`)."""


class PassphraseRequired(KdfError):
    """The chosen KDF stretches a passphrase; an empty one was
    supplied (mirrors `KdfError::PassphraseRequired`)."""


class EmptyPassphraseIncompatible(KdfError):
    """The legacy yubtc cascade is passphrase-free by definition; a
    non-empty passphrase was supplied (mirrors
    `KdfError::EmptyPassphraseIncompatible`)."""


class Bip32Error(KdfError):
    """BIP-32 derivation failed (mirrors `KdfError::Bip32`)."""


def default_kdf(passphrase: TPassphrase) -> str:
    """Choose the default KDF given a passphrase (mirrors
    `KdfAlgo::default_for`): empty -> 'yubtc' (the legacy cascade,
    bit-for-bit with pre-passphrase wallets), non-empty -> 'pbkdf2'
    (the BIP-39-compatible path)."""
    if passphrase:
        return KDF_PBKDF2
    return KDF_YUBTC


def _stretch_pbkdf2(seed: TSeed, passphrase: TPassphrase) -> bytes:
    """PBKDF2-HMAC-SHA512 with the BIP-39 standard parameters (mirrors
    `kdf.rs::pbkdf2`): NFKD-normalised seed and passphrase, salt
    `b'mnemonic' + passphrase`, 2048 iterations, 64-byte output.
    `pbkdf2_hmac` is infallible for valid inputs."""
    from hashlib import pbkdf2_hmac
    import unicodedata
    seed_bytes = unicodedata.normalize('NFKD', seed).encode('utf-8')
    pass_bytes = unicodedata.normalize('NFKD', passphrase).encode('utf-8')
    return pbkdf2_hmac(
        'sha512',
        seed_bytes,
        b'mnemonic' + pass_bytes,
        2048,
        dklen=STRETCH_LEN,
    )


def _stretch_argon2id(seed: TSeed, passphrase: TPassphrase) -> bytes:
    """Argon2id stretch (the compute step of `kdf.rs::argon2id_bip44`):
    salt `b'yubtc-argon2id-v1\x00' + passphrase`, frozen parameters
    m=64 MiB / t=3 / p=4, Argon2id v0x13, 64-byte output. Neither input
    is NFKD-normalised here -- the Rust side hashes the raw UTF-8
    bytes, so a decomposed passphrase derives a different (but equally
    reproducible) key than its composed form."""
    from argon2.low_level import Type, hash_secret_raw
    return hash_secret_raw(
        secret=seed.encode('utf-8'),
        salt=ARGON2_SALT_TAG + passphrase.encode('utf-8'),
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=STRETCH_LEN,
        type=Type.ID,
    )


def _stretch_scrypt(seed: TSeed, passphrase: TPassphrase) -> bytes:
    """scrypt stretch (the compute step of `kdf.rs::scrypt_bip44`):
    salt `b'yubtc-scrypt-v2\x00' + passphrase`, frozen parameters
    N=2^15 / r=16 (64 MiB) / p=1, 64-byte output. Raw UTF-8 bytes, no
    NFKD -- same convention as the Argon2id stretch."""
    from hashlib import scrypt
    return scrypt(
        seed.encode('utf-8'),
        salt=SCRYPT_SALT_TAG + passphrase.encode('utf-8'),
        n=1 << SCRYPT_LOG_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=STRETCH_LEN,
        maxmem=_SCRYPT_MAXMEM,
    )


# The stretch for each passphrase KDF; the BIP-44 walk after it is shared.
_STRETCH = {
    KDF_PBKDF2: _stretch_pbkdf2,
    KDF_ARGON2ID: _stretch_argon2id,
    KDF_SCRYPT: _stretch_scrypt,
}


def _bip32_leaf(stretched: bytes, nonce: TNonce, purpose: int) -> bytes:
    """Turn 64 stretched bytes into the BIP-32 receiving-chain leaf at
    `m/{purpose}'/0'/0'/0/<nonce>` (mirrors `kdf.rs::bip44_leaf`;
    Phase 13 parameterizes the purpose: 44 legacy, 84 native (BIP-84),
    86 taproot (BIP-86)).

    Every passphrase KDF funnels through here: the expensive stretch
    runs once per wallet, and each additional address costs one cheap
    BIP-32 walk -- which is what keeps address scanning affordable.
    Folding the nonce into the stretch salt instead would re-run the
    stretch per address."""
    from yubtc.bip32 import master_from_seed, derive_path
    if nonce >= 0x80000000:
        # BIP-32 limits non-hardened child indexes to < 2^31. The CLI
        # rejects such nonces upstream, but the library can't assume
        # that (mirrors `kdf.rs::make_bip44_path`).
        raise Bip32Error(
            f'BIP-32 derivation failed: path {nonce}: '
            f'non-hardened child index must be < 2^31')
    master_priv, master_chain = master_from_seed(seed=stretched)
    path = "m/{purpose}'/0'/0'/0/{nonce}".format(purpose=purpose, nonce=nonce)
    child_priv, _ = derive_path(master_priv=master_priv, master_chain=master_chain, path=path)
    return child_priv


def str2bytes(s: str) -> bytes:
    return s.encode('latin-1')


def bytes2str(b: bytes) -> str:
    return ''.join(map(chr, b))


def str2list(s: str) -> list:
    return [c for c in s]


@require_kwargs_only
def seed2bin(seed: TSeed = NotNone,
             nonce: TNonce = NotNone,
             passphrase: TPassphrase = None,
             kdf: str = OPTIONAL,
             addr_type: str = OPTIONAL) -> bytes:
    """KDF: turn `(seed, nonce, passphrase, kdf, addr_type)` into a
    32-byte secret.

    Four derivations, selected by the `kdf` name (mirrors
    `yubtc core/src/kdf.rs::seed2bin`; the names are `KdfAlgo::as_str`):

    - **'yubtc'** -- the legacy `blake2b -> keccak -> sha256` cascade
      over `pack('>L', nonce) || seed` (latin-1). Passphrase-free by
      definition: a non-empty passphrase raises
      `EmptyPassphraseIncompatible`. The output is bit-for-bit
      identical to the pre-passphrase code path, so a wallet that has
      been around since before passphrase support still opens.

    - **'pbkdf2'** -- BIP-39 + BIP-32 + BIP-44. The mnemonic and
      passphrase are NFKD-normalized and UTF-8-encoded, then stretched
      through standard PBKDF2-HMAC-SHA512 (salt `b'mnemonic' +
      passphrase`, 2048 iter, 64 bytes). Any BIP-44 wallet (Trezor,
      Ledger, Electrum, ...) with the same mnemonic and passphrase
      arrives at the same key for the same nonce. An empty passphrase
      raises `PassphraseRequired`.

    - **'argon2id'** -- Argon2id stretch (salt
      `b'yubtc-argon2id-v1\x00' + passphrase`, frozen parameters
      m=64 MiB / t=3 / p=4, v0x13) feeding the same BIP-44 walk.
      Memory-hard, so a stolen mnemonic is far more expensive to
      brute-force on GPU/ASIC. Yubtc-only; empty passphrase raises
      `PassphraseRequired`.

    - **'scrypt'** -- scrypt stretch (salt `b'yubtc-scrypt-v2\x00' +
      passphrase`, frozen parameters N=2^15 / r=16 -> 64 MiB / p=1)
      feeding the same BIP-44 walk. Yubtc-only; empty passphrase raises
      `PassphraseRequired`.

    All three passphrase KDFs share one shape: stretch the mnemonic to
    64 bytes once, then walk `m/{purpose}'/0'/0'/0/<nonce>` -- the
    BIP-44 receiving-chain path -- so `nonce` selects the address
    cheaply in every mode. A `nonce >= 2^31` raises `Bip32Error`
    (BIP-32 caps non-hardened child indexes).

    `kdf` may be omitted: the default is then chosen from the
    passphrase exactly as before this parameter existed (empty ->
    'yubtc', non-empty -> 'pbkdf2'), so existing callers keep deriving
    the same bytes. Passing `kdf` explicitly switches the algorithm --
    and its passphrase compatibility rules -- on. An unknown name
    raises `ValueError`.

    `addr_type` (Phase 13, spec ОВ-2) selects the derivation path for
    the BIP-39-compatible 'pbkdf2' KDF: `legacy` -> `m/44'/0'/0'/0/n`
    (unchanged), `native` -> `m/84'/0'/0'/0/n` (BIP-84), `taproot` ->
    `m/86'/0'/0'/0/n` (BIP-86); all elements hardened from the same
    BIP-39 master, so native/taproot addresses are reproducible by
    external BIP-84/86 wallets. For the non-BIP-32 KDFs ('yubtc',
    'argon2id', 'scrypt') **variant A** applies: the nonce->secret
    mapping does not change and every address type is a re-encoding of
    the same key (consequence, documented in the spec: revealing the
    pubkey in a P2WPKH/P2TR spend links all address types of that key
    on-chain -- cross-type linkability). Omitted `addr_type` means
    `legacy`, keeping every existing derivation byte-for-byte; an
    unknown value raises `ValueError`.
    """
    from yubtc.hash import sha256, keccak256, blake2b256
    from struct import pack
    resolved_addr_type = AddrType.LEGACY if addr_type is OPTIONAL else addr_type
    if resolved_addr_type not in _BIP32_PURPOSE:
        raise ValueError(f'unknown addr type: {resolved_addr_type!r}')
    if kdf is OPTIONAL:
        # Caller did not choose: keep the historic passphrase routing
        # (empty -> legacy cascade, non-empty -> pbkdf2). The branch is
        # gated on the *string* being empty, not on the seed -- a seed
        # of "" is rejected by `TPrivKey` / `Wallet` higher up.
        kdf = default_kdf(passphrase)
    if kdf not in _KDF_ALGOS:
        raise ValueError(f'unknown kdf: {kdf!r}')
    if kdf == KDF_YUBTC:
        if passphrase:
            raise EmptyPassphraseIncompatible(
                'empty passphrase is incompatible with kdf=yubtc '
                '(legacy cascade is passphrase-free)')
        # Backward-compatible path: existing wallets and tests keep
        # producing the same bytes they always did. Variant A (ОВ-2):
        # the addr type re-encodes the same key, the secret is fixed.
        data = pack(">L", nonce) + str2bytes(seed)
        return sha256(keccak256(blake2b256(data)))
    if not passphrase:
        raise PassphraseRequired(f'passphrase required for kdf={kdf}')
    # The stretch is the only thing that differs between the three
    # passphrase KDFs; the BIP-32 walk after it is shared. Only the
    # BIP-39-compatible KDF re-points the purpose per addr type; the
    # yubtc-only KDFs stay on the legacy path for every address type
    # (variant A, ОВ-2).
    purpose = _BIP32_PURPOSE[resolved_addr_type] if kdf == KDF_PBKDF2 else 44
    stretched = _STRETCH[kdf](seed, passphrase)
    return _bip32_leaf(stretched, nonce, purpose)


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
                 passphrase: TPassphrase = '',
                 kdf: str = OPTIONAL,
                 addr_type: str = OPTIONAL) -> PrivateKey:
    """Derive the signing key from `(seed, nonce, passphrase, kdf,
    addr_type)`.

    Clamp policy (decision C1): the X25519-style clamp applies ONLY to
    the legacy yubtc cascade (kdf='yubtc', which includes the default
    when `kdf` is omitted and the passphrase is empty), keeping
    bit-for-bit parity with pre-passphrase yubtc wallets. Every
    BIP-44-leaf KDF ('pbkdf2'/'argon2id'/'scrypt') feeds the raw
    32-byte leaf to secp256k1 verbatim, so addresses match what
    Trezor/Ledger/Electrum derive for the same (mnemonic, passphrase).
    Mirrors the Rust port's `seed2privkey_with_kdf`.

    `kdf` has the same meaning as in `seed2bin` (omit it to keep the
    historic passphrase routing; an unknown name or a passphrase
    incompatibility raises the same errors). `addr_type` likewise
    mirrors `seed2bin`: for 'pbkdf2' it selects the purpose path
    (44/84/86), for the non-BIP-32 KDFs it is variant A -- the same
    key regardless of the address type.
    """
    resolved = default_kdf(passphrase) if kdf is OPTIONAL else kdf
    raw = seed2bin(seed=seed, nonce=nonce, passphrase=passphrase,
                   kdf=resolved, addr_type=addr_type)
    if resolved == KDF_YUBTC:
        return PrivateKey(bin2privkey(raw))
    return PrivateKey(raw)


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


# --- SegWit / Taproot addresses (Phase 13) -----------------------------
#
# Mirror of `yubtc core/src/address.rs` (SegWit half): P2WPKH is
# bech32 (BIP-173) with witness version 0 and a 20-byte hash160
# program; P2TR is bech32m (BIP-350) with witness version 1 and a
# 32-byte x-only output key obtained by the BIP-86 key-path TapTweak.
# Decoding is strict and reports a typed `SegWitAddrError` subclass
# for every malformed case (one subclass per BIP-173/350 rejection
# rule plus the yubtc scope limits).


class SegWitAddrError(ValueError):
    """Base class for typed SegWit-address failures (mirrors
    `yubtc core/src/address.rs::SegWitAddrError`)."""


class SegWitInvalidCharacter(SegWitAddrError):
    """A character outside the printable US-ASCII range or outside the
    bech32 charset."""

    def __init__(self, char):
        self.char = char
        super().__init__(f'invalid character {char!r} in bech32 address')


class SegWitInvalidChecksum(SegWitAddrError):
    """Neither checksum matches -- or the checksum constant does not
    correspond to the witness version (BIP-350 rule 2: v0 -> bech32,
    v1+ -> bech32m)."""


class SegWitMixedCase(SegWitAddrError):
    """The string mixes lowercase and uppercase (BIP-173 decoders MUST
    reject mixed case)."""


class SegWitTooLong(SegWitAddrError):
    """The address exceeds the 90-character BIP-173 limit."""


class SegWitInvalidHrp(SegWitAddrError):
    """The human-readable part is not `bc` (yubtc is mainnet-only)."""


class SegWitInvalidProgramLength(SegWitAddrError):
    """The witness program length violates BIP-141 / the yubtc scope."""


class SegWitUnknownWitnessVersion(SegWitAddrError):
    """The witness version is outside the yubtc v0/v1 scope (versions
    >= 2 parse as valid BIP-350 addresses but are rejected)."""

    def __init__(self, version):
        self.version = version
        super().__init__(f'unknown witness version {version} '
                         f'(yubtc supports v0/v1 only)')


class SegWitUnsupportedProgram(SegWitAddrError):
    """A valid v0 P2WSH address (32-byte program): recognized by the
    parser but explicitly out of scope."""


class SegWitInvalidStructure(SegWitAddrError):
    """The string is structurally malformed: no `1` separator, empty
    HRP, no witness-version character, or a padding violation in the
    5->8 bit regrouping."""


class TapTweakError(ValueError):
    """The BIP-86 TapTweak could not be applied: either the supplied
    internal key is not a valid curve point, or `Q = P + t*G` came out
    as the point at infinity (probability ~2^-128, but reported as a
    typed error rather than crashing -- same policy as the Rust
    `AddressError::TapTweak`)."""


class WitnessProgram(NamedTuple):
    """A decoded native-SegWit witness program (mirrors
    `address.rs::TWitnessProgram`): the `OP_n` witness version plus
    the raw witness program bytes."""
    version: int
    program: bytes


def _tweak_output_key(p, t: int) -> bytes:
    """Add the tweak `t` to the lifted internal key `p` and return the
    x-only output key.

    Split out of `taproot_output_key` (same shape as the Rust
    `address.rs::tweak_output_key`) so the infinity branch stays
    testable with crafted `(P, t)` inputs -- unreachable through real
    keys (p ~ 2^-128)."""
    from coincurve import PrivateKey
    # t == 0 (mod n) is unreachable for a tagged hash (~2^-128);
    # coincurve rejects a zero secret outright, which would surface as
    # a plain ValueError before the combine below.
    try:
        tweaked = p.combine([PrivateKey(t.to_bytes(32, 'big')).public_key])
    except ValueError:
        raise TapTweakError('taproot tweak failed: output key Q is the point '
                            'at infinity (p ~ 2^-128)')
    return tweaked.format(compressed=True)[1:33]


@require_kwargs_only
def taproot_output_key(internal_xonly: bytes = NotNone) -> bytes:
    """Apply the BIP-86 key-path TapTweak to an x-only internal key.

    Contract: returns the 32-byte x-only output key
    `Q = lift_x(x(P)) + tagged_hash("TapTweak", x(P))*G` with the
    Merkle root empty (BIP-86: no script-path commitment).

    Errors: `TapTweakError` when `internal_xonly` is not a valid
    curve point, or when `Q` is the point at infinity (probability
    ~2^-128; reported, never a crash)."""
    from coincurve import PublicKey
    from yubtc.hash import tagged_hash
    from yubtc.bip32 import SECP256K1_N
    internal_xonly = bytes(internal_xonly)
    if len(internal_xonly) != 32:
        raise ValueError(f'internal pubkey must be 32 bytes, got {len(internal_xonly)}')
    # lift_x per BIP-340: an x-only key denotes the even-Y point.
    # Building the 0x02-prefixed SEC1 form and parsing it delegates
    # the on-curve check to libsecp256k1.
    try:
        p = PublicKey(b'\x02' + internal_xonly)
    except ValueError:
        raise TapTweakError('taproot tweak failed: internal pubkey is not a valid curve point')
    t = int.from_bytes(tagged_hash(b'TapTweak', internal_xonly), 'big') % SECP256K1_N
    return _tweak_output_key(p, t)


@require_kwargs_only
def pubkey2segwit_addr(pubkey: bytes = NotNone) -> str:
    """Compressed public key -> mainnet P2WPKH address (`bc1q...`,
    bech32, BIP-173). Mirrors `address.rs::pubkey_to_segwit_address`."""
    from yubtc.bech32 import BECH32, bytes_to_5bit, encode
    from yubtc.hash import hash160
    pubkey = bytes(pubkey)
    if len(pubkey) != 33:
        raise ValueError(f'pubkey must be 33 bytes, got {len(pubkey)}')
    data = bytes([0]) + bytes_to_5bit(data=hash160(pubkey))
    return encode(hrp=HRP_MAINNET, encoding=BECH32, data=data)


@require_kwargs_only
def pubkey2taproot_addr(pubkey: bytes = NotNone) -> str:
    """Compressed public key -> mainnet P2TR address (`bc1p...`,
    bech32m, BIP-350).

    The output key is the BIP-86 key-path TapTweak of the internal key
    (empty Merkle root); only the x coordinate of the input pubkey is
    used, so the 0x02/0x03 prefixes of the same key yield the same
    address. Mirrors `address.rs::pubkey_to_taproot_address`.

    Errors: `TapTweakError` (see `taproot_output_key`)."""
    from yubtc.bech32 import BECH32M, bytes_to_5bit, encode
    pubkey = bytes(pubkey)
    if len(pubkey) != 33:
        raise ValueError(f'pubkey must be 33 bytes, got {len(pubkey)}')
    output_key = taproot_output_key(internal_xonly=pubkey[1:33])
    data = bytes([1]) + bytes_to_5bit(data=output_key)
    return encode(hrp=HRP_MAINNET, encoding=BECH32M, data=data)


def _map_bech32_error(e):
    """Translate a generic bech32 codec error into its SegWit-address
    counterpart (mirrors the match in
    `address.rs::decode_segwit_address`)."""
    from yubtc.bech32 import (Bech32InvalidCharacter, Bech32InvalidChecksum,
                              Bech32MixedCase, Bech32TooLong)
    if isinstance(e, Bech32TooLong):
        return SegWitTooLong('bech32 address longer than 90 characters')
    if isinstance(e, Bech32InvalidCharacter):
        return SegWitInvalidCharacter(e.char)
    if isinstance(e, Bech32MixedCase):
        return SegWitMixedCase('mixed-case bech32 address')
    if isinstance(e, Bech32InvalidChecksum):
        return SegWitInvalidChecksum('bech32 checksum mismatch')
    # InvalidStructure and the encoder-side InvalidDataValue both mean
    # the string never formed a valid address structure.
    return SegWitInvalidStructure('malformed bech32 address structure')


@require_kwargs_only
def decode_segwit_addr(address: str = NotNone) -> WitnessProgram:
    """Strictly decode a mainnet SegWit address (`bc1...`) into its
    witness program. Mirrors
    `address.rs::decode_segwit_address` rule-for-rule, in order:

    1. generic bech32 structure and checksum (length <= 90, printable
       ASCII, no mixed case, `1` separator, charset, bech32/bech32m
       checksum);
    2. the HRP must be `bc` (`SegWitInvalidHrp`);
    3. the 5-bit payload must contain a witness-version value
       (`SegWitInvalidStructure`);
    4. the program must regroup into whole bytes with <= 4 zero
       padding bits and be 2..=40 bytes long
       (`SegWitInvalidStructure` / `SegWitInvalidProgramLength`);
    5. BIP-141 per-version lengths: v0 -> 20 or 32 bytes, otherwise
       `SegWitInvalidProgramLength`;
    6. BIP-350 rule 2: v0 requires the bech32 checksum, v1+ bech32m
       (`SegWitInvalidChecksum`);
    7. yubtc scope: v0/32-byte programs are P2WSH -- parsed but
       rejected (`SegWitUnsupportedProgram`); versions >= 2 are
       rejected (`SegWitUnknownWitnessVersion`).
    """
    from yubtc.bech32 import (BECH32, BECH32M, Bech32Error, five_bit_to_bytes,
                              decode)
    try:
        hrp, encoding, data = decode(s=address)
    except Bech32Error as e:
        raise _map_bech32_error(e) from e
    if hrp != HRP_MAINNET:
        raise SegWitInvalidHrp(f'invalid bech32 human-readable part {hrp!r} '
                               f'(mainnet "bc" only)')
    if not data:
        # No witness-version character at all.
        raise SegWitInvalidStructure('malformed bech32 address structure')
    version = data[0]
    program = five_bit_to_bytes(data=bytes(data[1:]))
    if program is None:
        raise SegWitInvalidStructure('malformed bech32 address structure')
    if len(program) < 2 or len(program) > 40:
        raise SegWitInvalidProgramLength(f'invalid witness program length {len(program)}')
    # Witness versions are 0..=16 (OP_0..OP_16); the 5-bit version
    # value can encode up to 31, which is unrepresentable on-chain.
    if version > 16:
        raise SegWitUnknownWitnessVersion(version)
    if version == 0 and len(program) not in (20, 32):
        raise SegWitInvalidProgramLength(f'invalid witness program length {len(program)}')
    # BIP-350 rule 2: the checksum constant must match the version.
    if version == 0 and encoding != BECH32:
        raise SegWitInvalidChecksum('bech32 checksum mismatch')
    if version != 0 and encoding != BECH32M:
        raise SegWitInvalidChecksum('bech32 checksum mismatch')
    # yubtc scope: P2WPKH (v0/20) and P2TR (v1/32) only.
    if version == 0 and len(program) == 32:
        raise SegWitUnsupportedProgram('P2WSH addresses (witness v0, 32-byte '
                                       'program) are out of scope')
    if version > 1:
        raise SegWitUnknownWitnessVersion(version)
    return WitnessProgram(version=version, program=program)


"""
>>> p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
>>> x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
>>> y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
>>> (x ** 3 + 7) % p == y**2 % p
"""


def make_lock_script(address: TAddress) -> 'CScript':
    """Build the lock script that pays to `address` (mirrors
    `wallet.rs::make_lock_script_for_address` after Phase 13).

    Dispatch on the address form: a `bc1`/`BC1` prefix goes to the
    bech32 path -- witness v0 builds a P2WPKH script, witness v1 a
    P2TR script (typed decode errors propagate); anything else takes
    the unchanged base58check path (P2PKH/P2SH, other version bytes
    raise `ValueError('address not supported')`)."""
    from yubtc.script import (CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY,
                              OP_CHECKSIG, OP_EQUAL, make_p2wpkh_lock_script,
                              make_p2tr_lock_script)
    from yubtc.crypto import PREFIX_P2PKH, PREFIX_P2SH
    from yubtc.misc import unpack_address
    # Legacy call sites pass base58 addresses as `bytes` (the
    # `privkey2addr`/`pubkey2addr` return type); SegWit addresses are
    # strings. Normalise the dispatch to `str`.
    addr_str = address.decode('ascii') if isinstance(address, bytes) else address
    if addr_str.startswith(('bc1', 'BC1')):
        wp = decode_segwit_addr(address=addr_str)
        if wp.version == 0:
            return make_p2wpkh_lock_script(hash160=wp.program)
        return make_p2tr_lock_script(output_key=wp.program)
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
