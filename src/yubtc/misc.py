from yubtc.fwd import TSatoshi, TBTC
from yubtc.util import NotNone, require_kwargs_only

raw_input = input

# Returns byte string value, not hex string


def varint(n: int) -> bytes:
    from struct import pack
    if n < 0xfd:
        return pack('<B', n)
    elif n < 0xffff:
        return pack('<cH', b'\xfd', n)
    elif n < 0xffffffff:
        return pack('<cL', b'\xfe', n)
    else:
        return pack('<cQ', b'\xff', n)

# Takes and returns byte string value, not hex string


def varstr(s: bytes) -> bytes:
    return varint(len(s)) + s


def yesno(question: str) -> bool:
    while True:
        choice = raw_input(question).lower()
        if choice[:1] == 'y':
            return True
        elif choice[:1] == 'n':
            return False
        else:
            print("Please respond with 'Yes' or 'No'\n")


def satoshi2btc(satoshi: TSatoshi) -> TBTC:
    return TBTC(satoshi) * TBTC((0, (1,), -8))


def btc2satoshi(btc: TBTC) -> TSatoshi:
    return TSatoshi(btc * TBTC((0, (1,), 8)))


def unpack_address(address) -> tuple:
    from yubtc.base58check import base58CheckDecode
    data = base58CheckDecode(address)
    prefix = data[0]
    dsthash = data[1:]
    return prefix, dsthash


@require_kwargs_only
def is_dust(amount: TSatoshi = NotNone, script: bytes = NotNone) -> bool:
    """Dust check per lock-script form (mirrors `wallet.rs::is_dust`).

    Returns True when `amount` satoshi paid to `script` falls below
    the protocol dust threshold for that script type: P2PKH (25 bytes)
    546, P2SH (23) 540, P2WPKH (22) 294, P2WSH (34, `00 20 ...` -- v0.3)
    330, P2TR (34) 330 -- Bitcoin Core `GetDustThreshold` with
    dustRelayFee 3 sat/kvB. Any other script shape is never flagged
    (the caller's UTXO validation rejects those upstream)."""
    from yubtc.fwd import (DUST_THRESHOLD_P2PKH, DUST_THRESHOLD_P2SH,
                           DUST_THRESHOLD_P2TR, DUST_THRESHOLD_P2WPKH,
                           DUST_THRESHOLD_P2WSH)
    size = len(script)
    if size == 25:
        return amount < DUST_THRESHOLD_P2PKH
    if size == 23:
        return amount < DUST_THRESHOLD_P2SH
    if size == 22:
        return amount < DUST_THRESHOLD_P2WPKH
    if size == 34:
        if script[0] == 0x00:
            return amount < DUST_THRESHOLD_P2WSH
        return amount < DUST_THRESHOLD_P2TR
    return False
