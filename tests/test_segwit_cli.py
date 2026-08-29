"""Phase 13 stage-2 CLI tests: the `--addr-type` flag and `bc1...`
recipients.

Mirrors the Rust CLI stage-2 tests: `--addr-type {native,taproot,legacy}`
(default native, spec ОВ-1) on `address`/`balance`/`send`/`dumpprivkey`;
the printed addresses follow the selected form while the WIF stays the
variant-A key's (empty-passphrase cascade); `send` accepts `bc1...`
recipients and announces the wire bytes + vsize.

All chain answers are stubbed (offline), and the pinned address strings
are fixed vectors of the `qwe` cascade derivations.
"""
from unittest.mock import MagicMock

import yubtc.net
from yubtc.fwd import AddrType

SEED = 'qwe'
LEGACY = '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
NATIVE = 'bc1qa944k3tpuuqhpst0289rp22znca7m6thu8w4k7'
TAPROOT = 'bc1ph3rjlhtq7zvy92q9s6hjdhdqtlzv3kw7tf3rsql42hh8jad25wdsgw7x8z'
PRIVWIF = 'Kx2X5mom9zTGkQq38v8swx3z5ApAuRnwq4wfyF52Y55v6Ke5dRq5'

_FORMS = (AddrType.LEGACY, AddrType.NATIVE, AddrType.TAPROOT)


def _address_for(seed, nonce, addr_type):
    from yubtc.crypto import privkey2pubkey, seed2privkey
    from yubtc.crypto import pubkey2addr, pubkey2segwit_addr, pubkey2taproot_addr
    pubkey = privkey2pubkey(privkey=seed2privkey(seed=seed, nonce=nonce,
                                                 passphrase=''))
    if addr_type == AddrType.NATIVE:
        return pubkey2segwit_addr(pubkey=pubkey)
    if addr_type == AddrType.TAPROOT:
        return pubkey2taproot_addr(pubkey=pubkey)
    return pubkey2addr(pubkey=pubkey).decode('ascii')


def _stub_offline(monkeypatch, unspent_by_address=None, used_forms=()):
    """Stub the chain: every (nonce < 3, form) is known and unused
    unless `unspent_by_address` gives it UTXOs or it is in
    `used_forms` (marked used-but-empty)."""
    unspent_by_address = unspent_by_address or {}
    info_by_addr = {}
    for nonce in range(3):
        for addr_type in _FORMS:
            address = _address_for(SEED, nonce, addr_type)
            used = (nonce, addr_type) in used_forms
            info_by_addr[address] = {
                'total_received': 1 if used else 0,
                'final_balance': 0, 'n_tx': 1 if used else 0,
            }

    def fake_info(backend, address):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        return info_by_addr.get(address,
                                {'total_received': 0, 'final_balance': 0,
                                 'n_tx': 0})

    def fake_unspent(backend, address, **kwargs):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        return list(unspent_by_address.get(address, []))

    monkeypatch.setattr(yubtc.net, 'get_address_info', fake_info)
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent)


def run(monkeypatch, args, stdin=None):
    from click.testing import CliRunner
    from yubtc.cli import cli
    result = CliRunner().invoke(cli, args, input=stdin)
    assert result.exit_code == 0, \
        f'{args} failed: {result.exception!r}\n{result.output}'
    return result.output


def _stdin():
    return '\n' + SEED + '\n\n'


# ---------------------------------------------------------------------------
# address: --addr-type selects the printed form (default native, ОВ-1)
# ---------------------------------------------------------------------------

def test_address_default_addr_type_is_native(monkeypatch):
    _stub_offline(monkeypatch)
    assert NATIVE in run(monkeypatch, ['address'], stdin=_stdin())


def test_address_legacy_flag_reproduces_v0_1_address(monkeypatch):
    _stub_offline(monkeypatch)
    output = run(monkeypatch, ['address', '--addr-type', 'legacy'],
                 stdin=_stdin())
    assert LEGACY in output
    assert NATIVE not in output


def test_address_taproot_flag_prints_bc1p(monkeypatch):
    _stub_offline(monkeypatch)
    output = run(monkeypatch, ['address', '--addr-type', 'taproot'],
                 stdin=_stdin())
    assert TAPROOT in output
    assert NATIVE not in output


def test_address_passes_addr_type_to_wallet(monkeypatch):
    _stub_offline(monkeypatch)
    import yubtc.cli as cli_mod
    seen = {}

    class SpyWallet(cli_mod.Wallet):
        def __init__(self, **kwargs):
            seen['addr_type'] = kwargs.get('addr_type')
            super().__init__(**kwargs)

    monkeypatch.setattr(cli_mod, 'Wallet', SpyWallet)
    run(monkeypatch, ['address', '--addr-type', 'taproot'], stdin=_stdin())
    assert seen['addr_type'] == AddrType.TAPROOT
    run(monkeypatch, ['address'], stdin=_stdin())
    assert seen['addr_type'] == AddrType.NATIVE


def test_address_rejects_unknown_addr_type(monkeypatch):
    _stub_offline(monkeypatch)
    from click.testing import CliRunner
    from yubtc.cli import cli
    result = CliRunner().invoke(cli, ['address', '--addr-type', 'bech32'],
                                input=_stdin())
    assert result.exit_code != 0
    assert 'bech32' in result.output


# ---------------------------------------------------------------------------
# dumpprivkey: form-aware address, variant-A WIF identical across types
# ---------------------------------------------------------------------------

def test_dumpprivkey_form_aware_address_same_variant_a_wif(monkeypatch):
    _stub_offline(monkeypatch)
    output = run(monkeypatch, ['dumpprivkey', '--addr-type', 'native'],
                 stdin=_stdin())
    assert f'Address: {NATIVE}' in output
    assert PRIVWIF in output
    output = run(monkeypatch, ['dumpprivkey', '--addr-type', 'legacy'],
                 stdin=_stdin())
    assert f'Address: {LEGACY}' in output
    # Variant A (ОВ-2): the same secret -- one WIF for every type.
    assert PRIVWIF in output
    output = run(monkeypatch, ['dumpprivkey'], stdin=_stdin())
    assert f'Address: {NATIVE}' in output


# ---------------------------------------------------------------------------
# balance: per-address lines in the selected form
# ---------------------------------------------------------------------------

def _native_utxo():
    from yubtc.crypto import privkey2pubkey, seed2privkey
    from yubtc.hash import hash160
    pubkey = privkey2pubkey(privkey=seed2privkey(seed=SEED, nonce=0,
                                                 passphrase=''))
    spk = bytes([0x00, 0x14]) + hash160(pubkey)
    return {NATIVE: [{'tx_hash': 'ab' * 32, 'tx_output_n': 0, 'value': 100_000,
                      'confirmations': 6, 'script': spk.hex()}]}


def test_balance_shows_selected_form_addresses(monkeypatch):
    _stub_offline(monkeypatch, unspent_by_address=_native_utxo(),
                  used_forms=((0, AddrType.NATIVE),))
    output = run(monkeypatch, ['balance'], stdin=_stdin())
    assert f'0# {NATIVE}: 0.00100000 BTC' in output
    assert 'Total: 0.00100000' in output
    # The unused gap nonce prints in the selected form as well.
    assert f'1# {_address_for(SEED, 1, AddrType.NATIVE)}: unused' in output


def test_balance_legacy_form(monkeypatch):
    _stub_offline(monkeypatch)
    output = run(monkeypatch, ['balance', '--addr-type', 'legacy'],
                 stdin=_stdin())
    assert f'0# {LEGACY}: unused' in output


# ---------------------------------------------------------------------------
# send: form-aware announce line and bc1... recipients
# ---------------------------------------------------------------------------

def test_send_prints_selected_form_address(monkeypatch):
    _stub_offline(monkeypatch)
    from tests.test_cli import _stub_make_transaction
    _stub_make_transaction(monkeypatch, amount=50_000)
    output = run(monkeypatch, ['send', LEGACY, '0.0005'], stdin=_stdin())
    assert f'Address: {NATIVE}' in output
    # make_transaction still receives the drain/amount contract.
    assert 'rawtx: ' in output


def test_send_threads_addr_type_to_wallet(monkeypatch):
    _stub_offline(monkeypatch)
    import yubtc.cli as cli_mod
    import yubtc.wallet as wallet_mod
    seen = {}

    class SpyWallet(cli_mod.Wallet):
        def __init__(self, **kwargs):
            seen['addr_type'] = kwargs.get('addr_type')
            super().__init__(**kwargs)

    monkeypatch.setattr(cli_mod, 'Wallet', SpyWallet)
    monkeypatch.setattr(wallet_mod.Wallet, 'send', lambda self, **kw: None)
    run(monkeypatch, ['send', '--addr-type', 'taproot', LEGACY, 'ALL'],
        stdin=_stdin())
    assert seen['addr_type'] == AddrType.TAPROOT


def test_send_scan_line_uses_source_form(monkeypatch):
    """`send --scan` prints one `{nonce}# {form addr}` line per
    contributing source, in the source's own form."""
    from yubtc.crypto import privkey2pubkey, seed2privkey
    from yubtc.hash import hash160
    pubkey = privkey2pubkey(privkey=seed2privkey(seed=SEED, nonce=0,
                                                 passphrase=''))
    spk = bytes([0x00, 0x14]) + hash160(pubkey)
    _stub_offline(monkeypatch,
                  unspent_by_address={
                      NATIVE: [{'tx_hash': 'ab' * 32, 'tx_output_n': 0,
                                'value': 60_000, 'confirmations': 6,
                                'script': spk.hex()}]},
                  used_forms=((0, AddrType.NATIVE),))
    import yubtc.wallet as wallet_mod

    def fake_send(self, **kwargs):
        # Force the on_address callback the way make_transaction's scan
        # would: one line per contributing source.
        kwargs['on_address'](self.privkeys[0], self.privkeys[0].get_unspent(
            confirmations=6))
    monkeypatch.setattr(wallet_mod.Wallet, 'send', fake_send)
    output = run(monkeypatch, ['send', '--scan', LEGACY, 'ALL'],
                 stdin=_stdin())
    assert f'0# {NATIVE}: 0.00060000 BTC' in output


def test_send_to_bc1_recipient_builds_witness_tx(monkeypatch):
    """A `bc1q...` recipient produces a signed witness transaction; the
    announced payload is the wire serialization with its vsize."""
    from yubtc.crypto import privkey2pubkey, pubkey2segwit_addr, seed2privkey
    dst = pubkey2segwit_addr(pubkey=privkey2pubkey(
        privkey=seed2privkey(seed='phase13witdst', nonce=0, passphrase='')))
    _stub_offline(monkeypatch, unspent_by_address=_native_utxo(),
                  used_forms=((0, AddrType.NATIVE),))
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)

    output = run(monkeypatch, ['send', dst, '0.0001'], stdin=_stdin())
    sent.assert_not_called()
    assert 'Not broadcast' in output
    assert 'vsize=' in output
    rawtx_line = next(line for line in output.splitlines()
                      if line.startswith('rawtx: '))
    rawtx = bytes.fromhex(rawtx_line.split('rawtx: ')[1])
    # Wire layout: version || 0x00 (marker) || 0x01 (flag) ...
    assert rawtx[4:6] == b'\x00\x01'
    # The witness carries the compressed pubkey of the spending key.
    pubkey = privkey2pubkey(privkey=seed2privkey(seed=SEED, nonce=0,
                                                 passphrase=''))
    assert pubkey in rawtx
    # The output pays the bc1q destination: OP_0 OP_PUSHBYTES_20 <hash>.
    from yubtc.hash import hash160
    dst_script = bytes([0x00, 0x14]) + hash160(privkey2pubkey(
        privkey=seed2privkey(seed='phase13witdst', nonce=0, passphrase='')))
    assert dst_script in rawtx


def test_send_to_bc1p_recipient_builds_taproot_output(monkeypatch):
    """A `bc1p...` recipient produces a P2TR output (34-byte script)."""
    from yubtc.crypto import (privkey2pubkey, pubkey2taproot_addr,
                              seed2privkey, taproot_output_key)
    dst = pubkey2taproot_addr(pubkey=privkey2pubkey(
        privkey=seed2privkey(seed='phase13witdst', nonce=0, passphrase='')))
    _stub_offline(monkeypatch, unspent_by_address=_native_utxo(),
                  used_forms=((0, AddrType.NATIVE),))
    output = run(monkeypatch, ['send', '--yes', dst, '0.0001'],
                 stdin=_stdin())
    rawtx_line = next(line for line in output.splitlines()
                      if line.startswith('rawtx: '))
    rawtx = bytes.fromhex(rawtx_line.split('rawtx: ')[1])
    internal = privkey2pubkey(privkey=seed2privkey(seed='phase13witdst',
                                                   nonce=0, passphrase=''))
    output_key = taproot_output_key(internal_xonly=internal[1:33])
    dst_script = bytes([0x51, 0x20]) + output_key
    assert dst_script in rawtx
