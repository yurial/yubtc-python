import pytest
from unittest.mock import MagicMock
from click.testing import CliRunner

import yubtc
import yubtc.net
from yubtc.fwd import TBTC
from yubtc.wallet import TxResult

# Vectors below are the same ones asserted in test_crypto.py, reached through
# the CLI instead of the crypto helpers.
SEED = 'qwe'
ADDRESS = '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
PRIVWIF = 'Kx2X5mom9zTGkQq38v8swx3z5ApAuRnwq4wfyF52Y55v6Ke5dRq5'


def _stub_offline(monkeypatch, unspent=None, info=None, used_nonces=0):
    """Stub out blockchain.info so the CLI can be exercised without network.

    `unspent`: list of fake UTXO dicts to return from `get_address_unspent`.
        Defaults to [] (no UTXOs).
    `info`: dict to return from `get_address_info`. Defaults to a "never used"
        address -- `total_received == 0`.
    `used_nonces`: number of leading nonces to mark as "used" (total_received=1).
        The remainder return the default info. Wallet's seed-scan loop walks
        nonces until it finds an unused address; pin how many are used so the
        loop terminates.

    The mock is keyed on the *address* (not call order) so it stays stable
    across the multiple `is_unused()` calls made by both Wallet.__init__
    and the balance/send loops -- otherwise an address marked "used" during
    init can flip to "unused" the second time it's queried.
    """
    if unspent is None:
        unspent = []
    if info is None:
        info = {'total_received': 0, 'final_balance': 0, 'n_tx': 0}
    used = {'total_received': 1, 'final_balance': 0, 'n_tx': 1}
    from yubtc.crypto import seed2privkey, privkey2addr
    address_for = {n: privkey2addr(privkey=seed2privkey(seed=SEED, nonce=n)).decode('ascii')
                   for n in range(used_nonces)}

    def fake_info(address):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        return used if address in address_for.values() else info
    monkeypatch.setattr(yubtc.net, 'get_address_info', fake_info)
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', lambda address, **kwargs: unspent)


@pytest.fixture
def offline(monkeypatch):
    """Default offline stub: no UTXOs, never-used address."""
    _stub_offline(monkeypatch)


def run(args, stdin=None):
    from yubtc.cli import cli
    result = CliRunner().invoke(cli, args, input=stdin)
    assert result.exit_code == 0, f'{args} failed: {result.exception!r}\n{result.output}'
    return result.output


# ---------------------------------------------------------------------------
# Shared helpers for the `send` tests.
#
# Each `send` test (dry-run, broadcast, --scan, --interactive) needs a fake
# signed tx to feed back from `make_transaction`, and nearly all of them also
# want to stub `make_transaction` itself. The two helpers below capture the
# boilerplate so a test only needs to specify the values it actually cares
# about (output amount, capture dict, etc.).
# ---------------------------------------------------------------------------

def _make_signed_tx(output_amount=0):
    """Build a minimal signed tx with a single output of `output_amount` satoshi.

    Avoids the 8x CIn/COut/CTransaction/sign boilerplate sprinkled across
    the send tests; the body matches the pinned shape every test would
    otherwise write by hand.
    """
    from yubtc.crypto import seed2privkey, privkey2pubkey
    from yubtc.transaction import CIn, COut, CTransaction
    privkey = seed2privkey(seed=SEED, nonce=0)
    pubkey = privkey2pubkey(privkey=privkey)
    return CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=output_amount, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubkey)])


def _stub_make_transaction(monkeypatch, *, tx=None, cashback=0, amount=50_000,
                           fee=1_000, capture=None):
    """Patch `Wallet.make_transaction` to return a known `TxResult`.

    `tx` defaults to a fresh signed tx with the same `amount` as the
    `TxResult` (so tests that assert on `tx.vout[0].amount` against the
    wallet's reported amount work out of the box). Pass an explicit `tx`
    when the test needs a different output amount.

    `capture` (optional dict) is cleared and then updated with the kwargs
    the CLI passes through, so tests can assert on what reached the wallet
    (e.g. that `scan=True` made it, that `amount` was the drain sentinel).
    Returns the `tx` used so the test can assert on its serialised hex.
    """
    if tx is None:
        tx = _make_signed_tx(amount)
    import yubtc.wallet as wallet_mod

    def fake(self, **kwargs):
        if capture is not None:
            capture.clear()
            capture.update(kwargs)
        return TxResult(tx=tx, cashback=cashback, amount=amount, fee=fee)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake)
    return tx


def _make_utxo(nonce=0, amount=100_000, tx_hash=None):
    """Build a fake UTXO dict locked to the address at `nonce` of `SEED`.

    The dict keys match what `get_address_unspent` / `get_unspent` expect
    after the blockchain.info -> wallet shape conversion (`tx_hash`/
    `tx_output_n` + `value` from the API, but the interactive tests use
    the wallet's own `tx`/`out_n`/`amount` field names -- both work,
    this helper returns the post-conversion wallet-shaped form).
    """
    from yubtc.crypto import seed2privkey, privkey2pubkey
    from yubtc.hash import hash160
    privkey = seed2privkey(seed=SEED, nonce=nonce)
    pubkey = privkey2pubkey(privkey=privkey)
    return {
        'tx': tx_hash or 'aa' * 32,
        'tx_hash': tx_hash or 'a' * 64,
        'out_n': 0,
        'tx_output_n': 0,
        'amount': amount,
        'value': amount,
        'confirmations': 10,
        'script': '76a914' + hash160(pubkey).hex() + '88ac',
    }


def _stub_no_network(monkeypatch):
    """Stub the two blockchain.info lookups to return "no funds" everywhere.

    Used by interactive tests that supply their own `_scan_inputs` stub
    and don't need the network stub to do anything specific.
    """
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])


def _stub_run_selection(monkeypatch, return_value):
    """Patch `yubtc.tui.run_selection` to return a fixed value.

    `return_value` can be either:
    - a value to return directly (None for "user cancelled", a list of
      (pk, utxo) for "user selected"), or
    - a callable `(sources, target, fee, feekb, cashback_addr)` whose
      return value is what the UI returns -- useful when the test needs
      to inspect the kwargs the CLI forwarded or assert on side effects.
    """
    import yubtc.tui as tui_mod

    def fake(*a, **kw):
        if callable(return_value):
            return return_value(*a, **kw)
        return return_value
    monkeypatch.setattr(tui_mod, 'run_selection', fake)


def _stub_scan_inputs(monkeypatch, return_value=None, side_effect=None):
    """Patch `Wallet._scan_inputs` to bypass the real walk.

    `return_value` is the `(sources, cashback_addr)` tuple the real method
    would have returned. The interactive tests all skip the scan and feed
    the UI directly, so this is the right point to fake.

    `side_effect`, if given, is a callable `(self, *args, **kwargs) -> tuple`
    that replaces the static return value -- for the rare test that needs
    to inspect what the CLI passed through (e.g. `target`, `confirmations`).
    """
    import yubtc.wallet as wallet_mod
    if side_effect is not None:
        def fake(self, *args, **kwargs):
            return side_effect(self, *args, **kwargs)
        monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake)
    else:
        monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs',
                            lambda self, *args, **kwargs: return_value)


# ---------------------------------------------------------------------------
# address / dumpprivkey / newseed / balance (happy paths).
# ---------------------------------------------------------------------------

def test_address(offline):
    assert ADDRESS in run(['address'], stdin=SEED + '\n')


def test_dumpprivkey(offline):
    output = run(['dumpprivkey'], stdin=SEED + '\n')
    assert ADDRESS in output
    assert PRIVWIF in output


def test_newseed_default_15_words(offline):
    """Default seed length is 15 words."""
    output = run(['newseed'])
    seed, shown = output.strip().split('\n')
    assert len(seed.split()) == 15


def test_newseed_custom_count(offline):
    """-n sets the number of words."""
    output = run(['newseed', '-n', '5'])
    assert len(output.split('\n')[0].split()) == 5


def test_newseed_unique_flag(offline):
    """--unique produces a seed with no duplicate words."""
    output = run(['newseed', '-n', '20', '--unique'])
    seed = output.strip().split('\n')[0]
    words = seed.split()
    assert len(words) == 20
    assert len(set(words)) == 20


def test_newseed_address_matches_seed(offline):
    """newseed must print the address that its own seed derives to at nonce 0."""
    from yubtc.crypto import seed2privkey, privkey2addr
    output = run(['newseed', '-n', '5'])
    seed, shown = output.strip().split('\n')
    assert len(seed.split()) == 5
    expected = privkey2addr(
        privkey=seed2privkey(seed=seed, nonce=0),
    ).decode('ascii')
    assert shown == 'Address: ' + expected


def test_balance(offline):
    assert 'Total:' in run(['balance'], stdin=SEED + '\n')


# ---------------------------------------------------------------------------
# balance: branches driven by unspent / info mocks.
# ---------------------------------------------------------------------------

def test_balance_hides_used_empty_addresses_by_default(monkeypatch):
    """Default balance hides empty-and-used addresses (the common case)."""
    # Nonce 0 is "used" but currently empty (no UTXOs); nonce 1+ is fresh.
    _stub_offline(monkeypatch, unspent=[], info={'total_received': 0, 'n_tx': 0}, used_nonces=1)
    output = run(['balance'], stdin=SEED + '\n')
    # The header line `<nonce># <address>: 0.00000000 BTC` is suppressed.
    assert ADDRESS not in output
    assert 'Total: 0.00000000' in output


def test_balance_shows_used_empty_addresses_with_empty_flag(monkeypatch):
    """-e forces the empty-but-used address to be printed."""
    _stub_offline(monkeypatch, unspent=[], info={'total_received': 0, 'n_tx': 0}, used_nonces=1)
    output = run(['balance', '-e'], stdin=SEED + '\n')
    assert ADDRESS in output
    assert '0.00000000 BTC' in output


def test_balance_shows_unspent_amount(monkeypatch):
    """An address with a real UTXO prints its amount."""
    # The wallet's get_unspent reads fields from the API response: tx_hash,
    # tx_output_n, value, confirmations, script. Convert to wallet's internal
    # format (tx, out_n, amount) before returning.
    raw = [{'tx_hash': 'a' * 64, 'tx_output_n': 0, 'value': 100_000_000,
            'confirmations': 10, 'script': '76a914' + 'aa' * 20 + '88ac'}]
    # Nonce 0 is "used" (has the UTXO); later nonces are unused so wallet
    # init's seed-scan terminates.
    _stub_offline(monkeypatch, unspent=raw, used_nonces=1)
    output = run(['balance'], stdin=SEED + '\n')
    assert '1.00000000 BTC' in output
    assert 'Total: 1.00000000' in output


def test_balance_verbose_prints_each_utxo(monkeypatch):
    """-v prints each (txid, out_n) under the address."""
    raw = [{'tx_hash': 'a' * 64,
            'tx_output_n': 0,
            'value': 50_000,
            'confirmations': 10,
            'script': '76a914' + 'aa' * 20 + '88ac'},
           {'tx_hash': 'b' * 64,
            'tx_output_n': 1,
            'value': 25_000,
            'confirmations': 10,
            'script': '76a914' + 'bb' * 20 + '88ac'},
           ]
    _stub_offline(monkeypatch, unspent=raw, used_nonces=1)
    output = run(['balance', '-v'], stdin=SEED + '\n')
    assert 'a' * 64 in output
    assert 'b' * 64 in output
    assert ':0)' in output
    assert ':1)' in output


def test_balance_filters_low_confirmation_utxos(monkeypatch):
    """UTXOs with confirmations < -c are filtered out by get_unspent."""
    raw = [{'tx_hash': 'a' * 64,
            'tx_output_n': 0,
            'value': 50_000,
            'confirmations': 1,
            'script': '76a914' + 'aa' * 20 + '88ac'},
           {'tx_hash': 'b' * 64,
            'tx_output_n': 1,
            'value': 50_000,
            'confirmations': 10,
            'script': '76a914' + 'bb' * 20 + '88ac'},
           ]
    _stub_offline(monkeypatch, unspent=raw, used_nonces=1)
    # With -c 5 and -v, only the second UTXO's txid is shown.
    output = run(['balance', '-v', '-c', '5'], stdin=SEED + '\n')
    assert 'a' * 64 not in output
    assert 'b' * 64 in output


def test_balance_shows_unused_label_for_unused_addresses(monkeypatch):
    """An address with no history (total_received=0) prints 'unused'."""
    # No UTXOs, no history -- this is the gap-limit address that the
    # wallet pre-generates with -n (default new_addresses=1).
    _stub_offline(monkeypatch, unspent=[], info={'total_received': 0, 'n_tx': 0},
                  used_nonces=0)
    output = run(['balance'], stdin=SEED + '\n')
    # The wallet contains one unused address; it should print 'unused'
    # instead of '0.00000000 BTC' so the operator can tell it apart from
    # a used-but-currently-empty address.
    assert f'0# {ADDRESS}: unused' in output
    assert 'Total: 0.00000000' in output


def test_balance_used_empty_address_keeps_zero_btc_label(monkeypatch):
    """-e shows '0.00000000 BTC' for a used-but-empty address, not 'unused'."""
    _stub_offline(monkeypatch, unspent=[], info={'total_received': 0, 'n_tx': 0},
                  used_nonces=1)
    output = run(['balance', '-e'], stdin=SEED + '\n')
    # Nonce 0 was used (total_received=1) but is now drained: '0.00000000 BTC'.
    assert f'0# {ADDRESS}: 0.00000000 BTC' in output


# ---------------------------------------------------------------------------
# send: the live broadcast path is a stub; pinning the dry-run and
# declined-by-user paths here covers the rest of the function.
# ---------------------------------------------------------------------------

def test_send_dry_run_prints_raw_tx(monkeypatch):
    """Default (no --broadcast) prints the raw tx hex; the network stub is not called."""
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)
    fake_tx = _stub_make_transaction(monkeypatch, amount=50_000)

    output = run(['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'], stdin=SEED + '\n')
    # The hex of the signed tx is printed.
    assert fake_tx.serialize().hex() in output
    # The broadcast stub was never invoked.
    sent.assert_not_called()
    # A dry-run notice is printed so the user sees the tx didn't go to the network.
    assert 'Not broadcast' in output


def test_send_amount_all_means_none(monkeypatch):
    """Amount=ALL is converted to None before passing to the wallet."""
    captured = {}
    _stub_make_transaction(monkeypatch, amount=0, capture=captured)
    run(['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'], stdin=SEED + '\n')
    assert captured['amount'] is None


def test_send_declined_by_user_prints_nothing(monkeypatch):
    """With --broadcast, answering 'n' to the confirm prompt skips sendTx but the dump is still printed."""
    fake_tx = _stub_make_transaction(monkeypatch, amount=50_000)
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    # --broadcast + 'n' answer -> sendTx is NOT called.
    output = run(['send', '--broadcast', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
                 stdin=SEED + '\nn\n')
    sent.assert_not_called()
    # The dump (id + rawtx) is still printed.
    assert fake_tx.serialize().hex() in output
    # Since --broadcast was given, the dry-run notice is NOT printed.
    assert 'Not broadcast' not in output


def test_send_dry_run_does_not_prompt_yesno(monkeypatch):
    """Without --broadcast, no confirmation prompt is asked -- the dump just prints."""
    fake_tx = _stub_make_transaction(monkeypatch, amount=50_000)
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    prompted = []
    import yubtc.misc as misc
    monkeypatch.setattr(misc, 'yesno', lambda q: (prompted.append(q), True)[1])

    output = run(['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
                 stdin=SEED + '\n')
    assert prompted == []
    sent.assert_not_called()
    assert fake_tx.serialize().hex() in output


def test_send_with_broadcast_flag_calls_sendTx(monkeypatch):
    """--broadcast routes the tx through net.sendTx (the stub)."""
    _stub_make_transaction(monkeypatch, amount=50_000)
    # Mock sendTx to record the call.
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    # --broadcast combined with 'y' confirmation -> sendTx is called.
    run(['send', '--broadcast', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
        stdin=SEED + '\ny\n')
    sent.assert_called_once()


def test_send_with_scan_flag_passes_scan_to_wallet(monkeypatch):
    """--scan routes through Wallet.send with scan=True."""
    captured = {}
    _stub_make_transaction(monkeypatch, amount=50_000, capture=captured)
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    run(['send', '--scan', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
        stdin=SEED + '\n')
    assert captured['scan'] is True
    sent.assert_not_called()


def test_send_with_scan_and_all_drains(monkeypatch):
    """--scan + ALL drains every scanned UTXO."""
    captured = {}
    _stub_make_transaction(monkeypatch, amount=80_000, capture=captured)
    monkeypatch.setattr(yubtc.net, 'sendTx', MagicMock())

    run(['send', '--scan', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'],
        stdin=SEED + '\n')
    assert captured['scan'] is True
    # amount=None is the drain sentinel.
    assert captured['amount'] is None


def test_send_scan_prints_each_address_like_balance(monkeypatch):
    """`send --scan` emits a per-address line in the same format as `balance`."""
    from yubtc.crypto import seed2privkey, privkey2addr, privkey2pubkey
    from yubtc.hash import hash160

    def addr_for(seed, nonce):
        return privkey2addr(privkey=seed2privkey(seed=seed, nonce=nonce)).decode('ascii')

    def script_for(seed, nonce):
        pubkey = privkey2pubkey(privkey=seed2privkey(seed=seed, nonce=nonce))
        return '76a914' + hash160(pubkey).hex() + '88ac'

    def fake_unspent(specs):
        def get_unspent(address, **kwargs):
            address = address.decode('ascii') if isinstance(address, bytes) else address
            for n, amts in specs.items():
                if addr_for(SEED, n) == address:
                    return [
                        {'tx_hash': f'{n:064x}'[-64:], 'tx_output_n': i,
                         'value': amt, 'confirmations': 10,
                         'script': script_for(SEED, n)}
                        for i, amt in enumerate(amts)
                    ]
            return []
        return get_unspent

    import yubtc.wallet as wallet_mod

    def fake_make_transaction(self, **kwargs):
        # Run the real scan to drive the on_address callback.
        sources, src = self._scan_inputs(
            target=kwargs['amount'], confirmations=kwargs['confirmations'],
            on_address=kwargs.get('on_address'),
        )
        # Sign a stub tx so make_transaction's tail is happy.
        from yubtc.crypto import seed2privkey, privkey2pubkey
        privkey = seed2privkey(seed=SEED, nonce=0)
        pubkey = privkey2pubkey(privkey=privkey)
        vout_script = bytes.fromhex(script_for(SEED, 1))
        from yubtc.transaction import CIn, COut, CTransaction
        tx = CTransaction(
            vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
            vout=[COut(amount=80_000, script=vout_script)],
            locktime=0,
        ).sign(signers=[(privkey, pubkey)])
        return TxResult(tx=tx, cashback=39_000, amount=80_000, fee=1_000)

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent({0: [60_000], 1: [60_000]}))

    monkeypatch.setattr(yubtc.net, 'sendTx', MagicMock())
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)

    output = run(
        ['send', '--scan', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0008'],
        stdin=SEED + '\n',
    )
    # Per-address lines in the `balance` format: `{nonce}# {addr}: {amount:0.08f} BTC`.
    assert f'0# {addr_for(SEED, 0)}: 0.00060000 BTC' in output
    assert f'1# {addr_for(SEED, 1)}: 0.00060000 BTC' in output


def test_send_without_scan_does_not_emit_per_address_lines(monkeypatch):
    """Without --scan, send does not invoke the per-address on_address path."""
    _stub_make_transaction(monkeypatch, amount=50_000)
    _stub_no_network(monkeypatch)
    monkeypatch.setattr(yubtc.net, 'sendTx', MagicMock())

    output = run(
        ['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
        stdin=SEED + '\n',
    )
    # The format is `{nonce}# {address}: ... BTC`. A plain send with the
    # primary address's nonce=0 line would still match the prefix if the
    # wallet printed its own address. We just verify the per-address
    # balance line never shows up: the tx-id line is the only data line.
    assert '# ' not in output


# ---------------------------------------------------------------------------
# send --interactive: scan to gap, run selection UI, build tx.
# ---------------------------------------------------------------------------


def test_send_interactive_passes_scan_target_none_to_gap(monkeypatch):
    """--interactive always scans to the gap limit (target=None)."""
    import yubtc.wallet as wallet_mod
    from yubtc.crypto import seed2privkey, privkey2addr
    captured = {}

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    cashback = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=1))
    # Big enough UTXO to cover the 0.001 BTC request so the feasibility
    # short-circuit doesn't kick in.
    utxo = _make_utxo(nonce=0, amount=1_000_000, tx_hash='aa' * 32)

    def fake_scan_inputs(self, *args, **kwargs):
        captured['target'] = kwargs.get('target')
        captured['confirmations'] = kwargs.get('confirmations')
        captured['cashback_addr'] = cashback
        return [(pk0, [utxo])], cashback

    def fake_run_selection(sources, target, fee, feekb, cashback_addr):
        captured['ui_target'] = target
        captured['ui_fee'] = fee
        captured['ui_feekb'] = feekb
        captured['ui_cashback_addr'] = cashback_addr
        # User immediately cancels.
        return None

    def fake_make_transaction(self, **kwargs):
        raise AssertionError('make_transaction should not run after cancel')

    _stub_no_network(monkeypatch)
    _stub_scan_inputs(monkeypatch, side_effect=fake_scan_inputs)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    _stub_run_selection(monkeypatch, fake_run_selection)

    output = run(
        ['send', '-i', '-f', '0', '-k', '2000',
         '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.001'],
        stdin=SEED + '\n',
    )
    # Scan was forced to target=None (gap limit), not the user's amount.
    assert captured['target'] is None
    # The UI's target is the exact requested amount (no fee padding).
    assert captured['ui_target'] == 100_000  # 0.001 BTC in satoshi
    # The hard-set fee (0) and feekb (2000) are forwarded.
    assert captured['ui_fee'] == 0
    assert captured['ui_feekb'] == 2000
    # The cashback address from _scan_inputs is forwarded so the UI
    # can show where any change would land.
    assert captured['ui_cashback_addr'] == cashback
    assert 'Cancelled' in output


def test_send_interactive_builds_tx_with_caller_selection(monkeypatch):
    """When the UI returns a selection, make_transaction receives it
    as `sources` plus the gap-limit cashback address."""
    import yubtc.wallet as wallet_mod
    from yubtc.crypto import seed2privkey, privkey2addr

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    cashback = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=1))
    utxo_dict = _make_utxo(nonce=0, amount=100_000, tx_hash='a' * 64)

    captured_make = {}
    _stub_make_transaction(monkeypatch, amount=99_000, capture=captured_make)
    _stub_no_network(monkeypatch)
    _stub_scan_inputs(monkeypatch, ([(pk0, [utxo_dict])], cashback))
    _stub_run_selection(monkeypatch, [(pk0, utxo_dict)])

    output = run(
        ['send', '-i', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'],
        stdin=SEED + '\n',
    )
    # The selected UTXO reaches make_transaction grouped under its key.
    assert captured_make['sources'] == [(pk0, [utxo_dict])]
    assert captured_make['cashback_addr'] == cashback
    # The interactive path passes scan=False because the scan already ran
    # in the CLI to feed the UI.
    assert captured_make['scan'] is False
    # A successful tx prints the id and the raw hex.
    assert 'id:' in output
    assert 'rawtx:' in output
    # Without --broadcast, a dry-run notice is printed.
    assert 'Not broadcast' in output


def test_send_interactive_prints_no_funds_when_scan_empty(monkeypatch):
    """If the scan finds nothing, the interactive path prints a notice."""
    def fake_run_selection(sources, target, fee, feekb):
        raise AssertionError('UI must not run when there are no funds')

    _stub_no_network(monkeypatch)
    _stub_scan_inputs(monkeypatch, ([], b''))
    _stub_run_selection(monkeypatch, fake_run_selection)

    output = run(
        ['send', '-i', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.001'],
        stdin=SEED + '\n',
    )
    assert 'No funds' in output


def test_send_interactive_skips_tui_when_target_unreachable(monkeypatch):
    """When the requested amount exceeds total available UTXOs, skip
    the UI and print an insufficient-funds message naming both numbers."""
    import yubtc.wallet as wallet_mod

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    # Tiny UTXO (100 satoshi = 0.00000100 BTC); the request is 0.001 BTC.
    utxo = _make_utxo(nonce=0, amount=100, tx_hash='aa' * 32)

    def fake_run_selection(sources, target, fee, feekb, cashback_addr):
        raise AssertionError('UI must not run when target is unreachable')

    def fake_make_transaction(self, **kwargs):
        raise AssertionError(
            'make_transaction must not run when target is unreachable')

    _stub_no_network(monkeypatch)
    _stub_scan_inputs(monkeypatch, ([(pk0, [utxo])], b'cashback_addr'))
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    _stub_run_selection(monkeypatch, fake_run_selection)

    output = run(
        ['send', '-i', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.001'],
        stdin=SEED + '\n',
    )
    assert 'Insufficient funds' in output
    # Both amounts appear so the operator sees the gap.
    assert '0.00100000' in output
    assert '0.00000100' in output


def test_send_interactive_drain_mode_skips_feasibility_check(monkeypatch):
    """With amount=ALL (drain mode, target=None), the feasibility
    short-circuit is skipped even if available funds are tiny."""
    import yubtc.wallet as wallet_mod

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    utxo = _make_utxo(nonce=0, amount=100, tx_hash='aa' * 32)

    ui_called = []

    def fake_run_selection(sources, target, fee, feekb, cashback_addr):
        # In drain mode target is None -- the UI is reached.
        ui_called.append(target)
        return None  # user cancels

    _stub_no_network(monkeypatch)
    _stub_scan_inputs(monkeypatch, ([(pk0, [utxo])], b'cashback_addr'))
    _stub_run_selection(monkeypatch, fake_run_selection)

    output = run(
        ['send', '-i', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'],
        stdin=SEED + '\n',
    )
    # The UI ran with target=None (drain).
    assert ui_called == [None]
    assert 'Insufficient funds' not in output
    assert 'Cancelled' in output


def test_send_interactive_broadcast_prompts_and_calls_sendtx(monkeypatch):
    """--interactive + --broadcast: yesno('broadcast?') feeds into sendTx."""
    import yubtc.wallet as wallet_mod
    from yubtc.crypto import seed2privkey, privkey2addr

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    cashback = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=1))
    utxo_dict = _make_utxo(nonce=0, amount=100_000, tx_hash='a' * 64)

    _stub_make_transaction(monkeypatch, amount=99_000)
    prompts = []

    def fake_yesno(prompt):
        prompts.append(prompt)
        return True

    _stub_no_network(monkeypatch)
    _stub_scan_inputs(monkeypatch, ([(pk0, [utxo_dict])], cashback))
    _stub_run_selection(monkeypatch, [(pk0, utxo_dict)])
    import yubtc.misc as misc
    monkeypatch.setattr(misc, 'yesno', fake_yesno)
    monkeypatch.setattr(yubtc.net, 'sendTx', MagicMock())

    run(
        ['send', '-i', '--broadcast', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'],
        stdin=SEED + '\n',
    )
    assert prompts == ['broadcast? ']
    assert yubtc.net.sendTx.called


def test_send_interactive_broadcast_declined_does_not_send(monkeypatch):
    """--interactive + --broadcast + 'n' prompt: sendTx is not called."""
    import yubtc.wallet as wallet_mod
    from yubtc.crypto import seed2privkey, privkey2addr

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    cashback = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=1))
    utxo_dict = _make_utxo(nonce=0, amount=100_000, tx_hash='a' * 64)

    _stub_make_transaction(monkeypatch, amount=99_000)
    prompts = []

    def fake_yesno(prompt):
        prompts.append(prompt)
        return False

    _stub_no_network(monkeypatch)
    _stub_scan_inputs(monkeypatch, ([(pk0, [utxo_dict])], cashback))
    _stub_run_selection(monkeypatch, [(pk0, utxo_dict)])
    import yubtc.misc as misc
    monkeypatch.setattr(misc, 'yesno', fake_yesno)
    sendtx = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sendtx)

    output = run(
        ['send', '-i', '--broadcast', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'],
        stdin=SEED + '\n',
    )
    # The prompt was shown, but the user said no.
    assert prompts == ['broadcast? ']
    sendtx.assert_not_called()
    # The rawtx is still printed so the operator can broadcast by other means.
    assert 'rawtx:' in output


# ---------------------------------------------------------------------------
# __main__ block in cli.py: cli() runs when the module is executed.
# ---------------------------------------------------------------------------


def test_send_interactive_rejects_positional_args():
    """_send_interactive is kwargs-only."""
    from yubtc.cli import _send_interactive
    with pytest.raises(Exception, match='only kwargs allowed'):
        _send_interactive(None)


def test_send_interactive_raises_when_required_kwarg_missing():
    """Each required kwarg has its own 'X not set' guard."""
    from yubtc.cli import _send_interactive
    from yubtc.wallet import Wallet
    base = dict(wallet=Wallet(seed='qwe', nonce=0, new_addresses=1),
                address='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k',
                amount=None, fee=TBTC(0), feekb=2000, confirmations=0,
                broadcast=False)
    for missing in ('wallet', 'address', 'fee', 'feekb',
                    'confirmations', 'broadcast'):
        kwargs = {k: v for k, v in base.items() if k != missing}
        with pytest.raises(Exception, match=f'{missing} not set'):
            _send_interactive(**kwargs)


def test_send_invalid_amount_shows_friendly_error():
    """`-f foo` (where `foo` isn't a number) is caught by click and prints
    a sensible message rather than a Decimal traceback."""
    from yubtc.cli import cli
    result = CliRunner().invoke(cli, ['send', '-f', 'abc', 'ADDR', '0.5'],
                                input=SEED + '\n')
    assert result.exit_code != 0
    # Click wraps the ValueError raised by TBTC() in BadParameter.
    assert 'not a valid BTC amount' in result.output or 'Invalid value' in result.output
# This block was removed from cli.py -- yubtc/__main__.py already invokes
# `cli`, so the guard was redundant. See test_main.py for the real entry-point
# test.
