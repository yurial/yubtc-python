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
    import yubtc.net as net
    import yubtc.wallet as wallet_mod
    sent = MagicMock()
    monkeypatch.setattr(net, 'sendTx', sent)
    # Replace make_transaction with a stub that returns a known tx.
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = privkey2pubkey(privkey=privkey)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=50_000, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubwif)])

    def fake_make_transaction(self, **kwargs):
        return TxResult(tx=fake_tx, cashback=0, amount=50_000, fee=1_000)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)

    output = run(['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'], stdin=SEED + '\ny\n')
    # The hex of the signed tx is printed.
    assert fake_tx.serialize().hex() in output
    # The broadcast stub was never invoked.
    sent.assert_not_called()


def test_send_amount_all_means_none(monkeypatch):
    """Amount=ALL is converted to None before passing to the wallet."""
    import yubtc.wallet as wallet_mod
    captured = {}

    def fake_make_transaction(self, **kwargs):
        captured['amount'] = kwargs['amount']
        from yubtc.transaction import CIn, COut, CTransaction
        from yubtc.crypto import seed2privkey, privkey2pubkey
        privkey = seed2privkey(seed='qwe', nonce=0)
        pubwif = privkey2pubkey(privkey=privkey)
        tx = CTransaction(
            vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
            vout=[COut(amount=0, script=b'\xac')],
            locktime=0,
        ).sign(signers=[(privkey, pubwif)])
        return TxResult(tx=tx, cashback=0, amount=0, fee=1_000)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    run(['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'], stdin=SEED + '\ny\n')
    assert captured['amount'] is None


def test_send_declined_by_user_prints_nothing(monkeypatch):
    """With --broadcast, answering 'n' to the confirm prompt skips sendTx but the dump is still printed."""
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = privkey2pubkey(privkey=privkey)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=0, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubwif)])

    def fake_make_transaction(self, **kwargs):
        return TxResult(tx=fake_tx, cashback=0, amount=50_000, fee=1_000)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)

    sent = MagicMock()
    import yubtc.net as net
    monkeypatch.setattr(net, 'sendTx', sent)

    # --broadcast + 'n' answer -> sendTx is NOT called.
    output = run(['send', '--broadcast', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
                 stdin=SEED + '\nn\n')
    sent.assert_not_called()
    # The dump (id + rawtx) is still printed.
    assert fake_tx.serialize().hex() in output


def test_send_dry_run_does_not_prompt_yesno(monkeypatch):
    """Without --broadcast, no confirmation prompt is asked -- the dump just prints."""
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = privkey2pubkey(privkey=privkey)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=0, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubwif)])

    def fake_make_transaction(self, **kwargs):
        return TxResult(tx=fake_tx, cashback=0, amount=50_000, fee=1_000)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)

    sent = MagicMock()
    import yubtc.net as net
    monkeypatch.setattr(net, 'sendTx', sent)

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
    import yubtc.net as net
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = privkey2pubkey(privkey=privkey)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=0, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubwif)])

    def fake_make_transaction(self, **kwargs):
        return TxResult(tx=fake_tx, cashback=0, amount=50_000, fee=1_000)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)

    # Mock sendTx to record the call.
    sent = MagicMock()
    monkeypatch.setattr(net, 'sendTx', sent)

    # --broadcast combined with 'y' confirmation -> sendTx is called.
    run(['send', '--broadcast', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
        stdin=SEED + '\ny\n')
    sent.assert_called_once()


def test_send_with_scan_flag_passes_scan_to_wallet(monkeypatch):
    """--scan routes through Wallet.send with scan=True."""
    import yubtc.net as net
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = privkey2pubkey(privkey=privkey)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=0, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubwif)])

    captured = {}

    def fake_make_transaction(self, **kwargs):
        captured['scan'] = kwargs.get('scan')
        return TxResult(tx=fake_tx, cashback=0, amount=50_000, fee=1_000)

    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    sent = MagicMock()
    monkeypatch.setattr(net, 'sendTx', sent)

    run(['send', '--scan', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
        stdin=SEED + '\n')
    assert captured['scan'] is True
    sent.assert_not_called()


def test_send_with_scan_and_all_drains(monkeypatch):
    """--scan + ALL drains every scanned UTXO."""
    import yubtc.net as net
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = privkey2pubkey(privkey=privkey)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=80_000, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubwif)])

    captured = {}

    def fake_make_transaction(self, **kwargs):
        captured['amount'] = kwargs.get('amount')
        captured['scan'] = kwargs.get('scan')
        return TxResult(tx=fake_tx, cashback=0, amount=80_000, fee=1_000)

    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    monkeypatch.setattr(net, 'sendTx', MagicMock())

    run(['send', '--scan', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'],
        stdin=SEED + '\n')
    assert captured['scan'] is True
    # amount=None is the drain sentinel.
    assert captured['amount'] is None


def test_send_scan_prints_each_address_like_balance(monkeypatch):
    """`send --scan` emits a per-address line in the same format as `balance`."""
    import yubtc.wallet as wallet_mod
    from yubtc.crypto import seed2privkey, privkey2addr, privkey2pubkey
    from yubtc.transaction import CIn, COut, CTransaction
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

    def fake_make_transaction(self, **kwargs):
        # Run the real scan to drive the on_address callback.
        sources, src = self._scan_inputs(
            target=kwargs['amount'], confirmations=kwargs['confirmations'],
            on_address=kwargs.get('on_address'),
        )
        # Sign a stub tx so make_transaction's tail is happy.
        privkey = seed2privkey(seed=SEED, nonce=0)
        pubkey = privkey2pubkey(privkey=privkey)
        vout_script = bytes.fromhex(script_for(SEED, 1))
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

    import yubtc.net as net
    monkeypatch.setattr(net, 'sendTx', MagicMock())
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
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed=SEED, nonce=0)
    pubkey = privkey2pubkey(privkey=privkey)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=0, script=b'\xac')],
        locktime=0,
    ).sign(signers=[(privkey, pubkey)])

    def fake_make_transaction(self, **kwargs):
        return TxResult(tx=fake_tx, cashback=0, amount=50_000, fee=1_000)

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    import yubtc.net as net
    monkeypatch.setattr(net, 'sendTx', MagicMock())
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)

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
    captured = {}

    def fake_scan_inputs(self, *args, **kwargs):
        captured['target'] = kwargs.get('target')
        captured['confirmations'] = kwargs.get('confirmations')
        # Return one source with a UTXO big enough to cover the 0.001 BTC
        # request (so the feasibility short-circuit doesn't kick in) and
        # the gap-limit cashback address.
        from yubtc.crypto import seed2privkey, privkey2addr
        pk = wallet_mod.TPrivKey(seed='qwe', nonce=0)
        utxo = {
            'tx': 'aa' * 32, 'out_n': 0, 'amount': 1_000_000,
            'confirmations': 10, 'script': '76a914' + 'aa' * 20 + '88ac',
        }
        captured['cashback_addr'] = privkey2addr(
            privkey=seed2privkey(seed='qwe', nonce=1))
        return [(pk, [utxo])], captured['cashback_addr']

    def fake_run_selection(sources, target, fee, feekb, cashback_addr):
        captured['ui_target'] = target
        captured['ui_fee'] = fee
        captured['ui_feekb'] = feekb
        captured['ui_cashback_addr'] = cashback_addr
        # User immediately cancels.
        return None

    def fake_make_transaction(self, **kwargs):
        raise AssertionError('make_transaction should not run after cancel')

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake_scan_inputs)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod, 'run_selection', fake_run_selection)

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
    assert captured['ui_cashback_addr'] == captured['cashback_addr']
    assert 'Cancelled' in output


def test_send_interactive_builds_tx_with_caller_selection(monkeypatch):
    """When the UI returns a selection, make_transaction receives it
    as `sources` plus the gap-limit cashback address."""
    import yubtc.wallet as wallet_mod
    from yubtc.crypto import seed2privkey, privkey2addr, privkey2pubkey
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.hash import hash160

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    cashback = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=1))
    utxo_dict = {
        'tx_hash': 'a' * 64, 'out_n': 0, 'amount': 100_000,
        'confirmations': 10,
        'script': '76a914' + hash160(privkey2pubkey(privkey=pk0.privkey)).hex() + '88ac',
    }

    def fake_scan_inputs(self, *args, **kwargs):
        return [(pk0, [utxo_dict])], cashback

    def fake_make_transaction(self, **kwargs):
        captured_make['sources'] = kwargs.get('sources')
        captured_make['cashback_addr'] = kwargs.get('cashback_addr')
        captured_make['scan'] = kwargs.get('scan')
        privkey = pk0.privkey
        pubkey = privkey2pubkey(privkey=privkey)
        stx = CTransaction(
            vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
            vout=[COut(amount=99_000, script=b'\xac')],
            locktime=0,
        ).sign(signers=[(privkey, pubkey)])
        return TxResult(tx=stx, cashback=0, amount=99_000, fee=1_000)

    captured_make = {}
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake_scan_inputs)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    # UI returns the one available UTXO pre-selected.
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod, 'run_selection',
                        lambda sources, target, fee, feekb, cashback_addr: [(pk0, utxo_dict)])

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


def test_send_interactive_prints_no_funds_when_scan_empty(monkeypatch):
    """If the scan finds nothing, the interactive path prints a notice."""
    import yubtc.wallet as wallet_mod

    def fake_scan_inputs(self, *args, **kwargs):
        return [], b''

    def fake_run_selection(sources, target, fee, feekb):
        raise AssertionError('UI must not run when there are no funds')

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake_scan_inputs)
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod, 'run_selection', fake_run_selection)

    output = run(
        ['send', '-i', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.001'],
        stdin=SEED + '\n',
    )
    assert 'No funds' in output


def test_send_interactive_skips_tui_when_target_unreachable(monkeypatch):
    """When the requested amount exceeds total available UTXOs, skip
    the UI and print an insufficient-funds message naming both numbers."""
    import yubtc.wallet as wallet_mod

    def fake_scan_inputs(self, *args, **kwargs):
        # One source with a tiny UTXO (100 satoshi = 0.00000100 BTC).
        pk = wallet_mod.TPrivKey(seed='qwe', nonce=0)
        utxo = {
            'tx': 'aa' * 32, 'out_n': 0, 'amount': 100,
            'confirmations': 10, 'script': '76a914' + 'aa' * 20 + '88ac',
        }
        return [(pk, [utxo])], b'cashback_addr'

    def fake_run_selection(sources, target, fee, feekb, cashback_addr):
        raise AssertionError('UI must not run when target is unreachable')

    def fake_make_transaction(self, **kwargs):
        raise AssertionError(
            'make_transaction must not run when target is unreachable')

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake_scan_inputs)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod, 'run_selection', fake_run_selection)

    # 0.001 BTC requested, only 0.00000100 BTC available.
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

    def fake_scan_inputs(self, *args, **kwargs):
        pk = wallet_mod.TPrivKey(seed='qwe', nonce=0)
        utxo = {
            'tx': 'aa' * 32, 'out_n': 0, 'amount': 100,
            'confirmations': 10, 'script': '76a914' + 'aa' * 20 + '88ac',
        }
        return [(pk, [utxo])], b'cashback_addr'

    ui_called = []

    def fake_run_selection(sources, target, fee, feekb, cashback_addr):
        # In drain mode target is None -- the UI is reached.
        ui_called.append(target)
        return None  # user cancels

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake_scan_inputs)
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod, 'run_selection', fake_run_selection)

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
    from yubtc.crypto import seed2privkey, privkey2addr, privkey2pubkey
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.hash import hash160

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    cashback = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=1))
    utxo_dict = {
        'tx_hash': 'a' * 64, 'out_n': 0, 'amount': 100_000,
        'confirmations': 10,
        'script': '76a914' + hash160(privkey2pubkey(privkey=pk0.privkey)).hex() + '88ac',
    }

    def fake_scan_inputs(self, *args, **kwargs):
        return [(pk0, [utxo_dict])], cashback

    def fake_make_transaction(self, **kwargs):
        privkey = pk0.privkey
        pubkey = privkey2pubkey(privkey=privkey)
        stx = CTransaction(
            vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
            vout=[COut(amount=99_000, script=b'\xac')],
            locktime=0,
        ).sign(signers=[(privkey, pubkey)])
        return TxResult(tx=stx, cashback=0, amount=99_000, fee=1_000)

    prompts = []

    def fake_yesno(prompt):
        prompts.append(prompt)
        return True

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake_scan_inputs)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod, 'run_selection',
                        lambda sources, target, fee, feekb, cashback_addr: [(pk0, utxo_dict)])
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
    from yubtc.crypto import seed2privkey, privkey2addr, privkey2pubkey
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.hash import hash160

    pk0 = wallet_mod.TPrivKey(seed='qwe', nonce=0)
    cashback = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=1))
    utxo_dict = {
        'tx_hash': 'a' * 64, 'out_n': 0, 'amount': 100_000,
        'confirmations': 10,
        'script': '76a914' + hash160(privkey2pubkey(privkey=pk0.privkey)).hex() + '88ac',
    }

    def fake_scan_inputs(self, *args, **kwargs):
        return [(pk0, [utxo_dict])], cashback

    def fake_make_transaction(self, **kwargs):
        privkey = pk0.privkey
        pubkey = privkey2pubkey(privkey=privkey)
        stx = CTransaction(
            vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
            vout=[COut(amount=99_000, script=b'\xac')],
            locktime=0,
        ).sign(signers=[(privkey, pubkey)])
        return TxResult(tx=stx, cashback=0, amount=99_000, fee=1_000)

    prompts = []

    def fake_yesno(prompt):
        prompts.append(prompt)
        return False

    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda address, **kwargs: [])
    monkeypatch.setattr(wallet_mod.Wallet, '_scan_inputs', fake_scan_inputs)
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod, 'run_selection',
                        lambda sources, target, fee, feekb, cashback_addr: [(pk0, utxo_dict)])
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
