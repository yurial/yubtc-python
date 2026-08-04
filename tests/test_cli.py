import pytest
from unittest.mock import MagicMock
from click.testing import CliRunner

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
    """
    import yubtc.misc
    if unspent is None:
        unspent = []
    if info is None:
        info = {'total_received': 0, 'final_balance': 0, 'n_tx': 0}
    used = {'total_received': 1, 'final_balance': 0, 'n_tx': 1}
    # The wallet addresses we encounter are at nonce 0, 1, 2, ... in order.
    # Cache the --used_nonces first addresses as "used"; the rest as "fresh".
    counters = {'n': 0}

    def fake_info(address):
        counters['n'] += 1
        return used if counters['n'] <= used_nonces else info
    monkeypatch.setattr(yubtc.misc, 'get_address_info', fake_info)
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', lambda address, **kwargs: unspent)


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
    expected = privkey2addr(privkey=seed2privkey(seed=seed, nonce=0), compressed=True).decode('ascii')
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
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent',
                        lambda address, **kwargs: raw)
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
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
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent',
                        lambda address, **kwargs: raw)
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
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
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent',
                        lambda address, **kwargs: raw)
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    # With -c 5 and -v, only the second UTXO's txid is shown.
    output = run(['balance', '-v', '-c', '5'], stdin=SEED + '\n')
    assert 'a' * 64 not in output
    assert 'b' * 64 in output


# ---------------------------------------------------------------------------
# send: the live broadcast path is a stub; pinning the dry-run and
# declined-by-user paths here covers the rest of the function.
# ---------------------------------------------------------------------------

def test_send_dry_run_prints_raw_tx(monkeypatch):
    """Default (no --send) prints the raw tx hex; the network stub is not called."""
    import yubtc.net as net
    import yubtc.wallet as wallet_mod
    sent = MagicMock()
    monkeypatch.setattr(net, 'sendTx', sent)
    # Replace make_transaction with a stub that returns a known tx.
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=50_000, script=b'\xac')],
        locktime=0,
    ).sign(privkey=privkey, pubwif=pubwif)

    def fake_make_transaction(self, **kwargs):
        return fake_tx, 0, 50_000, 1_000
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
        from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
        privkey = seed2privkey(seed='qwe', nonce=0)
        pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
        tx = CTransaction(
            vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
            vout=[COut(amount=0, script=b'\xac')],
            locktime=0,
        ).sign(privkey=privkey, pubwif=pubwif)
        return tx, 0, 0, 1_000
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    run(['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 'ALL'], stdin=SEED + '\ny\n')
    assert captured['amount'] is None


def test_send_declined_by_user_prints_nothing(monkeypatch):
    """If the user answers 'n' to the confirmation prompt, no tx is printed."""
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=0, script=b'\xac')],
        locktime=0,
    ).sign(privkey=privkey, pubwif=pubwif)

    def fake_make_transaction(self, **kwargs):
        return fake_tx, 0, 50_000, 1_000
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)
    # User says 'no' to the confirmation.
    output = run(['send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
                 stdin=SEED + '\nn\n')
    # The raw tx hex is NOT printed.
    assert fake_tx.serialize().hex() not in output


def test_send_with_broadcast_flag_calls_sendTx(monkeypatch):
    """--send routes the tx through net.sendTx (the stub)."""
    import yubtc.net as net
    import yubtc.wallet as wallet_mod
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
    fake_tx = CTransaction(
        vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=0, script=b'\xac')],
        locktime=0,
    ).sign(privkey=privkey, pubwif=pubwif)

    def fake_make_transaction(self, **kwargs):
        return fake_tx, 0, 50_000, 1_000
    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', fake_make_transaction)

    # Mock sendTx to record the call.
    sent = MagicMock()
    monkeypatch.setattr(net, 'sendTx', sent)

    # --send combined with 'y' confirmation -> sendTx is called.
    run(['send', '--send', '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', '0.0005'],
        stdin=SEED + '\ny\n')
    sent.assert_called_once()


# ---------------------------------------------------------------------------
# __main__ block in cli.py: cli() runs when the module is executed.
# ---------------------------------------------------------------------------
# This block was removed from cli.py -- yubtc/__main__.py already invokes
# `cli`, so the guard was redundant. See test_main.py for the real entry-point
# test.
