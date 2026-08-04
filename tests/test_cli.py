import pytest
from click.testing import CliRunner

# Vectors below are the same ones asserted in test_crypto.py, reached through
# the CLI instead of the crypto helpers.
SEED = 'qwe'
ADDRESS = '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
PRIVWIF = 'Kx2X5mom9zTGkQq38v8swx3z5ApAuRnwq4wfyF52Y55v6Ke5dRq5'


@pytest.fixture
def offline(monkeypatch):
    """Stub out blockchain.info so the CLI can be exercised without network."""
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'final_balance': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent',
                        lambda address, **kwargs: [], raising=False)


def run(args, stdin=None):
    from yubtc.cli import cli
    result = CliRunner().invoke(cli, args, input=stdin)
    assert result.exit_code == 0, f'{args} failed: {result.exception!r}\n{result.output}'
    return result.output


def test_address(offline):
    assert ADDRESS in run(['address'], stdin=SEED + '\n')


def test_dumpprivkey(offline):
    output = run(['dumpprivkey'], stdin=SEED + '\n')
    assert ADDRESS in output
    assert PRIVWIF in output


def test_balance(offline):
    assert 'Total:' in run(['balance'], stdin=SEED + '\n')


def test_newseed_address_matches_seed(offline):
    """newseed must print the address that its own seed derives to at nonce 0."""
    from yubtc.crypto import seed2privkey, privkey2addr
    output = run(['newseed', '-n', '5'])
    seed, shown = output.strip().split('\n')
    assert len(seed.split()) == 5
    expected = privkey2addr(seed2privkey(seed, nonce=0), True).decode('ascii')
    assert shown == 'Address: ' + expected
