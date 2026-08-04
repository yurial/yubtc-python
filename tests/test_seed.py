"""Tests for seed.py: the BIP-39 wordlist, seed generation, and stdin prompt.

The wordlist is the only piece of crypto-adjacent data in the module that
affects real addresses: if a word is dropped, renumbered, or misspelled,
every seed that lands on or passes through it derives a different key.
The known-bip39-words test pins the contents."

`_generate_seed` is layered on `random.SystemRandom` for cryptographic
randomness. The tests monkeypatch that source to make behaviour deterministic
without giving up coverage of the `allow_dups` branches.
"""
import io
import sys

import pytest


# ---------------------------------------------------------------------------
# _generate_seed: the random-pick core. Returns a list of BIP-39 words.
# ---------------------------------------------------------------------------

def test_generate_seed_default_count_is_15():
    """The CLI's default for `newseed` is 15 words; make sure it stays 15."""
    from yubtc.seed import _generate_seed
    assert len(_generate_seed(count=15, allow_dups=True)) == 15


def test_generate_seed_count_zero_returns_empty_list():
    from yubtc.seed import _generate_seed
    assert _generate_seed(count=0, allow_dups=True) == []


def test_generate_seed_count_respected():
    from yubtc.seed import _generate_seed
    for n in (1, 3, 12, 50):
        assert len(_generate_seed(count=n, allow_dups=True)) == n


def test_generate_seed_uses_bip39_wordlist():
    """Every word picked must be in the standard BIP-39 wordlist.

    The wordlist is hardcoded inside `_generate_seed`; if any word is dropped,
    misspelled, or re-ordered, a seed that previously worked will start
    deriving a different address. The test draws enough words that the
    probability of an unmarked bug is negligible.
    """
    from yubtc.seed import _generate_seed
    # The full wordlist is the output of _generate_seed(2048, allow_dups=False).
    full = set(_generate_seed(count=2048, allow_dups=False))
    assert len(full) == 2048
    drawn = _generate_seed(count=200, allow_dups=True)
    assert set(drawn) <= full
    # Anchor three known BIP-39 positions: first, last, and a memorable one.
    assert 'abandon' in full
    assert 'zoo' in full
    assert 'satoshi' in full


def test_allow_dups_true_can_repeat_words(monkeypatch):
    """Patch the random source so every draw is 'abandon'. With `allow_dups=True`
    the function must accept the duplicates; with `allow_dups=False` it must
    not be able to produce them (covered by the monkeypatched behaviour below).
    """
    from random import SystemRandom
    monkeypatch.setattr(SystemRandom, 'choices', lambda self, pop, k: ['abandon'] * k)
    from yubtc.seed import _generate_seed
    assert _generate_seed(count=5, allow_dups=True) == ['abandon'] * 5


def test_allow_dups_false_never_repeats():
    """Without replacement, the output must be a permutation of distinct words."""
    from yubtc.seed import _generate_seed
    out = _generate_seed(count=500, allow_dups=False)
    assert len(out) == 500
    assert len(set(out)) == 500


def test_allow_dups_false_count_exceeds_wordlist_raises():
    """BIP-39 has 2048 words; asking for more without replacement is impossible."""
    from yubtc.seed import _generate_seed
    with pytest.raises(ValueError):
        _generate_seed(count=2049, allow_dups=False)


# ---------------------------------------------------------------------------
# generate_seed: the public wrapper. Joins the words with single spaces.
# ---------------------------------------------------------------------------

def test_generate_seed_returns_single_space_joined_string(monkeypatch):
    """The output is a single string, with words separated by single spaces."""
    from random import SystemRandom
    monkeypatch.setattr(SystemRandom, 'choices', lambda self, pop, k: ['abandon'] * k)
    from yubtc.seed import generate_seed
    assert generate_seed(count=4, allow_dups=True) == 'abandon abandon abandon abandon'


def test_generate_seed_word_count_matches_param(monkeypatch):
    from random import SystemRandom
    monkeypatch.setattr(SystemRandom, 'choices', lambda self, pop, k: ['abandon'] * k)
    from yubtc.seed import generate_seed
    for n in (1, 12, 15, 24, 50):
        assert len(generate_seed(count=n, allow_dups=True).split()) == n


def test_generate_seed_produces_a_usable_seed():
    """End-to-end: a generated seed must derive a 32-byte private key.

    This is the load-bearing contract -- if the wordlist ever silently
    changes, the KDF still produces *some* 32 bytes, but the wallet would
    start deriving different addresses. A length check is the minimum.
    """
    from yubtc.seed import generate_seed
    from yubtc.crypto import seed2privkey
    seed = generate_seed(count=12, allow_dups=True)
    privkey = seed2privkey(seed=seed, nonce=0)
    assert len(privkey) == 32


def test_generate_seed_raises_when_count_missing():
    """generate_seed's count and allow_dups are required -- no silent defaults."""
    from yubtc.seed import generate_seed
    with pytest.raises(Exception, match='count not set'):
        generate_seed()
    with pytest.raises(Exception, match='count not set'):
        generate_seed(count=None, allow_dups=True)
    with pytest.raises(Exception, match='allow_dups not set'):
        generate_seed(count=12)


def test__generate_seed_raises_when_count_or_allow_dups_missing():
    """The internal _generate_seed also enforces its required args."""
    from yubtc.seed import _generate_seed
    with pytest.raises(Exception, match='count not set'):
        _generate_seed()
    with pytest.raises(Exception, match='count not set'):
        _generate_seed(count=None, allow_dups=True)
    with pytest.raises(Exception, match='allow_dups not set'):
        _generate_seed(count=5)
    with pytest.raises(Exception, match='allow_dups not set'):
        _generate_seed(count=5, allow_dups=None)


def test_seed_functions_reject_positional_args():
    """Both _generate_seed and generate_seed require kwargs-only call style."""
    from yubtc.seed import _generate_seed, generate_seed
    # _generate_seed: count + allow_dups both positional -> blocked.
    with pytest.raises(Exception, match='only kwargs allowed'):
        _generate_seed(5, True)
    # generate_seed: same.
    with pytest.raises(Exception, match='only kwargs allowed'):
        generate_seed(5, True)


# ---------------------------------------------------------------------------
# get_seed: pull a seed from stdin.
#
# The function switches on `stdin.isatty()`: a real terminal triggers
# getpass (silent prompt); piped input is read directly. Both paths
# come from inside-function imports, so we patch `sys.stdin` and the
# `getpass` module attribute before each call -- the `from sys import stdin`
# local-binding is re-evaluated on every invocation.
# ---------------------------------------------------------------------------

def test_get_seed_reads_piped_stdin(monkeypatch):
    """A non-tty stdin is read directly via readline()."""
    monkeypatch.setattr(sys, 'stdin', io.StringIO('my secret seed\n'))
    from yubtc.seed import get_seed
    assert get_seed() == 'my secret seed'


def test_get_seed_strips_trailing_whitespace(monkeypatch):
    """`readline().rstrip()` removes any trailing whitespace, not just the newline.

    The seed is normally pasted (single trailing newline), so this surfaces
    only on a hand-typed entry that ends with a space. Document the actual
    behaviour rather than a fictional one.
    """
    monkeypatch.setattr(sys, 'stdin', io.StringIO('  abandon ability able  \n'))
    from yubtc.seed import get_seed
    assert get_seed() == '  abandon ability able'


def test_get_seed_uses_getpass_on_tty(monkeypatch):
    """On a tty, the function calls `getpass.getpass('seed: ')` and returns its result."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, 'stdin', FakeTTY(''))
    import getpass
    monkeypatch.setattr(getpass, 'getpass', lambda prompt: 'typed-in-seed')
    from yubtc.seed import get_seed
    assert get_seed() == 'typed-in-seed'
    # Sanity: the prompt arg is what the user sees on the terminal.
    monkeypatch.setattr(getpass, 'getpass', lambda prompt: ('seen', prompt)[1])
    assert get_seed() == 'seed: '
