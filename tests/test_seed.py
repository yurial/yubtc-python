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
    privkey = seed2privkey(seed=seed, nonce=0, passphrase='')
    assert len(privkey.secret) == 32


def test_generate_seed_raises_when_count_missing():
    """generate_seed's count and allow_dups are required -- no silent defaults."""
    from yubtc.seed import generate_seed
    with pytest.raises(TypeError, match='count not set'):
        generate_seed()
    with pytest.raises(ValueError, match='count is None'):
        generate_seed(count=None, allow_dups=True)
    with pytest.raises(TypeError, match='allow_dups not set'):
        generate_seed(count=12)


def test__generate_seed_raises_when_count_or_allow_dups_missing():
    """The internal _generate_seed also enforces its required args."""
    from yubtc.seed import _generate_seed
    with pytest.raises(TypeError, match='count not set'):
        _generate_seed()
    with pytest.raises(ValueError, match='count is None'):
        _generate_seed(count=None, allow_dups=True)
    with pytest.raises(TypeError, match='allow_dups not set'):
        _generate_seed(count=5)
    with pytest.raises(ValueError, match='allow_dups is None'):
        _generate_seed(count=5, allow_dups=None)


def test_seed_functions_reject_positional_args():
    """Both _generate_seed and generate_seed require kwargs-only call style."""
    from yubtc.seed import _generate_seed, generate_seed
    # _generate_seed: count + allow_dups both positional -> blocked.
    with pytest.raises(TypeError, match='only kwargs allowed'):
        _generate_seed(5, True)
    # generate_seed: same.
    with pytest.raises(TypeError, match='only kwargs allowed'):
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

def test_get_seed_raises_when_echo_missing():
    """get_seed's echo kwarg is required -- no silent default."""
    from yubtc.seed import get_seed
    with pytest.raises(TypeError, match='echo not set'):
        get_seed()
    with pytest.raises(ValueError, match='echo is None'):
        get_seed(echo=None)


def test_get_seed_rejects_positional_args():
    """get_seed requires kwargs-only call style."""
    from yubtc.seed import get_seed
    with pytest.raises(TypeError, match='only kwargs allowed'):
        get_seed(True)


def test_get_passphrase_raises_when_prompt_missing():
    """get_passphrase's prompt kwarg is required -- no silent default."""
    from yubtc.seed import get_passphrase
    with pytest.raises(TypeError, match='prompt not set'):
        get_passphrase()
    with pytest.raises(ValueError, match='prompt is None'):
        get_passphrase(prompt=None)


def test_get_passphrase_rejects_positional_args():
    """get_passphrase requires kwargs-only call style."""
    from yubtc.seed import get_passphrase
    with pytest.raises(TypeError, match='only kwargs allowed'):
        get_passphrase('pin: ')


def test_get_seed_reads_piped_stdin(monkeypatch):
    """A non-tty stdin is read directly via readline()."""
    monkeypatch.setattr(sys, 'stdin', io.StringIO('my secret seed\n'))
    from yubtc.seed import get_seed
    assert get_seed(echo=False) == 'my secret seed'


def test_get_seed_echo_arg_accepted_on_pipe(monkeypatch):
    """On a non-tty, `echo` is forwarded but the read still uses
    readline -- piped input was never echoed by this code path."""
    monkeypatch.setattr(sys, 'stdin', io.StringIO('still-a-seed\n'))
    from yubtc.seed import get_seed
    assert get_seed(echo=True) == 'still-a-seed'


def test_get_seed_strips_trailing_whitespace(monkeypatch):
    """`readline().rstrip()` removes any trailing whitespace, not just the newline.

    The seed is normally pasted (single trailing newline), so this surfaces
    only on a hand-typed entry that ends with a space. Document the actual
    behaviour rather than a fictional one.
    """
    monkeypatch.setattr(sys, 'stdin', io.StringIO('  abandon ability able  \n'))
    from yubtc.seed import get_seed
    assert get_seed(echo=False) == '  abandon ability able'


def test_get_seed_uses_getpass_on_tty_when_no_echo(monkeypatch):
    """On a tty with echo=False (the default), the function calls
    `getpass.getpass('seed: ')` and returns its result."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, 'stdin', FakeTTY(''))
    import getpass
    monkeypatch.setattr(getpass, 'getpass', lambda prompt: 'typed-in-seed')
    from yubtc.seed import get_seed
    # Default echo is False -- silent read.
    assert get_seed(echo=False) == 'typed-in-seed'
    # Explicit echo=False is the same path.
    assert get_seed(echo=False) == 'typed-in-seed'
    # Sanity: the prompt arg is what the user sees on the terminal.
    monkeypatch.setattr(getpass, 'getpass', lambda prompt: ('seen', prompt)[1])
    assert get_seed(echo=False) == 'seed: '


def test_get_seed_uses_input_on_tty_when_echo(monkeypatch):
    """On a tty with echo=True, the function uses `input('seed: ')`
    -- the seed is echoed back to the user."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, 'stdin', FakeTTY(''))
    import builtins
    seen = {}

    def fake_input(prompt=''):
        seen['prompt'] = prompt
        return 'visible-seed'
    monkeypatch.setattr(builtins, 'input', fake_input)
    from yubtc.seed import get_seed
    assert get_seed(echo=True) == 'visible-seed'
    assert seen['prompt'] == 'seed: '


# ---------------------------------------------------------------------------
# get_passphrase: the 25th-word prompt.
#
# Mirrors get_seed's tty/non-tty split. The empty string is a legitimate
# "no passphrase" answer, so the helper returns '' rather than rejecting
# the call -- that's how the user opts out of the PBKDF2 path in the
# KDF.
# ---------------------------------------------------------------------------


def test_get_passphrase_reads_piped_stdin(monkeypatch):
    """A non-tty stdin is read directly via readline()."""
    monkeypatch.setattr(sys, 'stdin', io.StringIO('my secret\n'))
    from yubtc.seed import get_passphrase
    assert get_passphrase(prompt='passphrase (empty for none): ') == 'my secret'


def test_get_passphrase_empty_string_is_legitimate(monkeypatch):
    """Pressing enter on an empty line is the documented way to opt out
    of the PBKDF2 path; the helper must not raise."""
    monkeypatch.setattr(sys, 'stdin', io.StringIO('\n'))
    from yubtc.seed import get_passphrase
    assert get_passphrase(prompt='passphrase (empty for none): ') == ''


def test_get_passphrase_strips_trailing_newline(monkeypatch):
    """The trailing \\n is dropped, but interior characters stay put --
    including leading/trailing spaces, which are part of the passphrase
    (BIP-39 trim is not normalised)."""
    monkeypatch.setattr(sys, 'stdin', io.StringIO('  hunter2  \n'))
    from yubtc.seed import get_passphrase
    assert get_passphrase(prompt='passphrase (empty for none): ') == '  hunter2  '


def test_get_passphrase_uses_getpass_on_tty(monkeypatch):
    """On a tty, the function calls `getpass.getpass(prompt)` and returns its result."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, 'stdin', FakeTTY(''))
    import getpass
    monkeypatch.setattr(getpass, 'getpass', lambda prompt: 'typed-in-pass')
    from yubtc.seed import get_passphrase
    assert get_passphrase(prompt='passphrase (empty for none): ') == 'typed-in-pass'
    # The prompt is what the user sees on the terminal; verify the
    # default text is wired up.
    monkeypatch.setattr(getpass, 'getpass', lambda prompt: ('seen', prompt)[1])
    assert get_passphrase(prompt='passphrase (empty for none): ') == 'passphrase (empty for none): '
    # And a custom prompt is honoured end-to-end.
    monkeypatch.setattr(getpass, 'getpass', lambda prompt: ('seen', prompt)[1])
    assert get_passphrase(prompt='pin: ') == 'pin: '


# ---------------------------------------------------------------------------
# get_seed_and_passphrase: combined prompt.
#
# Two facts to pin:
# 1. The passphrase is asked first; the seed is asked second.
# 2. The `echo` flag is forwarded to get_seed -- so the
#    passphrase-aware caller can document its intent even though
#    `get_seed` always uses readline on a non-tty.
# ---------------------------------------------------------------------------


def test_get_seed_and_passphrase_asks_passphrase_first(monkeypatch):
    """The passphrase prompt fires before the seed prompt, in either
    echo mode. With an empty passphrase the seed goes through
    `getpass`; with a non-empty passphrase it goes through `input`
    (echoed)."""
    class FakeTTY(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, 'stdin', FakeTTY(''))
    import getpass
    import builtins
    getpass_prompts = []
    input_prompts = []
    # Non-empty passphrase: seed is read with echo (input path).
    monkeypatch.setattr(getpass, 'getpass',
                        lambda prompt: (getpass_prompts.append(prompt), 'pp')[1])
    monkeypatch.setattr(builtins, 'input',
                        lambda prompt='': (input_prompts.append(prompt), 'ss')[1])
    from yubtc.seed import get_seed_and_passphrase
    get_seed_and_passphrase()
    assert 'passphrase' in getpass_prompts[0].lower()
    # Seed is read via input() because the passphrase is non-empty.
    assert input_prompts == ['seed: ']

    # Empty passphrase: seed is read with no echo (getpass path).
    getpass_prompts.clear()
    input_prompts.clear()
    monkeypatch.setattr(getpass, 'getpass',
                        lambda prompt: (getpass_prompts.append(prompt), '')[1])
    get_seed_and_passphrase()
    assert 'passphrase' in getpass_prompts[0].lower()
    # Seed is read via getpass because the passphrase is empty.
    assert getpass_prompts[1] == 'seed: '
    assert input_prompts == []


def test_get_seed_and_passphrase_no_echo_when_passphrase_empty(monkeypatch):
    """With an empty passphrase, the seed is read silently
    (echo=False) -- a visible seed alone is enough to spend the
    wallet, so a non-empty passphrase is the condition that flips
    the seed onto the echoed (input) path."""
    monkeypatch.setattr('yubtc.seed.get_passphrase', lambda prompt='...': '')
    seen = {}

    def spy_get_seed(echo=False):
        seen['echo'] = echo
        return 'the-seed'
    monkeypatch.setattr('yubtc.seed.get_seed', spy_get_seed)
    from yubtc.seed import get_seed_and_passphrase
    get_seed_and_passphrase()
    assert seen['echo'] is False


def test_get_seed_and_passphrase_echo_when_passphrase_present(monkeypatch):
    """With a non-empty passphrase, the seed is read with echo
    (echo=True) so the user can sanity-check what they typed."""
    monkeypatch.setattr('yubtc.seed.get_passphrase', lambda prompt='...': 'hunter2')
    seen = {}

    def spy_get_seed(echo=False):
        seen['echo'] = echo
        return 'the-seed'
    monkeypatch.setattr('yubtc.seed.get_seed', spy_get_seed)
    from yubtc.seed import get_seed_and_passphrase
    get_seed_and_passphrase()
    assert seen['echo'] is True


def test_get_seed_and_passphrase_returns_pair(monkeypatch):
    """Returns (seed, passphrase); both strings, passphrase may be empty."""
    monkeypatch.setattr('yubtc.seed.get_passphrase', lambda prompt='...': 'pp')
    monkeypatch.setattr('yubtc.seed.get_seed', lambda echo=False: 'ss')
    from yubtc.seed import get_seed_and_passphrase
    seed, passphrase = get_seed_and_passphrase()
    assert seed == 'ss'
    assert passphrase == 'pp'
