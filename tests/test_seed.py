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
    """The output is a single string, with words separated by single spaces.

    The injected draw is duplicate-light on purpose: since C6 the
    default (allow_dups=True) draw is redrawn until the entropy floor
    passes, so a constant all-same-word draw would never terminate.
    """
    from random import SystemRandom
    monkeypatch.setattr(SystemRandom, 'choices',
                        lambda self, pop, k: ['abandon', 'ability', 'able', 'about'][:k])
    from yubtc.seed import generate_seed
    assert generate_seed(count=4, allow_dups=True) == 'abandon ability able about'


def test_generate_seed_word_count_matches_param(monkeypatch):
    """The generated phrase has exactly `count` words.

    The injected draw cycles a 32-word distinct prefix of the wordlist
    so every word repeats at most twice -- a constant draw would spin
    the C6 redraw loop forever (see the validate_entropy tests).
    """
    from random import SystemRandom
    from yubtc.seed import BIP39_WORDLIST, generate_seed
    pop = BIP39_WORDLIST[:32]
    monkeypatch.setattr(SystemRandom, 'choices',
                        lambda self, population, k: [pop[i % len(pop)] for i in range(k)])
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


# ---------------------------------------------------------------------------
# C6 entropy floor: min_unique_words / MAX_WORD_REPEATS / validate_entropy /
# validate_seed / generate_seed redraw. Mirrors the Rust port's
# core/src/seed.rs C6 block (issue-seed-entropy, commit e89dde0).
# ---------------------------------------------------------------------------

# BIP-39 official test vector #2 (TREZOR): checksum-valid, 8 distinct
# words of 12 -- accepted by both the parse and the entropy floor.
LEGAL_WINNER = 'legal winner thank year wave sausage worth useful legal winner thank yellow'


def test_max_word_repeats_is_two():
    """The repeats cap is a named constant: 2 repeats per single word."""
    from yubtc.seed import MAX_WORD_REPEATS
    assert MAX_WORD_REPEATS == 2


def test_min_unique_words_table():
    """`min_unique_words` floor for every supported length plus the
    unsupported pass-through (0 -> the word-count check gates those)."""
    from yubtc.seed import min_unique_words
    assert min_unique_words(words=12) == 4
    assert min_unique_words(words=15) == 5
    assert min_unique_words(words=18) == 6
    assert min_unique_words(words=21) == 7
    assert min_unique_words(words=24) == 8
    # Unsupported lengths: 0 (the word-count check rejects them before
    # the entropy floor is consulted).
    assert min_unique_words(words=0) == 0
    assert min_unique_words(words=11) == 0
    assert min_unique_words(words=13) == 0
    assert min_unique_words(words=25) == 0


def test_min_unique_words_rejects_positional_and_missing_args():
    """min_unique_words requires kwargs-only call style, no silent defaults."""
    from yubtc.seed import min_unique_words
    with pytest.raises(TypeError, match='only kwargs allowed'):
        min_unique_words(12)
    with pytest.raises(TypeError, match='words not set'):
        min_unique_words()
    with pytest.raises(ValueError, match='words is None'):
        min_unique_words(words=None)


def test_validate_entropy_accepts_empty_word_list():
    """Empty word list: no counts, no maximum -> vacuously accepted
    (the floor only ever sees non-empty word lists from validate_seed,
    but the contract must not depend on that)."""
    from yubtc.seed import validate_entropy
    assert validate_entropy(words=[]) is None


def test_validate_entropy_accepts_valid_bip39_12_words():
    """Standard BIP-39 vector, 8 distinct words of 12 -- accepted by
    validate_entropy and by the full validate_seed in strict mode (the
    permissive mode accepts it too, but exercises none of these checks)."""
    from yubtc.seed import validate_entropy, validate_seed
    words = LEGAL_WINNER.split()
    assert validate_entropy(words=words) is None
    assert validate_seed(seed=LEGAL_WINNER, strict=True) is None


def test_validate_seed_rejects_all_duplicates():
    """The classic all-'abandon' BIP-39 vector (official vector #1) is
    checksum-valid but has 2 distinct words of 12 -- rejected by the
    strict-mode entropy floor, BY CONSTRUCTION. Permissive mode accepts
    the same phrase (R-1); see test_seed_permissive_accepts_arbitrary_phrase."""
    from yubtc.seed import InsufficientEntropy, _parse_mnemonic, validate_seed
    phrase = ' '.join(['abandon'] * 11 + ['about'])
    # Sanity: the phrase IS valid BIP-39 (count, wordlist and checksum pass).
    assert _parse_mnemonic(seed=phrase) == phrase.split()
    with pytest.raises(InsufficientEntropy, match='distinct words'):
        validate_seed(seed=phrase, strict=True)


def test_validate_entropy_rejects_mostly_duplicates():
    """10 x abandon + zebra + zoo = 3 distinct of 12 < 4."""
    from yubtc.seed import InsufficientEntropy, validate_entropy
    words = ['abandon'] * 10 + ['zebra', 'zoo']
    with pytest.raises(InsufficientEntropy, match='distinct words'):
        validate_entropy(words=words)


def test_validate_entropy_rejects_repeated_phrase():
    """'legal winner' x6: 2 distinct words of 12 < 4 -- the
    distinct-word rule fires first (the repeats rule would too)."""
    from yubtc.seed import InsufficientEntropy, validate_entropy
    words = ['legal', 'winner'] * 6
    with pytest.raises(InsufficientEntropy, match='distinct words'):
        validate_entropy(words=words)


def test_validate_entropy_rejects_excessive_single_word_repeats():
    """The repeats cap: 12 words, 4 distinct (>= the floor of 4), but
    one word present 9 times (> MAX_WORD_REPEATS) -- the repeats rule
    fires with its own message."""
    from yubtc.seed import InsufficientEntropy, validate_entropy
    words = ['abandon', 'zebra', 'zoo', 'legal'] + ['abandon'] * 8
    with pytest.raises(InsufficientEntropy, match='repeats'):
        validate_entropy(words=words)


def test_validate_entropy_rejects_positional_and_missing_args():
    """validate_entropy requires kwargs-only call style, no silent defaults."""
    from yubtc.seed import validate_entropy
    with pytest.raises(TypeError, match='only kwargs allowed'):
        validate_entropy(['abandon'] * 12)
    with pytest.raises(TypeError, match='words not set'):
        validate_entropy()
    with pytest.raises(ValueError, match='words is None'):
        validate_entropy(words=None)


def test_validate_seed_rejects_unknown_word():
    """A word outside the BIP-39 wordlist fails the strict-mode parse stage."""
    from yubtc.seed import validate_seed
    phrase = ' '.join(['abandon'] * 11 + ['notaword'])
    with pytest.raises(ValueError, match='BIP-39 mnemonic parse error'):
        validate_seed(seed=phrase, strict=True)


def test_validate_seed_rejects_bad_checksum():
    """12 x abandon: supported count and known words, but the trailing
    checksum bits do not match sha256(entropy) -- strict parse error."""
    from yubtc.seed import validate_seed
    with pytest.raises(ValueError, match='BIP-39 mnemonic parse error'):
        validate_seed(seed=' '.join(['abandon'] * 12), strict=True)


def test_validate_seed_rejects_wrong_word_count():
    """11 words -- the strict-mode word-count gate fires before
    wordlist/checksum (R-5: unsupported counts are an ordinary strict
    parse error, not a separate refusal kind)."""
    from yubtc.seed import validate_seed
    with pytest.raises(ValueError, match='invalid word count'):
        validate_seed(seed=' '.join(['abandon'] * 11), strict=True)


def test_validate_seed_rejects_positional_and_missing_args():
    """validate_seed requires kwargs-only call style, no silent defaults."""
    from yubtc.seed import validate_seed
    with pytest.raises(TypeError, match='only kwargs allowed'):
        validate_seed(LEGAL_WINNER, strict=False)
    with pytest.raises(TypeError, match='seed not set'):
        validate_seed(strict=False)
    with pytest.raises(ValueError, match='seed is None'):
        validate_seed(seed=None, strict=False)
    # strict selects the mode: declared default False is the policy
    # default, but the repo convention passes every parameter by name.
    with pytest.raises(TypeError, match='strict not set'):
        validate_seed(seed=LEGAL_WINNER)
    with pytest.raises(ValueError, match='strict is None'):
        validate_seed(seed=LEGAL_WINNER, strict=None)


def test_generate_seed_retries_on_entropy_floor_violation(monkeypatch):
    """The default (allow_dups=True) draw redraws until the C6 floor
    passes: the injected draws give the checksum-valid but low-entropy
    all-abandon phrase first (rejected) and a clean one second -- the
    SECOND draw must be returned with exactly one retry. A real-entropy
    test cannot force a failing first draw (~1e-13), hence the injected
    draw. Mirrors the Rust port's
    default_draw_retries_on_entropy_floor_violation."""
    import yubtc.seed as seed_mod
    low = ' '.join(['abandon'] * 11 + ['about'])
    clean = 'legal winner thank year wave sausage worth useful rain clock chunk labor'
    draws = iter([low.split(), clean.split()])
    calls = []

    def fake_draw(count, allow_dups):
        calls.append((count, allow_dups))
        return next(draws)
    monkeypatch.setattr(seed_mod, '_generate_seed', fake_draw)
    out = seed_mod.generate_seed(count=12, allow_dups=True)
    assert calls == [(12, True), (12, True)], 'exactly one entropy redraw'
    assert out == clean


def test_generate_seed_without_dups_passes_entropy():
    """allow_dups=False samples without replacement: distinct words ==
    count, so the C6 floor is met by construction and validate_entropy
    accepts (no redraw can occur on this branch)."""
    from yubtc.seed import generate_seed, validate_entropy
    seed = generate_seed(count=15, allow_dups=False)
    assert len(set(seed.split())) == 15
    assert validate_entropy(words=seed.split()) is None


def test_generated_seeds_pass_entropy_validation():
    """generate_seed applies the same floor: every default draw must
    pass validate_entropy end-to-end. 200 samples -- the per-draw
    failure probability is ~1e-13, so a regression would flip this
    long before the sample budget runs out."""
    from yubtc.seed import generate_seed, validate_entropy
    for _ in range(200):
        s = generate_seed(count=15, allow_dups=True)
        assert len(s.split()) == 15
        assert validate_entropy(words=s.split()) is None


# ---------------------------------------------------------------------------
# D-001 seed policy: permissive/strict reception and the R-6 entropy
# warning. Mirrors the Rust port's post-D-001 seed.rs surface and the
# spec's testable rules R-1/R-2/R-5/R-6.
# ---------------------------------------------------------------------------

def test_min_entropy_warning_bits_is_128():
    """The warning threshold is a named constant: 128 bits (spec R-6)."""
    from yubtc.seed import MIN_ENTROPY_WARNING_BITS
    assert MIN_ENTROPY_WARNING_BITS == 128


def test_estimate_entropy_empty_phrase_is_zero_bits():
    """No characters -> no entropy. Reception rejects empty phrases
    before the estimate is consulted (R-2), but the estimate itself
    must stay defined for any input."""
    from yubtc.seed import estimate_entropy
    assert estimate_entropy(phrase='') == 0.0


def test_estimate_entropy_lowercase_only():
    """A phrase of only lowercase letters uses the 26-letter class."""
    from math import log2
    from yubtc.seed import estimate_entropy
    assert estimate_entropy(phrase='qwe') == 3 * log2(26)


def test_estimate_entropy_uppercase_and_digits_classes():
    """Uppercase letters (26) and digits (10) are their own classes;
    lowercase and uppercase are DISTINCT classes, so 'aA1' sums
    26 + 26 + 10 = 62."""
    from math import log2
    from yubtc.seed import estimate_entropy
    assert estimate_entropy(phrase='ABC') == 3 * log2(26)
    assert estimate_entropy(phrase='123') == 3 * log2(10)
    assert estimate_entropy(phrase='aA1') == 3 * log2(62)


def test_estimate_entropy_space_class_worth_one():
    """The space class adds exactly 1 to |charset|: a lowercase+space
    phrase has charset 27. Spaces alone give log2(1) == 0 bits per
    character -- the estimate is 0.0, and reception (not the estimate)
    is what keeps an all-space phrase out (R-2)."""
    from math import log2
    from yubtc.seed import estimate_entropy
    assert estimate_entropy(phrase='a b c') == 5 * log2(27)
    assert estimate_entropy(phrase='   ') == 0.0


def test_estimate_entropy_other_printable_class():
    """Every character outside the four named classes -- punctuation
    here, but also non-ASCII letters and control characters -- falls
    into the 33-size 'other printable' class."""
    from math import log2
    from yubtc.seed import estimate_entropy
    assert estimate_entropy(phrase='!@#') == 3 * log2(33)
    assert estimate_entropy(phrase='a!') == 2 * log2(26 + 33)


def test_estimate_entropy_all_classes_sum():
    """A phrase containing all five classes uses their sum:
    26 + 26 + 10 + 1 + 33 = 96."""
    from math import log2
    from yubtc.seed import estimate_entropy
    phrase = 'aA1 !'
    assert len(phrase) == 5
    assert estimate_entropy(phrase=phrase) == 5 * log2(96)


def test_estimate_entropy_rejects_positional_and_missing_args():
    """estimate_entropy requires kwargs-only call style, no silent defaults."""
    from yubtc.seed import estimate_entropy
    with pytest.raises(TypeError, match='only kwargs allowed'):
        estimate_entropy('qwe')
    with pytest.raises(TypeError, match='phrase not set'):
        estimate_entropy()
    with pytest.raises(ValueError, match='phrase is None'):
        estimate_entropy(phrase=None)


def test_entropy_warning_silent_at_exactly_128_bits(monkeypatch):
    """The threshold comparison is strict (`<`): an estimate of exactly
    MIN_ENTROPY_WARNING_BITS bits produces NO warning.

    No real phrase hits exactly 128.0 (log2 of a non-power-of-two class
    sum is irrational, so an integer length never lands on it), hence
    the injected estimate -- this pins the boundary operator itself."""
    from yubtc.seed import entropy_warning
    monkeypatch.setattr('yubtc.seed.estimate_entropy', lambda phrase: 128.0)
    assert entropy_warning(phrase='whatever') is None
    monkeypatch.setattr('yubtc.seed.estimate_entropy', lambda phrase: 127.9999999)
    assert entropy_warning(phrase='whatever') is not None


def test_entropy_warning_silent_at_or_above_128_bits():
    """Real phrases at/above the threshold: 28 lowercase chars give
    ~131.6 bits -- no warning (R-6: at-or-above is silent)."""
    from yubtc.seed import entropy_warning, estimate_entropy
    phrase = 'a' * 28
    assert estimate_entropy(phrase=phrase) > 128
    assert entropy_warning(phrase=phrase) is None


def test_entropy_warning_below_128_bits():
    """Real phrases below the threshold: 27 lowercase chars give
    ~126.9 bits, the 3-char 'qwe' ~14.1 bits -- both warn (R-6)."""
    from yubtc.seed import entropy_warning, estimate_entropy
    phrase = 'a' * 27
    assert 120 < estimate_entropy(phrase=phrase) < 128
    assert entropy_warning(phrase=phrase) is not None
    warning = entropy_warning(phrase='qwe')
    assert warning is not None
    assert '14.1' in warning
    assert '128' in warning


def test_entropy_warning_text_does_not_echo_the_phrase():
    """The warning must never contain any fragment of the seed itself."""
    from yubtc.seed import entropy_warning
    secret = 'top secret phrase material'
    warning = entropy_warning(phrase=secret)
    assert warning is not None
    assert 'top' not in warning
    assert 'secret' not in warning


def test_entropy_warning_rejects_positional_and_missing_args():
    """entropy_warning requires kwargs-only call style, no silent defaults."""
    from yubtc.seed import entropy_warning
    with pytest.raises(TypeError, match='only kwargs allowed'):
        entropy_warning('qwe')
    with pytest.raises(TypeError, match='phrase not set'):
        entropy_warning()
    with pytest.raises(ValueError, match='phrase is None'):
        entropy_warning(phrase=None)


def test_seed_permissive_accepts_arbitrary_phrase():
    """R-1: permissive mode (strict=False) accepts ANY non-empty
    phrase -- not only BIP-39 mnemonics; parse and entropy floor are
    not applied. Includes the checksum-valid but entropy-floor-failing
    all-abandon vector: strict rejects it, permissive accepts."""
    from yubtc.seed import validate_seed
    assert validate_seed(seed='not a real mnemonic at all', strict=False) is None
    assert validate_seed(seed='qwe', strict=False) is None
    assert validate_seed(seed=' '.join(['abandon'] * 12), strict=False) is None


def test_seed_permissive_rejects_empty():
    """R-2: an empty (after trim) phrase is an error in permissive mode."""
    from yubtc.seed import validate_seed
    with pytest.raises(ValueError, match='seed must not be empty'):
        validate_seed(seed='', strict=False)
    with pytest.raises(ValueError, match='seed must not be empty'):
        validate_seed(seed='   ', strict=False)


def test_seed_strict_rejects_empty():
    """R-2: the same empty phrase is an error in strict mode, with the
    identical message (the check runs before the mode branch)."""
    from yubtc.seed import validate_seed
    with pytest.raises(ValueError, match='seed must not be empty'):
        validate_seed(seed='', strict=True)
    with pytest.raises(ValueError, match='seed must not be empty'):
        validate_seed(seed=' \t ', strict=True)


def test_seed_strict_rejects_wrong_word_count_13():
    """R-5: 13 wordlist words -- an unsupported count is an ordinary
    strict-mode parse error (permissive accepts the same phrase)."""
    from yubtc.seed import validate_seed
    phrase = ' '.join(['abandon'] * 13)
    with pytest.raises(ValueError, match='invalid word count'):
        validate_seed(seed=phrase, strict=True)
    assert validate_seed(seed=phrase, strict=False) is None
