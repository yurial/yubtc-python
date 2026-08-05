## Migration discipline

When swapping a self-written module for a third-party library, only remove
functions that the new library actually implements. Don't remove protocol-
specific logic on the assumption that the library covers it: e.g. Bitcoin
transaction hashing is `double-SHA256`, not `ECDSA`, and the `coincurve`
signing primitive does not include that prefix.

If a migration goes sideways, the user can ask to roll back. Don't try to
partially rescue a bad migration — full rollback is the default.

## Quality gates

The CI enforces:
- 100% line + branch coverage (`fail_under = 100` in `pyproject.toml`).
- `flake8 --max-line-length=120` against `src/yubtc` and `tests`.

If a guard is loosened in this repo, that's a deliberate change, not a
mistake to undo.

## API design conventions

These are baked into the codebase by the user, not me. New code should
follow the same shape:
- Required arguments are kwargs-only. Positional calls raise
  `'only kwargs allowed'`.
- Missing required kwargs raise `'X not set'`.
- No silent defaults for required arguments.

## Test conventions

- Tests run fully offline; `yubtc.misc.get_address_info` and
  `get_address_unspent` are monkeypatched.
- Random sources (e.g. `random.SystemRandom.choices`) are monkeypatched when
  the test depends on the chosen value.
- The BIP-39 wordlist is pinned via `test_generate_seed_uses_bip39_wordlist`;
  any change to that list is a balance-breaking event.

## Workflow

- One task per isolated change. Don't bundle unrelated cleanups into a fix.
- After a non-trivial change, run the full test suite (`pytest`) and
  `flake8 src/yubtc tests --max-line-length=120` before reporting completion.
