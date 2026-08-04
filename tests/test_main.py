"""Tests for __main__.py: the `python -m yubtc` entry point.

The module is just an import + a guarded `cli()` call. Two things to verify:

1. The module imports cleanly and exposes the click `cli` object —
   confirms the binding `cli = ...` is the same object the `cli.py`
   `click.group` decorated, not a re-instantiated wrapper.

2. When run as `__main__` (i.e. `python -m yubtc`), the guarded block
   actually invokes `cli()`. We exercise this with `runpy.run_module`
   and a sentinel `cli` so we can observe the call without binding to
   stdin.
"""
import runpy
import sys
from unittest.mock import MagicMock


def test_main_module_exposes_cli():
    """`from yubtc.cli import cli` makes `cli` a module attribute of __main__."""
    # Drop any cached copy so we observe the import fresh.
    sys.modules.pop('yubtc.__main__', None)
    import yubtc.__main__ as main
    from yubtc.cli import cli
    assert main.cli is cli
    # And it's a click group (has the `.command` decorator registration).
    assert hasattr(main.cli, 'commands')


def test_main_module_invokes_cli_when_run_as_main():
    """Running the module with run_name='__main__' reaches the `cli()` call.

    We replace `yubtc.cli.cli` with a sentinel. The module imports it as
    `from yubtc.cli import cli`, so the sentinel becomes the local `cli`
    in __main__'s namespace. The `if __name__ == '__main__':` block then
    calls our sentinel.
    """
    sentinel = MagicMock(name='cli')
    # Make sure __main__ is fresh so the import rebinds to our sentinel.
    sys.modules.pop('yubtc.__main__', None)

    # The module does `from yubtc.cli import cli`. Pre-seed `yubtc.cli`
    # with a controlled `cli` attribute so the import picks up our sentinel.
    saved_cli_attr = sys.modules['yubtc.cli'].__dict__.get('cli')
    sys.modules['yubtc.cli'].cli = sentinel
    try:
        runpy.run_module('yubtc.__main__', run_name='__main__')
    finally:
        # Restore so other tests aren't poisoned.
        if saved_cli_attr is not None:
            sys.modules['yubtc.cli'].cli = saved_cli_attr

    sentinel.assert_called_once_with()


def test_main_module_skipped_when_imported_normally():
    """The `if __name__ == '__main__':` block is gated on __name__.

    Importing the module (without `run_name='__main__'`) must NOT call
    `cli()`. We verify by importing and asserting the sentinel was never
    invoked.
    """
    sentinel = MagicMock(name='cli')
    saved_cli_attr = sys.modules['yubtc.cli'].__dict__.get('cli')
    sys.modules['yubtc.cli'].cli = sentinel
    try:
        sys.modules.pop('yubtc.__main__', None)
        import yubtc.__main__  # noqa: F401  -- import has the side effect
    finally:
        if saved_cli_attr is not None:
            sys.modules['yubtc.cli'].cli = saved_cli_attr

    sentinel.assert_not_called()
