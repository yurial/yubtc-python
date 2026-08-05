import pytest

from yubtc.util import NotNone, require_kwargs_only


def test_require_kwargs_only_rejects_positional_args():
    @require_kwargs_only
    def f(foo=NotNone):
        return foo

    with pytest.raises(Exception, match='only kwargs allowed'):
        f('positional')


def test_require_kwargs_only_rejects_missing_required_kwarg():
    @require_kwargs_only
    def f(foo=NotNone, bar=NotNone):
        return (foo, bar)

    with pytest.raises(Exception, match='foo not set'):
        f(bar=1)
    with pytest.raises(Exception, match='bar not set'):
        f(foo=1)


def test_require_kwargs_only_rejects_explicit_none_for_required_kwarg():
    """An explicit `None` is rejected for a param declared with `= NotNone`.

    The `NotNone` default says "the caller must pass a real value here";
    `None` does not satisfy that. `= None` (or any other concrete default)
    is the way to declare a param that legitimately accepts `None`.
    The error distinguishes "not passed" from "passed None".
    """
    @require_kwargs_only
    def f(foo=NotNone):
        return foo

    with pytest.raises(Exception, match='foo is None'):
        f(foo=None)


def test_require_kwargs_only_returns_value_when_all_set():
    @require_kwargs_only
    def f(foo=NotNone, bar=NotNone):
        return foo + bar

    assert f(foo=2, bar=3) == 5


def test_require_kwargs_only_ignores_extra_kwargs():
    """Extra kwargs beyond the required set are passed through untouched."""
    @require_kwargs_only
    def f(foo=NotNone, **kwargs):
        return (foo, kwargs)

    assert f(foo=1, extra='x') == (1, {'extra': 'x'})


def test_require_kwargs_only_preserves_metadata():
    """`functools.wraps` keeps __name__/__doc__ for debugging/introspection."""
    @require_kwargs_only
    def my_func(foo=NotNone):
        """my doc."""
        return foo

    assert my_func.__name__ == 'my_func'
    assert my_func.__doc__ == 'my doc.'


def test_require_kwargs_only_falsy_non_none_values_pass():
    """`0`, `False`, empty bytes, etc. are not the same as `None`."""
    @require_kwargs_only
    def f(foo=NotNone):
        return foo

    assert f(foo=0) == 0
    assert f(foo=False) is False
    assert f(foo=b'') == b''


def test_require_kwargs_only_only_checks_notnone_default_params():
    """Kwargs with a default other than `NotNone` are optional.

    `= None` declares a param that may legitimately receive `None` (a real
    value); `= 'default'` (or any other concrete value) marks it as
    optional with a fallback. The decorator skips both.
    """
    @require_kwargs_only
    def f(foo=NotNone, none_opt=None, opt='default'):
        return (foo, none_opt, opt)

    assert f(foo=1) == (1, None, 'default')
    assert f(foo=1, none_opt=0, opt='x') == (1, 0, 'x')
    assert f(foo=1, none_opt=None) == (1, None, 'default')
    with pytest.raises(Exception, match='foo not set'):
        f()


def test_require_kwargs_only_skips_self_on_methods():
    """For a method, the bound `self` is not a positional violation."""
    class Thing:
        @require_kwargs_only
        def __init__(self, foo=NotNone, bar=NotNone):
            self.foo = foo
            self.bar = bar

    t = Thing(foo=1, bar=2)
    assert t.foo == 1
    assert t.bar == 2


def test_require_kwargs_only_method_rejects_extra_positional():
    """Positional args past `self` still trigger `only kwargs allowed`."""
    class Thing:
        @require_kwargs_only
        def m(self, foo=NotNone):
            return foo

    t = Thing()
    with pytest.raises(Exception, match='only kwargs allowed'):
        t.m(1)


def test_require_kwargs_only_method_required_kwargs_checked():
    """Required kwargs on methods (other than `self`) are still enforced."""
    class Thing:
        @require_kwargs_only
        def __init__(self, foo=NotNone):
            self.foo = foo

        @require_kwargs_only
        def run(self, x=NotNone):
            return x

    t = Thing(foo=1)
    assert t.run(x=2) == 2
    with pytest.raises(Exception, match='x not set'):
        t.run()
    with pytest.raises(Exception, match='x is None'):
        t.run(x=None)


def test_NotNone_is_singleton():
    """`NotNone` is a single shared instance; identity comparisons work."""
    from yubtc.util import _NotNoneType
    again = _NotNoneType()
    assert again is NotNone


def test_NotNone_repr_and_bool():
    """`repr` prints the sentinel name; `bool` is True so `if default:`
    doesn't mistake "not set" for "falsy"."""
    assert repr(NotNone) == 'NotNone'
    assert bool(NotNone) is True
