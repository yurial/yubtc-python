import functools
import inspect


class _NotNoneType:
    """Sentinel type marking "this parameter must be supplied with a real
    value -- `None` does not count".

    A parameter declared as `foo: T = NotNone` is required: the caller
    must pass it explicitly, and the value must not be `None`. A
    parameter declared as `foo: T = None` is also required (the caller
    must pass it explicitly), but `None` is a legitimate value -- it
    means "the caller decided to pass nothing". A parameter with a
    concrete default (an int, a string, `b''`, ...) is fully optional.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return 'NotNone'

    def __bool__(self) -> bool:
        # `if foo:` would treat a default of NotNone as truthy, but the
        # parameter is "not set" until the caller passes something. Keep
        # the sentinel truthy so defaulting expressions (e.g. `a or b`)
        # don't misbehave if anyone reaches for it.
        return True


class _OptionalType:
    """Sentinel marking a parameter as genuinely optional: the caller
    may omit it entirely, and the wrapped function applies its own
    default behaviour.

    A parameter declared as `foo: T = OPTIONAL` is the one exception to
    the "every parameter is passed explicitly" rule: the wrapper does
    not raise `'foo not set'` when it is missing -- the function simply
    sees the sentinel and resolves the default itself. This exists for
    parameters whose default is a *behaviour* ("pick the value from
    another argument") rather than a constant, and is deliberately
    obscure so it stays rare. An explicit `None` is still rejected
    (`ValueError('foo is None')`), the same as for every other
    parameter whose default is not `None`.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return 'OPTIONAL'

    def __bool__(self) -> bool:
        # `if foo:` would treat the sentinel as falsy, but "not chosen"
        # is not "empty": defaulting expressions (e.g. `foo or fallback`)
        # must not misfire just because the sentinel landed there.
        return True


NotNone = _NotNoneType()
OPTIONAL = _OptionalType()


def require_kwargs_only(func):
    """Reject positional args and require explicitly-passed kwargs.

    Every parameter must be passed by name. A `NameError` substitutes for
    a missing argument -- the call must supply each parameter the
    function declares. The `NotNone` sentinel picks out parameters that
    additionally reject `None` as a value: for those, the wrapper raises
    `ValueError('<name> is None')` instead of forwarding a `None`. The
    check `p.default is not None` covers the `NotNone` sentinel and
    any concrete default (a string, `b''`, an int, ...) -- it skips
    only parameters declared as `= None`, which legitimately accept
    `None`.

    For methods, the first positional argument (`self` / `cls`) is
    treated as the bound instance and is *not* counted as a positional
    call to the wrapped function -- only positional args past the first
    one trigger the `only kwargs allowed` check.

    Raises:
    - `TypeError('only kwargs allowed')` when the caller passes any
      positional argument beyond `self`/`cls`.
    - `TypeError('<name> not set')` for a parameter that wasn't passed
      by name (including parameters with a concrete default -- the
      wrapper doesn't treat any default as "optional"). The single
      exception is a parameter declared `= OPTIONAL` (see
      `_OptionalType`): omitting it is allowed, and the function sees
      the sentinel to resolve its own default behaviour.
    - `ValueError('<name> is None')` when a parameter whose default is
      not `None` (i.e. `NotNone`, `OPTIONAL`, or a concrete value) was
      passed explicitly as `None`. The exception is the `NotNone`
      sentinel's primary signal; concrete-default parameters rarely hit
      it in practice.
    """
    sig = inspect.signature(func)
    params = list(sig.parameters.values())
    is_method = bool(params) and params[0].name in ('self', 'cls')
    required = params[1:] if is_method else params

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if is_method and len(args) > 1:
            raise TypeError('only kwargs allowed')
        if not is_method and args:
            raise TypeError('only kwargs allowed')
        for p in required:
            if p.name not in kwargs:
                if p.default is OPTIONAL:
                    # Genuinely optional: the sentinel reaches the
                    # function, which resolves its own default behaviour.
                    continue
                raise TypeError(f'{p.name} not set')
            if p.default is not None and kwargs[p.name] is None:
                raise ValueError(f'{p.name} is None')
        return func(*args, **kwargs)

    return wrapper
