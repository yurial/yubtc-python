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


NotNone = _NotNoneType()


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
      wrapper doesn't treat any default as "optional").
    - `ValueError('<name> is None')` when a parameter whose default is
      not `None` (i.e. `NotNone` or a concrete value) was passed
      explicitly as `None`. The exception is the `NotNone` sentinel's
      primary signal; concrete-default parameters rarely hit it in
      practice.
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
                raise TypeError(f'{p.name} not set')
            if p.default is not None and kwargs[p.name] is None:
                raise ValueError(f'{p.name} is None')
        return func(*args, **kwargs)

    return wrapper
