import functools
import inspect


class _NotNoneType:
    """Sentinel type marking a required kwarg.

    A parameter declared as `foo: T = NotNone` is required: the caller
    must pass it explicitly. The decorator checks `kwargs[name] is not
    None` rather than just membership, so the caller's `None` is also
    rejected (a real value, not a missing argument).
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


def _required_kwargs(func) -> tuple:
    """Names of the function's kwargs whose default is `NotNone`.

    A "required" kwarg is one whose default is the `NotNone` sentinel:
    the caller must pass it explicitly. Any other default (`None`, a
    concrete value, or a mutable like `b''`) marks the parameter as
    optional -- it has a real "no value" representation the caller can
    legitimately use, including `None` itself.
    """
    sig = inspect.signature(func)
    params = list(sig.parameters.items())
    if params and params[0][0] in ('self', 'cls'):
        params = params[1:]
    return tuple(
        name for name, param in params
        if param.default is NotNone
    )


def require_kwargs_only(func):
    """Reject positional args and require explicitly-passed kwargs.

    A kwarg is "required" when its default is the `NotNone` sentinel
    declared in this module. The wrapper checks two conditions:
    - `name in kwargs` -- the caller must pass the kwarg explicitly.
    - `kwargs[name] is not None` -- a real value is required; an explicit
      `None` is rejected. The two failure modes produce different messages
      so callers can see whether they forgot the kwarg or passed `None`.

    For methods, the first positional argument (`self` / `cls`) is
    treated as the bound instance and is *not* counted as a positional
    call to the wrapped function -- only positional args past the first
    one trigger the `only kwargs allowed` check.

    Raises the same messages the hand-written checks used before:
    - `Exception('only kwargs allowed')` when the caller passes any
      positional argument beyond `self`/`cls`.
    - `Exception('<name> not set')` for a required kwarg that wasn't
      passed.
    - `Exception('<name> is None')` for a required kwarg that was passed
      explicitly as `None`.
    """
    sig = inspect.signature(func)
    params = list(sig.parameters.items())
    is_method = bool(params) and params[0][0] in ('self', 'cls')
    required = _required_kwargs(func)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if is_method and len(args) > 1:
            raise Exception('only kwargs allowed')
        if not is_method and args:
            raise Exception('only kwargs allowed')
        for name in required:
            if name in kwargs:
                if kwargs[name] is None:
                    raise Exception(f'{name} is None')
            else:
                raise Exception(f'{name} not set')
        return func(*args, **kwargs)

    return wrapper
