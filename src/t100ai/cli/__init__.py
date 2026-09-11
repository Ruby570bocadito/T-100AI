"""T-100AI CLI - Command Line Interface"""

__all__ = ["app", "run_t100ai"]


def __getattr__(name: str):
    # Import diferido: evita la doble importación de cli.main (y su
    # RuntimeWarning de runpy) cuando se ejecuta `python -m t100ai.cli.main`.
    if name in __all__:
        from . import main

        return getattr(main, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
