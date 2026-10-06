"""
AirBL Web GUI Module.

Provides a web interface for viewing scan results.
"""

__all__ = ["create_app", "run_server"]


def __getattr__(name):
    # Imported lazily: loading .app at package import pulls in tasks -> gluetun,
    # which itself imports airbl.web.state, so `import airbl.gluetun` would fail
    # on the half-initialised module.
    if name in __all__:
        from . import app
        return getattr(app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
