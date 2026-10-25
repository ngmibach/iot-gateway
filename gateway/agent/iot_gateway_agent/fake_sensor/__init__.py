"""Gateway-side fake sensor simulator (runs inside ``iotgw-fake-*`` netns)."""

__all__ = ["load_config", "run_simulator"]


def __getattr__(name: str):
    if name in ("load_config", "run_simulator"):
        from . import simulator

        return getattr(simulator, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
