import os
import sys


def get_static_dir() -> str:
    """
    Resolves the actual app/static directory eel serves from, regardless of
    dev vs frozen (PyInstaller) mode and regardless of the process's current
    working directory.

    Screenshots and other runtime-written files must be saved here (not a
    hardcoded relative "app/static") or they silently fail to save when
    running as a frozen exe launched from somewhere other than the project
    root - os.path.join("app", "static", ...) resolves relative to the
    current working directory, which in a frozen onefile build has nothing
    to do with where the app's actual static folder was extracted to.
    """
    if getattr(sys, "frozen", False):
        base = os.path.join(sys._MEIPASS, "app", "static")
        if not os.path.exists(base):
            base = os.path.join(sys._MEIPASS, "static")
        return base
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
