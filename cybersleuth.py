"""
Shim so that `from cybersleuth import tools` works when the package is
installed as an editable install pointing to this directory.
"""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_cybersleuth_tools",
    Path(__file__).parent / "tools.py",
)
tools = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tools)
