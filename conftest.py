"""
conftest.py — root-level pytest configuration.

Problem: the repo root contains detector.py, types.py, gateway.py, etc.
When pytest adds the repo root to sys.path, those files shadow
`aacp_protocol.detector`, `aacp_protocol.types`, etc., causing ImportError
or silent wrong-module imports.

Fix: insert the repo root AFTER the package so Python resolves
`aacp_protocol.*` from the package directory first, and removes any
accidental import of the root-level shadow files.
"""
import sys
import os

# Ensure the repo root is on sys.path so `aacp_protocol` is importable
# as an installed package (src layout not used here).
root = os.path.dirname(os.path.abspath(__file__))
if root not in sys.path:
    sys.path.insert(0, root)

# Guard: if somehow a root-level module got imported under the package name,
# remove it so the real package module takes precedence.
_SHADOW_MODULES = [
    "detector", "types", "gateway", "policy", "audit",
    "provenance", "llm_detector",
]
for _mod in _SHADOW_MODULES:
    # Only evict if the loaded module's file is NOT inside aacp_protocol/
    if _mod in sys.modules:
        loaded = sys.modules[_mod]
        mod_file = getattr(loaded, "__file__", "") or ""
        if "aacp_protocol" not in mod_file:
            del sys.modules[_mod]
