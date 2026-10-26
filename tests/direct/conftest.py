import os


if os.name == "nt":
    _original_unlink = os.unlink

    def _safe_unlink(path):
        try:
            _original_unlink(path)
        except PermissionError:
            # gltest-direct replaces stdin with a temp file on Windows.
            pass

    os.unlink = _safe_unlink
