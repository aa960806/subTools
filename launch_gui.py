"""Start the Tk GUI with visible failure reporting, including under pythonw."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import runpy
import sys
import traceback


def _show_error(message: str) -> None:
    if os.name == "nt":
        ctypes.windll.user32.MessageBoxW(None, message, "OpenAI Reauth", 0x10)
    elif sys.stderr is not None:
        print(message, file=sys.stderr)


def main() -> int:
    root = Path(__file__).resolve().parent
    log_path = root / "gui-error.log"
    try:
        log = log_path.open("a", encoding="utf-8", buffering=1)
    except OSError as exc:
        _show_error(f"Cannot open the startup log:\n{log_path}\n\n{exc}")
        return 1

    original_stdout, original_stderr = sys.stdout, sys.stderr
    try:
        sys.stdout = sys.stderr = log
        os.chdir(root)
        runpy.run_path(str(root / "openai_reauth_gui.py"), run_name="__main__")
        return 0
    except BaseException as exc:
        if isinstance(exc, SystemExit) and exc.code in (None, 0):
            return 0
        traceback.print_exc(file=log)
        log.flush()
        _show_error(f"OpenAI Reauth could not start or exited unexpectedly.\n\nSee the error log:\n{log_path}")
        return 1
    finally:
        sys.stdout, sys.stderr = original_stdout, original_stderr
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
