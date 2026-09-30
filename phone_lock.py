"""OS-backed lease for the phone-order journal; released even on process exit."""
import os
from pathlib import Path


class PhoneBatchLease:
    def __init__(self, path):
        self.path = Path(path)
        self.file = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise RuntimeError("另一个工具实例正在接码或清理订单，请等待其结束后再启动。") from None
        self.file = handle
        return self

    def __exit__(self, *args):
        # Keep the lock file: unlinking it creates races with waiting processes.
        if self.file is not None:
            self.file.close()
            self.file = None
