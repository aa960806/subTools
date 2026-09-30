"""Browser handoff on the Playwright owner thread; no public CDP/VNC port."""
import queue
import threading
import time

_current = threading.local()

def bind(bridge):
    _current.bridge = bridge

def attach(page):
    bridge = getattr(_current, 'bridge', None)
    if bridge is not None:
        bridge.clear()
        bridge.page = page

def detach():
    bridge = getattr(_current, 'bridge', None)
    if bridge is not None:
        bridge.page = None
        bridge.clear()

class BrowserBridge:
    def __init__(self):
        self.page = None
        self.frame = None
        self.updated = 0.0
        self.commands = queue.Queue(maxsize=40)
        self.enabled = False

    def clear(self):
        self.frame = None
        self.updated = 0
        while True:
            try:
                self.commands.get_nowait()
            except queue.Empty:
                break

    def pump(self):
        page = self.page
        if page is None or not self.enabled:
            return
        try:
            for _ in range(8):
                try:
                    command = self.commands.get_nowait()
                except queue.Empty:
                    break
                if command['action'] == 'click':
                    page.mouse.click(command['x'], command['y'])
                elif command['action'] == 'text':
                    page.keyboard.insert_text(command['text'])
                elif command['action'] == 'key':
                    page.keyboard.press(command['key'])
                elif command['action'] == 'scroll':
                    page.mouse.wheel(0, command['delta'])
            if time.monotonic() - self.updated >= 1:
                self.frame = page.screenshot(type='jpeg', quality=65, timeout=1500)
                self.updated = time.monotonic()
        except Exception:
            # Navigation can invalidate a frame; next tick refreshes it.
            self.frame = None

class StopEvent:
    def __init__(self, bridge):
        self.event = threading.Event()
        self.bridge = bridge
        self.owner = None
    def set(self):
        self.event.set()
    def is_set(self):
        if threading.get_ident() == self.owner and not self.event.is_set():
            self.bridge.pump()
        return self.event.is_set()
    def wait(self, timeout=None):
        return self.event.wait(timeout)
