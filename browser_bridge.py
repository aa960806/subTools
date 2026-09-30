"""Browser handoff on the Playwright owner thread; no public CDP/VNC port."""
import queue
import threading
import time
import uuid

_current = threading.local()

def bind(bridge):
    _current.bridge = bridge

def attach(page):
    bridge = getattr(_current, 'bridge', None)
    if bridge is not None:
        with bridge.lock:
            bridge.clear()
            bridge.page = page

def detach():
    bridge = getattr(_current, 'bridge', None)
    if bridge is not None:
        with bridge.lock:
            bridge.page = None
            bridge.clear()

class BrowserBridge:
    def __init__(self):
        self.lock = threading.RLock()
        self.generation = uuid.uuid4().hex
        self.page = None
        self.frame = None
        self.updated = 0.0
        self.commands = queue.Queue(maxsize=40)
        self.enabled = False

    def clear(self):
        with self.lock:
            self.generation = uuid.uuid4().hex
            self.frame = None
            self.updated = 0
            while True:
                try:
                    self.commands.get_nowait()
                except queue.Empty:
                    break

    def snapshot(self):
        with self.lock:
            return self.frame, self.generation

    def submit(self, generation, command):
        with self.lock:
            if not self.enabled or self.page is None or self.frame is None:
                raise ValueError('当前没有可操作的浏览器画面，请等待页面就绪')
            if generation != self.generation:
                raise ValueError('浏览器已切换账号或任务，请等待新画面后重试')
            try:
                self.commands.put_nowait({**command, 'generation': generation})
            except queue.Full:
                raise ValueError('操作过快，请稍候') from None

    def pump(self):
        page = self.page
        generation = self.generation
        if page is None or not self.enabled:
            return
        try:
            for _ in range(8):
                try:
                    command = self.commands.get_nowait()
                except queue.Empty:
                    break
                if command.get('generation') != generation:
                    continue
                if command['action'] == 'click':
                    page.mouse.click(command['x'], command['y'])
                elif command['action'] == 'text':
                    page.keyboard.insert_text(command['text'])
                elif command['action'] == 'key':
                    page.keyboard.press(command['key'])
                elif command['action'] == 'scroll':
                    page.mouse.wheel(0, command['delta'])
            if time.monotonic() - self.updated >= 1:
                frame = page.screenshot(type='jpeg', quality=65, timeout=1500)
                with self.lock:
                    if generation == self.generation and page is self.page:
                        self.frame = frame
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
        self.bridge.clear()
    def is_set(self):
        if threading.get_ident() == self.owner and not self.event.is_set():
            self.bridge.pump()
        return self.event.is_set()
    def wait(self, timeout=None):
        return self.event.wait(timeout)
