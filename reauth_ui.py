"""Shared visual styles and lightweight Tk widgets for OpenAI Reauth.

This module intentionally uses only the standard library.  It contains no
authorization logic or application state.
"""

from __future__ import annotations

from functools import lru_cache
import tkinter as tk
from tkinter import font, ttk


COLORS = {
    "bg": "#12161A", "nav": "#0C1012", "card": "#1A2126",
    "soft": "#1A2126", "border": "#2A3238", "hover": "#252D33",
    "accent": "#009F70", "accent_hover": "#0CB582", "selected": "#20372F",
    "text": "#E8EDEF", "muted": "#8B9894", "disabled": "#515C61",
    "log": "#1A2126", "log_text": "#B7C3CA",
    "success": "#36D49B", "warning": "#E1B86C", "error": "#F07882",
}
TOKENS = {"radius": 12, "control_radius": 8, "control_height": 36,
          "space": 8, "gap": 16, "padding": 20}




def _available_font(root: tk.Misc, candidates: tuple[str, ...]) -> str:
    available = {name.casefold(): name for name in font.families(root)}
    return next(
        (available[name.casefold()] for name in candidates if name.casefold() in available),
        "TkDefaultFont",
    )


@lru_cache(maxsize=128)
def _rounded_png(fill, outline, radius=8, stroke=1, size=96):
    """Small antialiased nine-slice assets; no third-party runtime dependency."""
    import struct
    import zlib
    def rgb(value):
        return tuple(int(value[i:i+2], 16) for i in (1, 3, 5))
    inside, edge = rgb(fill), rgb(outline)
    def contains(x, y, inset):
        if not (inset <= x <= size-inset and inset <= y <= size-inset):
            return False
        r = max(radius-inset, 0)
        cx = min(max(x, inset+r), size-inset-r)
        cy = min(max(y, inset+r), size-inset-r)
        return (x-cx)**2 + (y-cy)**2 <= r*r
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            if (radius <= x < size-radius or radius <= y < size-radius):
                color = edge if min(x,y,size-1-x,size-1-y) < stroke else inside
                rows.extend((*color,255))
                continue
            sums = [0, 0, 0]; count = 0
            for dy in (0.125, 0.375, 0.625, 0.875):
                for dx in (0.125, 0.375, 0.625, 0.875):
                    if contains(x+dx, y+dy, 0):
                        color = inside if contains(x+dx, y+dy, stroke) else edge
                        count += 1
                        for i in range(3): sums[i] += color[i]
            rows.extend([*(round(v/count) if count else 0 for v in sums), round(count/16*255)])
    def chunk(kind, data):
        return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data)&0xffffffff)
    png = b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',size,size,8,6,0,0,0))
    png += chunk(b'IDAT',zlib.compress(bytes(rows)))+chunk(b'IEND',b'')
    return png


def _rounded_image(root, fill, outline, radius=8, stroke=1, size=96, mark=None):
    result = tk.PhotoImage(master=root, data=_rounded_png(fill,outline,radius,stroke,size), format='png')
    if mark == 'check':
        for x,y in ((5,9),(6,10),(7,11),(8,10),(9,9),(10,8),(11,7),(12,6)):
            result.put(COLORS['text'], to=(x,y,x+2,y+2))
    return result


def _dark_titlebar(root):
    """DWM appearance only: retain native drag, snap and system buttons."""
    import sys
    if sys.platform != 'win32':
        return
    import ctypes
    from ctypes import wintypes
    try:
        user32, dwm = ctypes.windll.user32, ctypes.windll.dwmapi
        user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetAncestor.restype = wintypes.HWND
        dwm.DwmSetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        hwnd = user32.GetAncestor(root.winfo_id(), 2)
        dark = ctypes.c_int(1)
        if dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(dark), 4) != 0:
            dwm.DwmSetWindowAttribute(hwnd, 19, ctypes.byref(dark), 4)
        for attribute, color in ((35, COLORS['nav']), (36, COLORS['text']), (34, COLORS['nav'])):
            rgb = int(color[1:3],16) | int(color[3:5],16)<<8 | int(color[5:7],16)<<16
            value = wintypes.DWORD(rgb)
            dwm.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value), 4)
    except (AttributeError, OSError, tk.TclError):
        pass


def setup_theme(root: tk.Misc) -> ttk.Style:
    """Custom painted ttk elements preserve native editing and keyboard APIs."""
    style = ttk.Style(root)
    if getattr(root, '_reauth_theme_ready', False):
        return style
    root._reauth_theme_ready = True
    style.theme_use('clam')
    family = _available_font(root, ('Microsoft YaHei UI', 'Segoe UI', 'Arial'))
    mono = _available_font(root, ('Cascadia Mono', 'Consolas', 'Courier New'))
    root._reauth_ui_font, root._reauth_mono_font = family, mono
    font.nametofont('TkDefaultFont', root=root).configure(family=family, size=10)
    font.nametofont('TkTextFont', root=root).configure(family=family, size=10)
    root.configure(background=COLORS['bg'])
    root._reauth_theme_images = images = []
    asset_cache = {}
    def asset(fill, border=None, radius=8, stroke=1, size=96, mark=None):
        key=(fill, border or fill, radius, stroke, size, mark)
        if key not in asset_cache:
            asset_cache[key] = _rounded_image(root, *key)
            images.append(asset_cache[key])
        return asset_cache[key]
    def surface(name, normal, hover=None, disabled=None, selected=None, border=None, radius=8):
        border = border or COLORS['border']
        states = [(('disabled',), asset(disabled or normal, COLORS['border'])),
                  (('focus',), asset(normal, COLORS['accent'], radius, 2))]
        if selected: states.append((('selected',), asset(selected, selected, radius)))
        if hover: states.append((('active',), asset(hover, border, radius)))
        style.element_create(name, 'image', asset(normal, border, radius), *states, border=radius+1, padding=0, width=28, height=28, sticky='nsew')
    style.configure('.', font=(family,10), background=COLORS['bg'], foreground=COLORS['text'],
                    bordercolor=COLORS['border'], lightcolor=COLORS['border'], darkcolor=COLORS['border'])
    for name,bg in (('App','bg'),('Card','card'),('Soft','soft'),('Panel','card')):
        style.configure(name+'.TFrame', background=COLORS[bg])
    style.configure('Panel.TFrame', background=COLORS['bg'])
    surface('Reauth.panel', COLORS['card'], radius=12)
    style.layout('Panel.TFrame', [('Reauth.panel', {'sticky':'nsew'})])
    for name,size,weight,fg,bg in (
        ('TLabel',10,'normal','text','bg'), ('Title.TLabel',18,'bold','text','bg'),
        ('Subtitle.TLabel',9,'normal','muted','bg'), ('Eyebrow.TLabel',9,'normal','muted','bg'),
        ('Section.TLabel',11,'bold','text','card'), ('Metric.TLabel',20,'bold','text','card'),
        ('Hint.TLabel',9,'normal','muted','card'), ('CardHint.TLabel',9,'normal','muted','card'),
        ('Card.TLabel',10,'normal','text','card'), ('Body.TLabel',10,'normal','text','card'),
        ('Footer.TLabel',9,'normal','muted','bg'), ('Success.TLabel',9,'normal','success','card'),
        ('Warning.TLabel',9,'normal','warning','card'), ('Error.TLabel',9,'normal','error','card')):
        style.configure(name,font=(family,size,weight),foreground=COLORS[fg],background=COLORS[bg])
    surface('Reauth.pill', COLORS['selected'], border=COLORS['selected'], radius=12)
    style.layout('Badge.TLabel',[('Reauth.pill',{'sticky':'nsew','children':[('Label.padding',{'sticky':'nsew','children':[('Label.label',{'sticky':'nsew'})]})]})])
    style.configure('Badge.TLabel',font=(family,9),foreground=COLORS['success'],padding=(10,3))
    for name,base,fg,border in (
        ('TButton','card','text','border'), ('Secondary.TButton','card','text','border'),
        ('Ghost.TButton','card','muted','card'), ('Primary.TButton','accent','text','accent'),
        ('Danger.TButton','card','error','border'), ('Segment.TButton','card','muted','card'),
        ('SegmentActive.TButton','hover','text','hover'), ('Nav.TButton','nav','muted','nav'),
        ('NavActive.TButton','card','text','card'),
        ('Page.Primary.TButton','accent','text','accent'),
        ('Page.Secondary.TButton','bg','text','border'),
        ('Page.Ghost.TButton','bg','muted','bg')):
        element = 'Reauth.'+name
        behind = COLORS['nav'] if name.startswith('Nav') else COLORS['bg'] if name.startswith('Page.') else COLORS['card']
        surface(element,COLORS[base],COLORS['accent_hover'] if base=='accent' else COLORS['hover'],
                behind,border=COLORS[border])
        style.layout(name,[(element,{'sticky':'nsew','children':[('Button.padding',{'sticky':'nsew','children':[('Button.label',{'sticky':'nsew'})]})]})])
        style.configure(name,padding=(12,7),width=0,anchor='center',background=behind,
                        font=(family,10,'bold' if base=='accent' else 'normal'),foreground=COLORS[fg])
        style.map(name,foreground=[('disabled',COLORS['disabled'])],background=[('disabled',behind),('active',behind)])
    for name in ('Nav.TButton','NavActive.TButton'):
        style.configure(name,padding=(16,12),anchor='w')
    for name in ('Segment.TButton','SegmentActive.TButton'):
        style.configure(name,padding=(4,7),font=(family,9))
    surface('Reauth.field',COLORS['card'],COLORS['hover'],COLORS['card'])
    style.layout('TEntry',[('Reauth.field',{'sticky':'nsew','children':[('Entry.padding',{'sticky':'nsew','children':[('Entry.textarea',{'sticky':'nsew'})]})]})])
    style.configure('TEntry',padding=(10,7),fieldbackground=COLORS['card'],foreground=COLORS['text'],
                    insertcolor=COLORS['text'],selectbackground=COLORS['selected'],selectforeground=COLORS['text'])
    style.map('TEntry',foreground=[('disabled',COLORS['disabled'])])
    arrow = tk.PhotoImage(master=root,width=16,height=16)
    for x,y in ((4,6),(5,7),(6,8),(7,9),(8,8),(9,7),(10,6)):
        arrow.put(COLORS['muted'],to=(x,y,x+2,y+2))
    images.append(arrow)
    style.element_create('Reauth.downarrow','image',arrow,sticky='')
    style.layout('TCombobox',[('Reauth.field',{'sticky':'nsew','children':[
        ('Combobox.padding',{'sticky':'nsew','children':[
            ('Reauth.downarrow',{'side':'right','sticky':'ns'}),
            ('Combobox.textarea',{'sticky':'nsew'})]})]})])
    style.configure('TCombobox',padding=(10,7),fieldbackground=COLORS['card'],foreground=COLORS['text'],
                    selectbackground=COLORS['card'],selectforeground=COLORS['text'])
    style.map('TCombobox',fieldbackground=[('readonly',COLORS['card'])],foreground=[('disabled',COLORS['disabled']),('readonly',COLORS['text'])])
    for option,value in (('background',COLORS['card']),('foreground',COLORS['text']),
                         ('selectBackground',COLORS['selected']),('selectForeground',COLORS['text']),
                         ('font',(family,10)),('relief','flat'),('borderWidth',0)):
        root.option_add('*TCombobox*Listbox.'+option,value)
    unchecked=asset(COLORS['card'], '#536169',radius=4,size=18)
    checked=asset(COLORS['accent'],COLORS['accent'],radius=4,size=18,mark='check')
    disabled=asset(COLORS['card'],COLORS['border'],radius=4,size=18)
    checked_disabled=asset(COLORS['card'],COLORS['disabled'],radius=4,size=18,mark='check')
    style.element_create('Reauth.check','image',unchecked,('disabled selected',checked_disabled),('disabled',disabled),('selected',checked),width=26,sticky='w')
    surface('Reauth.checkrow',COLORS['card'],border=COLORS['card'])
    style.layout('TCheckbutton',[('Reauth.checkrow',{'sticky':'nsew','children':[('Checkbutton.padding',{'sticky':'nsew','children':[
        ('Reauth.check',{'side':'left','sticky':'w'}),('Checkbutton.label',{'sticky':'nsew'})]})]})])
    style.configure('TCheckbutton',padding=(2,7),background=COLORS['card'],foreground=COLORS['text'])
    style.map('TCheckbutton',foreground=[('disabled',COLORS['disabled']),('focus',COLORS['success'])],background=[('active',COLORS['card'])])
    surface('Reauth.choice',COLORS['card'],COLORS['hover'],selected=COLORS['selected'])
    style.layout('Format.TRadiobutton',[('Reauth.choice',{'sticky':'nsew','children':[('Radiobutton.padding',{'sticky':'nsew','children':[('Radiobutton.label',{'sticky':'nsew'})]})]})])
    style.configure('Format.TRadiobutton',padding=(12,7),foreground=COLORS['muted'],anchor='center')
    style.map('Format.TRadiobutton',foreground=[('selected',COLORS['success'])])
    for orient in ('Horizontal','Vertical'):
        style.layout(orient+'.TScrollbar',[(orient+'.Scrollbar.trough',{'sticky':'nswe','children':[(orient+'.Scrollbar.thumb',{'sticky':'nswe'})]})])
        style.configure(orient+'.TScrollbar',background='#43515A',troughcolor=COLORS['card'],
                        borderwidth=0,bordercolor=COLORS['card'],lightcolor='#43515A',darkcolor='#43515A',width=6,arrowsize=6)
        style.map(orient+'.TScrollbar',background=[('active','#64737B'),('pressed','#71838D')])
    style.element_create('Reauth.progress.track','image',asset(COLORS['border'],radius=2,size=4),border=1,padding=0,sticky='nsew')
    style.element_create('Reauth.progress.fill','image',asset(COLORS['accent'],radius=2,size=4),border=1,padding=0,sticky='nsew')
    style.layout('Slim.Horizontal.TProgressbar',[('Reauth.progress.track',{'sticky':'nswe','children':[('Reauth.progress.fill',{'side':'left','sticky':'ns'})]})])
    style.configure('Slim.Horizontal.TProgressbar',background=COLORS['card'],borderwidth=0,thickness=4,padding=0)
    style.configure('TSeparator',background=COLORS['border'])
    style.configure('Treeview',background=COLORS['card'],fieldbackground=COLORS['card'],
                    foreground=COLORS['text'],rowheight=40,borderwidth=0)
    style.layout('Treeview',[('Treeview.treearea',{'sticky':'nswe'})])
    style.configure('Treeview.Heading',font=(family,9,'bold'),background=COLORS['card'],
                    foreground=COLORS['muted'],padding=(10,9),relief='flat',borderwidth=0)
    style.map('Treeview',background=[('selected',COLORS['selected'])],foreground=[('selected',COLORS['text'])])
    style.layout('Flat.TNotebook',[('Notebook.client', {'sticky':'nswe'})])
    style.layout('Flat.TNotebook.Tab',[])
    style.configure('Flat.TNotebook',background=COLORS['card'],borderwidth=0,tabmargins=0,
                    bordercolor=COLORS['card'],lightcolor=COLORS['card'],darkcolor=COLORS['card'])
    root.bind('<Map>',lambda e: _dark_titlebar(root) if e.widget is root else None,add='+')
    root.after_idle(lambda: _dark_titlebar(root))
    return style


class AppNavigation(tk.Frame):
    """Persistent sidebar. Page instances and their input stay alive."""
    def __init__(self, parent, commands):
        super().__init__(parent, background=COLORS["nav"], width=174)
        self.pack_propagate(False)
        family = getattr(parent, "_reauth_ui_font", "TkDefaultFont")
        tk.Frame(self, bg=COLORS["border"], width=1).pack(side=tk.RIGHT, fill=tk.Y)
        content = tk.Frame(self, bg=COLORS["nav"], padx=12, pady=24)
        content.pack(fill=tk.BOTH, expand=True)
        brand = tk.Frame(content, bg=COLORS["nav"])
        brand.pack(fill=tk.X, pady=(0, 28))
        brand_mark(brand, 30).pack(side=tk.LEFT, padx=(0, 9))
        words = tk.Frame(brand, bg=COLORS["nav"])
        words.pack(side=tk.LEFT)
        tk.Label(words, text="Reauth", font=(family, 15, "bold"),
                 bg=COLORS["nav"], fg=COLORS["text"]).pack(anchor="w")
        tk.Label(words, text="账号工作台", font=(family, 8),
                 bg=COLORS["nav"], fg=COLORS["muted"]).pack(anchor="w", pady=(2, 0))
        self.buttons = {}
        self.indicators = {}
        self.active = "auth"
        for category, items in (("账号处理", (("auth", "批量授权"), ("phone", "手机接码"))),
                                ("数据管理", (("convert", "格式转换"), ("pool", "推送到池")))):
            group = tk.Frame(content, bg=COLORS["nav"])
            group.pack(fill=tk.X, pady=(0, 22))
            tk.Label(group, text=category, font=(family, 8), bg=COLORS["nav"],
                     fg=COLORS["muted"]).pack(anchor="w", padx=15, pady=(0, 8))
            for key, label in items:
                row = tk.Frame(group, bg=COLORS["nav"])
                row.pack(fill=tk.X, pady=3)
                indicator = tk.Frame(row, width=3, bg=COLORS["nav"])
                indicator.pack(side=tk.LEFT, fill=tk.Y, pady=9)
                button = ttk.Button(row, text=label, style="Nav.TButton", command=commands[key])
                button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
                self.buttons[key] = button
                self.indicators[key] = indicator
        footer = card(content, padding=12)
        footer.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(footer, text="OpenAI / Codex", font=(family, 9),
                 bg=COLORS["card"], fg=COLORS["text"]).pack(anchor="w")
        tk.Label(footer, text="本地凭据管理", font=(family, 8),
                 bg=COLORS["card"], fg=COLORS["muted"]).pack(anchor="w", pady=(5, 0))
        self.select("auth")

    def select(self, key):
        self.active = key
        for name, button in self.buttons.items():
            button.configure(style="NavActive.TButton" if name == key else "Nav.TButton")
            self.indicators[name].configure(bg=COLORS["accent"] if name == key else COLORS["nav"])


def page_header(parent, title, description, category):
    """Quiet breadcrumb, one clear title and a short task description."""
    header = ttk.Frame(parent, style="App.TFrame")
    ttk.Label(header, text=f"工作台   /   {category}", style="Footer.TLabel").pack(anchor="w", pady=(0, 8))
    row = ttk.Frame(header, style="App.TFrame")
    row.pack(fill=tk.X)
    ttk.Label(row, text=title, style="Title.TLabel").pack(side=tk.LEFT)
    ttk.Label(header, text=description, style="Subtitle.TLabel").pack(anchor="w", pady=(5, 0))
    return header


class AutoScrollbar(ttk.Scrollbar):
    """Only reserve space when content overflows; preserve grid/pack order."""
    def __init__(self, master, **kwargs):
        self.content_widget = kwargs.pop('content_widget', None)
        super().__init__(master, **kwargs)
        self._saved_layout = None

    def set(self, first, last):
        super().set(first, last)
        empty = isinstance(self.content_widget, ttk.Treeview) and not self.content_widget.get_children()
        needed = not empty and (float(first) > 0.0001 or float(last) < 0.9999)
        manager = self.winfo_manager()
        if not needed and manager:
            info = self.grid_info() if manager == 'grid' else self.pack_info()
            self._saved_layout = (manager, info)
            if manager == 'pack':
                siblings = self.master.pack_slaves()
                self._pack_following = siblings[siblings.index(self)+1:]
            if manager == 'grid': self.grid_remove()
            elif manager == 'pack': self.pack_forget()
        elif needed and not manager and self._saved_layout:
            manager, info = self._saved_layout
            if manager == 'grid': self.grid(**info)
            elif manager == 'pack':
                before = next((w for w in getattr(self,'_pack_following',()) if w.winfo_exists() and w.winfo_manager()=='pack'),None)
                self.pack(**info, **({'before': before} if before else {}))


class SegmentedNotebook(ttk.Frame):
    """Notebook-compatible interface with equal-width, flat segment buttons."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, style='Card.TFrame', **kwargs)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        self.bar = ttk.Frame(self, style='Card.TFrame', padding=(8,8,8,4))
        self.bar.grid(row=0,column=0,sticky='ew')
        self.book = ttk.Notebook(self, style='Flat.TNotebook', takefocus=False)
        self.book.grid(row=1,column=0,sticky='nsew')
        self.buttons = []
        self.book.bind('<<NotebookTabChanged>>', self._selected)

    def add(self, child, **kwargs):
        index = len(self.buttons)
        self.book.add(child, **kwargs)
        button = ttk.Button(self.bar, text=kwargs.get('text',''), style='Segment.TButton',
                            command=lambda: self.select(index))
        button.grid(row=0,column=index,sticky='ew',padx=2)
        self.bar.columnconfigure(index,weight=1,uniform='segments')
        button.bind('<Left>',lambda e,i=index: self._move(i,-1))
        button.bind('<Right>',lambda e,i=index: self._move(i,1))
        button.bind('<Home>',lambda e: self._move(0,0))
        button.bind('<End>',lambda e: self._move(len(self.buttons)-1,0))
        self.buttons.append(button)
        self._selected()

    def _move(self, index, delta):
        index = (index+delta)%len(self.buttons)
        self.select(index)
        self.buttons[index].focus_set()
        return 'break'

    def select(self, tab_id=None):
        if tab_id is None: return self.book.select()
        result = self.book.select(tab_id)
        self._selected()
        return result

    def tabs(self): return self.book.tabs()
    def index(self, tab_id): return self.book.index(tab_id)
    def tab(self, tab_id, option=None, **kwargs): return self.book.tab(tab_id,option,**kwargs)

    def _selected(self, _event=None):
        current = self.book.index('current') if self.book.tabs() else -1
        for i, button in enumerate(self.buttons):
            button.configure(style='SegmentActive.TButton' if i==current else 'Segment.TButton')
        self.event_generate('<<NotebookTabChanged>>')


class DataTable(ttk.Treeview):
    """Present empty datasets without column chrome; stripe real data only."""
    def __init__(self, parent, *, empty_text='暂无结果', empty_command=None, **kwargs):
        super().__init__(parent, **kwargs)
        self._data_show = kwargs.get('show','headings')
        self._empty = ttk.Frame(self,style='Card.TFrame')
        ttk.Label(self._empty,text=empty_text,style='Hint.TLabel').pack(pady=(0,6))
        if empty_command:
            ttk.Button(self._empty,text='导入文件',style='Ghost.TButton',command=empty_command).pack()
        self.tag_configure('stripe',background='#1D252B')
        self.bind('<Configure>',lambda e:self._present())
        self._present()

    def _present(self):
        has_data=bool(self.get_children())
        if getattr(self,'_has_data',None)==has_data: return
        self._has_data=has_data
        if has_data:
            self._empty.place_forget()
            self.configure(show=self._data_show)
        else:
            self.configure(show='')
            self._empty.place(relx=.5,rely=.5,anchor='center')

    def insert(self,parent,index,iid=None,**kwargs):
        tags = list(kwargs.get('tags',()))
        if len(self.get_children(parent))%2: tags.append('stripe')
        kwargs['tags']=tags
        result=super().insert(parent,index,iid,**kwargs)
        self._present()
        return result

    def delete(self,*items):
        result=super().delete(*items)
        self._present()
        return result


def secret_field(parent, variable):
    """Local visibility toggle; no variable writes or persistence changes."""
    holder = ttk.Frame(parent,style='Card.TFrame')
    holder.columnconfigure(0,weight=1)
    entry=ttk.Entry(holder,textvariable=variable,show='•')
    entry.grid(row=0,column=0,sticky='ew')
    def toggle():
        hidden=bool(entry.cget('show'))
        entry.configure(show='' if hidden else '•')
        button.configure(image=hidden_icon if hidden else eye_icon)
    # Draw an eye and a crossed eye; retained PhotoImages belong to the button.
    eye_icon=tk.PhotoImage(master=parent,width=20,height=20)
    for x in range(3,17):
        offset=round(4*(1-((x-9.5)/7)**2))
        for y in (10-offset,10+offset):eye_icon.put(COLORS['muted'],to=(x,y,x+1,y+1))
    eye_icon.put(COLORS['text'],to=(8,8,12,12))
    hidden_icon=eye_icon.copy()
    for i in range(3,17):hidden_icon.put(COLORS['text'],to=(i,i,i+1,i+1))
    button=ttk.Button(holder,image=eye_icon,style='Ghost.TButton',command=toggle,takefocus=True)
    button._icons=(eye_icon,hidden_icon)
    button.grid(row=0,column=1,padx=(4,0))
    return holder,entry


def json_highlight(text):
    """Colour the already-masked preview; never change its contents."""
    import re
    for tag,color in (('json_key','#85B7E0'),('json_string','#A5D2B8'),
                      ('json_number','#D6B481'),('json_literal','#BBA5D8')):
        text.tag_configure(tag,foreground=color)
        text.tag_remove(tag,'1.0',tk.END)
    content=text.get('1.0','end-1c')
    pattern=r'"(?:[^"\\]|\\.)*"|\b(?:true|false|null)\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b'
    for match in re.finditer(pattern,content):
        value=match.group()
        if value.startswith('"'):
            tag='json_key' if content[match.end():].lstrip().startswith(':') else 'json_string'
        else: tag='json_literal' if value in ('true','false','null') else 'json_number'
        text.tag_add(tag,f'1.0+{match.start()}c',f'1.0+{match.end()}c')


def set_hint(text, hint):
    """An overlay placeholder is never part of the editable text or clipboard."""
    old=getattr(text,'_hint_label',None)
    if old is None:
        old=tk.Label(text,text=hint,bg=COLORS['card'],fg=COLORS['muted'],
                     font=(getattr(text.winfo_toplevel(),'_reauth_ui_font','TkDefaultFont'),9),anchor='nw')
        text._hint_label=old
        old.bind('<Button-1>',lambda e:text.focus_set())
    old.configure(text=hint)
    old.place(x=12,y=10) if not text.get('1.0','end-1c') else old.place_forget()


def hide_hint(text):
    label=getattr(text,'_hint_label',None)
    if label is not None: label.place_forget()


def present_running(page, key, running):
    """Presentation only; callers keep ownership of all worker/control states."""
    normal={'auth':'开始授权','phone':'开始接码','pool':'开始推送'}[key]
    page.start_btn.configure(text='进行中…' if running else normal)
    if key == 'auth':
        roomy = page.root.winfo_width() >= 1100
        page.auth_layout.columnconfigure(1, minsize=328 if running and roomy else 286)
    nav=getattr(page.start_btn.winfo_toplevel(),'_reauth_navigation',None)
    if nav:
        labels={'auth':'批量授权','phone':'手机接码','pool':'推送到池'}
        nav.buttons[key].configure(text=labels[key]+('  ·' if running else ''))


def scroll_settings(parent, padding=16, width=290):
    """One independently scrollable settings tab; no global mouse bindings."""
    holder = ttk.Frame(parent, style="Card.TFrame")
    holder.columnconfigure(0, weight=1)
    holder.rowconfigure(0, weight=1)
    canvas = tk.Canvas(holder, bg=COLORS["card"], highlightthickness=0, width=width)
    canvas.grid(row=0, column=0, sticky="nsew")
    scrollbar = AutoScrollbar(holder, orient=tk.VERTICAL, command=canvas.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    canvas.configure(yscrollcommand=scrollbar.set)
    body = ttk.Frame(canvas, style="Card.TFrame", padding=padding)
    body.columnconfigure(0, weight=1)
    window = canvas.create_window((0, 0), window=body, anchor="nw")
    body.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
    def wheel(event):
        if canvas.yview() != (0.0, 1.0):
            canvas.yview_scroll(-int(event.delta / 120), "units")
        return "break"
    def bind_children(widget):
        if not isinstance(widget, (tk.Text, tk.Listbox, ttk.Treeview)):
            if not getattr(widget, "_reauth_scroll_bound", False):
                widget.bind("<MouseWheel>", wheel)
                widget._reauth_scroll_bound = True
            for child in widget.winfo_children():
                bind_children(child)
    holder.bind("<Map>", lambda _e: bind_children(body))
    canvas.bind("<MouseWheel>", wheel)
    return holder, body, canvas


def card(parent: tk.Misc, padding: int | tuple = 18) -> ttk.Frame:
    """Return a padded dark panel that can directly contain grid/pack children."""
    return ttk.Frame(parent, style="Panel.TFrame", padding=padding if padding else 8)


def text_area(
    parent: tk.Misc, height: int = 8, wrap: str = tk.NONE,
    bg: str | None = None, fg: str | None = None, state: str = tk.NORMAL,
) -> tuple[tk.Frame, tk.Text]:
    """Return a bordered text surface and its editable/readonly text widget."""
    background = COLORS["card"]
    foreground = fg or COLORS["text"]
    root = parent.winfo_toplevel()
    family = getattr(root, "_reauth_mono_font", None) or _available_font(root, ("Cascadia Mono", "Consolas", "Courier New"))
    holder = ttk.Frame(parent,style='Field.TFrame',padding=2)
    # Reuse the custom rounded entry surface without a nested black box.
    style=ttk.Style(parent)
    style.layout('Field.TFrame',[('Reauth.field',{'sticky':'nsew'})])
    holder.rowconfigure(0, weight=1)
    holder.columnconfigure(0, weight=1)
    text = tk.Text(holder, height=height, width=1, wrap=wrap, state=state,
                   background=background, foreground=foreground,
                   insertbackground=foreground, font=(family, 9),
                   relief="flat", borderwidth=0, highlightthickness=0,
                   padx=10, pady=8, spacing1=2, spacing3=4,
                   selectbackground=COLORS['selected'], selectforeground=COLORS["text"],
                   inactiveselectbackground=COLORS['hover'], undo=state == tk.NORMAL)
    vertical = AutoScrollbar(holder, orient=tk.VERTICAL, command=text.yview)
    horizontal = AutoScrollbar(holder, orient=tk.HORIZONTAL, command=text.xview)
    text._vertical_scrollbar, text._horizontal_scrollbar = vertical, horizontal
    text.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    text.grid(row=0, column=0, sticky="nsew",padx=6,pady=6)
    vertical.grid(row=0, column=1, sticky="ns", pady=8,padx=(0,4))
    if wrap == tk.NONE:
        horizontal.grid(row=1, column=0, sticky="ew", padx=8,pady=(0,4))
    text.bind("<FocusIn>", lambda _event: holder.state(['focus']), add="+")
    text.bind("<FocusOut>", lambda _event: holder.state(['!focus']), add="+")
    for tag,color in (('success','success'),('warning','warning'),('error','error')):
        text.tag_configure(tag,foreground=COLORS[color])
    return holder, text


def brand_mark(parent: tk.Misc, size: int = 42) -> tk.Canvas:
    """Create an original refresh mark; this is not an OpenAI logo."""
    try:
        background = parent.cget("background")
    except tk.TclError:
        background = ttk.Style(parent).lookup(parent.cget("style") or "TFrame", "background")
    canvas = tk.Canvas(parent, width=size, height=size, background=background or COLORS["bg"],
                       highlightthickness=0, borderwidth=0)
    unit = size / 42
    points = [8, 1, 34, 1, 41, 8, 41, 34, 34, 41, 8, 41, 1, 34, 1, 8]
    canvas.create_polygon(*(v * unit for v in points), fill=COLORS["accent"],
                          outline="", smooth=True, splinesteps=18)
    canvas.create_arc(11 * unit, 11 * unit, 31 * unit, 31 * unit,
                      start=35, extent=255, style=tk.ARC, width=2.5 * unit,
                      outline="white")
    canvas.create_polygon(28 * unit, 8 * unit, 32 * unit, 16 * unit,
                          23 * unit, 15 * unit, fill="white", outline="")
    return canvas


def attach_window_icon(window: tk.Toplevel | tk.Tk) -> None:
    """Attach a small generated icon without shipping an image dependency."""
    icon = tk.PhotoImage(master=window, width=32, height=32)
    icon.put(COLORS["accent"], to=(5, 2, 27, 30))
    icon.put(COLORS["accent"], to=(2, 5, 30, 27))
    for rectangle in ((10, 8, 21, 11), (8, 10, 11, 22),
                      (10, 21, 23, 24), (21, 17, 24, 22),
                      (19, 7, 22, 13), (17, 11, 25, 14)):
        icon.put("white", to=rectangle)
    window.iconphoto(True, icon)
    window._reauth_window_icon = icon
