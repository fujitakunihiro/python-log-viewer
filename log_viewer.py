from __future__ import annotations

import json
import os
import sys
import re
import html
import ctypes
import tkinter as tk
from tkinter import colorchooser, filedialog, messagebox, simpledialog, ttk
from typing import Dict, List, Tuple, Optional, Any

# --- DnD Support ---
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    ROOT_CLASS = TkinterDnD.Tk
    HAS_DND = True
except ImportError:
    ROOT_CLASS = tk.Tk
    HAS_DND = False

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "keywords": [
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True, "extra_lines": 0},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True, "extra_lines": 0},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True, "extra_lines": 0}
    ],
    "replace_patterns": []
}

class LineNumberCanvas(tk.Canvas):
    def __init__(self, master, text_widget, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        for ev in ['<KeyRelease>', '<MouseWheel>', '<Configure>', '<<Modified>>', '<Button-1>']:
            self.text_widget.bind(ev, self.redraw)

    def redraw(self, *args):
        self.delete("all")
        i = self.text_widget.index("@0,0")
        while True:
            dline = self.text_widget.dlineinfo(i)
            if dline is None: break
            y = dline[1]
            linenum = str(i).split(".")[0]
            self.create_text(40, y, anchor="ne", text=linenum, fill="#666666")
            i = self.text_widget.index(f"{i}+1line")

class LogTab(tk.Frame):
    def __init__(self, master, app, path, content, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged
        self.source_files: List[str] = []

        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=800)
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right_frame = tk.Frame(self.paned_window)
        self.paned_window.add(right_frame, minsize=100, stretch="always", width=450)
        self.hsb_cmt = tk.Scrollbar(right_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        self.comment_text = tk.Text(right_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa",
                                    yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        def sync_yview(*args):
            self.text.yview(*args); self.comment_text.yview(*args); self.linenumbers.redraw()
        self.vsb.config(command=sync_yview)
        self.hsb_log.config(command=self.text.xview); self.hsb_cmt.config(command=self.comment_text.xview)
        def on_mw(e):
            d = int(-1*(e.delta/120)) if e.delta else 0
            self.text.yview_scroll(d, "units"); self.comment_text.yview_scroll(d, "units"); self.linenumbers.redraw()
            return "break"
        for w in [self.text, self.comment_text]: w.bind('<MouseWheel>', on_mw)

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1450x850")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.replace_patterns_config = []
        self.use_keyword_filter = False
        self.keywords_dlg_ref = None
        self.replace_dlg_ref = None

        self._build_ui()
        if os.path.exists(self.config_path): self.load_config(self.config_path)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        fmenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        fmenu.add_command(label="マージして表示...", command=self.merge_logs_action)
        fmenu.add_separator()
        fmenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel)
        fmenu.add_separator()
        fmenu.add_command(label="終了", command=self.root.quit)
        menubar.add_cascade(label="ファイル", menu=fmenu)
        
        cmenu = tk.Menu(menubar, tearoff=0)
        cmenu.add_command(label="設定読み込み...", command=self.load_config_dialog)
        cmenu.add_command(label="設定保存...", command=self.save_config_dialog)
        cmenu.add_separator()
        cmenu.add_command(label="フィルタ設定の編集...", command=self.edit_keywords_dialog)
        cmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        menubar.add_cascade(label="設定", menu=cmenu)
        self.root.config(menu=menubar)

        toolbar = tk.Frame(self.root); toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=15, command=self.toggle_filter)
        self.btn_kw_filter.pack(side=tk.LEFT)
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e3f2fd").pack(side=tk.LEFT, padx=10)

        self.notebook = ttk.Notebook(self.root); self.notebook.pack(fill=tk.BOTH, expand=True)
        self.status_var = tk.StringVar(value="準備完了"); tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e: [self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None

    # --- File/Merge Actions ---
    def open_file(self):
        for p in filedialog.askopenfilenames(): self._open_file_path(p)

    def close_tab(self):
        t = self.get_current_tab()
        if t: self.notebook.forget(t)

    def _open_file_path(self, path: str):
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        tab = LogTab(self.notebook, self, path, content)
        self.notebook.add(tab, text=os.path.basename(path))
        self.notebook.select(tab); self.apply_display_update(tab)

    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
        target_tabs = [t for t in tabs if not t.is_merged]
        if len(target_tabs) < 2: return
        ts_len = simpledialog.askinteger("マージ", "時刻ソート用の先頭文字数:", initialvalue=19, minvalue=0)
        if ts_len is None: return
        all_entries = []
        for t in target_tabs:
            fn = os.path.basename(t.file_path)
            for line in t.original_content.splitlines():
                if line.strip(): all_entries.append((line[:ts_len], line, fn))
        all_entries.sort(key=lambda x: x[0])
        m_tab = LogTab(self.notebook, self, "Merged", "\n".join([x[1] for x in all_entries]), is_merged=True)
        m_tab.source_files = [x[2] for x in all_entries]
        self.notebook.add(m_tab, text="[マージ結果]"); self.notebook.select(m_tab); self.apply_display_update(m_tab)

    # --- Core Logic (Display & Filter) ---
    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        self.btn_kw_filter.config(text=f"フィルタ: {'ON' if self.use_keyword_filter else 'OFF'}", bg="#bbdefb" if self.use_keyword_filter else "SystemButtonFace")
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def apply_display_update(self, tab: LogTab):
        data = tab.original_content
        if self.replace_patterns_config: data = self._apply_replacements(data)
        
        orig_lines = data.splitlines()
        num_lines = len(orig_lines)
        line_matches = [None] * num_lines
        
        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try:
                    kw_rules.append({
                        "regex": re.compile(itm["pattern"], re.I),
                        "comment": itm.get("comment", ""),
                        "color": itm.get("color", "#ffffff"),
                        "extra": int(itm.get("extra_lines", 0))
                    })
                except: pass

        # 行ごとのマッチング属性の決定 (+行 波及ロジック)
        for idx in range(num_lines):
            for rule in kw_rules:
                if rule["regex"].search(orig_lines[idx]):
                    for j in range(idx, min(idx + rule["extra"] + 1, num_lines)):
                        if line_matches[j] is None: line_matches[j] = rule
                    break

        flines, fcmts, tag_info = [], [], []
        srcs = tab.source_files if tab.is_merged else [""] * num_lines

        for i in range(num_lines):
            match = line_matches[i]
            if self.use_keyword_filter and match is None: continue
            
            flines.append(orig_lines[i])
            src_name = f"[{srcs[i]}] " if srcs[i] else ""
            m_cmt = match["comment"] if match else ""
            fcmts.append(f"{src_name}{m_cmt}")
            if match and match["color"] != "#ffffff":
                tag_info.append((len(flines), match["color"]))

        tab.text.delete("1.0", tk.END); tab.text.insert("1.0", "\n".join(flines))
        tab.comment_text.delete("1.0", tk.END); tab.comment_text.insert("1.0", "\n".join(fcmts))
        
        # ハイライト
        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for l_num, col in tag_info:
            tname = f"kw_{col.replace('#','')}"
            tab.text.tag_configure(tname, background=col)
            tab.text.tag_add(tname, f"{l_num}.0", f"{l_num}.end")
        
        tab.linenumbers.redraw()

    def _apply_replacements(self, content: str) -> str:
        for itm in self.replace_patterns_config:
            if itm.get("enabled", True):
                try: content = re.sub(itm["search"], lambda m: f"{m.group(0)}({m.expand(itm['replace'])})", content, flags=re.I)
                except: pass
        return content

    # --- Preset Menu ---
    def create_preset_menu(self, parent_btn, entry_widget):
        menu = tk.Menu(self.root, tearoff=0)
        presets_groups = [
            ("--- 数値・値 ---", None),
            ("整数 (例: 123)", r"\d+"),
            ("16進数 (例: 0xA1)", r"0x[0-9A-Fa-f]+"),
            ("小数/符号付 (例: -12.5)", r"[-+]?\d+(\.\d+)?"),
            ("--- ネットワーク・ID ---", None),
            ("IPアドレス", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
            ("MACアドレス (例: AA:BB:CC...)", r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"),
            ("--- 文字列・構造 ---", None),
            ("[]の中身 (例: [INFO])", r"\[.*?\]"),
            ("Key=Value (例: Err=1)", r"\w+\s*=\s*\S+"),
            ("--- グループ・論理 ---", None),
            ("グループ化 (グループ番号取得)", r"()"),
            ("いずれか (A|B)", r"|"),
            ("--- ワイルドカード ---", None),
            ("任意の文字列 (.*)", r".*"),
        ]
        def ins(t):
            if t: entry_widget.insert(tk.INSERT, t)
        for label, regex in presets_groups:
            if regex is None: menu.add_separator(); menu.add_command(label=label, state="disabled")
            else: menu.add_command(label=label, command=lambda t=regex: ins(t))
        menu.tk_popup(parent_btn.winfo_rootx(), parent_btn.winfo_rooty() + parent_btn.winfo_height())

    # --- Edit Dialogs (UI 形式の復元) ---
    def edit_keywords_dialog(self):
        if self.keywords_dlg_ref and self.keywords_dlg_ref.winfo_exists(): self.keywords_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); self.keywords_dlg_ref = dlg
        dlg.title("フィルタ設定の編集 ※正規表現にマッチした行を抽出し、指定の色とコメントを付与します。")
        dlg.geometry("1150x500"); dlg.transient(self.root); dlg.grab_set()

        container = tk.Frame(dlg); container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        left_fr = tk.Frame(container, relief=tk.GROOVE, borderwidth=1); left_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header = tk.Frame(left_fr); header.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(header, width=135).pack(side=tk.LEFT) # Spacer for checkbox/up/down/del
        tk.Label(header, text="正規表現パターン", width=30, anchor="w").pack(side=tk.LEFT, padx=(5, 0))
        tk.Frame(header, width=35).pack(side=tk.LEFT) # ▼ btn space
        tk.Label(header, text="色", width=10, anchor="w").pack(side=tk.LEFT)
        tk.Frame(header, width=55).pack(side=tk.LEFT) # 色選択 btn space
        tk.Label(header, text="コメント", width=25, anchor="w").pack(side=tk.LEFT, padx=(5,0))
        tk.Label(header, text="+行", width=5, anchor="w").pack(side=tk.LEFT, padx=(5,0))

        canvas = tk.Canvas(left_fr, highlightthickness=0); scr = tk.Scrollbar(left_fr, command=canvas.yview)
        sf = tk.Frame(canvas); canvas.configure(yscrollcommand=scr.set)
        scr.pack(side=tk.RIGHT, fill=tk.Y); canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cv_win = canvas.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cv_win, width=e.width))

        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, (en, kv, cv, cmtv, exv) in enumerate(entries):
                row = tk.Frame(sf); row.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(row, variable=en).pack(side=tk.LEFT, padx=2)
                up = tk.Button(row, text="↑", width=2, command=lambda idx=i: move(idx, -1)); up.pack(side=tk.LEFT)
                dw = tk.Button(row, text="↓", width=2, command=lambda idx=i: move(idx, 1)); dw.pack(side=tk.LEFT)
                if i==0: up.config(state="disabled")
                if i==len(entries)-1: dw.config(state="disabled")
                tk.Button(row, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                ek = tk.Entry(row, textvariable=kv, width=32); ek.pack(side=tk.LEFT, padx=(5, 2))
                bh = tk.Button(row, text="▼", width=2, command=lambda b=None, e=ek: self.create_preset_menu(bh, ek)); bh.pack(side=tk.LEFT, padx=(0, 5))
                tk.Entry(row, textvariable=cv, width=8).pack(side=tk.LEFT)
                tk.Button(row, text="色選択", command=lambda v=cv: v.set(colorchooser.askcolor(v.get(), parent=dlg)[1] or v.get())).pack(side=tk.LEFT, padx=2)
                tk.Entry(row, textvariable=cmtv, width=50).pack(side=tk.LEFT, padx=(10, 5))
                tk.Entry(row, textvariable=exv, width=4).pack(side=tk.LEFT, padx=5)

        def add(k="", c="#ffffff", cmt="", ex="0", en=True):
            entries.append((tk.BooleanVar(value=en), tk.StringVar(value=k), tk.StringVar(value=c), tk.StringVar(value=cmt), tk.StringVar(value=str(ex)))); refresh()
        def delete(idx): del entries[idx]; refresh()
        def move(idx, d): entries[idx], entries[idx+d] = entries[idx+d], entries[idx]; refresh()

        for it in self.keywords_config: add(it.get("pattern"), it.get("color"), it.get("comment"), it.get("extra_lines", 0), it.get("enabled", True))
        if not entries: add()

        rf = tk.Frame(container); rf.pack(side=tk.RIGHT, fill=tk.Y, padx=(10,0))
        tk.Button(rf, text="行を追加", command=add, width=10, height=2).pack(pady=5)
        def save():
            self.keywords_config = [{"pattern":kv.get(),"color":cv.get(),"comment":cmtv.get(),"extra_lines":exv.get(),"enabled":en.get()} for en,kv,cv,cmtv,exv in entries if kv.get()]
            dlg.destroy(); t = self.get_current_tab(); 
            if t: self.apply_display_update(t)
        tk.Button(rf, text="OK", command=save, width=10, height=2, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    def edit_replace_patterns_dialog(self):
        if self.replace_dlg_ref and self.replace_dlg_ref.winfo_exists(): self.replace_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); self.replace_dlg_ref = dlg
        dlg.title("説明パターンの編集 ※正規表現にマッチした文字列の直後に、 (説明)を付与します。")
        dlg.geometry("950x450"); dlg.transient(self.root); dlg.grab_set()

        container = tk.Frame(dlg); container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        left_fr = tk.Frame(container, relief=tk.GROOVE, borderwidth=1); left_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header = tk.Frame(left_fr); header.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(header, width=135).pack(side=tk.LEFT) # Spacer
        tk.Label(header, text="正規表現パターン", width=35, anchor="w").pack(side=tk.LEFT, padx=(5, 0))
        tk.Frame(header, width=30).pack(side=tk.LEFT) # ▼ spacer
        tk.Label(header, text="説明", width=40, anchor="w").pack(side=tk.LEFT)

        canvas = tk.Canvas(left_fr, highlightthickness=0); scr = tk.Scrollbar(left_fr, command=canvas.yview)
        sf = tk.Frame(canvas); canvas.configure(yscrollcommand=scr.set)
        scr.pack(side=tk.RIGHT, fill=tk.Y); canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cv_win = canvas.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cv_win, width=e.width))

        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, (en, pv, dv) in enumerate(entries):
                row = tk.Frame(sf); row.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(row, variable=en).pack(side=tk.LEFT, padx=2)
                up = tk.Button(row, text="↑", width=2, command=lambda idx=i: move(idx, -1)); up.pack(side=tk.LEFT)
                dw = tk.Button(row, text="↓", width=2, command=lambda idx=i: move(idx, 1)); dw.pack(side=tk.LEFT)
                if i==0: up.config(state="disabled")
                if i==len(entries)-1: dw.config(state="disabled")
                tk.Button(row, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                ep = tk.Entry(row, textvariable=pv, width=35); ep.pack(side=tk.LEFT, padx=(5, 2))
                bh = tk.Button(row, text="▼", width=2, command=lambda b=None, e=ep: self.create_preset_menu(bh, ep)); bh.pack(side=tk.LEFT, padx=(0, 5))
                tk.Entry(row, textvariable=dv, width=60).pack(side=tk.LEFT, padx=(0, 5))

        def add(p="", d="", en=True):
            entries.append((tk.BooleanVar(value=en), tk.StringVar(value=p), tk.StringVar(value=d))); refresh()
        def delete(idx): del entries[idx]; refresh()
        def move(idx, d): entries[idx], entries[idx+d] = entries[idx+d], entries[idx]; refresh()

        for it in self.replace_patterns_config: add(it.get("search"), it.get("replace"), it.get("enabled", True))
        if not entries: add()

        rf = tk.Frame(container); rf.pack(side=tk.RIGHT, fill=tk.Y, padx=(10,0))
        tk.Button(rf, text="行を追加", command=add, width=10, height=2).pack(pady=5)
        def save():
            self.replace_patterns_config = [{"search":pv.get(),"replace":dv.get(),"enabled":en.get()} for en,pv,dv in entries if pv.get()]
            dlg.destroy(); t = self.get_current_tab(); 
            if t: self._open_file_path(t.file_path) if not t.is_merged else self.apply_display_update(t)
        tk.Button(rf, text="OK", command=save, width=10, height=2, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    # --- Config I/O ---
    def load_config_dialog(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")]); 
        if p: self.load_config(p)
    def save_config_dialog(self):
        p = filedialog.asksaveasfilename(defaultextension=".json"); 
        if p:
            with open(p, "w", encoding="utf-8") as f: json.dump({"keywords":self.keywords_config, "replace_patterns":self.replace_patterns_config}, f, indent=2, ensure_ascii=False)
    def load_config(self, p):
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f); self.keywords_config = d.get("keywords", []); self.replace_patterns_config = d.get("replace_patterns", [])
        t = self.get_current_tab(); 
        if t: self.apply_display_update(t)

    # --- Find & Export ---
    def open_find_dialog(self):
        k = simpledialog.askstring("検索", "検索文字列:"); 
        if k: self.last_search_keyword = k; self.find_next(True)
    def find_next(self, first=False):
        tab = self.get_current_tab()
        if not tab or not self.last_search_keyword: return
        start = "1.0" if first else f"{tab.text.index(tk.INSERT)}+1c"
        pos = tab.text.search(self.last_search_keyword, start, nocase=True)
        if pos:
            tab.text.mark_set(tk.INSERT, pos); tab.text.see(pos)
            tab.text.tag_remove("found", "1.0", tk.END); tab.text.tag_add("found", pos, f"{pos}+{len(self.last_search_keyword)}c")
            tab.text.tag_config("found", background="yellow"); tab.text.focus_set()

    def export_to_excel(self):
        tab = self.get_current_tab()
        if not tab: return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not path: return
        try:
            log_lines = tab.text.get("1.0", "end-1c").splitlines()
            cmt_lines = tab.comment_text.get("1.0", "end-1c").splitlines()
            rules = []
            for it in self.keywords_config:
                if it.get("enabled", True):
                    try: rules.append((re.compile(it["pattern"], re.I), it.get("color", "#ffffff"), int(it.get("extra_lines", 0))))
                    except: pass
            html_colors = ["#ffffff"] * len(log_lines)
            for idx in range(len(log_lines)):
                for pat, col, extra in rules:
                    if pat.search(log_lines[idx]):
                        for j in range(idx, min(idx + extra + 1, len(log_lines))): html_colors[j] = col
                        break
            h = ['<html><head><meta charset="utf-8"><style>table{border-collapse:collapse;width:100%;font-family:monospace;} th{background:#ddd;border:1px solid #999;} td{border:1px solid #ccc;padding:2px 4px;white-space:pre-wrap;}</style></head><body><table>']
            h.append('<thead><tr><th>Line</th><th>Log Content</th><th>Comment</th></tr></thead><tbody>')
            for i, line in enumerate(log_lines):
                c = cmt_lines[i] if i < len(cmt_lines) else ""
                h.append(f'<tr style="background:{html_colors[i]}"><td>{i+1}</td><td>{html.escape(line)}</td><td>{html.escape(c)}</td></tr>')
            with open(path, "w", encoding="utf-8-sig") as f: f.write("\n".join(h) + "</tbody></table></body></html>")
            messagebox.showinfo("完了", "保存しました")
        except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS(); app = LogViewerApp(root); root.mainloop()