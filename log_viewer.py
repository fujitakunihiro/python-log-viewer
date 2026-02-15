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

# --- DnD Support (Optional) ---
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
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True},
        {"pattern": r"\[\d+\]",   "color": "#e0e0e0", "comment": "タイムスタンプ",   "enabled": True}
    ],
    "replace_patterns": []
}

class LineNumberCanvas(tk.Canvas):
    """行番号を描画するキャンバス"""
    def __init__(self, master, text_widget, **kwargs):
        super().__init__(master, **kwargs)
        self.text_widget = text_widget
        self.text_widget.bind('<KeyRelease>', self.redraw)
        self.text_widget.bind('<MouseWheel>', self.redraw)
        self.text_widget.bind('<Configure>', self.redraw)
        self.text_widget.bind('<<Modified>>', self.redraw)
        self.text_widget.bind('<Button-1>', self.redraw)

    def redraw(self, *args):
        self.delete("all")
        i = self.text_widget.index("@0,0")
        while True:
            dline = self.text_widget.dlineinfo(i)
            if dline is None: 
                break
            y = dline[1]
            linenum = str(i).split(".")[0]
            self.create_text(40, y, anchor="ne", text=linenum, fill="#666666")
            i = self.text_widget.index(f"{i}+1line")

class LogTab(tk.Frame):
    """個別のログ表示タブ"""
    def __init__(self, master, app, path, content, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged

        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)

        # 左: ログ
        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=720) 
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        self.text = tk.Text(left_frame, wrap=tk.NONE, undo=False, maxundo=0,
                            yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_log.config(command=self.text.xview)

        # 右: コメント
        right_frame = tk.Frame(self.paned_window)
        self.paned_window.add(right_frame, minsize=100, stretch="always", width=480) 
        self.hsb_cmt = tk.Scrollbar(right_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        self.comment_text = tk.Text(right_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa",
                                    yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)

        def sync_yview(*args):
            self.text.yview(*args); self.comment_text.yview(*args); self.linenumbers.redraw()
        self.vsb.config(command=sync_yview)

        def on_mousewheel(event):
            delta = int(-1*(event.delta/120)) if event.delta else 0
            self.text.yview_scroll(delta, "units"); self.comment_text.yview_scroll(delta, "units"); self.linenumbers.redraw()
            return "break"
        for w in [self.text, self.comment_text]:
            w.bind('<MouseWheel>', on_mousewheel)
            w.bind('<Button-4>', lambda e: on_mousewheel(type('obj', (object,), {'delta': 120})()))
            w.bind('<Button-5>', lambda e: on_mousewheel(type('obj', (object,), {'delta': -120})()))

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1200x800")

        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.replace_patterns_config = []
        self.use_keyword_filter = False
        self.last_search_keyword = ""
        self.keywords_dlg_ref = None
        self.replace_dlg_ref = None

        self._build_ui()
        self._bind_shortcuts()
        if os.path.exists(self.config_path):
            self.load_config(self.config_path)

    def _build_ui(self) -> None:
        menubar = tk.Menu(self.root)
        
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="開く...", accelerator="Ctrl+O", command=self.open_file)
        filemenu.add_command(label="現在のタブを閉じる", accelerator="Ctrl+W", command=self.close_tab)
        filemenu.add_command(label="マージして表示...", command=self.merge_logs_action)
        filemenu.add_separator()
        filemenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel)
        filemenu.add_separator()
        filemenu.add_command(label="終了", command=self.root.quit)
        menubar.add_cascade(label="ファイル", menu=filemenu)

        editmenu = tk.Menu(menubar, tearoff=0)
        editmenu.add_command(label="検索...", accelerator="Ctrl+F", command=self.open_find_dialog)
        editmenu.add_command(label="次を検索", accelerator="F3", command=self.find_next)
        menubar.add_cascade(label="編集", menu=editmenu)

        configmenu = tk.Menu(menubar, tearoff=0)
        configmenu.add_command(label="設定読み込み...", command=self.load_config_dialog)
        configmenu.add_command(label="設定保存...", command=self.save_config_dialog)
        configmenu.add_separator()
        configmenu.add_command(label="フィルタ設定の編集...", command=self.edit_keywords_dialog)
        configmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        menubar.add_cascade(label="設定", menu=configmenu)
        self.root.config(menu=menubar)

        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=15, command=self.toggle_filter)
        self.btn_kw_filter.pack(side=tk.LEFT)
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e1f5fe").pack(side=tk.LEFT, padx=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="準備完了")
        tk.Label(self.root, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN).pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e: [self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def _bind_shortcuts(self):
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-w>', lambda e: self.close_tab())
        self.root.bind('<Control-f>', lambda e: self.open_find_dialog())
        self.root.bind('<F3>', lambda e: self.find_next())

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None

    # --- File/Merge ---
    def open_file(self):
        paths = filedialog.askopenfilenames()
        for p in paths: self._open_file_path(p)

    def close_tab(self):
        tab = self.get_current_tab()
        if tab: self.notebook.forget(tab)

    def _open_file_path(self, path: str):
        content = None
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        if content is not None:
            tab = LogTab(self.notebook, self, path, content)
            self.notebook.add(tab, text=os.path.basename(path))
            self.notebook.select(tab); self.apply_display_update(tab)

    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs()]
        target_tabs = [t for t in tabs if isinstance(t, LogTab) and not t.is_merged]
        if len(target_tabs) < 2:
            messagebox.showwarning("マージ", "マージするには複数のファイルを開いてください。"); return

        ts_len = simpledialog.askinteger("マージ設定", "時刻として扱う先頭の文字数:", initialvalue=19, minvalue=0)
        if ts_len is None: return

        all_entries = []
        for t in target_tabs:
            fname = os.path.basename(t.file_path)
            for line in t.original_content.splitlines():
                if not line.strip(): continue
                all_entries.append((line[:ts_len], line, fname))
        all_entries.sort(key=lambda x: x[0])

        merged_content = "\n".join([x[1] for x in all_entries])
        source_comments = "\n".join([x[2] for x in all_entries])

        merged_tab = LogTab(self.notebook, self, "Merged", merged_content, is_merged=True)
        merged_tab.comment_text.insert("1.0", source_comments)
        self.notebook.add(merged_tab, text="[マージ結果]")
        self.notebook.select(merged_tab); self.apply_display_update(merged_tab, use_existing_comments=True)

    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        self.btn_kw_filter.config(text="フィルタ: ON" if self.use_keyword_filter else "フィルタ: OFF",
                                  bg="#aaccff" if self.use_keyword_filter else "SystemButtonFace")
        tab = self.get_current_tab()
        if tab: self.apply_display_update(tab, use_existing_comments=tab.is_merged)

    def apply_display_update(self, tab: LogTab, use_existing_comments=False):
        content = tab.original_content
        if self.replace_patterns_config: content = self._apply_replacements(content)
        lines = content.splitlines()
        
        check_list = []
        for item in self.keywords_config:
            if item.get("enabled", True) and item.get("pattern"):
                try: check_list.append((re.compile(item["pattern"], re.I), item.get("comment", "")))
                except: pass

        filtered_lines, final_comments = [], []
        existing_cmts = tab.comment_text.get("1.0", "end-1c").splitlines() if use_existing_comments else []

        for i, line in enumerate(lines):
            matched_cmt, is_match = "", False
            for pat, cmt in check_list:
                if pat.search(line): is_match = True; matched_cmt = cmt; break
            if self.use_keyword_filter and not is_match: continue
            filtered_lines.append(line)
            if use_existing_comments:
                src = existing_cmts[i] if i < len(existing_cmts) else ""
                final_comments.append(src if src else matched_cmt)
            else: final_comments.append(matched_cmt)

        tab.text.delete("1.0", tk.END); tab.text.insert("1.0", "\n".join(filtered_lines))
        tab.comment_text.delete("1.0", tk.END); tab.comment_text.insert("1.0", "\n".join(final_comments))
        self.highlight_keywords(tab); tab.linenumbers.redraw()

    def _apply_replacements(self, content: str) -> str:
        matches = []
        for item in self.replace_patterns_config:
            if not item.get("enabled", True): continue
            try:
                pattern = re.compile(item.get("search", ""), re.I)
                for m in pattern.finditer(content):
                    repl = item.get("replace", "")
                    try: rt = m.expand(repl)
                    except: rt = repl
                    matches.append((m.start(), m.end(), m.group(0), rt))
            except: continue
        if not matches: return content
        matches.sort(key=lambda x: x[0])
        out, pos = [], 0
        for s, e, orig, repl in matches:
            if s < pos: continue
            out.append(content[pos:s]); out.append(f"{orig}({repl})"); pos = e
        out.append(content[pos:]); return "".join(out)

    def highlight_keywords(self, tab: LogTab):
        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for item in self.keywords_config:
            if not item.get("enabled", True) or not item.get("pattern"): continue
            tag = f"kw_{abs(hash(item['pattern']))}"
            tab.text.tag_configure(tag, background=item.get("color", "#ffffff"))
            start, cv = "1.0", tk.IntVar()
            while True:
                try: pos = tab.text.search(item["pattern"], start, stopindex=tk.END, nocase=True, regexp=True, count=cv)
                except: break
                if not pos: break
                end = f"{pos}+{cv.get()}c"; tab.text.tag_add(tag, pos, end); start = end

    # --- Config I/O ---
    def load_config_dialog(self):
        path = filedialog.askopenfilename(filetypes=[("JSONファイル","*.json")])
        if path: self.load_config(path)

    def save_config_dialog(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSONファイル","*.json")])
        if path: self.save_config(path)

    def load_config(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f: data = json.load(f)
            self.keywords_config = data.get("keywords", [])
            self.replace_patterns_config = data.get("replace_patterns", [])
            tab = self.get_current_tab()
            if tab: self.apply_display_update(tab, tab.is_merged)
        except Exception as e: messagebox.showerror("エラー", f"読込失敗: {e}")

    def save_config(self, path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"keywords": self.keywords_config, "replace_patterns": self.replace_patterns_config}, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("保存", "保存しました。")
        except Exception as e: messagebox.showerror("エラー", f"保存失敗: {e}")

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
        def insert_text(text):
            if text: entry_widget.insert(tk.INSERT, text)
        for label, regex in presets_groups:
            if regex is None: menu.add_separator(); menu.add_command(label=label, state="disabled")
            else: menu.add_command(label=label, command=lambda t=regex: insert_text(t))
        try: menu.tk_popup(parent_btn.winfo_rootx(), parent_btn.winfo_rooty() + parent_btn.winfo_height())
        finally: menu.grab_release()

    # --- Edit Dialogs (UI 完全復元) ---
    def edit_keywords_dialog(self):
        if self.keywords_dlg_ref and self.keywords_dlg_ref.winfo_exists(): self.keywords_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); self.keywords_dlg_ref = dlg
        dlg.title("フィルタ設定の編集 ※正規表現にマッチした行を抽出し、指定の色とコメントを付与します。")
        dlg.geometry("1100x450"); dlg.transient(self.root); dlg.grab_set()
        
        container = tk.Frame(dlg); container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1); left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header = tk.Frame(left_frame); header.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(header, width=135).pack(side=tk.LEFT) # Spacer
        tk.Label(header, text="正規表現パターン", width=30, anchor="w").pack(side=tk.LEFT, padx=(5, 0))
        tk.Frame(header, width=35).pack(side=tk.LEFT)
        tk.Label(header, text="色", width=10, anchor="w").pack(side=tk.LEFT)
        tk.Frame(header, width=55).pack(side=tk.LEFT)
        tk.Label(header, text="コメント", width=20, anchor="w").pack(side=tk.LEFT)

        canvas = tk.Canvas(left_frame, highlightthickness=0); scr = tk.Scrollbar(left_frame, orient="vertical", command=canvas.yview)
        sf = tk.Frame(canvas); canvas.configure(yscrollcommand=scr.set)
        scr.pack(side=tk.RIGHT, fill=tk.Y); canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cv_win = canvas.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cv_win, width=e.width))

        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, (en, kv, cv, cmtv) in enumerate(entries):
                row = tk.Frame(sf); row.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(row, variable=en).pack(side=tk.LEFT, padx=2)
                up = tk.Button(row, text="↑", width=2, command=lambda idx=i: move(idx, -1)); up.pack(side=tk.LEFT)
                dw = tk.Button(row, text="↓", width=2, command=lambda idx=i: move(idx, 1)); dw.pack(side=tk.LEFT)
                if i==0: up.config(state="disabled")
                if i==len(entries)-1: dw.config(state="disabled")
                tk.Button(row, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                ek = tk.Entry(row, textvariable=kv, width=32); ek.pack(side=tk.LEFT, padx=(5, 2))
                bh = tk.Button(row, text="▼", width=2, command=lambda b=None, e=ek: self.create_preset_menu(bh, ek))
                bh.pack(side=tk.LEFT, padx=(0, 5))
                tk.Entry(row, textvariable=cv, width=8).pack(side=tk.LEFT)
                tk.Button(row, text="色選択", command=lambda v=cv: v.set(colorchooser.askcolor(v.get(), parent=dlg)[1] or v.get())).pack(side=tk.LEFT, padx=2)
                tk.Entry(row, textvariable=cmtv, width=80).pack(side=tk.LEFT, padx=(10, 5))

        def add(k="", c="#ffff99", cmt="", en=True):
            entries.append((tk.BooleanVar(value=en), tk.StringVar(value=k), tk.StringVar(value=c), tk.StringVar(value=cmt))); refresh()
        def delete(idx): del entries[idx]; refresh()
        def move(idx, d): entries[idx], entries[idx+d] = entries[idx+d], entries[idx]; refresh()

        for item in self.keywords_config: add(item.get("pattern",""), item.get("color","#ffffff"), item.get("comment",""), item.get("enabled",True))
        if not entries: add()
        
        rf = tk.Frame(container); rf.pack(side=tk.RIGHT, fill=tk.Y, padx=(10,0))
        tk.Button(rf, text="行を追加", command=add, width=10, height=2).pack(pady=5)
        def save():
            self.keywords_config = [{"pattern":kv.get(),"color":cv.get(),"comment":cmtv.get(),"enabled":en.get()} for en,kv,cv,cmtv in entries if kv.get()]
            dlg.destroy(); tab = self.get_current_tab()
            if tab: self.apply_display_update(tab, tab.is_merged)
        tk.Button(rf, text="OK", command=save, width=10, height=2, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    def edit_replace_patterns_dialog(self):
        if self.replace_dlg_ref and self.replace_dlg_ref.winfo_exists(): self.replace_dlg_ref.lift(); return
        dlg = tk.Toplevel(self.root); self.replace_dlg_ref = dlg
        dlg.title("説明パターンの編集 ※正規表現にマッチした文字列の直後に、 (説明)を付与します。")
        dlg.geometry("950x450"); dlg.transient(self.root); dlg.grab_set()

        container = tk.Frame(dlg); container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        left_frame = tk.Frame(container, relief=tk.GROOVE, borderwidth=1); left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header = tk.Frame(left_frame); header.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(header, width=135).pack(side=tk.LEFT)
        tk.Label(header, text="正規表現パターン", width=35, anchor="w").pack(side=tk.LEFT, padx=(5, 0))
        tk.Frame(header, width=30).pack(side=tk.LEFT)
        tk.Label(header, text="説明", width=40, anchor="w").pack(side=tk.LEFT)

        canvas = tk.Canvas(left_frame, highlightthickness=0); scr = tk.Scrollbar(left_frame, orient="vertical", command=canvas.yview)
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
                tk.Entry(row, textvariable=dv, width=80).pack(side=tk.LEFT, padx=(0, 5))

        def add(p="", d="", en=True):
            entries.append((tk.BooleanVar(value=en), tk.StringVar(value=p), tk.StringVar(value=d))); refresh()
        def delete(idx): del entries[idx]; refresh()
        def move(idx, d): entries[idx], entries[idx+d] = entries[idx+d], entries[idx]; refresh()

        for item in self.replace_patterns_config: add(item.get("search",""), item.get("replace",""), item.get("enabled",True))
        if not entries: add()

        rf = tk.Frame(container); rf.pack(side=tk.RIGHT, fill=tk.Y, padx=(10,0))
        tk.Button(rf, text="行を追加", command=add, width=10, height=2).pack(pady=5)
        def save():
            self.replace_patterns_config = [{"search":pv.get(),"replace":dv.get(),"enabled":en.get()} for en,pv,dv in entries if pv.get()]
            dlg.destroy(); tab = self.get_current_tab()
            if tab: self._open_file_path(tab.file_path) if not tab.is_merged else self.apply_display_update(tab, True)
        tk.Button(rf, text="OK", command=save, width=10, height=2, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    # --- Search/Export ---
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
        tab = self.get_current_tab(); 
        if not tab: return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not path: return
        try:
            log_lines, cmt_lines = tab.text.get("1.0", "end-1c").splitlines(), tab.comment_text.get("1.0", "end-1c").splitlines()
            html_data = ["<html><head><meta charset='utf-8'><style>td{border:1px solid #ccc; font-family:monospace;}</style></head><body><table>"]
            for i, line in enumerate(log_lines):
                c = cmt_lines[i] if i < len(cmt_lines) else ""
                html_data.append(f"<tr><td>{i+1}</td><td><pre>{html.escape(line)}</pre></td><td>{html.escape(c)}</td></tr>")
            with open(path, "w", encoding="utf-8-sig") as f: f.write("\n".join(html_data) + "</table></body></html>")
            messagebox.showinfo("完了", "エクスポートしました。")
        except Exception as e: messagebox.showerror("エラー", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS(); app = LogViewerApp(root); root.mainloop()