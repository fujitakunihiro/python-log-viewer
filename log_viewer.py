from __future__ import annotations

import json
import os
import sys
import re
import html
import tkinter as tk
from datetime import datetime, timedelta
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

# --- Constants ---
VSYNC_TAG = "<VSYNC>"
VSYNC_REGEX = r"V_START|V-Sync|VIRTUAL V-SYNC|\[VIRTUAL V-SYNC\]"
VSYNC_MARKER = "--- [VIRTUAL V-SYNC] ---"
VIRTUAL_SRC_NAME = "(Virtual)"

# --- Default Configuration ---
DEFAULT_CONFIG = {
    "keywords": [
        {"pattern": r".*ERROR.*", "color": "#ffcccc", "comment": "重大なエラー発生", "enabled": True, "extra_lines": 0},
        {"pattern": "WARN",       "color": "#ffebcc", "comment": "警告メッセージ",   "enabled": True, "extra_lines": 2},
        {"pattern": "INFO",       "color": "#ccffcc", "comment": "正常動作ログ",     "enabled": True, "extra_lines": 0},
        {"pattern": r"--- \[VIRTUAL V-SYNC\] ---", "color": "#e1bee7", "comment": "仮想V同期タイミング", "enabled": True, "extra_lines": 0}
    ],
    "sections": [
        {"name": "初期化(Server)", "start": "SRV_INIT_START", "start_wait": False, "end": "SRV_INIT_DONE", "end_wait": False, "color": "#e1f5fe", "file_pattern": "server.*", "enabled": True},
        {"name": "初期化(Client)", "start": "CLI_BOOT",       "start_wait": False, "end": "CLI_READY",     "end_wait": False, "color": "#e0f2f1", "file_pattern": "client.*", "enabled": True},
        {"name": "通信処理",       "start": "CONNECT",        "start_wait": False, "end": "DISCONNECT",    "end_wait": False, "color": "#fff3e0", "file_pattern": ".*",       "enabled": True}
    ],
    "replace_patterns": [],
    "analysis_rules": [
        {"name": "Input->V", "cmd_pattern": "Command|Input", "vsync_pattern": "V_START|V-Sync|VIRTUAL V-SYNC", "enabled": True}
    ],
    "analysis_time_pattern": r"^\[?(\d+(?:\.\d+)?)\]?",
    "vsync_auto_insert": {
        "enabled": True,
        "event_pattern": r"V_START|V-Sync",
        "time_pattern": r"^\[?(\d+(?:\.\d+)?)\]?",
        "mode": "auto", 
        "manual_ms": 16.666
    }
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
    def __init__(self, master, app, path, content, source_files_list=None, is_merged=False):
        super().__init__(master)
        self.app = app
        self.file_path = path
        self.original_content = content
        self.is_merged = is_merged
        
        self.source_file_names = source_files_list if source_files_list else ([os.path.basename(path)] if path else [])
        self.line_source_map: List[str] = []
        self.status_texts: Dict[str, tk.Text] = {}
        self.analysis_comments: Dict[int, str] = {}
        self._create_layout()

    def _create_layout(self):
        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.paned_window = tk.PanedWindow(self, orient=tk.HORIZONTAL, sashwidth=4, bg="#d0d0d0")
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(self.paned_window)
        self.paned_window.add(left_frame, minsize=100, stretch="always", width=650)
        
        header_text = "[Merged View]" if self.is_merged else (self.source_file_names[0] if self.source_file_names else "Log Content")
        tk.Label(left_frame, text=header_text, bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        
        self.hsb_log = tk.Scrollbar(left_frame, orient=tk.HORIZONTAL)
        self.hsb_log.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.text = tk.Text(left_frame, wrap=tk.NONE, yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_log.set)
        self.text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.text.tag_config("found", background="#0000cd", foreground="white")
        
        self.linenumbers = LineNumberCanvas(left_frame, self.text, width=45, bg='#f0f0f0')
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        
        self.timediff_text = tk.Text(left_frame, width=12, wrap=tk.NONE, bg="#f8f8f8", fg="#555555", yscrollcommand=self.vsb.set)
        self.timediff_text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.timediff_text.pack(side=tk.LEFT, fill=tk.Y)

        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_log.config(command=self.text.xview)
        
        cmt_frame = tk.Frame(self.paned_window)
        self.paned_window.add(cmt_frame, minsize=50, stretch="always", width=250)
        
        self.hsb_cmt = tk.Scrollbar(cmt_frame, orient=tk.HORIZONTAL)
        self.hsb_cmt.pack(side=tk.BOTTOM, fill=tk.X)
        
        tk.Label(cmt_frame, text="Comment / Tags / Analysis", bg="#e0e0e0", relief=tk.RAISED).pack(side=tk.TOP, fill=tk.X)
        
        self.comment_text = tk.Text(cmt_frame, wrap=tk.NONE, bg="#fcfcfc", fg="#0000aa", yscrollcommand=self.vsb.set, xscrollcommand=self.hsb_cmt.set)
        self.comment_text.tag_configure("sel", background="#cce8ff", foreground="black")
        self.comment_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.hsb_cmt.config(command=self.comment_text.xview)
        
        for fname in self.source_file_names:
            st_frame = tk.Frame(self.paned_window)
            self.paned_window.add(st_frame, minsize=50, stretch="always", width=120)
            tk.Label(st_frame, text=f"{fname}の区間", bg="#dcedc8", relief=tk.RAISED, font=("MS UI Gothic", 9, "bold")).pack(side=tk.TOP, fill=tk.X)
            
            hsb = tk.Scrollbar(st_frame, orient=tk.HORIZONTAL)
            hsb.pack(side=tk.BOTTOM, fill=tk.X)
            
            st_text = tk.Text(st_frame, wrap=tk.NONE, bg="#f8f8f8", fg="#333333", yscrollcommand=self.vsb.set, xscrollcommand=hsb.set)
            st_text.tag_configure("sel", background="#cce8ff", foreground="black")
            st_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            hsb.config(command=st_text.xview)
            self.status_texts[fname] = st_text
            
        all_texts = [self.text, self.timediff_text, self.comment_text] + list(self.status_texts.values())
        
        def sync_yview(*args):
            for t in all_texts: t.yview(*args)
            self.linenumbers.redraw()
        self.vsb.config(command=sync_yview)
        
        def on_mw(e):
            d = int(-1*(e.delta/120)) if e.delta else 0
            for t in all_texts: t.yview_scroll(d, "units")
            self.linenumbers.redraw()
            return "break"
        for t in all_texts: t.bind('<MouseWheel>', on_mw)

class LogViewerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Log Viewer")
        self.root.geometry("1450x850")
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        
        self.keywords_config = [x.copy() for x in DEFAULT_CONFIG["keywords"]]
        self.sections_config = [x.copy() for x in DEFAULT_CONFIG["sections"]]
        self.replace_patterns_config = []
        self.analysis_rules_config = [x.copy() for x in DEFAULT_CONFIG["analysis_rules"]]
        self.analysis_time_pattern = DEFAULT_CONFIG["analysis_time_pattern"]
        self.vsync_config = DEFAULT_CONFIG["vsync_auto_insert"].copy()
        
        self.use_keyword_filter = False
        self.show_vsync_lines = True 
        
        self.keywords_dlg_ref = None
        self.replace_dlg_ref = None
        self.sections_dlg_ref = None
        self.find_window_ref = None
        self.last_search_keyword = ""
        self.analysis_dlg_ref = None
        self.vsync_settings_dlg_ref = None

        self._build_ui()
        
        self.root.bind('<F5>', lambda e: self.reload_file())
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-w>', lambda e: self.close_tab())
        self.root.bind('<Control-f>', lambda e: self.open_find_dialog())
        self.root.bind('<F3>', lambda e: self.find_next())
        self.root.bind('<Shift-F3>', lambda e: self.find_prev())
        
        if os.path.exists(self.config_path):
            self.load_config(self.config_path)

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        fmenu = tk.Menu(menubar, tearoff=0)
        fmenu.add_command(label="開く...", command=self.open_file, accelerator="Ctrl+O")
        fmenu.add_command(label="現在のタブを閉じる", command=self.close_tab, accelerator="Ctrl+W")
        fmenu.add_command(label="再読み込み", command=self.reload_file, accelerator="F5")
        fmenu.add_separator()
        fmenu.add_command(label="マージして表示...", command=self.merge_logs_action)
        fmenu.add_separator()
        fmenu.add_command(label="Excel形式でエクスポート (HTML)...", command=self.export_to_excel)
        fmenu.add_separator()
        fmenu.add_command(label="終了", command=self.root.quit)
        menubar.add_cascade(label="ファイル", menu=fmenu)
        
        emenu = tk.Menu(menubar, tearoff=0)
        emenu.add_command(label="検索...", command=self.open_find_dialog, accelerator="Ctrl+F")
        emenu.add_command(label="次を検索", command=self.find_next, accelerator="F3")
        emenu.add_command(label="前を検索", command=self.find_prev, accelerator="Shift+F3")
        menubar.add_cascade(label="編集", menu=emenu)

        cmenu = tk.Menu(menubar, tearoff=0)
        cmenu.add_command(label="設定読み込み...", command=self.load_config_dialog)
        cmenu.add_command(label="設定保存...", command=self.save_config_dialog)
        cmenu.add_separator()
        cmenu.add_command(label="フィルタ設定の編集 (行単位)...", command=self.edit_keywords_dialog)
        cmenu.add_command(label="区間設定の編集 (開始-終了)...", command=self.edit_sections_dialog)
        cmenu.add_command(label="説明パターンの編集...", command=self.edit_replace_patterns_dialog)
        cmenu.add_separator()
        cmenu.add_command(label="イベント適用解析設定の編集...", command=self.edit_analysis_rules_dialog)
        cmenu.add_command(label="V周期(仮想)挿入の設定...", command=self.open_vsync_settings_dialog)
        menubar.add_cascade(label="設定", menu=cmenu)
        
        self.root.config(menu=menubar)
        
        toolbar = tk.Frame(self.root)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        self.btn_kw_filter = tk.Button(toolbar, text="フィルタ: OFF", width=12, command=self.toggle_filter)
        self.btn_kw_filter.pack(side=tk.LEFT)
        
        tk.Button(toolbar, text="ログをマージ", command=self.merge_logs_action, bg="#e3f2fd").pack(side=tk.LEFT, padx=10)
        
        self.btn_vsync_toggle = tk.Button(toolbar, text="V周期表示: ON", width=12, command=self.toggle_vsync_display)
        self.btn_vsync_toggle.pack(side=tk.LEFT, padx=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.status_var = tk.StringVar(value="準備完了")
        tk.Label(self.root, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill=tk.X, side=tk.BOTTOM)

        if HAS_DND:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', lambda e: [self._open_file_path(f) for f in self.root.tk.splitlist(e.data)])

    def get_current_tab(self) -> Optional[LogTab]:
        cid = self.notebook.select()
        return self.notebook.nametowidget(cid) if cid else None

    # --- File/Merge ---
    def open_file(self):
        for p in filedialog.askopenfilenames(): self._open_file_path(p)

    def close_tab(self):
        t = self.get_current_tab()
        if t: self.notebook.forget(t)

    def reload_file(self):
        tab = self.get_current_tab()
        if not tab: return
        if tab.is_merged:
            messagebox.showinfo("再読み込み", "マージ結果タブは再読み込みできません。")
            return
        if not tab.file_path or not os.path.exists(tab.file_path): return
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(tab.file_path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
        
        if self.vsync_config.get("enabled", True):
            fname = os.path.basename(tab.file_path)
            new_content, new_src_map = self._process_vsync_insertion(content, [fname]*len(content.splitlines()), [fname])
            tab.original_content = new_content
            tab.line_source_map = new_src_map
        else: 
            tab.original_content = content
            tab.line_source_map = [] 
            
        self.run_analysis_for_tab(tab)

    def _open_file_path(self, path: str):
        content = ""
        for enc in ['utf-8', 'cp932', 'shift_jis', 'latin-1']:
            try:
                with open(path, "r", encoding=enc) as f: content = f.read(); break
            except: continue
            
        fname = os.path.basename(path)
        if self.vsync_config.get("enabled", True):
            new_content, new_src_map = self._process_vsync_insertion(content, [fname]*len(content.splitlines()), [fname])
            tab = LogTab(self.notebook, self, path, new_content, source_files_list=[fname], is_merged=True)
            tab.line_source_map = new_src_map
            self.notebook.add(tab, text=fname)
            self.notebook.select(tab)
            self.run_analysis_for_tab(tab)
        else:
            tab = LogTab(self.notebook, self, path, content, source_files_list=[fname])
            self.notebook.add(tab, text=fname)
            self.notebook.select(tab)
            self.run_analysis_for_tab(tab)

    def merge_logs_action(self):
        tabs = [self.notebook.nametowidget(i) for i in self.notebook.tabs() if isinstance(self.notebook.nametowidget(i), LogTab)]
        target_tabs = [t for t in tabs if t.file_path and t.file_path != "Merged"]
        if len(target_tabs) < 2:
            messagebox.showinfo("マージ", "マージするには2つ以上のログファイルを開いてください。")
            return
            
        ts_len = simpledialog.askinteger("マージ", "時刻ソート用の先頭文字数:", initialvalue=19, minvalue=0)
        if ts_len is None: return
        
        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append((re.compile(itm["pattern"], re.I), int(itm.get("extra_lines", 0))))
                except: pass
                
        all_blocks = []
        unique_srcs = []
        
        for t in target_tabs:
            fn = os.path.basename(t.file_path)
            if fn not in unique_srcs: unique_srcs.append(fn)
            
            raw_lines = t.original_content.splitlines()
            if not raw_lines: continue
            
            effective_ts = []
            last_valid_ts = ""
            for line in raw_lines:
                ts_part = line[:ts_len]
                if ts_part.strip() and len(line) > 0 and not line[0].isspace(): last_valid_ts = ts_part
                effective_ts.append(last_valid_ts)
            first_ts = next((x for x in effective_ts if x), "0"*ts_len)
            effective_ts = [x if x else first_ts for x in effective_ts]
            
            i = 0
            while i < len(raw_lines):
                line = raw_lines[i]
                extra = 0
                for pat, ex in kw_rules:
                    if pat.search(line): extra = ex; break
                
                actual_extra = 0
                for j in range(1, extra + 1):
                    if i + j < len(raw_lines):
                        next_line = raw_lines[i + j]
                        ts_part_next = next_line[:ts_len]
                        if ts_part_next.strip() and len(next_line) > 0 and not next_line[0].isspace():
                            break
                        actual_extra += 1
                
                bl = raw_lines[i : i + actual_extra + 1]
                skey = effective_ts[i]
                current_src = t.line_source_map[i] if (t.line_source_map and i < len(t.line_source_map)) else fn
                all_blocks.append((skey, bl, current_src))
                i += actual_extra + 1
                
        all_blocks.sort(key=lambda x: x[0])
        final_lines, final_src = [], []
        for _, bl, src_name in all_blocks:
            final_lines.extend(bl)
            final_src.extend([src_name] * len(bl))
            
        m_tab = LogTab(self.notebook, self, "Merged", "\n".join(final_lines), source_files_list=unique_srcs, is_merged=True)
        m_tab.line_source_map = final_src
        self.notebook.add(m_tab, text="[マージ結果]")
        self.notebook.select(m_tab)
        self.run_analysis_for_tab(m_tab)

    # --- Analysis Features (Auto) ---
    def edit_analysis_rules_dialog(self):
        if self.analysis_dlg_ref and self.analysis_dlg_ref.winfo_exists():
            self.analysis_dlg_ref.lift()
            return
            
        dlg = tk.Toplevel(self.root)
        dlg.title("イベント適用解析設定の編集")
        dlg.geometry("900x500")
        self.analysis_dlg_ref = dlg

        fr = tk.Frame(dlg)
        fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(fr, text="「(先) 指示イベント」と「(後) 適用イベント」のペアを登録します。\nOKを押すと、全タブに対して解析が再実行され、パターンがフィルタ設定に自動追加されます。", anchor="w").pack(fill=tk.X)
        
        l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1)
        l_fr.pack(fill=tk.BOTH, expand=True, pady=5)
        
        hdr = tk.Frame(l_fr)
        hdr.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(hdr, width=120).pack(side=tk.LEFT) 
        tk.Label(hdr, text="解析名", width=20, anchor="w").pack(side=tk.LEFT, padx=5)
        tk.Label(hdr, text="(先) 指示イベント(Trigger)", width=30, anchor="w", fg="#0000aa").pack(side=tk.LEFT, padx=5)
        tk.Label(hdr, text="(後) 適用イベント(Apply)", width=30, anchor="w", fg="#aa0000").pack(side=tk.LEFT, padx=5)

        cv = tk.Canvas(l_fr)
        sc = tk.Scrollbar(l_fr, command=cv.yview)
        sf = tk.Frame(cv)
        cv.configure(yscrollcommand=sc.set)
        sc.pack(side=tk.RIGHT, fill=tk.Y)
        cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        win = cv.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))

        entries = []
        
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, item in enumerate(entries):
                r = tk.Frame(sf)
                r.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(r, variable=item["enabled"]).pack(side=tk.LEFT)
                tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)).pack(side=tk.LEFT)
                tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)).pack(side=tk.LEFT)
                tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                
                tk.Entry(r, textvariable=item["name"], width=20).pack(side=tk.LEFT, padx=5)
                tk.Entry(r, textvariable=item["cmd_pattern"], width=30).pack(side=tk.LEFT, padx=5)
                tk.Entry(r, textvariable=item["vsync_pattern"], width=30).pack(side=tk.LEFT, padx=5)

        def add(data=None):
            item = {
                "enabled": tk.BooleanVar(value=data.get("enabled", True) if data else True),
                "name": tk.StringVar(value=data.get("name", "") if data else ""),
                "cmd_pattern": tk.StringVar(value=data.get("cmd_pattern", "") if data else ""),
                "vsync_pattern": tk.StringVar(value=data.get("vsync_pattern", "") if data else "")
            }
            entries.append(item); refresh()
            
        def delete(i): del entries[i]; refresh()
        def move(i, d): 
            if 0 <= i+d < len(entries): entries[i], entries[i+d] = entries[i+d], entries[i]; refresh()

        if not self.analysis_rules_config: add()
        else:
            for r in self.analysis_rules_config: add(r)

        btn_bar = tk.Frame(fr)
        btn_bar.pack(fill=tk.X, pady=5)
        tk.Button(btn_bar, text="行を追加", command=add).pack(side=tk.LEFT)

        btm_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1)
        btm_fr.pack(fill=tk.X, pady=10, ipady=5)
        tk.Label(btm_fr, text="【共通設定】 時刻抽出パターン (行頭):").pack(side=tk.LEFT, padx=5)
        e_ts = tk.Entry(btm_fr, width=40)
        e_ts.pack(side=tk.LEFT, padx=5)
        e_ts.insert(0, self.analysis_time_pattern or r"^\[?(\d+(?:\.\d+)?)\]?") 

        act_fr = tk.Frame(dlg)
        act_fr.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=10)
        
        def save_and_run():
            new_rules = []
            for item in entries:
                r = {
                    "enabled": item["enabled"].get(),
                    "name": item["name"].get(),
                    "cmd_pattern": item["cmd_pattern"].get(),
                    "vsync_pattern": item["vsync_pattern"].get()
                }
                new_rules.append(r)
            
            self.analysis_rules_config = new_rules
            self.analysis_time_pattern = e_ts.get()
            
            # フィルタ設定への自動追加ロジック
            existing_patterns = set(kw.get("pattern", "") for kw in self.keywords_config)
            
            for rule in new_rules:
                if not rule["enabled"]: continue
                
                cmd_pat = rule["cmd_pattern"].strip()
                if cmd_pat and cmd_pat not in existing_patterns:
                    self.keywords_config.append({
                        "pattern": cmd_pat,
                        "color": "#ffffff",
                        "comment": "",
                        "enabled": True,
                        "extra_lines": 0
                    })
                    existing_patterns.add(cmd_pat)
                
                vsync_pat = rule["vsync_pattern"].strip()
                if vsync_pat and vsync_pat not in existing_patterns:
                    self.keywords_config.append({
                        "pattern": vsync_pat,
                        "color": "#ffffff",
                        "comment": "",
                        "enabled": True,
                        "extra_lines": 0
                    })
                    existing_patterns.add(vsync_pat)
            
            self.save_config_dialog_silent()
            
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab): self.run_analysis_for_tab(w)
                except: pass
            
            dlg.destroy()

        tk.Button(act_fr, text="OK", command=save_and_run, bg="#ddddff", width=15, height=2).pack(side=tk.RIGHT)

    def run_analysis_for_tab(self, tab: LogTab):
        tab.analysis_comments.clear()
        
        rules = [r for r in self.analysis_rules_config if r["enabled"] and r["cmd_pattern"] and r["vsync_pattern"]]
        if not rules:
            self.apply_display_update(tab)
            return

        ts_pat = self.analysis_time_pattern
        try:
            re_ts = re.compile(ts_pat)
            compiled_rules = []
            for r in rules:
                compiled_rules.append({
                    "name": r.get("name", ""),
                    "cmd_re": re.compile(r["cmd_pattern"], re.I),
                    "vsync_re": re.compile(r["vsync_pattern"], re.I)
                })
        except re.error as e:
            print(f"Regex Error in Analysis: {e}")
            self.apply_display_update(tab)
            return

        lines = tab.original_content.splitlines()
        events = []

        for i, line in enumerate(lines):
            ts = 0.0
            m = re_ts.search(line)
            if m: ts = self._parse_time_seconds(m.group(1)) or 0.0

            for rule_idx, rule in enumerate(compiled_rules):
                if rule["cmd_re"].search(line):
                    events.append({'line': i, 'ts': ts, 'type': 0, 'rule': rule_idx})
                if rule["vsync_re"].search(line):
                    events.append({'line': i, 'ts': ts, 'type': 1, 'rule': rule_idx})

        count = 0
        for rule_idx, rule in enumerate(compiled_rules):
            rule_events = [e for e in events if e['rule'] == rule_idx]
            pending_triggers = []

            for ev in rule_events:
                if ev['type'] == 0: 
                    pending_triggers.append(ev)
                elif ev['type'] == 1:
                    if pending_triggers:
                        for trig in pending_triggers:
                            diff_ms = (ev['ts'] - trig['ts']) * 1000.0 if (ev['ts'] > 0 and trig['ts'] > 0) else 0.0
                            prefix = f"[{rule['name']}]" if rule['name'] else ""
                            ts_str = f" (+{diff_ms:.1f}ms)" if diff_ms >= 0 else ""
                            
                            msg_cmd = f"{prefix}--> 適用: [[REF:{ev['line']}]]{ts_str}"
                            old_c = tab.analysis_comments.get(trig['line'], "")
                            tab.analysis_comments[trig['line']] = (old_c + " " + msg_cmd).strip()
                            
                            msg_vsync = f"{prefix}<-- 指示: [[REF:{trig['line']}]]"
                            old_v = tab.analysis_comments.get(ev['line'], "")
                            tab.analysis_comments[ev['line']] = (old_v + " " + msg_vsync).strip()
                            
                            count += 1
                        pending_triggers = []

        self.apply_display_update(tab)
        self.status_var.set(f"解析完了(自動): {count} 件のリンク作成")

    # --- Virtual V-Sync (Settings) ---
    def open_vsync_settings_dialog(self):
        if self.vsync_settings_dlg_ref and self.vsync_settings_dlg_ref.winfo_exists():
            self.vsync_settings_dlg_ref.lift()
            return
        
        dlg = tk.Toplevel(self.root)
        dlg.title("V周期(仮想)挿入の設定")
        dlg.geometry("450x350")
        self.vsync_settings_dlg_ref = dlg
        
        conf = self.vsync_config
        
        tk.Label(dlg, text="V周期(仮想)挿入の基準イベントとタイミングを設定します。\n設定を保存すると、次回ファイルを開く時から自動適用されます。", anchor="w", font=("", 9, "bold")).pack(pady=10, padx=10, fill=tk.X)
        
        tk.Label(dlg, text="基準イベント(正規表現):").pack(anchor="w", padx=10)
        e_pattern = tk.Entry(dlg, width=50)
        e_pattern.pack(padx=10, pady=2)
        e_pattern.insert(0, conf.get("event_pattern", r"V_START|V-Sync"))

        tk.Label(dlg, text="タイムスタンプ抽出(正規表現):").pack(anchor="w", padx=10, pady=(10,0))
        e_ts_pat = tk.Entry(dlg, width=50)
        e_ts_pat.pack(padx=10, pady=2)
        e_ts_pat.insert(0, conf.get("time_pattern", r"^\[?(\d+(?:\.\d+)?)\]?"))

        frame_mode = tk.LabelFrame(dlg, text="間隔設定")
        frame_mode.pack(fill=tk.X, padx=10, pady=10)
        
        mode_var = tk.StringVar(value=conf.get("mode", "auto"))
        rb_auto = tk.Radiobutton(frame_mode, text="自動計算 (最初の2つのイベント間隔を使用)", variable=mode_var, value="auto")
        rb_auto.pack(anchor="w", padx=5, pady=2)
        
        f_manual = tk.Frame(frame_mode)
        f_manual.pack(anchor="w", padx=5, pady=2)
        rb_manual = tk.Radiobutton(f_manual, text="手動指定 (ms):", variable=mode_var, value="manual")
        rb_manual.pack(side=tk.LEFT)
        e_ms = tk.Entry(f_manual, width=10)
        e_ms.pack(side=tk.LEFT, padx=5)
        e_ms.insert(0, str(conf.get("manual_ms", 16.666)))

        def save_conf():
            try: ms = float(e_ms.get())
            except: ms = 16.666
            
            self.vsync_config = {
                "enabled": True, 
                "event_pattern": e_pattern.get(),
                "time_pattern": e_ts_pat.get(),
                "mode": mode_var.get(),
                "manual_ms": ms
            }
            self.save_config_dialog_silent() 
            messagebox.showinfo("保存", "設定を保存しました。次回ファイルオープン時から適用されます。")
            dlg.destroy()

        btn_box = tk.Frame(dlg)
        btn_box.pack(pady=10, fill=tk.X)
        tk.Button(btn_box, text="保存", command=save_conf, bg="#ddddff", width=15).pack(side=tk.RIGHT, padx=10)

    def save_config_dialog_silent(self, filepath=None):
        target_path = filepath if filepath else self.config_path
        data = {
            "keywords": self.keywords_config, 
            "sections": self.sections_config, 
            "replace_patterns": self.replace_patterns_config, 
            "analysis_rules": self.analysis_rules_config,
            "analysis_time_pattern": self.analysis_time_pattern,
            "vsync_auto_insert": self.vsync_config
        }
        try:
            with open(target_path, "w", encoding="utf-8") as f: 
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e: 
            print(f"Config Save Error: {e}")

    def _parse_time_seconds(self, ts_str: str) -> Optional[float]:
        try:
            if ":" in ts_str:
                parts = ts_str.split(":")
                h = int(parts[0])
                m = int(parts[1])
                s = float(parts[2])
                return h * 3600 + m * 60 + s
            else:
                return float(ts_str)
        except:
            return None

    def _process_vsync_insertion(self, content: str, src_map: List[str], src_file_names: List[str]) -> Tuple[str, List[str]]:
        lines = content.splitlines()
        pat = self.vsync_config.get("event_pattern", r"V_START|V-Sync")
        ts_pat = self.vsync_config.get("time_pattern", r"^\[?(\d+(?:\.\d+)?)\]?")
        mode = self.vsync_config.get("mode", "auto")
        manual_ms = self.vsync_config.get("manual_ms", 16.666)
        
        re_event = re.compile(pat, re.I)
        re_ts = re.compile(ts_pat)
        events = []
        is_colon_format = False
        
        for i, line in enumerate(lines):
            if re_event.search(line):
                m = re_ts.search(line)
                if m:
                    ts_str = m.group(1)
                    if ":" in ts_str: is_colon_format = True
                    t = self._parse_time_seconds(ts_str)
                    if t is not None:
                        events.append(t)
                        if mode == "auto" and len(events) >= 2: break 
                        
        if not events: return content, src_map
        
        start_time = events[0]
        interval_sec = 0.016666
        if mode == "manual": interval_sec = manual_ms / 1000.0
        elif len(events) >= 2:
            interval_sec = events[1] - events[0]
            if interval_sec <= 0: interval_sec = 0.016666
            
        new_lines = []
        new_src_map = []
        current_src_map = src_map if len(src_map) == len(lines) else src_map + [""] * (len(lines) - len(src_map))
        next_virtual_ts = start_time + interval_sec
        
        def format_sec(s):
            if is_colon_format:
                h = int(s // 3600)
                m = int((s % 3600) // 60)
                sec = s % 60
                return f"{h:02d}:{m:02d}:{sec:06.3f}"
            else: return f"[{s:.6f}]"
            
        for i, line in enumerate(lines):
            m = re_ts.search(line)
            line_ts = None
            if m: line_ts = self._parse_time_seconds(m.group(1))
            
            if line_ts is not None and line_ts > start_time:
                insertion_count = 0
                while next_virtual_ts < line_ts and insertion_count < 100:
                    new_lines.append(f"{format_sec(next_virtual_ts)} {VSYNC_MARKER}")
                    new_src_map.append(VIRTUAL_SRC_NAME)
                    next_virtual_ts += interval_sec
                    insertion_count += 1
                if insertion_count >= 100: next_virtual_ts = line_ts + interval_sec
                
            new_lines.append(line)
            new_src_map.append(current_src_map[i])
            
        return "\n".join(new_lines), new_src_map

    # --- Filter & Display ---
    def toggle_filter(self):
        self.use_keyword_filter = not self.use_keyword_filter
        self.btn_kw_filter.config(text=f"フィルタ: {'ON' if self.use_keyword_filter else 'OFF'}", bg="#bbdefb" if self.use_keyword_filter else "SystemButtonFace")
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def toggle_vsync_display(self):
        self.show_vsync_lines = not self.show_vsync_lines
        self.btn_vsync_toggle.config(text=f"V周期表示: {'ON' if self.show_vsync_lines else 'OFF'}")
        t = self.get_current_tab()
        if t: self.apply_display_update(t)

    def apply_display_update(self, tab: LogTab):
        data = tab.original_content
        if self.replace_patterns_config: data = self._apply_replacements(data)
        lines = data.splitlines()
        
        line_attrs = [{"color": "#ffffff", "comment": "", "priority": 0} for _ in range(len(lines))]
        
        srcs = tab.line_source_map if tab.line_source_map else (tab.source_file_names * len(lines))
        if len(srcs) < len(lines): srcs.extend([""] * (len(lines) - len(srcs))) 

        section_rules = []
        for s in self.sections_config:
            if s.get("enabled", True):
                try: 
                    fp = s.get("file_pattern", ".*") or ".*"
                    end_pat = s["end"]
                    is_vsync_end = False
                    if end_pat == VSYNC_TAG: 
                        end_pat = VSYNC_REGEX
                        is_vsync_end = True
                        
                    section_rules.append({
                        "start": re.compile(s["start"], re.I),
                        "start_wait": s.get("start_wait", False),
                        "end": re.compile(end_pat, re.I),
                        "end_wait": s.get("end_wait", False),
                        "name": s["name"],
                        "color": s["color"],
                        "file_pat_re": re.compile(fp, re.I),
                        "is_vsync_end": is_vsync_end
                    })
                except: pass

        ts_pat = self.analysis_time_pattern
        try:
            re_ts = re.compile(ts_pat)
        except:
            re_ts = re.compile(r"^\[?(\d+(?:\.\d+)?)\]?")
            
        timestamps = []
        for line in lines:
            m = re_ts.search(line)
            if m:
                timestamps.append(self._parse_time_seconds(m.group(1)))
            else:
                timestamps.append(None)

        active_states = {fn: None for fn in tab.source_file_names}
        status_buffers = {fn: [] for fn in tab.source_file_names}
        
        re_vsync = re.compile(VSYNC_REGEX, re.I)

        for i, line in enumerate(lines):
            line_src = srcs[i]
            is_virtual_line = (line_src == VIRTUAL_SRC_NAME)
            is_vsync_line = (re_vsync.search(line) is not None) or is_virtual_line

            for fn in tab.source_file_names:
                rule_to_display = None
                display_text = ""
                
                state_info = active_states[fn]
                
                if state_info:
                    rule = state_info["rule"]
                    state = state_info["state"]
                    
                    if state == "START_PENDING":
                        if is_vsync_line:
                            state_info["state"] = "ACTIVE"
                            state_info["start_idx"] = i
                            rule_to_display = rule
                            display_text = f"{rule['name']} (開始)"
                    
                    elif state == "ACTIVE":
                        is_end_match = rule["end"].search(line)
                        if is_end_match and (fn == line_src or is_virtual_line or rule["is_vsync_end"]):
                            if rule["end_wait"]:
                                state_info["state"] = "END_PENDING"
                                rule_to_display = rule
                                display_text = rule['name']
                            else:
                                rule_to_display = rule
                                display_text = f"{rule['name']} (終了)"
                                
                                ts_start = timestamps[state_info["start_idx"]]
                                ts_end = timestamps[i]
                                if ts_start is not None and ts_end is not None:
                                    diff_ms = (ts_end - ts_start) * 1000.0
                                    old_txt, col = status_buffers[fn][state_info["start_idx"]]
                                    status_buffers[fn][state_info["start_idx"]] = (f"{old_txt} [{diff_ms:.1f}ms]", col)
                                    
                                active_states[fn] = None
                        else:
                            rule_to_display = rule
                            display_text = rule['name']
                            
                    elif state == "END_PENDING":
                        if is_vsync_line:
                            ts_start = timestamps[state_info["start_idx"]]
                            ts_end = timestamps[i]
                            if ts_start is not None and ts_end is not None:
                                diff_ms = (ts_end - ts_start) * 1000.0
                                old_txt, col = status_buffers[fn][state_info["start_idx"]]
                                status_buffers[fn][state_info["start_idx"]] = (f"{old_txt} [{diff_ms:.1f}ms]", col)
                                
                            active_states[fn] = None
                        else:
                            rule_to_display = rule
                            display_text = rule['name']

                if not rule_to_display and active_states[fn] is None:
                    if fn == line_src: 
                        for rule in section_rules:
                            if rule["file_pat_re"].search(fn) and rule["start"].search(line):
                                if rule["start_wait"]:
                                    active_states[fn] = {
                                        "state": "START_PENDING",
                                        "rule": rule,
                                        "start_idx": -1
                                    }
                                else:
                                    active_states[fn] = {
                                        "state": "ACTIVE",
                                        "rule": rule,
                                        "start_idx": i
                                    }
                                    rule_to_display = rule
                                    display_text = f"{rule['name']} (開始)"
                                    
                                    if not rule["end_wait"] and rule["end"].search(line) and (fn == line_src or is_virtual_line or rule["is_vsync_end"]):
                                        display_text = f"{rule['name']} (開始/終了) [0.0ms]"
                                        active_states[fn] = None
                                    elif rule["end_wait"] and rule["end"].search(line) and (fn == line_src or is_virtual_line or rule["is_vsync_end"]):
                                        active_states[fn]["state"] = "END_PENDING"
                                break

                if rule_to_display: 
                    status_buffers[fn].append((display_text, rule_to_display["color"]))
                else: 
                    status_buffers[fn].append(("", "#ffffff"))

        kw_rules = []
        for itm in self.keywords_config:
            if itm.get("enabled", True):
                try: kw_rules.append({
                        "regex": re.compile(itm["pattern"], re.I),
                        "comment": itm.get("comment", ""),
                        "color": itm.get("color", "#ffffff"),
                        "extra": int(itm.get("extra_lines", 0))
                    })
                except: pass

        for idx in range(len(lines)):
            for rule in kw_rules:
                if rule["regex"].search(lines[idx]):
                    for j in range(idx, min(idx + rule["extra"] + 1, len(lines))):
                        if line_attrs[j]["priority"] < 20:
                            line_attrs[j]["color"] = rule["color"]
                            base_cmt = line_attrs[j]["comment"]
                            new_cmt = rule["comment"]
                            line_attrs[j]["comment"] = f"{base_cmt} {new_cmt}".strip()
                            line_attrs[j]["priority"] = 20
                    break

        visible_mapping = {}
        is_visible = [True] * len(lines)
        display_line_count = 1
        
        for i in range(len(lines)):
            if not self.show_vsync_lines and VSYNC_MARKER in lines[i]:
                is_visible[i] = False
            else:
                attr = line_attrs[i]
                if self.use_keyword_filter:
                    if attr["priority"] == 0: 
                        is_visible[i] = False
                    elif re_vsync.search(lines[i]):
                        is_in_section = any(status_buffers[fn][i][0] != "" for fn in tab.source_file_names)
                        if not is_in_section:
                            is_visible[i] = False
                            
            if is_visible[i]:
                visible_mapping[i] = display_line_count
                display_line_count += 1

        flines, fcmts, ftimediffs = [], [], []
        main_tags = []
        final_st_lines = {fn: [] for fn in tab.source_file_names}
        final_st_tags = {fn: [] for fn in tab.source_file_names}
        
        line_count = 0
        base_ts = None
        
        for i in range(len(lines)):
            if not is_visible[i]:
                continue
            
            if base_ts is None and timestamps[i] is not None:
                base_ts = timestamps[i]
            
            line_count += 1
            flines.append(lines[i])
            s_name = f"[{srcs[i]}] " if (tab.is_merged and srcs[i]) else ""
            
            if timestamps[i] is not None and base_ts is not None:
                ftimediffs.append(f"{(timestamps[i] - base_ts):.6f}")
            else:
                ftimediffs.append("")
            
            base_cmt = f"{s_name}{line_attrs[i]['comment']}"
            ana_cmt = tab.analysis_comments.get(i, "")
            
            if ana_cmt:
                def replacer(match):
                    target_idx = int(match.group(1))
                    disp_num = visible_mapping.get(target_idx)
                    if disp_num is not None:
                        return f"L{disp_num}"
                    else:
                        return f"L{target_idx+1}(非表示)"
                        
                ana_cmt = re.sub(r"\[\[REF:(\d+)\]\]", replacer, ana_cmt)
                
                if base_cmt: 
                    base_cmt += " " + ana_cmt
                else: 
                    base_cmt = ana_cmt
            
            fcmts.append(base_cmt)
            
            if line_attrs[i]["color"] != "#ffffff":
                main_tags.append((line_count, line_attrs[i]["color"]))
            
            for fn in tab.source_file_names:
                txt, col = status_buffers[fn][i]
                final_st_lines[fn].append(txt)
                if col != "#ffffff":
                    final_st_tags[fn].append((line_count, col))
                    
        tab.text.delete("1.0", tk.END)
        tab.text.insert("1.0", "\n".join(flines))
        
        tab.timediff_text.delete("1.0", tk.END)
        tab.timediff_text.insert("1.0", "\n".join(ftimediffs))
        
        tab.comment_text.delete("1.0", tk.END)
        tab.comment_text.insert("1.0", "\n".join(fcmts))
        
        for fn in tab.source_file_names:
            w = tab.status_texts[fn]
            w.delete("1.0", tk.END)
            w.insert("1.0", "\n".join(final_st_lines[fn]))
            
            for tag in w.tag_names():
                 if tag.startswith("st_"): w.tag_delete(tag)
            for ln, col in final_st_tags[fn]:
                tn = f"st_{col.replace('#','')}"
                w.tag_configure(tn, background=col)
                w.tag_add(tn, f"{ln}.0", f"{ln}.end")

        for tag in tab.text.tag_names():
            if tag.startswith("kw_"): tab.text.tag_delete(tag)
        for ln, col in main_tags:
            tn = f"kw_{col.replace('#','')}"
            tab.text.tag_configure(tn, background=col)
            tab.text.tag_add(tn, f"{ln}.0", f"{ln}.end")
            
        tab.linenumbers.redraw()

    def _apply_replacements(self, content: str) -> str:
        for itm in self.replace_patterns_config:
            if itm.get("enabled", True):
                try: content = re.sub(itm["search"], lambda m: f"{m.group(0)}({m.expand(itm['replace'])})", content, flags=re.I)
                except: pass
        return content

    # --- Search Logic ---
    def open_find_dialog(self):
        if self.find_window_ref and self.find_window_ref.winfo_exists():
            self.find_window_ref.lift()
            return

        self.find_window_ref = tk.Toplevel(self.root)
        self.find_window_ref.title("検索")
        self.find_window_ref.geometry("350x120")
        self.find_window_ref.transient(self.root) 

        tk.Label(self.find_window_ref, text="検索文字列:").pack(pady=(10, 0))
        
        entry = tk.Entry(self.find_window_ref, width=40)
        entry.pack(pady=5, padx=10)
        entry.insert(0, self.last_search_keyword)
        entry.select_range(0, tk.END)
        entry.focus_set()

        btn_frame = tk.Frame(self.find_window_ref)
        btn_frame.pack(pady=10)

        def do_find_next():
            self.last_search_keyword = entry.get()
            self.find_next()

        def do_find_prev():
            self.last_search_keyword = entry.get()
            self.find_prev()

        tk.Button(btn_frame, text="次を検索 (Enter)", command=do_find_next).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="前を検索 (Shift+Ent)", command=do_find_prev).pack(side=tk.LEFT, padx=5)

        entry.bind('<Return>', lambda e: do_find_next())
        entry.bind('<Shift-Return>', lambda e: do_find_prev())

    def find_next(self): self._execute_search(backwards=False)
    def find_prev(self): self._execute_search(backwards=True)

    def _execute_search(self, backwards=False):
        tab = self.get_current_tab()
        if not tab or not self.last_search_keyword: return

        start_pos = "insert" if backwards else "insert + 1 chars"
        pos = tab.text.search(self.last_search_keyword, start_pos, stopindex=None, nocase=True, backwards=backwards)

        if pos:
            end_pos = f"{pos}+{len(self.last_search_keyword)}c"
            tab.text.tag_remove("found", "1.0", tk.END)
            tab.text.tag_add("found", pos, end_pos)
            tab.text.tag_raise("found") 
            
            tab.text.mark_set("insert", pos)
            tab.text.see(pos)
            self.status_var.set(f"検索: '{self.last_search_keyword}' が見つかりました。")
        else:
            self.status_var.set(f"検索: '{self.last_search_keyword}' は見つかりませんでした。")

    # --- UI Helpers ---
    def create_preset_menu(self, parent_btn, entry_widget):
        menu = tk.Menu(self.root, tearoff=0)
        presets = [("整数",r"\d+"),("16進",r"0x[0-9A-Fa-f]+"),("IP",r"\d{1,3}(\.\d{1,3}){3}"),("[]内",r"\[.*?\]"),("Key=Val",r"\w+=\S+")]
        for l, r in presets: menu.add_command(label=l, command=lambda t=r: entry_widget.insert(tk.INSERT, t))
        menu.tk_popup(parent_btn.winfo_rootx(), parent_btn.winfo_rooty() + parent_btn.winfo_height())

    def edit_keywords_dialog(self): 
        self._edit_dlg("フィルタ設定の編集 ※正規表現にマッチした行を抽出し、指定の色とコメントを付与します。", "keywords", ["pattern","color","comment","extra_lines"])
        
    def edit_replace_patterns_dialog(self): 
        self._edit_dlg("説明パターンの編集 ※正規表現にマッチした文字列の直後に、 (説明)を付与します。", "replace_patterns", ["search","replace"])
        
    def edit_sections_dialog(self): 
        self._edit_dlg("区間設定の編集 ※ファイル毎に開始～終了パターンを定義して色分けします。", "sections", ["file_pattern", "name", "start", "start_wait", "end", "end_wait", "color"])

    def _edit_dlg(self, title, key, fields):
        ref_attr = f"{key}_dlg_ref"
        ref = getattr(self, ref_attr, None)
        if ref and ref.winfo_exists():
            ref.lift()
            return
        
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.geometry("1150x500")
        setattr(self, ref_attr, dlg)
        
        fr = tk.Frame(dlg)
        fr.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        l_fr = tk.Frame(fr, relief=tk.GROOVE, borderwidth=1)
        l_fr.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        hdr = tk.Frame(l_fr)
        hdr.pack(fill=tk.X, padx=5, pady=2)
        tk.Frame(hdr, width=135).pack(side=tk.LEFT)
        
        if "file_pattern" in fields: tk.Label(hdr, text="対象ファイル(正規表現)", width=20, anchor="w").pack(side=tk.LEFT)
        if "pattern" in fields: tk.Label(hdr, text="正規表現", width=25, anchor="w").pack(side=tk.LEFT)
        if "search" in fields: tk.Label(hdr, text="検索文字列", width=25, anchor="w").pack(side=tk.LEFT)
        if "name" in fields: tk.Label(hdr, text="区間名", width=15, anchor="w").pack(side=tk.LEFT)
        
        if "start" in fields: tk.Label(hdr, text="開始パターン", width=15, anchor="w").pack(side=tk.LEFT)
        if "start_wait" in fields: tk.Label(hdr, text="V待", width=4).pack(side=tk.LEFT)
        if "end" in fields: tk.Label(hdr, text="終了パターン", width=15, anchor="w").pack(side=tk.LEFT)
        if "end_wait" in fields: tk.Label(hdr, text="V待", width=4).pack(side=tk.LEFT)
        
        if "color" in fields: tk.Label(hdr, text="色", width=10).pack(side=tk.LEFT, padx=15)
        if "replace" in fields: tk.Label(hdr, text="置換/説明", width=30).pack(side=tk.LEFT, padx=5)
        if "comment" in fields: tk.Label(hdr, text="コメント", width=20).pack(side=tk.LEFT, padx=5)
        if "extra_lines" in fields: tk.Label(hdr, text="+行", width=5).pack(side=tk.LEFT)

        cv = tk.Canvas(l_fr)
        sc = tk.Scrollbar(l_fr, command=cv.yview)
        sf = tk.Frame(cv)
        cv.configure(yscrollcommand=sc.set)
        sc.pack(side=tk.RIGHT, fill=tk.Y)
        cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        win = cv.create_window((0,0), window=sf, anchor="nw")
        sf.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))

        entries = []
        def refresh():
            for w in sf.winfo_children(): w.destroy()
            for i, item in enumerate(entries):
                r = tk.Frame(sf)
                r.pack(fill=tk.X, pady=2, padx=5)
                tk.Checkbutton(r, variable=item["enabled"]).pack(side=tk.LEFT)
                tk.Button(r, text="↑", width=2, command=lambda idx=i: move(idx, -1)).pack(side=tk.LEFT)
                tk.Button(r, text="↓", width=2, command=lambda idx=i: move(idx, 1)).pack(side=tk.LEFT)
                tk.Button(r, text="削除", width=3, command=lambda idx=i: delete(idx)).pack(side=tk.LEFT, padx=2)
                
                if "file_pattern" in fields:
                    tk.Entry(r, textvariable=item["file_pattern"], width=20).pack(side=tk.LEFT, padx=2)
                if "pattern" in fields:
                    tk.Entry(r, textvariable=item["pattern"], width=25).pack(side=tk.LEFT, padx=2)
                if "search" in fields:
                    tk.Entry(r, textvariable=item["search"], width=25).pack(side=tk.LEFT, padx=2)
                if "name" in fields:
                    tk.Entry(r, textvariable=item["name"], width=15).pack(side=tk.LEFT, padx=2)
                    
                if "start" in fields:
                    tk.Entry(r, textvariable=item["start"], width=15).pack(side=tk.LEFT, padx=2)
                if "start_wait" in fields:
                    tk.Checkbutton(r, variable=item["start_wait"]).pack(side=tk.LEFT, padx=2)
                    
                if "end" in fields:
                    tk.Entry(r, textvariable=item["end"], width=15).pack(side=tk.LEFT, padx=2)
                    if key == "sections":
                         tk.Button(r, text="<V>", width=3, command=lambda v=item["end"]: v.set(VSYNC_TAG), bg="#e1bee7").pack(side=tk.LEFT, padx=1)
                if "end_wait" in fields:
                    tk.Checkbutton(r, variable=item["end_wait"]).pack(side=tk.LEFT, padx=2)
                
                if "color" in fields:
                    tk.Entry(r, textvariable=item["color"], width=8).pack(side=tk.LEFT, padx=15)
                    tk.Button(r, text="色", command=lambda v=item["color"]: v.set(colorchooser.askcolor(v.get())[1] or v.get())).pack(side=tk.LEFT)
                
                if "replace" in fields:
                    tk.Entry(r, textvariable=item["replace"], width=30).pack(side=tk.LEFT, padx=5)
                if "comment" in fields:
                    tk.Entry(r, textvariable=item["comment"], width=20).pack(side=tk.LEFT, padx=5)
                if "extra_lines" in fields:
                    tk.Entry(r, textvariable=item["extra_lines"], width=4).pack(side=tk.LEFT, padx=5)

        def add(data=None):
            item = {"enabled": tk.BooleanVar(value=data.get("enabled", True) if data else True)}
            for f in fields:
                if f in ["start_wait", "end_wait"]:
                    item[f] = tk.BooleanVar(value=data.get(f, False) if data else False)
                else:
                    item[f] = tk.StringVar(value=str(data.get(f, "0" if f=="extra_lines" else "")) if data else ("0" if f=="extra_lines" else ""))
            entries.append(item)
            refresh()
            
        def delete(i): 
            del entries[i]
            refresh()
            
        def move(i, d): 
            if 0 <= i+d < len(entries): 
                entries[i], entries[i+d] = entries[i+d], entries[i]
                refresh()

        cfg = getattr(self, f"{key}_config")
        for c in cfg: add(c)
        if not entries: add()

        btn_fr = tk.Frame(fr)
        btn_fr.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        tk.Button(btn_fr, text="行を追加", command=add, width=10).pack(pady=5)
        
        def save():
            new_cfg = []
            for item in entries:
                valid = False
                for k in ["pattern", "search", "start"]:
                    if k in fields and item[k].get(): valid = True
                if valid:
                    d = {f: item[f].get() for f in fields}
                    d["enabled"] = item["enabled"].get()
                    new_cfg.append(d)
            
            setattr(self, f"{key}_config", new_cfg)
            self.save_config_dialog_silent()
            dlg.destroy()
            for tab_id in self.notebook.tabs():
                try:
                    w = self.notebook.nametowidget(tab_id)
                    if isinstance(w, LogTab): self.apply_display_update(w)
                except: pass

        tk.Button(btn_fr, text="OK", command=save, width=10, bg="#ddd").pack(side=tk.BOTTOM, pady=5)

    # --- IO ---
    def load_config_dialog(self):
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if p: self.load_config(p)
        
    def save_config_dialog(self):
        p = filedialog.asksaveasfilename(defaultextension=".json")
        if p: 
            self.save_config_dialog_silent(p)
            messagebox.showinfo("完了", "設定を保存しました。")
        
    def load_config(self, p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
                self.keywords_config = d.get("keywords", [])
                self.sections_config = d.get("sections", [])
                self.replace_patterns_config = d.get("replace_patterns", [])
                self.analysis_rules_config = d.get("analysis_rules", [])
                self.analysis_time_pattern = d.get("analysis_time_pattern", self.analysis_time_pattern)
                self.vsync_config = d.get("vsync_auto_insert", self.vsync_config)
            t = self.get_current_tab()
            if t: self.run_analysis_for_tab(t)
        except: pass

    def export_to_excel(self):
        tab = self.get_current_tab()
        if not tab: return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not p: return
        try:
            l = tab.text.get("1.0", "end-1c").splitlines()
            c = tab.comment_text.get("1.0", "end-1c").splitlines()
            td = tab.timediff_text.get("1.0", "end-1c").splitlines()
            srcs = tab.line_source_map if tab.is_merged else tab.source_file_names * len(l)
            if len(srcs) < len(l): srcs.extend([""] * (len(l) - len(srcs))) 
            
            section_rules = []
            for s in self.sections_config:
                if s.get("enabled", True):
                    fp = s.get("file_pattern", ".*") or ".*"
                    end_pat = s["end"]
                    is_vsync_end = False
                    if end_pat == VSYNC_TAG: 
                        end_pat = VSYNC_REGEX
                        is_vsync_end = True
                    section_rules.append({
                        "start": re.compile(s["start"], re.I),
                        "end": re.compile(end_pat, re.I),
                        "name": s["name"],
                        "color": s["color"],
                        "file_pat_re": re.compile(fp, re.I),
                        "is_vsync_end": is_vsync_end
                    })
                    
            active_states = {fn: None for fn in tab.source_file_names}
            status_buffers = {fn: [] for fn in tab.source_file_names}
            
            for i, line in enumerate(l):
                line_src = srcs[i]
                is_virtual_line = (line_src == VIRTUAL_SRC_NAME)
                for fn in tab.source_file_names:
                    rule_to_display = None
                    display_text = ""
                    
                    if active_states[fn]:
                        is_end_match = active_states[fn]["end"].search(line)
                        if is_end_match and (fn == line_src or is_virtual_line or active_states[fn]["is_vsync_end"]): 
                            rule_to_display = active_states[fn]
                            display_text = f"{rule_to_display['name']} (終了)"
                            active_states[fn] = None 
                        else: 
                            rule_to_display = active_states[fn]
                            display_text = rule_to_display['name']
                            
                    if not rule_to_display and not active_states[fn] and fn == line_src:
                        for rule in section_rules:
                            if rule["file_pat_re"].search(fn) and rule["start"].search(line):
                                rule_to_display = rule
                                display_text = f"{rule['name']} (開始)"
                                active_states[fn] = rule
                                if rule["end"].search(line) and (fn == line_src or is_virtual_line or rule["is_vsync_end"]): 
                                    display_text = f"{rule['name']} (開始/終了)"
                                    active_states[fn] = None
                                break
                    
                    gui_txt = tab.status_texts[fn].get(f"{i+1}.0", f"{i+1}.end")
                    status_buffers[fn].append((gui_txt, rule_to_display["color"] if rule_to_display else "#ffffff"))
                    
            colors = ["#ffffff"] * len(l)
            k_rules = []
            for it in self.keywords_config:
                if it["enabled"]: k_rules.append((re.compile(it["pattern"], re.I), it["color"], int(it["extra_lines"])))
            for i in range(len(l)):
                for pat, col, ext in k_rules:
                    if pat.search(l[i]):
                        for j in range(i, min(i+ext+1, len(l))): colors[j] = col
                        break
                        
            h = ['<html><head><meta charset="utf-8"><style>table{border-collapse:collapse;width:100%;font-family:monospace;} th{background:#ddd;border:1px solid #999;} td{border:1px solid #ccc;padding:2px 4px;white-space:pre-wrap;}</style></head><body><table>']
            header_row = '<thead><tr><th>Line</th><th>Time Diff</th><th>Log Content</th><th>Comment</th>'
            for fn in tab.source_file_names: header_row += f'<th>{html.escape(fn)}の区間</th>'
            h.append(header_row + '</tr></thead><tbody>')
            
            for i, line in enumerate(l):
                bg_color = "transparent"
                tags = tab.text.tag_names(f"{i+1}.0")
                for tag in tags:
                    if tag.startswith("kw_"):
                        bg_color = f"#{tag[3:]}"
                        break
                        
                cm = c[i] if i < len(c) else ""
                diff_str = td[i] if i < len(td) else ""
                row_html = f'<tr style="background:{bg_color}"><td>{i+1}</td><td>{html.escape(diff_str)}</td><td>{html.escape(line)}</td><td>{html.escape(cm)}</td>'
                
                for fn in tab.source_file_names:
                    txt, col = status_buffers[fn][i]
                    row_html += f'<td style="background:{col if col != "#ffffff" else "transparent"}">{html.escape(txt)}</td>'
                h.append(row_html + '</tr>')
                
            with open(p, "w", encoding="utf-8-sig") as f: f.write("\n".join(h) + "</tbody></table></body></html>")
            messagebox.showinfo("完了", "保存しました")
        except Exception as e: messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = ROOT_CLASS()
    app = LogViewerApp(root)
    root.mainloop()